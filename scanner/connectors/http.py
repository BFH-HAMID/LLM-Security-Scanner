"""Custom HTTP connector driven by a request template."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

import httpx

from scanner.connectors.base import mask_mapping, mask_secret
from scanner.connectors.configs import AuthConfig, HTTPTarget
from scanner.connectors.httpbase import HTTPConnectorBase
from scanner.connectors.jsonpath import MISSING, as_text, extract
from scanner.connectors.toolcalls import parse_tool_calls
from scanner.models import Message, TargetResponse
from scanner.templating import render

_WHOLE = re.compile(r"^\s*\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}\s*$")


def render_template(template: Any, variables: dict[str, Any]) -> Any:
    """Render a JSON-ish template. A string that is exactly ``{{name}}`` keeps the raw value's
    type (list, dict, None); placeholders embedded in longer strings are stringified."""
    if isinstance(template, str):
        m = _WHOLE.match(template)
        if m and m.group(1) in variables:
            return variables[m.group(1)]
        flat = {
            k: v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            for k, v in variables.items()
        }
        return render(template, flat, strict=False)
    if isinstance(template, dict):
        return {k: render_template(v, variables) for k, v in template.items()}
    if isinstance(template, list):
        return [render_template(v, variables) for v in template]
    return template


def auth_headers(auth: AuthConfig | None) -> dict[str, str]:
    if auth is None or auth.type == "none":
        return {}
    if auth.type == "bearer":
        return {"Authorization": f"Bearer {auth.token or ''}"}
    if auth.type == "basic":
        import base64

        raw = f"{auth.username or ''}:{auth.password or ''}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return {auth.header or "X-API-Key": auth.value or ""}


def parse_sse(text: str, path: str) -> str:
    """Concatenate the ``path`` value of every JSON ``data:`` event (plain-text events kept)."""
    parts: list[str] = []
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in ("", "[DONE]"):
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            parts.append(payload)
            continue
        value = extract(obj, path, default=MISSING)
        if value is not MISSING:
            parts.append(as_text(value))
    return "".join(parts)


class HTTPConnector(HTTPConnectorBase):
    kind = "http"

    def __init__(self, cfg: HTTPTarget, *, transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(
            name=cfg.name,
            timeout=cfg.timeout,
            verify_tls=cfg.verify_tls,
            headers={**cfg.headers, **auth_headers(cfg.auth)},
            transport=transport,
            max_response_chars=cfg.max_response_chars,
        )
        self.cfg = cfg
        self.supports_history = cfg.sends_history
        self.supports_tools = "tools" in _placeholders(cfg.body)
        self.supports_ingest = cfg.ingest is not None
        self._server_ids: dict[str, str] = {}

    # ------------------------------------------------------------------ send

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        cid = conversation_id or uuid.uuid4().hex
        variables = self._variables(messages, tools, cid)
        cfg = self.cfg
        url = render(
            cfg.url,
            {k: str(v) for k, v in variables.items() if not isinstance(v, (list, dict))},
            strict=False,
        )
        body = render_template(cfg.body, variables) if cfg.body is not None else None
        params = {k: str(render_template(v, variables)) for k, v in cfg.query.items()}
        kwargs: dict[str, Any] = {}
        if cfg.method != "GET" and body is not None:
            if cfg.body_format == "json":
                kwargs["json_body"] = body
            elif cfg.body_format == "form":
                kwargs["data"] = {
                    k: v if isinstance(v, str) else json.dumps(v) for k, v in dict(body).items()
                }
            else:
                kwargs["content"] = body if isinstance(body, str) else json.dumps(body)
        resp, err, ms = await self._do(cfg.method, url, params=params or None, **kwargs)
        if err is not None:
            return err
        assert resp is not None
        return self._parse(resp, ms, cid)

    def _variables(self, messages: list[Message], tools: Any, cid: str) -> dict[str, Any]:
        msg_dicts = [{"role": m.role, "content": m.content} for m in messages]
        last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        system = next((m.content for m in messages if m.role == "system"), "")
        history = [d for d in msg_dicts if d["role"] != "system"][:-1]
        server_cid = self._server_ids.get(cid, cid)
        tool_dicts = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in (tools or [])
        ]
        return {
            "prompt": last_user,
            "messages": msg_dicts,
            "history": history,
            "system": system,
            "conversation_id": server_cid,
            "tools": tool_dicts,
        }

    def _parse(self, resp: httpx.Response, ms: float, cid: str) -> TargetResponse:
        cfg = self.cfg
        tool_calls = []
        meta: dict[str, Any] = {"conversation_id": cid}
        raw: Any = None
        if cfg.response_format == "text":
            text = resp.text
        elif cfg.response_format == "sse":
            text = parse_sse(resp.text, cfg.response_path)
        else:
            try:
                raw = resp.json()
            except ValueError:
                snippet = resp.text.strip().replace("\n", " ")[:200]
                return TargetResponse(
                    error=f"response is not JSON (response_format=json): {snippet!r}",
                    status_code=resp.status_code,
                    latency_ms=ms,
                )
            value = extract(raw, cfg.response_path, default=MISSING)
            if value is MISSING:
                snippet = json.dumps(raw, ensure_ascii=False)[:300]
                return TargetResponse(
                    error=f"response_path {cfg.response_path!r} matched nothing in: {snippet}",
                    status_code=resp.status_code,
                    latency_ms=ms,
                    raw=raw,
                )
            text = as_text(value)
            if cfg.tool_calls_path:
                tool_calls = parse_tool_calls(extract(raw, cfg.tool_calls_path, default=None))
            if cfg.conversation_id_path:
                sid = extract(raw, cfg.conversation_id_path, default=None)
                if sid:
                    self._server_ids[cid] = str(sid)
                    meta["server_conversation_id"] = str(sid)
        return TargetResponse(
            text=self.truncate(text),
            tool_calls=tool_calls,
            status_code=resp.status_code,
            latency_ms=ms,
            meta=meta,
            raw=raw,
        )

    # ---------------------------------------------------------------- ingestion

    async def ingest(
        self, title: str, content: str, *, conversation_id: str | None = None
    ) -> str | None:
        ing = self.cfg.ingest
        if ing is None:
            raise NotImplementedError("this target has no ingest endpoint configured")
        variables = {"title": title, "content": content, "conversation_id": conversation_id or ""}
        resp, err, _ = await self._do(
            ing.method,
            ing.url,
            headers=ing.headers,
            json_body=render_template(ing.body, variables),
        )
        if err is not None:
            raise RuntimeError(f"ingest failed: {err.error}")
        assert resp is not None
        if ing.id_path:
            try:
                value = extract(resp.json(), ing.id_path, default=None)
            except ValueError:
                value = None
            return None if value is None else str(value)
        return None

    async def remove_document(self, document_id: str) -> None:
        ing = self.cfg.ingest
        if ing is None or not ing.delete_url or not document_id:
            return
        url = render(ing.delete_url, {"document_id": document_id}, strict=False)
        await self._do(ing.delete_method, url, headers=ing.headers)

    def describe(self) -> dict[str, Any]:
        cfg = self.cfg
        return {
            "kind": "http",
            "name": self.name,
            "url": cfg.url,
            "method": cfg.method,
            "headers": mask_mapping({**cfg.headers, **auth_headers(cfg.auth)}),
            "response_path": cfg.response_path,
            "history": self.supports_history,
            "ingest": bool(cfg.ingest),
            "auth": cfg.auth.type if cfg.auth else "none",
            **({"token": mask_secret(cfg.auth.token)} if cfg.auth and cfg.auth.token else {}),
        }


def _placeholders(obj: Any) -> set[str]:
    from scanner.connectors.configs import _flatten_placeholders

    return _flatten_placeholders(obj)
