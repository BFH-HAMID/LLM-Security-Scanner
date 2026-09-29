"""Anthropic Messages API connector."""

from __future__ import annotations

from typing import Any

import httpx

from scanner.connectors.base import mask_secret
from scanner.connectors.configs import AnthropicTarget
from scanner.connectors.httpbase import HTTPConnectorBase
from scanner.connectors.toolcalls import parse_tool_calls
from scanner.models import Message, TargetResponse


class AnthropicConnector(HTTPConnectorBase):
    kind = "anthropic"
    supports_tools = True

    def __init__(self, cfg: AnthropicTarget, *, transport: httpx.AsyncBaseTransport | None = None):
        headers = {"anthropic-version": cfg.anthropic_version, "content-type": "application/json"}
        headers.update(cfg.headers)
        if cfg.api_key:
            headers.setdefault("x-api-key", cfg.api_key)
        super().__init__(
            name=cfg.name,
            timeout=cfg.timeout,
            verify_tls=cfg.verify_tls,
            headers=headers,
            transport=transport,
            max_response_chars=cfg.max_response_chars,
        )
        self.cfg = cfg
        self.url = cfg.base_url.rstrip("/") + "/v1/messages"

    def build_body(self, messages: list[Message], tools: Any) -> dict[str, Any]:
        cfg = self.cfg
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        convo: list[dict[str, str]] = []
        for m in messages:
            if m.role == "system":
                continue
            role = "assistant" if m.role == "assistant" else "user"
            if convo and convo[-1]["role"] == role:  # the API requires alternating roles
                convo[-1]["content"] += "\n\n" + m.content
            else:
                convo.append({"role": role, "content": m.content})
        if not convo or convo[0]["role"] != "user":
            convo.insert(0, {"role": "user", "content": "."})
        body: dict[str, Any] = {"model": cfg.model, "max_tokens": cfg.max_tokens, "messages": convo}
        if system:
            body["system"] = system
        if cfg.temperature is not None:
            body["temperature"] = cfg.temperature
        if tools:
            body["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in tools
            ]
        return body

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        resp, err, ms = await self._do("POST", self.url, json_body=self.build_body(messages, tools))
        if err is not None:
            return err
        assert resp is not None
        try:
            data = resp.json()
            blocks = data["content"]
        except (ValueError, KeyError, TypeError):
            return TargetResponse(
                error=f"unexpected response shape from {self.url}: {resp.text[:200]!r}",
                status_code=resp.status_code,
                latency_ms=ms,
            )
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        tool_uses = [b for b in blocks if b.get("type") == "tool_use"]
        return TargetResponse(
            text=self.truncate(text),
            tool_calls=parse_tool_calls(tool_uses),
            status_code=resp.status_code,
            latency_ms=ms,
            usage=data.get("usage"),
            meta={"stop_reason": data.get("stop_reason"), "model": data.get("model")},
            raw=data,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "type": "anthropic",
            "name": self.name,
            "base_url": self.cfg.base_url,
            "model": self.cfg.model,
            "api_key": mask_secret(self.cfg.api_key or ""),
        }
