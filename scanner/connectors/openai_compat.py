"""OpenAI and OpenAI-compatible chat-completions connector."""

from __future__ import annotations

from typing import Any

import httpx

from scanner.connectors.base import mask_mapping, mask_secret
from scanner.connectors.configs import OpenAITarget
from scanner.connectors.httpbase import HTTPConnectorBase
from scanner.connectors.toolcalls import parse_tool_calls
from scanner.models import Message, TargetResponse


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content parts
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


class OpenAIConnector(HTTPConnectorBase):
    kind = "openai"
    supports_tools = True

    def __init__(self, cfg: OpenAITarget, *, transport: httpx.AsyncBaseTransport | None = None):
        headers = dict(cfg.headers)
        if cfg.api_key:
            headers.setdefault("Authorization", f"Bearer {cfg.api_key}")
        super().__init__(
            name=cfg.name,
            timeout=cfg.timeout,
            verify_tls=cfg.verify_tls,
            headers=headers,
            transport=transport,
            max_response_chars=cfg.max_response_chars,
        )
        self.cfg = cfg
        self.url = cfg.base_url.rstrip("/") + "/chat/completions"

    def build_body(self, messages: list[Message], tools: Any) -> dict[str, Any]:
        cfg = self.cfg
        body: dict[str, Any] = {
            "model": cfg.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if cfg.temperature is not None:
            body["temperature"] = cfg.temperature
        if cfg.max_tokens:
            body[cfg.max_tokens_param] = cfg.max_tokens
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]
        body.update(cfg.extra_body)
        return body

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        resp, err, ms = await self._do("POST", self.url, json_body=self.build_body(messages, tools))
        if err is not None:
            return err
        assert resp is not None
        try:
            data = resp.json()
            choice = data["choices"][0]
            message = choice.get("message") or {}
        except (ValueError, KeyError, IndexError, TypeError):
            return TargetResponse(
                error=f"unexpected response shape from {self.url}: {resp.text[:200]!r}",
                status_code=resp.status_code,
                latency_ms=ms,
            )
        text = _content_text(message.get("content")) or _content_text(message.get("refusal"))
        return TargetResponse(
            text=self.truncate(text),
            tool_calls=parse_tool_calls(message.get("tool_calls")),
            status_code=resp.status_code,
            latency_ms=ms,
            usage=data.get("usage"),
            meta={"finish_reason": choice.get("finish_reason"), "model": data.get("model")},
            raw=data,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "kind": "openai",
            "name": self.name,
            "base_url": self.cfg.base_url,
            "model": self.cfg.model,
            "api_key": mask_secret(self.cfg.api_key or ""),
            "headers": mask_mapping(self.cfg.headers),
        }
