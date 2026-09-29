"""Ollama native chat connector (``/api/chat``)."""

from __future__ import annotations

from typing import Any

import httpx

from scanner.connectors.configs import OllamaTarget
from scanner.connectors.httpbase import HTTPConnectorBase
from scanner.connectors.toolcalls import parse_tool_calls
from scanner.models import Message, TargetResponse


class OllamaConnector(HTTPConnectorBase):
    kind = "ollama"
    supports_tools = True

    def __init__(self, cfg: OllamaTarget, *, transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(
            name=cfg.name,
            timeout=cfg.timeout,
            verify_tls=cfg.verify_tls,
            transport=transport,
            max_response_chars=cfg.max_response_chars,
        )
        self.cfg = cfg
        self.url = cfg.base_url.rstrip("/") + "/api/chat"

    def build_body(self, messages: list[Message], tools: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
        }
        if self.cfg.options:
            body["options"] = self.cfg.options
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
        return body

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        resp, err, ms = await self._do("POST", self.url, json_body=self.build_body(messages, tools))
        if err is not None:
            return err
        assert resp is not None
        try:
            data = resp.json()
            message = data["message"]
        except (ValueError, KeyError, TypeError):
            return TargetResponse(
                error=f"unexpected response shape from {self.url}: {resp.text[:200]!r}",
                status_code=resp.status_code,
                latency_ms=ms,
            )
        usage = {
            "prompt_tokens": data.get("prompt_eval_count"),
            "completion_tokens": data.get("eval_count"),
        }
        return TargetResponse(
            text=self.truncate(message.get("content") or ""),
            tool_calls=parse_tool_calls(message.get("tool_calls")),
            status_code=resp.status_code,
            latency_ms=ms,
            usage=usage,
            meta={"model": data.get("model"), "done_reason": data.get("done_reason")},
            raw=data,
        )

    def describe(self) -> dict[str, Any]:
        return {
            "kind": "ollama",
            "name": self.name,
            "base_url": self.cfg.base_url,
            "model": self.cfg.model,
        }
