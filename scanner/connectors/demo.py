"""In-process connector for the bundled vulnerable demo app (no server or network needed)."""

from __future__ import annotations

import time
from typing import Any

from scanner.connectors.base import Connector
from scanner.connectors.configs import DemoTarget
from scanner.models import TargetResponse, ToolCall


class DemoConnector(Connector):
    kind = "demo"
    supports_history = True

    def __init__(self, cfg: DemoTarget, *, app: Any | None = None):
        from targets.vulnerable_app.core import DemoApp

        self.cfg = cfg
        self.name = cfg.name if cfg.name != "target" else f"demo-{cfg.surface}-{cfg.level}"
        self.app = app or DemoApp(cfg.level)
        self.supports_ingest = cfg.surface == "rag"

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        convo = [m for m in messages if m.role in ("user", "assistant")]
        if not convo or convo[-1].role != "user":
            return TargetResponse(error="conversation must end with a user message")
        history = [{"role": m.role, "content": m.content} for m in convo[:-1]]
        message = convo[-1].content
        start = time.perf_counter()
        try:
            if self.cfg.surface == "rag":
                out = self.app.rag_chat(message, conversation_id, history or None)
            elif self.cfg.surface == "agent":
                out = self.app.agent_chat(message, conversation_id, history or None)
            else:
                out = self.app.chat(message, conversation_id, history or None)
        except Exception as exc:
            return TargetResponse(error=f"demo app error: {type(exc).__name__}: {exc}")
        calls = [
            ToolCall(
                name=c["name"],
                arguments=c["arguments"],
                result=c.get("result"),
                blocked=bool(c.get("blocked")),
            )
            for c in out.tool_calls
        ]
        return TargetResponse(
            text=out.reply,
            tool_calls=calls,
            status_code=200,
            latency_ms=(time.perf_counter() - start) * 1000,
            meta={"conversation_id": out.conversation_id, "blocked": out.blocked},
        )

    async def ingest(
        self, title: str, content: str, *, conversation_id: str | None = None
    ) -> str | None:
        return self.app.ingest(title, content, conversation_id)

    async def remove_document(self, document_id: str) -> None:
        self.app.remove_document(document_id)

    def describe(self) -> dict[str, Any]:
        return {
            "kind": "demo",
            "name": self.name,
            "level": self.cfg.level,
            "surface": self.cfg.surface,
            "in_process": True,
        }
