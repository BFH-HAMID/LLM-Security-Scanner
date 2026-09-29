"""FastAPI surface of the demo app.

Routes are mounted once per defence level (``/weak``, ``/medium``, ``/hardened``) and the level
in ``TARGET_LEVEL`` (default ``weak``) is also served at the root. Each level has its own state.

    uvicorn targets.vulnerable_app.main:app --port 9000
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from targets.vulnerable_app.backends import make_backend
from targets.vulnerable_app.core import ChatOutcome, DemoApp, Level
from targets.vulnerable_app.tools import TOOL_SPECS


class HistoryItem(BaseModel):
    role: str
    content: str


class ChatIn(BaseModel):
    message: str = Field(max_length=20_000)
    conversation_id: str | None = None
    history: list[HistoryItem] | None = None


class IngestIn(BaseModel):
    title: str = "Untitled"
    content: str = Field(max_length=200_000)
    conversation_id: str | None = None


class OpenAIChatIn(BaseModel):
    model: str = "simulated"
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None


UI_HTML = """<!doctype html><meta charset=utf-8><title>AcmeCorp HelpBot ({level})</title>
<style>body{{font:15px system-ui;max-width:640px;margin:2rem auto}}#log div{{margin:.4rem 0;padding:.4rem .6rem;border-radius:6px;background:#f1f5f9}}
.me{{background:#dbeafe!important}}</style>
<h2>AcmeCorp HelpBot <small>({level})</small></h2><div id=log></div>
<form id=f><input id=m style="width:80%" placeholder="Ask about your order"> <button>Send</button></form>
<script>
const level = {level!r};
f.onsubmit = async (e) => {{
  e.preventDefault(); const text = m.value; m.value = "";
  const me = document.createElement("div"); me.className = "me"; me.textContent = text; log.append(me);
  const r = await fetch("chat", {{method: "POST", headers: {{"content-type": "application/json"}}, body: JSON.stringify({{message: text}})}});
  const j = await r.json(); const bot = document.createElement("div");
  // Deliberate insecure-output-handling sink below (unless hardened): model output is rendered as HTML.
  if (level === "hardened") bot.textContent = j.reply; else bot.innerHTML = j.reply;
  log.append(bot);
}};
</script>"""


def build_router(demo: DemoApp) -> APIRouter:
    r = APIRouter()

    def chat_payload(o: ChatOutcome) -> dict[str, Any]:
        return {"reply": o.reply, "conversation_id": o.conversation_id, "blocked": o.blocked}

    @r.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "level": demo.level.value, "backend": demo.backend.name}

    @r.post("/chat")
    def chat(body: ChatIn) -> dict[str, Any]:
        history = [h.model_dump() for h in body.history] if body.history else None
        return chat_payload(demo.chat(body.message, body.conversation_id, history))

    @r.post("/v1/chat/completions")
    def completions(body: OpenAIChatIn) -> dict[str, Any]:
        o = demo.complete(body.messages, body.tools)
        message: dict[str, Any] = {"role": "assistant", "content": o.reply or None}
        if o.tool_calls:
            import json

            message["tool_calls"] = [
                {
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])},
                }
                for i, c in enumerate(o.tool_calls)
            ]
        return {
            "id": f"chatcmpl-{o.conversation_id[:12]}",
            "object": "chat.completion",
            "model": demo.backend.name,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls" if o.tool_calls else "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    @r.post("/rag/chat")
    def rag_chat(body: ChatIn) -> dict[str, Any]:
        history = [h.model_dump() for h in body.history] if body.history else None
        o = demo.rag_chat(body.message, body.conversation_id, history)
        return {**chat_payload(o), "sources": o.sources}

    @r.post("/rag/ingest")
    def rag_ingest(body: IngestIn) -> dict[str, str]:
        return {"id": demo.ingest(body.title, body.content, body.conversation_id)}

    @r.get("/rag/documents")
    def rag_documents() -> list[dict[str, str]]:
        return [{"id": d.id, "title": d.title, "acl": d.acl} for d in demo.store.docs]

    @r.delete("/rag/documents/{doc_id}")
    def rag_delete(doc_id: str) -> dict[str, bool]:
        if not demo.remove_document(doc_id):
            raise HTTPException(404, "no such document")
        return {"deleted": True}

    @r.post("/agent/chat")
    def agent_chat(body: ChatIn) -> dict[str, Any]:
        history = [h.model_dump() for h in body.history] if body.history else None
        o = demo.agent_chat(body.message, body.conversation_id, history)
        return {**chat_payload(o), "tool_calls": o.tool_calls}

    @r.get("/agent/tools")
    def agent_tools() -> list[dict[str, Any]]:
        return TOOL_SPECS

    @r.get("/agent/state")
    def agent_state() -> dict[str, Any]:
        return demo.sandbox.state()

    @r.post("/agent/reset")
    def agent_reset() -> dict[str, str]:
        demo.sandbox.reset()
        return {"status": "reset"}

    @r.get("/ui", response_class=HTMLResponse)
    def ui() -> str:
        return UI_HTML.format(level=demo.level.value)

    return r


def create_app(default_level: str | None = None) -> FastAPI:
    app = FastAPI(
        title="AcmeCorp HelpBot (deliberately vulnerable demo)",
        description="Target for llm-security-scanner. Intentionally insecure — never expose publicly.",
        version="0.1.0",
    )
    backend = make_backend()
    demos = {lvl: DemoApp(lvl, backend) for lvl in Level}
    for lvl, demo in demos.items():
        app.include_router(build_router(demo), prefix=f"/{lvl.value}", tags=[lvl.value])
    default = Level(default_level or os.environ.get("TARGET_LEVEL", "weak"))
    app.include_router(build_router(demos[default]), tags=[f"root ({default.value})"])

    @app.get("/", include_in_schema=False)
    def index() -> dict[str, Any]:
        return {
            "name": "AcmeCorp HelpBot demo target",
            "warning": "deliberately vulnerable; do not expose",
            "levels": [lvl.value for lvl in Level],
            "default_level": default.value,
            "backend": backend.name,
            "docs": "/docs",
        }

    app.state.demos = demos
    return app


app = create_app()
