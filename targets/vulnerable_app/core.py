"""The demo application logic (framework-free): chat, RAG chat, agent and a raw-model façade."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from targets.vulnerable_app import data
from targets.vulnerable_app.backends import LLMBackend, SimulatedBackend
from targets.vulnerable_app.guard import Guard, Level
from targets.vulnerable_app.rag import DocumentStore
from targets.vulnerable_app.simulated_llm import ModelInput
from targets.vulnerable_app.tools import TOOL_NAMES, TOOL_SPECS, Sandbox

__all__ = ["ChatOutcome", "DemoApp", "Level"]


@dataclass
class ChatOutcome:
    reply: str
    conversation_id: str
    blocked: bool = False
    block_reason: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, str]] = field(default_factory=list)


class DemoApp:
    """One instance = one deployment at a given defence ``level`` with its own state."""

    def __init__(
        self,
        level: Level | str = Level.WEAK,
        backend: LLMBackend | None = None,
        system_prompt: str = data.SYSTEM_PROMPT,
    ):
        self.level = Level(level)
        self.guard = Guard(self.level)
        self.system_prompt = system_prompt
        self.backend = backend or SimulatedBackend(system_prompt)
        self.store = DocumentStore()
        self.sandbox = Sandbox()
        self.conversations: dict[str, list[dict[str, str]]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ helpers

    def reset(self) -> None:
        with self._lock:
            self.conversations.clear()
            self.store.reset()
            self.sandbox.reset()

    def _history(
        self, cid: str, client_history: list[dict[str, str]] | None
    ) -> list[dict[str, str]]:
        if client_history and self.guard.trusts_client_history:
            # Vulnerability: client-supplied assistant turns are trusted (enables fake histories).
            return [
                {"role": h["role"], "content": h["content"]}
                for h in client_history
                if h.get("role") in ("user", "assistant")
            ]
        with self._lock:
            return list(self.conversations.get(cid, []))

    def _remember(self, cid: str, user: str, assistant: str) -> None:
        with self._lock:
            turns = self.conversations.setdefault(cid, [])
            turns.append({"role": "user", "content": user})
            turns.append({"role": "assistant", "content": assistant})
            del turns[:-40]

    def _blocked(self, cid: str, message: str, reason: str) -> ChatOutcome:
        self._remember(cid, message, data.GUARD_BLOCK)
        return ChatOutcome(data.GUARD_BLOCK, cid, blocked=True, block_reason=reason)

    # --------------------------------------------------------------------- chat

    def chat(
        self,
        message: str,
        conversation_id: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ChatOutcome:
        cid = conversation_id or uuid.uuid4().hex
        reason = self.guard.check_input(message)
        if reason:
            return self._blocked(cid, message, reason)
        out = self.backend.generate(
            ModelInput(
                user=message,
                system=self.system_prompt,
                history=self._history(cid, history),
                docs_are_data=self.guard.docs_are_data,
            )
        )
        reply = self.guard.filter_output(out.text)
        self._remember(cid, message, reply)
        return ChatOutcome(reply, cid)

    # ------------------------------------------------------------------ raw model

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ChatOutcome:
        """OpenAI-style raw model endpoint: the *caller* provides the system prompt and tools.

        Tool calls are returned, never executed (exactly like a hosted model API).
        """
        system = next((m["content"] for m in messages if m.get("role") == "system"), None)
        convo = [m for m in messages if m.get("role") in ("user", "assistant")]
        if not convo or convo[-1]["role"] != "user":
            return ChatOutcome("", uuid.uuid4().hex)
        user, history = convo[-1]["content"], convo[:-1]
        cid = uuid.uuid4().hex
        reason = self.guard.check_input(user)
        if reason:
            return ChatOutcome(data.GUARD_BLOCK, cid, blocked=True, block_reason=reason)
        specs = [t.get("function", t) for t in (tools or [])]
        names = [s["name"] for s in specs] or None
        out = self.backend.generate(
            ModelInput(user=user, system=system, history=history, tools=names, tool_specs=specs)
        )
        return ChatOutcome(
            self.guard.filter_output(out.text),
            cid,
            tool_calls=[{"name": c["name"], "arguments": c["arguments"]} for c in out.tool_calls],
        )

    # ---------------------------------------------------------------------- RAG

    def ingest(
        self, title: str, content: str, conversation_id: str | None = None, acl: str = "public"
    ) -> str:
        clean = self.guard.sanitize_document(content)
        with self._lock:
            return self.store.add(title, clean, acl=acl, scope=conversation_id)

    def remove_document(self, doc_id: str) -> bool:
        with self._lock:
            return self.store.remove(doc_id)

    def rag_chat(
        self,
        message: str,
        conversation_id: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ChatOutcome:
        cid = conversation_id or uuid.uuid4().hex
        reason = self.guard.check_input(message)
        if reason:
            return self._blocked(cid, message, reason)
        with self._lock:
            docs = self.store.retrieve(message, acl_enforced=self.guard.acl_enforced, scope=cid)
        out = self.backend.generate(
            ModelInput(
                user=message,
                system=self.system_prompt,
                history=self._history(cid, history),
                docs=[{"title": d.title, "content": d.content} for d in docs],
                docs_are_data=self.guard.docs_are_data,
            )
        )
        reply = self.guard.filter_output(out.text)
        self._remember(cid, message, reply)
        return ChatOutcome(reply, cid, sources=[{"id": d.id, "title": d.title} for d in docs])

    # -------------------------------------------------------------------- agent

    def agent_chat(
        self,
        message: str,
        conversation_id: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ChatOutcome:
        cid = conversation_id or uuid.uuid4().hex
        reason = self.guard.check_input(message)
        if reason:
            return self._blocked(cid, message, reason)
        out = self.backend.generate(
            ModelInput(
                user=message,
                system=self.system_prompt,
                history=self._history(cid, history),
                tools=list(TOOL_NAMES),
                tool_specs=TOOL_SPECS,
                docs_are_data=self.guard.docs_are_data,
            )
        )
        records: list[dict[str, Any]] = []
        for call in out.tool_calls:
            args = dict(call["arguments"])
            if args.get("body") == "__EXFIL__":
                args["body"] = self.sandbox.customer_dump()
            allowed, why = self.guard.authorize_tool(call["name"], args, call.get("source", "user"))
            with self._lock:
                result = self.sandbox.execute(call["name"], args) if allowed else f"denied: {why}"
            records.append(
                {
                    "name": call["name"],
                    "arguments": args,
                    "result": result,
                    "blocked": not allowed,
                    "reason": why,
                }
            )
        text = out.text
        if records and all(r["blocked"] for r in records):
            text = f"I'm sorry, I can't do that: {records[0]['reason']}."
        reply = self.guard.filter_output(text)
        self._remember(cid, message, reply)
        return ChatOutcome(reply, cid, tool_calls=records)
