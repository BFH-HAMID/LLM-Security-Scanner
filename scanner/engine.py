"""The scan engine: run probes x mutators x repeats against a target and judge the results."""

from __future__ import annotations

import asyncio
import inspect
import random
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from scanner import __version__
from scanner.config import ScanConfig, ensure_canaries
from scanner.connectors.base import Connector
from scanner.connectors.configs import TargetBase
from scanner.detectors import DetectionContext, DetectionPipeline, Judge
from scanner.models import (
    AttemptResult,
    Message,
    RunReport,
    Status,
    TargetResponse,
    ToolCall,
    ToolInfo,
    utcnow,
)
from scanner.mutators import Mutator
from scanner.probes import AttackPlan, Probe, portable_path
from scanner.scoring import score
from scanner.taxonomy import CATEGORIES
from scanner.templating import make_variables, render

ResultCallback = Callable[[AttemptResult, int, int], Awaitable[None] | None]
CancelCheck = Callable[[], bool | Awaitable[bool]]


@dataclass
class WorkItem:
    probe: Probe
    mutator: Mutator | None
    repeat: int

    @property
    def mutator_name(self) -> str:
        return self.mutator.name if self.mutator else "none"


@dataclass
class Conversation:
    """Outcome of driving one attack conversation against the target."""

    history: list[Message] = field(default_factory=list)
    contexts: list[DetectionContext] = field(default_factory=list)
    responses: list[TargetResponse] = field(default_factory=list)
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    verdicts: list[Any] = field(default_factory=list)  # pre-computed per-turn verdicts (adaptive)

    @property
    def latency_ms(self) -> float:
        return sum(r.latency_ms for r in self.responses)


def coverage_notes(results: list[AttemptResult]) -> list[str]:
    """Caveats about what the run could and could not observe (shown next to the score)."""
    notes: list[str] = []
    skipped: dict[str, int] = {}
    abstained = 0
    tool_rule_attempts = 0
    tool_calls_seen = False
    for r in results:
        if r.tool_calls:
            tool_calls_seen = True
        for d in r.detections:
            if d.detector == "rules":
                for reason in d.meta.get("skipped", []):
                    skipped[reason] = skipped.get(reason, 0) + 1
                if any(x.get("detector") == "tool_call" for x in d.meta.get("results", [])):
                    tool_rule_attempts += 1
            elif d.detector.startswith("judge") and d.matched is None:
                abstained += 1
    for reason, n in sorted(skipped.items(), key=lambda kv: -kv[1]):
        notes.append(f"{n} attempt(s) could not use a rule: {reason}.")
    if tool_rule_attempts and not tool_calls_seen:
        notes.append(
            f"No tool call was observed from the target in the whole run, so {tool_rule_attempts} tool-abuse "
            "attempt(s) cannot show anything but 'resisted'. Test an agent surface, or set `tool_calls_path` "
            "so the scanner can see tool calls."
        )
    if abstained:
        notes.append(
            f"The judge abstained on {abstained} attempt(s) (offline heuristic judge). Use `--judge ollama:MODEL` "
            "(or any OpenAI-compatible / Anthropic model) for semantic scoring."
        )
    return notes


class Scanner:
    def __init__(
        self,
        connector: Connector,
        probes: list[Probe],
        *,
        target: TargetBase | None = None,
        config: ScanConfig | None = None,
        mutators: list[Mutator] | None = None,
        judge: Judge | None = None,
        judge_enabled: bool = True,
        attacker_factory: Callable[[str], Any] | None = None,
        on_result: ResultCallback | None = None,
        should_cancel: CancelCheck | None = None,
    ):
        self.connector = connector
        self.probes = probes
        self.target = target
        self.config = config or ScanConfig()
        self.mutators = mutators or []
        self.pipeline = DetectionPipeline(judge, judge_enabled=judge_enabled)
        self.attacker_factory = attacker_factory
        self.on_result = on_result
        self.should_cancel = should_cancel

        self.canaries = ensure_canaries(target) if target else {}
        self.system_prompt = self._render_system_prompt()
        self.fragments = list(target.system_prompt_fragments) if target else []
        self.known_sensitive = list(target.known_sensitive) if target else []
        self.done = 0
        self.total = 0
        self._ingest_lock = asyncio.Lock()
        self._abort = asyncio.Event()
        self._abort_reason: str | None = None
        self._cancelled = False

    # ------------------------------------------------------------------ planning

    def _render_system_prompt(self) -> str | None:
        if not self.target or not self.target.system_prompt:
            return None
        variables = make_variables(
            probe_id="-", mutator="-", repeat=0, seed=0, canaries=self.canaries
        )
        return render(self.target.system_prompt, variables, strict=False)

    def plan_items(self) -> list[WorkItem]:
        items: list[WorkItem] = []
        for probe in self.probes:
            variants: list[Mutator | None] = [None] if self.config.include_original else []
            for m in self.mutators:
                parts = getattr(m, "parts", [m])
                if all(probe.allows_mutator(p.name) for p in parts):
                    variants.append(m)
            for variant in variants:
                for r in range(self.config.repeats):
                    items.append(WorkItem(probe, variant, r))
        return items

    # ----------------------------------------------------------------------- run

    async def run(self) -> RunReport:
        started = utcnow()
        t0 = time.perf_counter()
        items = self.plan_items()
        if not items:
            raise ValueError(
                "nothing to run: no probes matched the selection (or all mutators were excluded)"
            )
        self.total = len(items)
        sem = asyncio.Semaphore(self.config.concurrency)
        results: list[AttemptResult] = []
        consecutive_errors = 0
        last_error = ""

        async def worker(item: WorkItem) -> None:
            nonlocal consecutive_errors, last_error
            async with sem:
                if self._abort.is_set():
                    return
                if await self._is_cancelled():
                    self._cancelled = True
                    self._abort.set()
                    return
                result = await self._run_item(item)
            results.append(result)
            self.done += 1
            if result.status is Status.ERROR:
                consecutive_errors += 1
                last_error = result.error or ""
                if consecutive_errors >= self.config.max_consecutive_errors:
                    self._abort_reason = (
                        f"aborted after {consecutive_errors} consecutive target errors "
                        f"(last: {last_error[:200]})"
                    )
                    self._abort.set()
            else:
                consecutive_errors = 0
            await self._emit(result)

        await asyncio.gather(*(worker(i) for i in items))

        order = {c: i for i, c in enumerate(CATEGORIES)}
        results.sort(key=lambda r: (order[r.category], r.probe_id, r.mutator, r.repeat))
        status = "completed"
        error = None
        if self._cancelled:
            status = "cancelled"
        elif self._abort_reason:
            status, error = "failed", self._abort_reason
        finished = utcnow()
        notes = coverage_notes(results)
        return RunReport(
            notes=notes,
            id=uuid.uuid4().hex,
            name=self.config.name,
            status=status,
            target=self.connector.describe(),
            config=self._config_summary(),
            authorization=self.config.authorization.model_dump(),
            started_at=started,
            finished_at=finished,
            duration_s=round(time.perf_counter() - t0, 3),
            score=score(results),
            results=results,
            error=error,
            tool=ToolInfo(version=__version__),
        )

    def _config_summary(self) -> dict[str, Any]:
        c = self.config
        return {
            "categories": [x.value for x in c.categories],
            "min_severity": c.min_severity.value if c.min_severity else None,
            "mutators": [m.name for m in self.mutators],
            "include_original": c.include_original,
            "repeats": c.repeats,
            "concurrency": c.concurrency,
            "rps": c.rps,
            "seed": c.seed,
            "probes": len(self.probes),
            "judge": c.judge.mode,
            "canaries": sorted(self.canaries),
        }

    async def _is_cancelled(self) -> bool:
        if self.should_cancel is None:
            return False
        out = self.should_cancel()
        return bool(await out) if inspect.isawaitable(out) else bool(out)

    async def _emit(self, result: AttemptResult) -> None:
        if self.on_result is None:
            return
        out = self.on_result(result, self.done, self.total)
        if inspect.isawaitable(out):
            await out

    # ---------------------------------------------------------------- one attempt

    async def _run_item(self, item: WorkItem) -> AttemptResult:
        probe = item.probe
        started = utcnow()
        try:
            return await self._attempt(item, started)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return self._result(
                item,
                started,
                Status.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                reason="internal error while running the probe",
            )
        finally:
            _ = probe

    async def _attempt(self, item: WorkItem, started: Any) -> AttemptResult:
        probe = item.probe
        cfg = self.config
        variables = make_variables(
            probe_id=probe.id,
            mutator=item.mutator_name,
            repeat=item.repeat,
            seed=cfg.seed,
            canaries=self.canaries,
            target=self.connector.name,
        )
        rng = random.Random(f"{cfg.seed}|{probe.id}|{item.mutator_name}|{item.repeat}")
        plan = await self._make_plan(item, variables, rng)
        cid = uuid.uuid4().hex
        system_text = self.system_prompt if self.system_prompt is not None else plan.system_prompt
        system_msg = Message(role="system", content=system_text) if system_text else None

        doc_ids: list[str] = []
        needs_lock = bool(plan.documents)
        if needs_lock:
            await self._ingest_lock.acquire()
        try:
            for doc in plan.documents:
                doc_id = await self.connector.ingest(doc.title, doc.content, conversation_id=cid)
                if doc_id:
                    doc_ids.append(doc_id)
            if plan.kind == "adaptive":
                convo = await self._converse_adaptive(
                    probe, plan, cid, system_msg, system_text, variables
                )
            else:
                convo = await self._converse(probe, plan, cid, system_msg, system_text, variables)
        finally:
            for doc_id in doc_ids:
                try:
                    await self.connector.remove_document(doc_id)
                except Exception:
                    pass
            if needs_lock:
                self._ingest_lock.release()

        meta: dict[str, Any] = {
            "conversation_id": cid,
            "kind": plan.kind,
            "delivery": plan.delivery,
            "payload": plan.payload[:600],
            "turns": len(convo.responses),
            **convo.meta,
        }
        if plan.documents:
            meta["documents"] = [
                {"title": d.title, "carrier": d.carrier, "content": d.content[:4000]}
                for d in plan.documents
            ]
        if convo.error:
            return self._result(
                item,
                started,
                Status.ERROR,
                convo,
                error=convo.error,
                reason="target error",
                meta=meta,
            )
        if convo.verdicts:
            verdict = self.pipeline.combine(convo.verdicts)
        else:
            verdict = await self.pipeline.evaluate(probe, convo.contexts)
        last = convo.responses[-1] if convo.responses else TargetResponse()
        return self._result(
            item,
            started,
            verdict.status,
            convo,
            confidence=verdict.confidence,
            reason=verdict.reason,
            detections=verdict.detections,
            evidence=verdict.evidence,
            meta={**meta, **verdict.meta},
            response_text=last.text,
            tool_calls=last.tool_calls,
        )

    def _result(
        self,
        item: WorkItem,
        started: Any,
        status: Status,
        convo: Conversation | None = None,
        *,
        confidence: float = 0.0,
        reason: str = "",
        error: str | None = None,
        detections: list | None = None,
        evidence: list | None = None,
        meta: dict[str, Any] | None = None,
        response_text: str = "",
        tool_calls: list[ToolCall] | None = None,
    ) -> AttemptResult:
        p = item.probe
        return AttemptResult(
            probe_id=p.id,
            probe_name=p.name,
            category=p.category,
            severity=p.severity,
            owasp=list(p.owasp),
            atlas=list(p.atlas),
            tags=list(p.tags),
            mutator=item.mutator_name,
            repeat=item.repeat,
            status=status,
            confidence=confidence,
            reason=reason,
            transcript=list(convo.history) if convo else [],
            response_text=response_text,
            tool_calls=tool_calls or [],
            detections=detections or [],
            evidence=evidence or [],
            remediation=p.remediation_text,
            latency_ms=round(convo.latency_ms, 1) if convo else 0.0,
            error=error,
            started_at=started,
            source_file=portable_path(p.source_file),
            meta=meta or {},
        )

    async def _make_plan(
        self, item: WorkItem, variables: dict[str, str], rng: random.Random
    ) -> AttackPlan:
        probe = item.probe
        can_ingest = bool(self.connector.supports_ingest)
        if item.mutator is None:
            return probe.plan(variables, can_ingest=can_ingest)
        seen: list[str] = []

        def record(text: str) -> str:
            seen.append(text)
            return text

        probe.plan(variables, record, can_ingest=can_ingest)
        mutated = {t: await item.mutator.mutate(t, rng) for t in dict.fromkeys(seen)}
        plan = probe.plan(variables, lambda t: mutated.get(t, t), can_ingest=can_ingest)
        plan.meta["mutated"] = True
        return plan

    # -------------------------------------------------------------- conversations

    def _context(
        self,
        probe: Probe,
        resp: TargetResponse,
        history: list[Message],
        system_text: str | None,
        variables: dict[str, str],
        turn: int,
    ) -> DetectionContext:
        return DetectionContext(
            probe=probe,
            response_text=resp.text,
            transcript=list(history),
            tool_calls=list(resp.tool_calls),
            canaries=self.canaries,
            system_prompt=system_text if self.system_prompt is not None else None,
            system_prompt_fragments=self.fragments,
            known_sensitive=self.known_sensitive,
            variables=variables,
            turn=turn,
        )

    async def _send(
        self,
        history: list[Message],
        fake: list[Message],
        plan_tools: list[Any],
        cid: str,
    ) -> TargetResponse:
        """Send the conversation so far, adapting to connectors without history support."""
        if self.connector.supports_history:
            outgoing = list(history)
        else:
            system = [m for m in history if m.role == "system"]
            last = history[-1]
            content = last.content
            if fake:
                transcript = "\n".join(f"{m.role.capitalize()}: {m.content}" for m in fake)
                content = f"{transcript}\n\nUser: {content}"
                fake.clear()
            outgoing = [*system, Message(role="user", content=content)]
        tools = plan_tools if (plan_tools and self.connector.supports_tools) else None
        return await self.connector.send(outgoing, tools=tools, conversation_id=cid)

    async def _converse(
        self,
        probe: Probe,
        plan: AttackPlan,
        cid: str,
        system_msg: Message | None,
        system_text: str | None,
        variables: dict[str, str],
    ) -> Conversation:
        convo = Conversation()
        history: list[Message] = [system_msg] if system_msg else []
        fake: list[Message] = []  # scripted (fabricated) turns awaiting inline delivery
        turns = plan.turns
        i = 0
        while i < len(turns):
            t = turns[i]
            if t.role == "system":
                history.append(Message(role="system", content=t.content))
            elif t.role == "assistant":
                msg = Message(role="assistant", content=t.content)
                history.append(msg)
                fake.append(msg)
            elif i + 1 < len(turns) and turns[i + 1].role == "assistant":
                msg = Message(role="user", content=t.content)  # scripted history: not sent
                history.append(msg)
                fake.append(msg)
            else:
                history.append(Message(role="user", content=t.content))
                resp = await self._send(history, fake, plan.tools, cid)
                convo.responses.append(resp)
                if resp.error:
                    convo.error = resp.error
                    break
                history.append(
                    Message(role="assistant", content=resp.text, tool_calls=resp.tool_calls)
                )
                convo.contexts.append(
                    self._context(probe, resp, history, system_text, variables, len(convo.contexts))
                )
            i += 1
        convo.history = history
        return convo

    async def _converse_adaptive(
        self,
        probe: Probe,
        plan: AttackPlan,
        cid: str,
        system_msg: Message | None,
        system_text: str | None,
        variables: dict[str, str],
    ) -> Conversation:
        from scanner.multiturn import run_adaptive

        return await run_adaptive(self, probe, plan, cid, system_msg, system_text, variables)
