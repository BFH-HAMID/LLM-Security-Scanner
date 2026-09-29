"""Drive an adaptive (attacker-agent) probe against the target."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scanner.models import Message, Status
from scanner.multiturn.attackers import Attacker, AttackState, Exchange, HeuristicAttacker

if TYPE_CHECKING:
    from scanner.engine import Conversation, Scanner
    from scanner.probes import AttackPlan, Probe


async def run_adaptive(
    scanner: Scanner,
    probe: Probe,
    plan: AttackPlan,
    cid: str,
    system_msg: Message | None,
    system_text: str | None,
    variables: dict[str, str],
) -> Conversation:
    """Run up to ``max_turns`` attacker/target exchanges, stopping early on success.

    *crescendo* keeps a single conversation. *pair* starts a fresh conversation each round, so the
    target never sees earlier attempts (the attacker still does).
    """
    from scanner.engine import Conversation

    spec = probe.adaptive
    assert spec is not None
    factory = scanner.attacker_factory
    attacker: Attacker = (
        factory(spec.strategy) if factory else HeuristicAttacker(spec.strategy, spec.tactics)
    )
    state = AttackState(goal=plan.payload, strategy=spec.strategy, max_turns=spec.max_turns)
    convo = Conversation()
    transcript: list[Message] = []
    history: list[Message] = [system_msg] if system_msg else []
    round_cid = cid
    rounds: list[dict[str, Any]] = []

    for turn in range(spec.max_turns):
        state.turn = turn
        message = await attacker.next_message(state)
        if not message:
            break
        if spec.strategy == "pair" and turn > 0:
            history = [system_msg] if system_msg else []
            round_cid = f"{cid}-r{turn}"
        if spec.strategy == "pair" and turn > 0:
            transcript.append(
                Message(role="system", content=f"[round {turn + 1}: fresh conversation]")
            )
        history.append(Message(role="user", content=message))
        transcript.append(history[-1])
        resp = await scanner._send(history, [], plan.tools, round_cid)
        convo.responses.append(resp)
        if resp.error:
            convo.error = resp.error
            break
        assistant = Message(role="assistant", content=resp.text, tool_calls=resp.tool_calls)
        history.append(assistant)
        transcript.append(assistant)
        ctx = scanner._context(probe, resp, transcript, system_text, variables, len(convo.contexts))
        convo.contexts.append(ctx)
        verdict = await scanner.pipeline.evaluate(probe, [ctx])
        convo.verdicts.append(verdict)
        state.exchanges.append(
            Exchange(attacker=message, target=resp.text, succeeded=verdict.status is Status.FAIL)
        )
        rounds.append({"turn": turn + 1, "status": verdict.status.value, "message": message[:200]})
        if verdict.status is Status.FAIL:
            break

    convo.history = ([system_msg] if system_msg else []) + [
        m for m in transcript if m is not system_msg
    ]
    convo.meta = {
        "attacker": getattr(attacker, "name", "attacker"),
        "strategy": spec.strategy,
        "rounds": rounds,
        "goal": plan.payload,
        "stopped_early": bool(convo.verdicts) and convo.verdicts[-1].status is Status.FAIL,
    }
    tactics = getattr(attacker, "used", None)
    if tactics:
        convo.meta["tactics"] = list(tactics)
    return convo
