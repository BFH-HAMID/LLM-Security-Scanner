"""High-level entry point shared by the CLI and the API worker: config in, report out."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from scanner.config import ScanConfig, resolve_target_spec
from scanner.connectors import build_connector
from scanner.connectors.base import Connector
from scanner.connectors.configs import TargetBase, parse_target
from scanner.detectors import HeuristicJudge, Judge, LLMJudge
from scanner.engine import CancelCheck, ResultCallback, Scanner
from scanner.models import RunReport
from scanner.multiturn import Attacker, LLMAttacker
from scanner.mutators import resolve_mutators
from scanner.probes import Probe, default_probes_dir, load_probes, select_probes
from scanner.redact import redact_report
from scanner.scope import authorization_record, check_scope


class ScopeError(RuntimeError):
    """The target is not in an allowed scope (see docs/ETHICS.md)."""


@dataclass
class ScanRequest:
    target: TargetBase
    scan: ScanConfig = field(default_factory=ScanConfig)
    probes: list[Probe] | None = None  # pre-loaded probes (skips loading + selection)
    config_path: str | None = None
    acknowledged_flag: bool = False
    transport: httpx.AsyncBaseTransport | None = None  # tests: route into an in-process ASGI app
    judge_transport: httpx.AsyncBaseTransport | None = None
    on_result: ResultCallback | None = None
    should_cancel: CancelCheck | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def load_probe_set(scan: ScanConfig) -> list[Probe]:
    """Built-in library (unless disabled) plus any extra paths, then the selection filters."""
    paths: list[str | Path] = []
    if scan.builtin_probes:
        paths.append(default_probes_dir())
    paths.extend(scan.probe_paths)
    return select_probes(load_probes(paths), scan.selection())


def build_judge(
    scan: ScanConfig, transport: httpx.AsyncBaseTransport | None
) -> tuple[Judge | None, bool, Connector | None]:
    cfg = scan.judge
    if cfg.mode == "off":
        return None, False, None
    if cfg.mode == "heuristic" or (cfg.mode == "auto" and cfg.target is None):
        return HeuristicJudge(), True, None
    if cfg.target is None:
        raise ValueError("judge.mode is 'llm' but judge.target is not set (e.g. ollama:llama3.1)")
    connector = build_connector(
        parse_target(resolve_target_spec(cfg.target)), transport=transport, concurrency=2, retries=2
    )
    return LLMJudge(connector, votes=cfg.votes, max_chars=cfg.max_chars), True, connector


def build_attacker_factory(
    scan: ScanConfig, transport: httpx.AsyncBaseTransport | None
) -> tuple[Callable[[str], Attacker] | None, Connector | None]:
    cfg = scan.attacker
    if cfg.mode == "heuristic" or (cfg.mode == "auto" and cfg.target is None):
        return None, None
    if cfg.target is None:
        raise ValueError("attacker.mode is 'llm' but attacker.target is not set")
    connector = build_connector(
        parse_target(resolve_target_spec(cfg.target)), transport=transport, concurrency=1, retries=2
    )
    return (lambda strategy: LLMAttacker(connector, strategy)), connector


async def run_scan(req: ScanRequest) -> RunReport:
    """Run a complete scan: scope check, probe selection, engine, redaction, audit metadata."""
    scan = req.scan
    decision = check_scope(req.target, scan, acknowledged_flag=req.acknowledged_flag)
    if not decision.allowed:
        raise ScopeError(decision.message)

    probes = req.probes if req.probes is not None else load_probe_set(scan)
    rps = scan.rps if scan.rps is not None else decision.default_rps
    if req.target.timeout and scan.timeout:
        req.target = req.target.model_copy(update={"timeout": scan.timeout})

    connector = build_connector(
        req.target,
        transport=req.transport,
        rps=rps,
        concurrency=scan.concurrency,
        retries=scan.retries,
    )
    judge, judge_enabled, judge_conn = build_judge(scan, req.judge_transport)
    attacker_factory, attacker_conn = build_attacker_factory(scan, req.judge_transport)
    mutators = resolve_mutators(scan.mutators)
    scanner = Scanner(
        connector,
        probes,
        target=req.target,
        config=scan,
        mutators=mutators,
        judge=judge,
        judge_enabled=judge_enabled,
        attacker_factory=attacker_factory,
        on_result=req.on_result,
        should_cancel=req.should_cancel,
    )
    try:
        report = await scanner.run()
    finally:
        for c in (connector, judge_conn, attacker_conn):
            if c is not None:
                await c.aclose()
    report.authorization = authorization_record(scan, decision, via_flag=req.acknowledged_flag)
    report.config["config_file"] = req.config_path
    report.config["scope"] = decision.kind
    if scan.redact:
        report = redact_report(report, extra=req.target.known_sensitive)
    return report
