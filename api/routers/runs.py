"""Runs: create, poll, cancel, inspect results, export reports, compare, baseline checks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import ValidationError

from api.deps import Principal, get_principal, get_settings, get_store
from api.masking import mask_config
from api.routers.system import probe_library
from api.routers.targets import _strip_env_refs, check_host_policy
from api.schemas import Progress, RunCreate, RunDetail, RunList, RunOut
from api.settings import Settings
from scanner.baseline import check_baseline, make_baseline
from scanner.compare import compare_reports
from scanner.config import AuthorizationConfig, ScanConfig
from scanner.connectors.configs import parse_target
from scanner.models import Status
from scanner.mutators import UnknownMutatorError
from scanner.probes import select_probes
from scanner.reporting import FORMATS, render
from scanner.reporting.common import HeatCell, HeatRow
from scanner.runner import count_attempts
from scanner.scope import authorization_record, check_scope
from scanner.storage import Store
from scanner.storage.models import RunRow

router = APIRouter(tags=["runs"])

MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "sarif": "application/sarif+json",
    "md": "text/markdown; charset=utf-8",
}
FORBIDDEN_SCAN_KEYS = {"probe_paths", "builtin_probes"}


def run_out(row: RunRow) -> RunOut:
    return RunOut(
        id=row.id,
        name=row.name,
        status=row.status,
        target_id=row.target_id,
        target=mask_config(row.target_summary or {}),
        risk_score=row.risk_score,
        grade=row.grade,
        findings=row.findings,
        progress=Progress(done=row.progress_done, total=row.progress_total),
        error=row.error,
        duration_s=row.duration_s,
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def planned_attempts(scan: ScanConfig) -> int:
    return count_attempts(select_probes(probe_library(), scan.selection()), scan)


@router.post("/runs", response_model=RunDetail, status_code=202)
def create_run(
    body: RunCreate,
    request: Request,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> RunDetail:
    # ---- target
    if bool(body.target_id) == bool(body.target):
        raise HTTPException(422, "provide exactly one of target_id or target")
    target_id = body.target_id
    if target_id:
        row = store.get_target(principal.project_id, target_id)
        if row is None:
            raise HTTPException(404, "no such target")
        target_config = row.config
    else:
        target_config = body.target or {}
    try:
        target = parse_target(_strip_env_refs(target_config))
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, f"invalid target config: {exc}") from None
    if target.type == "demo" and not settings.allow_demo_target:
        raise HTTPException(403, "the demo target is disabled on this server")
    check_host_policy(target, settings)

    # ---- scan config (API callers may not point the scanner at server-side files)
    bad = FORBIDDEN_SCAN_KEYS & set(body.scan)
    if bad:
        raise HTTPException(422, f"scan option(s) not allowed over the API: {sorted(bad)}")
    raw_scan = dict(body.scan)
    if body.authorization:
        raw_scan["authorization"] = body.authorization.model_dump()
    if body.name:
        raw_scan["name"] = body.name
    try:
        scan = ScanConfig.model_validate(raw_scan)
    except ValidationError as exc:
        raise HTTPException(422, f"invalid scan config: {exc.errors(include_url=False)}") from None
    for nested in (scan.judge.target, scan.attacker.target):
        if isinstance(nested, dict):
            check_host_policy(parse_target(_strip_env_refs(nested)), settings)
    scan = scan.model_copy(update={"concurrency": min(scan.concurrency, settings.max_concurrency)})
    try:
        attempts = planned_attempts(scan)
    except UnknownMutatorError as exc:
        raise HTTPException(422, str(exc)) from None
    if attempts == 0:
        raise HTTPException(422, "the selection matches no probes")
    if attempts > settings.max_attempts_per_run:
        raise HTTPException(
            422, f"{attempts} attempts exceeds the server limit of {settings.max_attempts_per_run}"
        )

    # ---- scope guard (docs/ETHICS.md)
    acknowledged = bool(body.authorization and body.authorization.acknowledged)
    decision = check_scope(target, scan, acknowledged_flag=acknowledged)
    if not decision.allowed:
        raise HTTPException(403, decision.message)
    auth = authorization_record(scan, decision, via_flag=acknowledged)

    summary = {"type": target.type, "name": target.name}
    summary |= {
        k: v
        for k, v in mask_config(target_config).items()
        if k in ("url", "base_url", "model", "level", "surface", "method")
    }
    run = store.create_run(
        principal.project_id,
        target_id=target_id,
        scan_config=scan.model_dump(mode="json"),
        target_summary=summary,
        name=body.name,
        authorization=auth,
        target_config=target_config,
        progress_total=attempts,
    )
    request.app.state.queue.enqueue(run.id)
    return run_detail(store, run)


def run_detail(store: Store, row: RunRow) -> RunDetail:
    notes: list[str] = []
    if row.status in ("completed", "cancelled", "failed") and row.score is not None:
        report = store.load_report(row.id)
        notes = report.notes if report else []
    base = run_out(row).model_dump()
    return RunDetail(
        **base,
        score=row.score,
        notes=notes,
        authorization=row.authorization,
        scan=mask_config(row.scan_config or {}),
    )


@router.get("/runs", response_model=RunList)
def list_runs(
    target_id: str | None = None,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> RunList:
    rows, total = store.list_runs(
        principal.project_id, target_id=target_id, status=status, limit=limit, offset=offset
    )
    return RunList(items=[run_out(r) for r in rows], total=total)


def _get_run(store: Store, principal: Principal, run_id: str) -> RunRow:
    row = store.get_run(principal.project_id, run_id)
    if row is None:
        raise HTTPException(404, "no such run")
    return row


@router.get("/runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> RunDetail:
    return run_detail(store, _get_run(store, principal, run_id))


@router.post("/runs/{run_id}/cancel", response_model=RunOut)
def cancel_run(
    run_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> RunOut:
    _get_run(store, principal, run_id)
    store.request_cancel(principal.project_id, run_id)
    return run_out(_get_run(store, principal, run_id))


@router.delete("/runs/{run_id}", status_code=204)
def delete_run(
    run_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> None:
    row = _get_run(store, principal, run_id)
    if row.status in ("queued", "running"):
        raise HTTPException(409, "cancel the run before deleting it")
    store.delete_run(principal.project_id, run_id)


@router.get("/runs/{run_id}/results")
def list_results(
    run_id: str,
    status: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    probe_id: str | None = None,
    mutator: str | None = None,
    include_transcript: bool = False,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    _get_run(store, principal, run_id)
    if status and status not in {s.value for s in Status}:
        raise HTTPException(422, f"unknown status {status!r}")
    items, total = store.query_results(
        run_id,
        status=status,
        category=category,
        severity=severity,
        probe_id=probe_id,
        mutator=mutator,
        limit=limit,
        offset=offset,
    )
    exclude = (
        None
        if include_transcript
        else {"transcript", "detections", "meta", "tool_calls", "remediation", "response_text"}
    )
    return {"total": total, "items": [r.model_dump(mode="json", exclude=exclude) for r in items]}


@router.get("/runs/{run_id}/results/{result_id}")
def get_result(
    run_id: str,
    result_id: str,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    _get_run(store, principal, run_id)
    result = store.get_result(run_id, result_id)
    if result is None:
        raise HTTPException(404, "no such result")
    return result.model_dump(mode="json")


@router.get("/runs/{run_id}/heatmap")
def heatmap(
    run_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> dict[str, Any]:
    """Probe x mutator pass/fail matrix for the run-detail heatmap."""
    _get_run(store, principal, run_id)
    rows: dict[str, HeatRow] = {}
    mutators: list[str] = []
    for probe_id, name, category, severity, mutator, status in store.heatmap_rows(run_id):
        if mutator not in mutators:
            mutators.append(mutator)
        row = rows.setdefault(probe_id, HeatRow(probe_id, name, category, severity))
        cell = row.cells.setdefault(mutator, HeatCell("pass", 0, 0))
        cell.total += 1
        if status == "fail":
            cell.failed += 1
            cell.status = "fail"
        elif status in ("error", "inconclusive") and cell.status == "pass":
            cell.status = status
    mutators.sort(key=lambda m: (m != "none", m))
    order = {
        c: i
        for i, c in enumerate(
            [
                "prompt_injection",
                "indirect_injection",
                "jailbreak",
                "system_prompt_extraction",
                "sensitive_data_leakage",
                "insecure_output_handling",
                "excessive_agency",
            ]
        )
    }
    ordered = sorted(rows.values(), key=lambda r: (order.get(r.category, 99), r.probe_id))
    return {
        "mutators": mutators,
        "rows": [
            {
                "probe_id": r.probe_id,
                "name": r.name if hasattr(r, "name") else r.probe_id,
                "probe_name": r.name,
                "category": r.category,
                "severity": r.severity,
                "cells": {
                    m: {"status": c.status, "failed": c.failed, "total": c.total}
                    for m, c in r.cells.items()
                },
            }
            for r in ordered
        ],
    }


@router.get("/runs/{run_id}/report")
def download_report(
    run_id: str,
    format: str = Query("json", description="json | html | pdf | sarif | md"),
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> Response:
    _get_run(store, principal, run_id)
    if format not in FORMATS:
        raise HTTPException(422, f"format must be one of {', '.join(FORMATS)}")
    report = store.load_report(run_id, principal.project_id)
    if report is None:
        raise HTTPException(404, "no such run")
    body = render(report, format, config_path=None)
    ext = {"sarif": "sarif", "md": "md"}.get(format, format)
    headers = {"Content-Disposition": f'attachment; filename="llmscan-{run_id[:8]}.{ext}"'}
    if format == "html":
        # the report is self-contained; forbid scripts and remote loads as defence in depth
        headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
        )
    return Response(content=body, media_type=MEDIA_TYPES[format], headers=headers)


@router.get("/runs/{run_id}/baseline-check")
def baseline_check(
    run_id: str,
    tolerance: float = 5.0,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    run = _get_run(store, principal, run_id)
    if run.target_id is None:
        raise HTTPException(409, "this run has no stored target, so it has no baseline")
    target = store.get_target(principal.project_id, run.target_id)
    if target is None or not target.baseline_run_id:
        raise HTTPException(404, "the target has no baseline: PUT /targets/{id}/baseline first")
    base = store.load_report(target.baseline_run_id, principal.project_id)
    current = store.load_report(run_id, principal.project_id)
    if base is None or current is None:
        raise HTTPException(404, "baseline or run report is missing")
    return check_baseline(current, make_baseline(base), tolerance=tolerance).model_dump(mode="json")


@router.get("/compare")
def compare(
    a: str,
    b: str,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    ra = store.load_report(a, principal.project_id)
    rb = store.load_report(b, principal.project_id)
    if ra is None or rb is None:
        raise HTTPException(404, "run not found")
    return compare_reports(ra, rb).model_dump(mode="json")


__all__ = ["AuthorizationConfig", "router"]
