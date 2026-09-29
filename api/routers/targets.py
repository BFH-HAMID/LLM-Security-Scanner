"""Scan targets: what to attack. Stored configs are masked when returned."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from api.deps import Principal, get_principal, get_settings, get_store
from api.masking import mask_config, merge_masked
from api.schemas import BaselineSet, TargetIn, TargetOut, TargetUpdate
from api.settings import Settings
from scanner.connectors.configs import parse_target
from scanner.scope import classify_host, target_url
from scanner.storage import Store
from scanner.storage.models import TargetRow

router = APIRouter(tags=["targets"])


def validate_target_config(config: dict[str, Any], settings: Settings) -> str:
    """Validate a target config and apply server policy. Returns the target type.

    ``${ENV}`` references are resolved later, on the worker, so they are only checked structurally.
    """
    try:
        cfg = parse_target(_strip_env_refs(config))
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, f"invalid target config: {exc}") from None
    if cfg.type == "demo" and not settings.allow_demo_target:
        raise HTTPException(403, "the demo target is disabled on this server")
    check_host_policy(cfg, settings)
    return cfg.type


def _strip_env_refs(obj: Any) -> Any:
    import re

    if isinstance(obj, str):
        return re.sub(r"\$\{[^}]*\}", "placeholder", obj)
    if isinstance(obj, dict):
        return {k: _strip_env_refs(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_env_refs(v) for v in obj]
    return obj


def check_host_policy(cfg: Any, settings: Settings) -> None:
    """Optional SSRF hardening for hosted deployments (see docs/SECURITY.md)."""
    import fnmatch
    from urllib.parse import urlparse

    url = target_url(cfg)
    if not url:
        return
    host = (urlparse(url).hostname or "").lower()
    if settings.target_allowlist and not any(
        fnmatch.fnmatch(host, pat.lower()) for pat in settings.target_allowlist
    ):
        raise HTTPException(403, f"target host {host!r} is not in LLMSCAN_TARGET_ALLOWLIST")
    if settings.block_private_targets and classify_host(host) in ("local", "private"):
        raise HTTPException(
            403,
            "private and loopback targets are blocked on this server (LLMSCAN_BLOCK_PRIVATE_TARGETS)",
        )


def target_out(row: TargetRow) -> TargetOut:
    return TargetOut(
        id=row.id,
        name=row.name,
        type=str(row.config.get("type", "")),
        config=mask_config(row.config),
        baseline_run_id=row.baseline_run_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/targets", response_model=list[TargetOut])
def list_targets(
    principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> list[TargetOut]:
    return [target_out(t) for t in store.list_targets(principal.project_id)]


@router.post("/targets", response_model=TargetOut, status_code=201)
def create_target(
    body: TargetIn,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> TargetOut:
    validate_target_config(body.config, settings)
    return target_out(store.create_target(principal.project_id, body.name, body.config))


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> TargetOut:
    row = store.get_target(principal.project_id, target_id)
    if row is None:
        raise HTTPException(404, "no such target")
    return target_out(row)


@router.put("/targets/{target_id}", response_model=TargetOut)
def update_target(
    target_id: str,
    body: TargetUpdate,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> TargetOut:
    row = store.get_target(principal.project_id, target_id)
    if row is None:
        raise HTTPException(404, "no such target")
    config = None
    if body.config is not None:
        config = merge_masked(row.config, body.config)
        validate_target_config(config, settings)
    updated = store.update_target(principal.project_id, target_id, name=body.name, config=config)
    assert updated is not None
    return target_out(updated)


@router.delete("/targets/{target_id}", status_code=204)
def delete_target(
    target_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> None:
    if not store.delete_target(principal.project_id, target_id):
        raise HTTPException(404, "no such target")


@router.put("/targets/{target_id}/baseline", response_model=TargetOut)
def set_baseline(
    target_id: str,
    body: BaselineSet,
    principal: Principal = Depends(get_principal),
    store: Store = Depends(get_store),
) -> TargetOut:
    run = store.get_run(principal.project_id, body.run_id)
    if run is None:
        raise HTTPException(404, "no such run")
    if run.status != "completed":
        raise HTTPException(409, "only a completed run can be a baseline")
    if not store.set_baseline(principal.project_id, target_id, run.id):
        raise HTTPException(404, "no such target")
    return target_out(store.get_target(principal.project_id, target_id))  # type: ignore[arg-type]


@router.delete("/targets/{target_id}/baseline", status_code=204)
def clear_baseline(
    target_id: str, principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> None:
    if not store.set_baseline(principal.project_id, target_id, None):
        raise HTTPException(404, "no such target")
