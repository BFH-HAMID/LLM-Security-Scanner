"""Health, identity, metadata and the probe library."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from api.deps import Principal, get_principal, get_store
from scanner import __version__
from scanner.models import Category, Severity
from scanner.mutators import REGISTRY
from scanner.probes import Probe, load_probes
from scanner.storage import Store
from scanner.taxonomy import (
    ATLAS_MITIGATIONS,
    ATLAS_TECHNIQUES,
    ATLAS_VERSION,
    CATEGORIES,
    OWASP_EDITION,
    OWASP_LLM_TOP10,
)

router = APIRouter()


@lru_cache(maxsize=1)
def probe_library() -> tuple[Probe, ...]:
    return tuple(load_probes())


def probe_summary(p: Probe) -> dict[str, Any]:
    return {
        "id": p.id,
        "name": p.name,
        "category": p.category.value,
        "severity": p.severity.value,
        "kind": p.kind,
        "owasp": p.owasp,
        "atlas": p.atlas,
        "tags": p.tags,
        "description": p.description,
    }


@router.get("/health", tags=["system"])
def health(request: Request) -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "queue": request.app.state.queue.name}


@router.get("/me", tags=["system"])
def me(
    principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> dict[str, Any]:
    project = store.get_project(principal.project_id)
    return {
        "project": {"id": principal.project_id, "name": project.name if project else None},
        "is_admin": principal.is_admin,
        "key_id": principal.key_id,
    }


@router.get("/meta", tags=["system"])
def meta(_: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Everything the UI needs to build its forms (categories, mutators, taxonomy)."""
    return {
        "version": __version__,
        "categories": [
            {
                "key": c.value,
                "title": info.title,
                "description": info.description,
                "owasp": list(info.owasp),
                "atlas": list(info.atlas),
                "probes": sum(1 for p in probe_library() if p.category == c),
            }
            for c, info in CATEGORIES.items()
        ],
        "severities": [s.value for s in Severity],
        "mutators": [{"name": n, "description": cls.description} for n, cls in REGISTRY.items()],
        "owasp": {"edition": OWASP_EDITION, "items": OWASP_LLM_TOP10},
        "atlas": {
            "version": ATLAS_VERSION,
            "techniques": ATLAS_TECHNIQUES,
            "mitigations": ATLAS_MITIGATIONS,
        },
        "target_types": ["http", "openai", "anthropic", "ollama", "demo"],
        "judge_modes": ["auto", "heuristic", "llm", "off"],
        "category_order": [c.value for c in Category],
    }


@router.get("/probes", tags=["probes"])
def list_probes(
    category: str | None = None, severity: str | None = None, _: Principal = Depends(get_principal)
) -> list[dict[str, Any]]:
    out = [
        probe_summary(p)
        for p in probe_library()
        if (not category or p.category.value == category)
        and (not severity or p.severity.value == severity)
    ]
    return out


@router.get("/probes/{probe_id}", tags=["probes"])
def get_probe(probe_id: str, _: Principal = Depends(get_principal)) -> dict[str, Any]:
    for p in probe_library():
        if p.id.lower() == probe_id.lower():
            return {
                **probe_summary(p),
                "spec": p.model_dump(mode="json", exclude_none=True),
                "remediation": p.remediation_text,
            }
    raise HTTPException(404, f"no probe {probe_id!r}")
