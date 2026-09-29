"""Projects and API keys (multi-project support)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.deps import Principal, get_principal, get_store, require_admin
from api.schemas import KeyCreate, ProjectCreate
from scanner.storage import Store

router = APIRouter(tags=["admin"])


def _key(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "prefix": row.prefix,
        "is_admin": row.is_admin,
        "revoked": row.revoked,
        "created_at": row.created_at,
        "last_used_at": row.last_used_at,
    }


@router.get("/projects")
def list_projects(
    principal: Principal = Depends(require_admin), store: Store = Depends(get_store)
) -> list[dict[str, Any]]:
    return [
        {"id": p.id, "name": p.name, "description": p.description, "created_at": p.created_at}
        for p in store.list_projects()
    ]


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectCreate,
    principal: Principal = Depends(require_admin),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    try:
        p = store.create_project(body.name, body.description)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {"id": p.id, "name": p.name, "description": p.description, "created_at": p.created_at}


@router.post("/projects/{project_id}/keys", status_code=201)
def create_project_key(
    project_id: str,
    body: KeyCreate,
    principal: Principal = Depends(require_admin),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    if store.get_project(project_id) is None:
        raise HTTPException(404, "no such project")
    row, plaintext = store.create_api_key(project_id, body.name, is_admin=body.is_admin)
    return {**_key(row), "key": plaintext, "note": "store this key now; it cannot be shown again"}


@router.get("/keys")
def list_keys(
    principal: Principal = Depends(get_principal), store: Store = Depends(get_store)
) -> list[dict[str, Any]]:
    return [_key(k) for k in store.list_api_keys(principal.project_id)]


@router.post("/keys", status_code=201)
def create_key(
    body: KeyCreate,
    principal: Principal = Depends(require_admin),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    row, plaintext = store.create_api_key(principal.project_id, body.name, is_admin=body.is_admin)
    return {**_key(row), "key": plaintext, "note": "store this key now; it cannot be shown again"}


@router.delete("/keys/{key_id}", status_code=204)
def revoke_key(
    key_id: str, principal: Principal = Depends(require_admin), store: Store = Depends(get_store)
) -> None:
    if not store.revoke_api_key(principal.project_id, key_id):
        raise HTTPException(404, "no such key")
