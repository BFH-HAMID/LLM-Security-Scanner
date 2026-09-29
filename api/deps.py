"""FastAPI dependencies: settings, store and authentication."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request

from api.settings import Settings
from scanner.storage import Store


@dataclass
class Principal:
    project_id: str
    key_id: str | None
    is_admin: bool


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> Store:
    return request.app.state.store


def get_principal(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> Principal:
    settings: Settings = request.app.state.settings
    store: Store = request.app.state.store
    if settings.auth_disabled:
        project = store.ensure_project()
        return Principal(project.id, None, True)
    key = x_api_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization[7:].strip()
    if not key:
        raise HTTPException(
            401,
            "missing API key (send it in the X-API-Key header)",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    row = store.verify_api_key(key)
    if row is None:
        raise HTTPException(
            401, "invalid or revoked API key", headers={"WWW-Authenticate": "ApiKey"}
        )
    return Principal(row.project_id, row.id, row.is_admin)


def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(403, "this operation needs an admin API key")
    return principal
