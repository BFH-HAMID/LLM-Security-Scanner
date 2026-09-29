"""FastAPI application factory.

uvicorn api.main:create_app --factory --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from api.jobs.runner import CeleryQueue, InProcessQueue
from api.routers import admin, runs, system, targets
from api.settings import Settings
from scanner import __version__
from scanner.storage import DEFAULT_PROJECT, Store

log = logging.getLogger("llmscan.api")
API_PREFIX = "/api/v1"


def bootstrap(store: Store, settings: Settings) -> str | None:
    """Ensure a default project and, on first start, an admin key. Returns a generated key (if any)."""
    project = store.ensure_project(DEFAULT_PROJECT, "Default project")
    if store.has_api_keys():
        return None
    key = settings.bootstrap_api_key
    generated = None
    if not key:
        key = generated = "llmscan_" + secrets.token_urlsafe(32)
    store.create_api_key(project.id, "bootstrap admin", is_admin=True, key=key)
    if generated:
        log.warning(
            "Bootstrap admin API key (shown once, set LLMSCAN_BOOTSTRAP_API_KEY to choose it): %s",
            generated,
        )
    return generated


def create_app(
    settings: Settings | None = None, *, store: Store | None = None, queue: Any | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or Store(settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        app.state.queue.shutdown()  # let in-flight runs finish or be marked failed on next start

    app = FastAPI(
        lifespan=lifespan,
        title="LLM Security Scanner API",
        version=__version__,
        description="Run LLM security scans and read scored results. Authenticate with the X-API-Key header.",
        # The interactive docs are unauthenticated (they describe the API, not any data);
        # hardened deployments switch them off with LLMSCAN_DOCS_ENABLED=false.
        docs_url=f"{API_PREFIX}/docs" if settings.docs_enabled else None,
        openapi_url=f"{API_PREFIX}/openapi.json" if settings.docs_enabled else None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.store = store
    if settings.auth_disabled:
        log.warning(
            "LLMSCAN_AUTH_DISABLED is on: the API accepts unauthenticated requests. Development only!"
        )
    generated = bootstrap(store, settings)
    app.state.bootstrap_key = generated
    if queue is None:
        if settings.queue == "celery":
            queue = CeleryQueue()
        else:
            store.fail_orphaned_runs()
            queue = InProcessQueue(store, settings.workers, env=settings.allowed_env())
    app.state.queue = queue

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith(API_PREFIX) and "cache-control" not in response.headers:
            response.headers["Cache-Control"] = "no-store"
        return response

    for r in (system.router, admin.router, targets.router, runs.router):
        app.include_router(r, prefix=API_PREFIX)

    return app


_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    """``uvicorn api.main:app`` works without creating the database at import time."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
