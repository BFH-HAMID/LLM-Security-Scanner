"""API settings, read from the environment (12-factor)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    database_url: str = "llmscan.db"
    queue: str = "inprocess"  # inprocess | celery
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    workers: int = 2  # in-process job threads
    auth_disabled: bool = False  # development only
    bootstrap_api_key: str | None = None
    cors_origins: list[str] = field(default_factory=list)
    max_attempts_per_run: int = 20_000
    max_concurrency: int = 16
    allow_demo_target: bool = True
    docs_enabled: bool = True  # /api/v1/docs and /openapi.json (unauthenticated, schema only)
    target_allowlist: list[str] = field(default_factory=list)  # fnmatch host patterns; empty = any
    block_private_targets: bool = False  # for hosted deployments (SSRF hardening)
    # Environment variables a stored target config may reference as ${NAME}. Empty = none: otherwise
    # any API user could aim a target at their own server and have the worker send them the secret.
    env_allowlist: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_url=os.environ.get("DATABASE_URL", "llmscan.db"),
            queue=os.environ.get("LLMSCAN_QUEUE", "inprocess").lower(),
            celery_broker_url=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
            celery_result_backend=os.environ.get(
                "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
            ),
            workers=int(os.environ.get("LLMSCAN_WORKERS", "2")),
            auth_disabled=_bool("LLMSCAN_AUTH_DISABLED"),
            bootstrap_api_key=os.environ.get("LLMSCAN_BOOTSTRAP_API_KEY") or None,
            cors_origins=[
                o.strip()
                for o in os.environ.get("LLMSCAN_CORS_ORIGINS", "").split(",")
                if o.strip()
            ],
            max_attempts_per_run=int(os.environ.get("LLMSCAN_MAX_ATTEMPTS", "20000")),
            max_concurrency=int(os.environ.get("LLMSCAN_MAX_CONCURRENCY", "16")),
            allow_demo_target=_bool("LLMSCAN_ALLOW_DEMO_TARGET", True),
            docs_enabled=_bool("LLMSCAN_DOCS_ENABLED", True),
            target_allowlist=[
                h.strip()
                for h in os.environ.get("LLMSCAN_TARGET_ALLOWLIST", "").split(",")
                if h.strip()
            ],
            block_private_targets=_bool("LLMSCAN_BLOCK_PRIVATE_TARGETS"),
            env_allowlist=[
                n.strip()
                for n in os.environ.get("LLMSCAN_ENV_ALLOWLIST", "").split(",")
                if n.strip()
            ],
        )

    def allowed_env(self) -> dict[str, str]:
        """The only environment variables a worker may expand into a stored config."""
        return {n: os.environ[n] for n in self.env_allowlist if n in os.environ}
