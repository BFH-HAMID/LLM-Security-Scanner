"""Celery application (``celery -A api.jobs.celery_app worker``). Broker and backend: Redis."""

from __future__ import annotations

from celery import Celery

from api.jobs.runner import execute_run
from api.settings import Settings
from scanner.storage import open_store

settings = Settings.from_env()

celery_app = Celery(
    "llmscan", broker=settings.celery_broker_url, backend=settings.celery_result_backend
)
celery_app.conf.update(
    task_acks_late=True,  # a crashed worker's run is re-delivered
    worker_prefetch_multiplier=1,  # long tasks: do not hoard
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,
)

_store = None


def _get_store():
    global _store
    if _store is None:
        _store = open_store(settings.database_url)
    return _store


@celery_app.task(name="llmscan.execute_run")
def execute_run_task(run_id: str) -> str:
    execute_run(_get_store(), run_id)
    return run_id
