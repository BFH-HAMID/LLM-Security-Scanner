"""Execute one stored run. Used by the in-process thread pool and by the Celery task."""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx

from scanner.config import ScanConfig, interpolate_env
from scanner.connectors.configs import parse_target
from scanner.models import AttemptResult, Status
from scanner.runner import ScanRequest, ScopeError, run_scan
from scanner.storage import Store

log = logging.getLogger("llmscan.jobs")


async def execute_run_async(
    store: Store,
    run_id: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    judge_transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    run = store.get_run(None, run_id)
    if run is None or run.status in ("cancelled", "completed"):
        return
    if run.cancel_requested:
        store.finish_cancelled(run_id)
        return
    store.mark_running(run_id)
    try:
        target = parse_target(interpolate_env(run.target_config or {}))
        scan = ScanConfig.model_validate(run.scan_config)
        findings = 0

        async def on_result(result: AttemptResult, done: int, total: int) -> None:
            nonlocal findings
            findings += result.status is Status.FAIL
            await asyncio.to_thread(store.add_result, run_id, result)
            await asyncio.to_thread(store.set_progress, run_id, done, total, findings)

        async def cancelled() -> bool:
            return await asyncio.to_thread(store.is_cancel_requested, run_id)

        report = await run_scan(
            ScanRequest(
                target,
                scan,
                acknowledged_flag=bool((run.authorization or {}).get("acknowledged")),
                transport=transport,
                judge_transport=judge_transport,
                on_result=on_result,
                should_cancel=cancelled,
            )
        )
        report.id = run_id
        store.finish_run(run_id, report, save_results=scan.redact)
    except ScopeError as exc:
        store.fail_run(run_id, f"scope check failed: {exc}")
    except Exception as exc:
        log.exception("run %s failed", run_id)
        store.fail_run(run_id, f"{type(exc).__name__}: {exc}")


def execute_run(store: Store, run_id: str, **kwargs) -> None:
    asyncio.run(execute_run_async(store, run_id, **kwargs))


class InProcessQueue:
    """Default job queue: a small thread pool inside the API process (no Redis needed)."""

    name = "inprocess"

    def __init__(self, store: Store, workers: int = 2):
        self.store = store
        self.pool = ThreadPoolExecutor(
            max_workers=max(1, workers), thread_name_prefix="llmscan-job"
        )

    def enqueue(self, run_id: str) -> None:
        self.pool.submit(execute_run, self.store, run_id)

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)


class CeleryQueue:
    """Distributed job queue: Celery workers pull runs from Redis."""

    name = "celery"

    def enqueue(self, run_id: str) -> None:
        from api.jobs.celery_app import execute_run_task

        execute_run_task.delay(run_id)

    def shutdown(self) -> None:
        return None
