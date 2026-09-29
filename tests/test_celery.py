"""Celery/Redis job queue: eager mode always, real Redis worker when a server is available."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from api.jobs import celery_app as celery_module
from api.jobs.runner import CeleryQueue
from api.main import create_app
from api.settings import Settings
from scanner.storage import Store

KEY = "llmscan_celery_key"
P = "/api/v1"
DEMO = {
    "type": "demo",
    "level": "weak",
    "surface": "chat",
    "canaries": {"system": "CANARY-7f3a9c1e-ACME"},
}


@pytest.fixture(autouse=True)
def fresh_celery_pools():
    """Celery caches broker connection pools per app; tests that swap broker URLs must not share them."""

    def reset():
        app = celery_module.celery_app
        app._pool = None
        app.amqp._producer_pool = None

    reset()
    yield
    reset()


def build(tmp_path):
    settings = Settings(database_url=str(tmp_path / "c.db"), bootstrap_api_key=KEY, queue="celery")
    store = Store(settings.database_url)
    celery_module._store = store  # the worker task uses this store
    return create_app(settings, store=store, queue=CeleryQueue()), store


async def create_and_poll(app, timeout=60):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        tid = (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).json()["id"]
        rid = (
            await c.post(
                f"{P}/runs", json={"target_id": tid, "scan": {"seed": 1, "max_probes": 20}}
            )
        ).json()["id"]
        end = time.time() + timeout
        while time.time() < end:
            d = (await c.get(f"{P}/runs/{rid}")).json()
            if d["status"] in ("completed", "failed", "cancelled"):
                return d
            await asyncio.sleep(0.1)
    raise AssertionError("run did not finish")


async def test_celery_task_in_eager_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(celery_module.celery_app.conf, "task_always_eager", True)
    monkeypatch.setattr(celery_module.celery_app.conf, "task_eager_propagates", True)
    app, _ = build(tmp_path)
    done = await create_and_poll(app)
    assert done["status"] == "completed" and done["progress"]["done"] == 20


def test_celery_configuration_is_production_safe():
    conf = celery_module.celery_app.conf
    assert conf.task_acks_late is True and conf.worker_prefetch_multiplier == 1
    assert conf.accept_content == ["json"] and conf.task_serializer == "json"
    assert celery_module.execute_run_task.name == "llmscan.execute_run"


@pytest.mark.integration
async def test_celery_worker_with_real_redis(tmp_path, redis_url, monkeypatch):
    from celery.contrib.testing.worker import start_worker

    conf = celery_module.celery_app.conf
    monkeypatch.setattr(conf, "task_always_eager", False)
    monkeypatch.setattr(conf, "broker_url", redis_url)
    monkeypatch.setattr(conf, "result_backend", redis_url.rsplit("/", 1)[0] + "/1")
    app, _ = build(tmp_path)
    with start_worker(
        celery_module.celery_app,
        perform_ping_check=False,
        pool="solo",
        loglevel="WARNING",
        shutdown_timeout=30,
    ):
        done = await create_and_poll(app, timeout=90)
    assert done["status"] == "completed" and done["progress"]["done"] == 20 and done["findings"] > 0
