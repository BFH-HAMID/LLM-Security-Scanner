"""PostgreSQL specifics: the whole storage suite also runs on Postgres (see test_storage.py).

These tests add what only a real server can prove: concurrent writers, JSON round-trips and the API
running a scan end to end on Postgres.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid

import httpx
import pytest
from sqlalchemy import text

from api.main import create_app
from api.settings import Settings
from scanner.storage import Store

pytestmark = pytest.mark.integration
KEY = "llmscan_pg_key"
P = "/api/v1"
DEMO = {
    "type": "demo",
    "level": "weak",
    "surface": "chat",
    "canaries": {"system": "CANARY-7f3a9c1e-ACME"},
}


@pytest.fixture()
def pg_store(pg_database):
    s = Store(pg_database)
    yield s
    s.close()


def test_driver_and_tables(pg_store):
    with pg_store.session() as s:
        assert "PostgreSQL" in s.execute(text("select version()")).scalar_one()
        tables = {
            r[0]
            for r in s.execute(text("select tablename from pg_tables where schemaname = 'public'"))
        }
    assert {"projects", "api_keys", "targets", "runs", "results"} <= tables


def test_large_unicode_json_roundtrips(pg_store, small_report):
    rep = small_report.model_copy(deep=True)
    rep.results[0].response_text = "naïve ✓ 日本語 " + "x" * 50_000 + " \\u0000-literal"
    rid = pg_store.save_report(rep)
    assert pg_store.load_report(rid).results[0].response_text == rep.results[0].response_text


def test_concurrent_writers_do_not_lose_results(pg_store, small_report):
    project = pg_store.ensure_project()
    ids = [
        pg_store.create_run(project.id, target_id=None, scan_config={}, target_summary={}).id
        for _ in range(4)
    ]
    errors: list[Exception] = []

    def work(run_id):
        try:
            pg_store.mark_running(run_id)
            for i, r in enumerate(small_report.results[:40], 1):
                pg_store.add_result(run_id, r.model_copy(update={"id": uuid.uuid4().hex}))
                pg_store.set_progress(run_id, i, 40, 0)
        except Exception as exc:  # pragma: no cover - only on failure
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in ids]
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    assert not errors
    for run_id in ids:
        assert pg_store.query_results(run_id, limit=1)[1] == 40
        assert pg_store.get_run(None, run_id).progress_done == 40


async def test_api_runs_a_scan_on_postgres(pg_database):
    settings = Settings(database_url=pg_database, bootstrap_api_key=KEY, workers=2)
    app = create_app(settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        tid = (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).json()["id"]
        rid = (
            await c.post(
                f"{P}/runs",
                json={
                    "target_id": tid,
                    "scan": {"seed": 1, "mutators": ["base64"], "max_probes": 20},
                },
            )
        ).json()["id"]
        end = time.time() + 60
        while time.time() < end:
            run = (await c.get(f"{P}/runs/{rid}")).json()
            if run["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.1)
        assert run["status"] == "completed" and run["progress"] == {"done": 40, "total": 40}
        assert (
            (await c.get(f"{P}/runs/{rid}/results?status=fail&limit=3")).json()["total"]
            == run["findings"]
            > 0
        )
        assert (await c.get(f"{P}/runs/{rid}/report?format=sarif")).status_code == 200
        assert len((await c.get(f"{P}/runs/{rid}/heatmap")).json()["rows"]) == 20
    app.state.store.close()
