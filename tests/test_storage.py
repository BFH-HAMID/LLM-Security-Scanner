"""SQLAlchemy store: round-trips, API keys, retention and cascade behaviour."""

from __future__ import annotations

import datetime as dt

import pytest

from scanner.models import RunReport, Status, utcnow
from scanner.storage import Store, hash_key, normalize_url
from scanner.storage.models import ResultRow, RunRow, UTCDateTime


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.integration)])
def store(request, tmp_path):
    """Every storage test runs on SQLite and, when one is available, on a real PostgreSQL."""
    url = (
        str(tmp_path / "t.db")
        if request.param == "sqlite"
        else request.getfixturevalue("pg_database")
    )
    s = Store(url)
    yield s
    s.close()


def test_url_normalisation(tmp_path):
    assert normalize_url("relative.db") == "sqlite:///relative.db"
    assert normalize_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_url("sqlite:///x.db") == "sqlite:///x.db"


def test_report_roundtrip_preserves_everything(store, small_report):
    rid = store.save_report(small_report)
    back = store.load_report(rid)
    assert back.model_dump(mode="json", exclude={"tool"}) == small_report.model_dump(
        mode="json", exclude={"tool"}
    )
    row = store.get_run(None, rid)
    assert (
        row.status == "completed"
        and row.risk_score == small_report.score.risk_score
        and row.findings == small_report.score.failed
    )


def test_query_results_filters_and_pagination(store, small_report):
    rid = store.save_report(small_report)
    fails, total = store.query_results(rid, status="fail")
    assert total == small_report.score.failed and all(r.status is Status.FAIL for r in fails)
    page1, t1 = store.query_results(rid, limit=10, offset=0)
    page2, _ = store.query_results(rid, limit=10, offset=10)
    assert t1 == len(small_report.results) and not {r.id for r in page1} & {r.id for r in page2}
    _, only_b64 = store.query_results(rid, mutator="base64")
    assert 0 < only_b64 < t1
    assert (
        store.get_result(rid, fails[0].id).id == fails[0].id
        and store.get_result("other", fails[0].id) is None
    )
    assert store.heatmap_rows(rid)[0][4] in {"none", "base64", "roleplay"}


def test_api_keys_are_hashed_and_revocable(store):
    project = store.ensure_project()
    row, key = store.create_api_key(project.id, "ci", is_admin=False)
    assert (
        key.startswith("llmscan_")
        and row.key_hash == hash_key(key)
        and key not in (row.key_hash, row.prefix)
    )
    assert store.verify_api_key(key).id == row.id and store.verify_api_key(key + "x") is None
    assert store.list_api_keys(project.id)[0].last_used_at is not None
    assert store.revoke_api_key(project.id, row.id) and store.verify_api_key(key) is None
    assert not store.revoke_api_key("other-project", row.id)
    assert store.has_api_keys()


def test_projects_isolate_targets_and_runs(store):
    a, b = store.ensure_project("a"), store.create_project("b")
    with pytest.raises(ValueError):
        store.create_project("b")
    t = store.create_target(a.id, "t", {"type": "demo"})
    assert store.get_target(a.id, t.id) and store.get_target(b.id, t.id) is None
    run = store.create_run(a.id, target_id=t.id, scan_config={}, target_summary={})
    assert store.get_run(a.id, run.id) and store.get_run(b.id, run.id) is None
    assert store.list_runs(b.id)[1] == 0 and store.list_runs(a.id)[1] == 1
    assert not store.delete_target(b.id, t.id) and store.delete_target(a.id, t.id)
    assert store.get_run(a.id, run.id).target_id is None  # run survives its target


def test_cancel_and_orphan_recovery(store):
    p = store.ensure_project()
    queued = store.create_run(p.id, target_id=None, scan_config={}, target_summary={})
    running = store.create_run(p.id, target_id=None, scan_config={}, target_summary={})
    store.mark_running(running.id)
    assert (
        store.request_cancel(p.id, queued.id)
        and store.get_run(None, queued.id).status == "cancelled"
    )
    assert store.request_cancel(p.id, running.id) and store.is_cancel_requested(running.id)
    assert not store.request_cancel(p.id, "nope")
    assert store.fail_orphaned_runs() == 1 and store.get_run(None, running.id).status == "failed"


def test_delete_run_cascades_and_clears_baselines(store, small_report):
    p = store.ensure_project()
    t = store.create_target(p.id, "t", {})
    rid = store.save_report(small_report, project_id=p.id, target_id=t.id)
    assert (
        store.set_baseline(p.id, t.id, rid) and store.get_target(p.id, t.id).baseline_run_id == rid
    )
    assert store.delete_run(p.id, rid)
    assert store.get_target(p.id, t.id).baseline_run_id is None
    with store.session() as s:
        assert s.query(ResultRow).filter_by(run_id=rid).count() == 0


def test_purge_only_removes_old_finished_runs(store, small_report):
    old = store.save_report(small_report)
    fresh = RunReport(results=small_report.results[:3], score=small_report.score)
    fresh_id = store.save_report(fresh)
    running = store.create_run(
        store.ensure_project().id, target_id=None, scan_config={}, target_summary={}
    )
    store.mark_running(running.id)
    with store.session() as s:
        for rid in (old, running.id):
            s.get(RunRow, rid).created_at = utcnow() - dt.timedelta(days=90)
    assert store.purge(30) == 1
    assert (
        store.get_run(None, old) is None
        and store.get_run(None, fresh_id)
        and store.get_run(None, running.id)
    )


def test_datetimes_are_timezone_aware_utc(store, small_report):
    rid = store.save_report(small_report)
    back = store.load_report(rid)
    assert back.started_at.tzinfo is not None and back.started_at.utcoffset() == dt.timedelta(0)
    assert UTCDateTime().process_bind_param(dt.datetime(2026, 1, 1), None).tzinfo is not None
