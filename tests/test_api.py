"""REST API: auth, isolation, masking, the run lifecycle, exports and policy."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import httpx
import jsonschema
import pytest

from api.jobs.runner import execute_run
from api.main import create_app
from api.settings import Settings
from scanner.storage import Store

KEY = "llmscan_test_admin_key"
SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())
DEMO = {
    "type": "demo",
    "level": "weak",
    "surface": "chat",
    "canaries": {"system": "CANARY-7f3a9c1e-ACME"},
}
P = "/api/v1"


class ManualQueue:
    """Records run ids instead of executing them (lets tests inspect the 'queued' state)."""

    name = "manual"

    def __init__(self):
        self.ids: list[str] = []

    def enqueue(self, run_id):
        self.ids.append(run_id)

    def shutdown(self):
        return None


def make_app(tmp_path, queue=None, **settings):
    s = Settings(
        database_url=str(tmp_path / "api.db"), bootstrap_api_key=KEY, workers=2, **settings
    )
    return create_app(s, store=Store(s.database_url), queue=queue)


@pytest.fixture()
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture()
async def client(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        yield c


async def wait_done(client, run_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        d = (await client.get(f"{P}/runs/{run_id}")).json()
        if d["status"] in ("completed", "failed", "cancelled"):
            return d
        await asyncio.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish")


async def new_target(client, config=None, name="demo"):
    r = await client.post(f"{P}/targets", json={"name": name, "config": config or DEMO})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def run_and_wait(client, target_id, scan=None, **body):
    r = await client.post(
        f"{P}/runs", json={"target_id": target_id, "scan": {"seed": 1, **(scan or {})}, **body}
    )
    assert r.status_code == 202, r.text
    return await wait_done(client, r.json()["id"])


# --------------------------------------------------------------------------------- auth


async def test_health_is_open_but_everything_else_needs_a_key(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api"
    ) as anon:
        assert (await anon.get(f"{P}/health")).json()["status"] == "ok"
        for path in ("/runs", "/targets", "/meta", "/probes", "/me", "/keys"):
            r = await anon.get(P + path)
            assert r.status_code == 401 and r.headers["www-authenticate"] == "ApiKey", path
        assert (await anon.get(f"{P}/me", headers={"X-API-Key": "wrong"})).status_code == 401
        assert (
            await anon.get(f"{P}/me", headers={"Authorization": f"Bearer {KEY}"})
        ).status_code == 200


async def test_security_headers(client):
    r = await client.get(f"{P}/me")
    assert (
        r.headers["x-content-type-options"] == "nosniff"
        and r.headers["cache-control"] == "no-store"
    )


async def test_keys_projects_and_isolation(client, app):
    assert (await client.get(f"{P}/me")).json()["is_admin"] is True
    p = (await client.post(f"{P}/projects", json={"name": "team-b"})).json()
    assert (await client.post(f"{P}/projects", json={"name": "team-b"})).status_code == 409
    key_b = (await client.post(f"{P}/projects/{p['id']}/keys", json={"name": "b-user"})).json()
    assert key_b["key"].startswith("llmscan_") and "key_hash" not in key_b
    tid = await new_target(client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://api",
        headers={"X-API-Key": key_b["key"]},
    ) as b:
        assert (await b.get(f"{P}/me")).json()["project"]["name"] == "team-b"
        assert (await b.get(f"{P}/targets")).json() == []  # A's target is invisible
        assert (await b.get(f"{P}/targets/{tid}")).status_code == 404
        assert (
            await b.post(f"{P}/projects", json={"name": "x"})
        ).status_code == 403  # not an admin
        assert (await b.post(f"{P}/runs", json={"target_id": tid})).status_code == 404
    keys = (await client.get(f"{P}/keys")).json()
    assert all("key" not in k and "key_hash" not in k for k in keys)
    kid = next(k["id"] for k in keys if k["name"] == "bootstrap admin")
    extra = (await client.post(f"{P}/keys", json={"name": "ci"})).json()
    assert (await client.delete(f"{P}/keys/{extra['id']}")).status_code == 204
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://api",
        headers={"X-API-Key": extra["key"]},
    ) as revoked:
        assert (await revoked.get(f"{P}/me")).status_code == 401
    assert kid


async def test_auth_can_be_disabled_for_local_development(tmp_path):
    app = make_app(tmp_path, auth_disabled=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api"
    ) as anon:
        assert (await anon.get(f"{P}/runs")).status_code == 200


# ------------------------------------------------------------------------------ targets


async def test_target_secrets_are_masked_and_preserved_on_update(client, app):
    cfg = {
        "type": "http",
        "url": "http://localhost:9/chat",
        "auth": {"type": "bearer", "token": "super-secret-token-123"},
        "headers": {"X-Api-Key": "abc-key-456789"},
    }
    r = await client.post(f"{P}/targets", json={"name": "svc", "config": cfg})
    body = r.json()
    blob = json.dumps(body)
    assert (
        "super-secret-token-123" not in blob and "abc-key-456789" not in blob and "sup***23" in blob
    )
    tid = body["id"]
    # the UI sends the masked config back unchanged: the stored secret must survive
    upd = await client.put(
        f"{P}/targets/{tid}",
        json={"config": {**body["config"], "url": "http://localhost:9/v2/chat"}},
    )
    assert upd.status_code == 200
    stored = app.state.store.get_target(app.state.store.ensure_project().id, tid).config
    assert stored["auth"]["token"] == "super-secret-token-123" and stored["url"].endswith(
        "/v2/chat"
    )
    # a genuinely new secret replaces it
    await client.put(
        f"{P}/targets/{tid}",
        json={
            "config": {**body["config"], "auth": {"type": "bearer", "token": "rotated-token-000"}}
        },
    )
    assert (
        app.state.store.get_target(app.state.store.ensure_project().id, tid).config["auth"]["token"]
        == "rotated-token-000"
    )
    assert "rotated-token-000" not in (await client.get(f"{P}/targets/{tid}")).text
    assert (await client.get(f"{P}/targets")).status_code == 200 and (
        await client.delete(f"{P}/targets/{tid}")
    ).status_code == 204
    assert (await client.get(f"{P}/targets/{tid}")).status_code == 404


async def test_target_validation(client):
    for cfg in ({"type": "http"}, {"type": "nope"}, {"type": "http", "url": "x", "bogus": 1}, {}):
        assert (
            await client.post(f"{P}/targets", json={"name": "x", "config": cfg})
        ).status_code == 422
    assert (await client.post(f"{P}/targets", json={"name": "", "config": DEMO})).status_code == 422
    env_ref = {
        "type": "http",
        "url": "http://localhost:1/x",
        "auth": {"type": "bearer", "token": "${MY_TOKEN}"},
    }
    # ${VAR} would be expanded from the worker's environment: refused unless allowlisted
    # (see test_api_secrets.py for the policy and its tests)
    assert (
        await client.post(f"{P}/targets", json={"name": "env", "config": env_ref})
    ).status_code == 422


async def test_server_side_target_policy(tmp_path):
    app = make_app(
        tmp_path,
        target_allowlist=["*.acme.com"],
        block_private_targets=True,
        allow_demo_target=False,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:

        def post(url):
            return c.post(
                f"{P}/targets", json={"name": "t", "config": {"type": "http", "url": url}}
            )

        assert (await post("https://chat.acme.com/x")).status_code == 201
        assert (await post("https://evil.example.org/x")).status_code == 403
        assert (await post("http://localhost:8000/x")).status_code == 403
        assert (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).status_code == 403
    app2 = (
        make_app(tmp_path / "x", block_private_targets=True)
        if (tmp_path / "x").mkdir() is None
        else None
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app2), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        assert (
            await c.post(
                f"{P}/targets",
                json={"name": "t", "config": {"type": "http", "url": "http://169.254.169.254/x"}},
            )
        ).status_code == 403


# ---------------------------------------------------------------------------------- runs


async def test_full_run_lifecycle(client):
    tid = await new_target(client)
    r = await client.post(
        f"{P}/runs",
        json={
            "target_id": tid,
            "name": "nightly",
            "scan": {"seed": 1, "mutators": ["base64"], "max_probes": 30},
        },
    )
    assert r.status_code == 202
    created = r.json()
    assert (
        created["status"] in ("queued", "running")
        and created["progress"]["total"] == 60
        and created["name"] == "nightly"
    )
    assert created["scan"]["mutators"] == ["base64"] and created["scan"]["seed"] == 1
    done = await wait_done(client, created["id"])
    assert done["status"] == "completed" and done["error"] is None
    # what was requested never changes; what was learned while running is kept separately
    assert done["scan"] == created["scan"]
    assert done["summary"]["probes"] == 30 and done["summary"]["mutators"] == ["base64"]
    assert done["target"]["type"] == "demo" and created["target"]["type"] == "demo"
    assert done["progress"] == {"done": 60, "total": 60}
    assert done["grade"] in "ABCDF" and done["risk_score"] > 0 and done["findings"] > 0
    assert done["score"]["total"] == 60 and set(done["score"]["categories"]) <= {
        "prompt_injection",
        "indirect_injection",
        "jailbreak",
        "system_prompt_extraction",
        "sensitive_data_leakage",
        "insecure_output_handling",
        "excessive_agency",
    }
    assert (
        done["authorization"]["scope"] == "demo"
        and done["scan"]["mutators"] == ["base64"]
        and done["target"]["type"] == "demo"
    )
    listing = (await client.get(f"{P}/runs")).json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == created["id"]
    assert (await client.get(f"{P}/runs?status=failed")).json()["total"] == 0
    assert (await client.get(f"{P}/runs?target_id={tid}")).json()["total"] == 1

    res = (await client.get(f"{P}/runs/{created['id']}/results?status=fail&limit=5")).json()
    assert res["total"] == done["findings"] and len(res["items"]) == 5
    assert all(i["status"] == "fail" and "transcript" not in i for i in res["items"])
    assert (
        await client.get(
            f"{P}/runs/{created['id']}/results?category=prompt_injection&severity=critical"
        )
    ).json()["total"] >= 0
    assert (await client.get(f"{P}/runs/{created['id']}/results?status=bogus")).status_code == 422
    one = (await client.get(f"{P}/runs/{created['id']}/results/{res['items'][0]['id']}")).json()
    assert (
        one["transcript"][-1]["role"] == "assistant"
        and one["evidence"]
        and one["remediation"]
        and one["owasp"]
    )
    heat = (await client.get(f"{P}/runs/{created['id']}/heatmap")).json()
    assert heat["mutators"] == ["none", "base64"] and len(heat["rows"]) == 30
    assert set(heat["rows"][0]["cells"]) == {"none", "base64"}
    assert (await client.get(f"{P}/runs/nope")).status_code == 404

    assert (await client.delete(f"{P}/runs/{created['id']}")).status_code == 204
    assert (await client.get(f"{P}/runs/{created['id']}")).status_code == 404


async def test_report_exports(client):
    tid = await new_target(client)
    run = await run_and_wait(client, tid, {"max_probes": 40})
    rid = run["id"]
    expected = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
        "sarif": "application/sarif+json",
        "md": "text/markdown",
    }
    for fmt, ctype in expected.items():
        r = await client.get(f"{P}/runs/{rid}/report?format={fmt}")
        assert r.status_code == 200 and r.headers["content-type"].startswith(ctype), fmt
        assert "attachment" in r.headers["content-disposition"] and len(r.content) > 200
    html = await client.get(f"{P}/runs/{rid}/report?format=html")
    assert (
        "default-src 'none'" in html.headers["content-security-policy"]
        and "<script" not in html.text
    )
    assert (await client.get(f"{P}/runs/{rid}/report?format=pdf")).content.startswith(b"%PDF")
    sarif = (await client.get(f"{P}/runs/{rid}/report?format=sarif")).json()
    assert not list(jsonschema.Draft7Validator(SCHEMA).iter_errors(sarif))
    assert len(sarif["runs"][0]["results"]) == run["findings"]
    assert json.loads((await client.get(f"{P}/runs/{rid}/report?format=json")).content)["id"] == rid
    assert (await client.get(f"{P}/runs/{rid}/report?format=docx")).status_code == 422


async def test_compare_and_baseline_flow(client):
    weak, hard = (
        await new_target(client, DEMO, "weak"),
        await new_target(client, {**DEMO, "level": "hardened"}, "hard"),
    )
    a = await run_and_wait(client, weak)
    b = await run_and_wait(client, hard)
    cmp = (await client.get(f"{P}/compare?a={a['id']}&b={b['id']}")).json()
    assert (
        cmp["verdict"] == "better"
        and cmp["risk_delta"] < 0
        and cmp["fixed"]
        and not cmp["regressions"]
    )
    assert all("delta" in c for c in cmp["categories"])
    rev = (await client.get(f"{P}/compare?a={b['id']}&b={a['id']}")).json()
    assert rev["verdict"] == "worse" and rev["regressions"]
    assert (await client.get(f"{P}/compare?a={a['id']}&b=nope")).status_code == 404

    # baseline: mark the hardened run good, then check the weak run against it
    assert (await client.get(f"{P}/runs/{b['id']}/baseline-check")).status_code == 404  # none yet
    assert (await client.put(f"{P}/targets/{hard}/baseline", json={"run_id": b["id"]})).json()[
        "baseline_run_id"
    ] == b["id"]
    ok = (await client.get(f"{P}/runs/{b['id']}/baseline-check")).json()
    assert ok["ok"] is True and ok["risk_delta"] == 0
    again = await run_and_wait(client, hard)
    assert (await client.get(f"{P}/runs/{again['id']}/baseline-check")).json()["ok"] is True
    assert (
        await client.put(f"{P}/targets/{weak}/baseline", json={"run_id": "nope"})
    ).status_code == 404
    assert (await client.delete(f"{P}/targets/{hard}/baseline")).status_code == 204
    assert (await client.get(f"{P}/targets/{hard}")).json()["baseline_run_id"] is None


async def test_run_validation_and_policy_errors(client, tmp_path):
    tid = await new_target(client)
    post = lambda **body: client.post(f"{P}/runs", json=body)  # noqa: E731
    assert (await post()).status_code == 422  # neither target nor target_id
    assert (await post(target_id=tid, target=DEMO)).status_code == 422  # both
    assert (await post(target_id="nope")).status_code == 404
    assert (
        await post(target_id=tid, scan={"probe_paths": ["/etc"]})
    ).status_code == 422  # no server-side file access
    assert (await post(target_id=tid, scan={"builtin_probes": False})).status_code == 422
    assert (await post(target_id=tid, scan={"repeats": 0})).status_code == 422
    assert (await post(target_id=tid, scan={"mutators": ["nope"]})).status_code == 422
    assert (
        await post(target_id=tid, scan={"ids": ["ZZ-999"]})
    ).status_code == 422  # matches nothing
    assert (await post(target_id=tid, scan={"bogus": 1})).status_code == 422
    small = (
        make_app(tmp_path / "s", max_attempts_per_run=50)
        if (tmp_path / "s").mkdir() is None
        else None
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=small), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        t2 = (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).json()["id"]
        r = await c.post(f"{P}/runs", json={"target_id": t2, "scan": {}})
        assert r.status_code == 422 and "exceeds the server limit" in r.text


async def test_scope_guard_over_the_api(tmp_path):
    q = ManualQueue()
    app = make_app(tmp_path, queue=q)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        public = {"type": "http", "url": "https://chat.acme-corp.com/api"}
        tid = (await c.post(f"{P}/targets", json={"name": "prod", "config": public})).json()["id"]
        refused = await c.post(f"{P}/runs", json={"target_id": tid})
        assert refused.status_code == 403 and "authorised" in refused.text and q.ids == []
        ok = await c.post(
            f"{P}/runs",
            json={
                "target_id": tid,
                "authorization": {
                    "acknowledged": True,
                    "note": "own staging",
                    "contact": "sec@acme-corp.com",
                },
            },
        )
        assert ok.status_code == 202 and len(q.ids) == 1
        auth = ok.json()["authorization"]
        assert (
            auth["acknowledged"]
            and auth["via"] == "flag"
            and auth["note"] == "own staging"
            and auth["scope"] == "public"
        )
        assert ok.json()["scan"]["authorization"]["acknowledged"] is True


async def test_cancel_a_queued_run_and_refuse_to_delete_active_runs(tmp_path):
    q = ManualQueue()
    app = make_app(tmp_path, queue=q)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        tid = (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).json()["id"]
        rid = (await c.post(f"{P}/runs", json={"target_id": tid})).json()["id"]
        assert (await c.delete(f"{P}/runs/{rid}")).status_code == 409
        assert (await c.post(f"{P}/runs/{rid}/cancel")).json()["status"] == "cancelled"
        await asyncio.to_thread(
            execute_run, app.state.store, rid
        )  # a late worker must not resurrect it
        assert (await c.get(f"{P}/runs/{rid}")).json()["status"] == "cancelled"
        assert (await c.delete(f"{P}/runs/{rid}")).status_code == 204


async def test_cancel_a_running_run_keeps_partial_results(tmp_path):
    q = ManualQueue()
    app = make_app(tmp_path, queue=q)
    store = app.state.store
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    ) as c:
        tid = (await c.post(f"{P}/targets", json={"name": "d", "config": DEMO})).json()["id"]
        rid = (
            await c.post(
                f"{P}/runs",
                json={"target_id": tid, "scan": {"seed": 1, "rps": 100, "concurrency": 1}},
            )
        ).json()["id"]
        worker = threading.Thread(target=execute_run, args=(store, rid))
        worker.start()
        for _ in range(200):
            if (await c.get(f"{P}/runs/{rid}")).json()["progress"]["done"] >= 5:
                break
            await asyncio.sleep(0.02)
        assert (await c.post(f"{P}/runs/{rid}/cancel")).status_code == 200
        worker.join(timeout=30)
        final = (await c.get(f"{P}/runs/{rid}")).json()
        assert final["status"] == "cancelled" and 5 <= final["progress"]["done"] < 88
        assert (await c.get(f"{P}/runs/{rid}/results?limit=1")).json()["total"] == final[
            "progress"
        ]["done"]  # partial results kept


async def test_a_minimal_demo_target_config_still_detects_leaks(client):
    """The dashboard sends {type: demo, level, surface}; it must find exactly what the CLI shorthand finds."""
    from scanner.models import Category
    from tests.conftest import run_demo

    cats = [Category.SENSITIVE_DATA_LEAKAGE, Category.SYSTEM_PROMPT_EXTRACTION]
    expected = await asyncio.to_thread(run_demo, "demo:weak", categories=cats)
    tid = await new_target(
        client, {"type": "demo", "level": "weak", "surface": "chat"}, "bare demo"
    )
    run = await run_and_wait(client, tid, {"categories": [c.value for c in cats], "seed": 1})
    assert expected.score.failed >= 10
    assert (
        run["findings"] == expected.score.failed and run["risk_score"] == expected.score.risk_score
    )


async def test_coverage_notes_survive_the_database(client):
    """'No tool call observed' style warnings are part of an honest result; they must not be lost."""
    tid = await new_target(client, {**DEMO, "level": "hardened"}, "hardened chat")
    run = await run_and_wait(client, tid, {"categories": ["excessive_agency"]})
    assert any("No tool call was observed" in n for n in run["notes"]), run["notes"]
    report = json.loads((await client.get(f"{P}/runs/{run['id']}/report?format=json")).content)
    assert report["notes"] == run["notes"] and report["config"]["probes"] == 12


async def test_a_failing_target_marks_the_run_failed(client):
    dead = {
        "type": "http",
        "url": "http://127.0.0.1:9/chat",
        "timeout": 1,
        "response_path": "$.reply",
    }
    tid = await new_target(client, dead, "dead")
    run = await run_and_wait(
        client, tid, {"retries": 0, "max_probes": 12, "max_consecutive_errors": 3, "concurrency": 1}
    )
    assert run["status"] == "failed" and "consecutive target errors" in run["error"]


async def test_redacted_runs_store_masked_transcripts(client, app):
    tid = await new_target(client)
    run = await run_and_wait(client, tid, {"redact": True, "ids": ["DL-002"]})
    item = (await client.get(f"{P}/runs/{run['id']}/results?include_transcript=true")).json()[
        "items"
    ][0]
    blob = json.dumps(item)
    assert (
        "987-65-4320" not in blob
        and "alice.johnson@example.com" not in blob
        and "[REDACTED" in blob
    )


async def test_meta_and_probe_endpoints(client):
    meta = (await client.get(f"{P}/meta")).json()
    assert len(meta["categories"]) == 7 and sum(c["probes"] for c in meta["categories"]) == 88
    assert {"base64", "roleplay"} <= {m["name"] for m in meta["mutators"]} and meta["owasp"][
        "edition"
    ] == "2025"
    probes = (await client.get(f"{P}/probes?category=jailbreak")).json()
    assert len(probes) == 16 and all(p["category"] == "jailbreak" for p in probes)
    one = (await client.get(f"{P}/probes/pi-001")).json()
    assert one["id"] == "PI-001" and one["spec"]["success_criteria"] and one["remediation"]
    assert (await client.get(f"{P}/probes/ZZ-1")).status_code == 404
    assert (await client.get(f"{P}/docs")).status_code == 200 and (
        await client.get(f"{P}/openapi.json")
    ).json()["info"]["title"]
