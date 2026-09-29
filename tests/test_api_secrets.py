"""The API must never hand the server's secrets to a target chosen by an API caller.

Two ways the worker's environment could leak to an attacker-controlled URL:
  1. ``${NAME}`` references in a stored target config (expanded on the worker), and
  2. provider shorthands such as ``openai:MODEL@https://evil/v1`` for the judge / attacker, which used
     to copy OPENAI_API_KEY from the process environment.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from api.jobs.runner import execute_run
from tests.test_api import KEY, ManualQueue, P, make_app, new_target

SECRET = "sk-server-secret-0123456789"
HTTP_TARGET = {
    "type": "http",
    "url": "http://target.internal/chat",
    "body": {"message": "{{prompt}}"},
    "response_path": "$.reply",
}


class Recorder:
    """A fake network: records every request and answers like a chatbot / judge."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if request.url.path.endswith("/chat/completions"):
                return httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "content": '{"succeeded": false, "confidence": 0.9, "rationale": "no"}'
                                }
                            }
                        ]
                    },
                )
            return httpx.Response(200, json={"reply": "I can only help with orders."})

        return httpx.MockTransport(handler)

    def header_values(self) -> str:
        return "\n".join(f"{k}: {v}" for r in self.requests for k, v in r.headers.items())


def client_for(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api", headers={"X-API-Key": KEY}
    )


# ------------------------------------------------------------- 1. ${NAME} references


async def test_env_references_are_refused_by_default(tmp_path):
    async with client_for(make_app(tmp_path)) as c:
        cfg = {**HTTP_TARGET, "auth": {"type": "bearer", "token": "${OPENAI_API_KEY}"}}
        r = await c.post(f"{P}/targets", json={"name": "x", "config": cfg})
        assert r.status_code == 422
        assert "${OPENAI_API_KEY}" in r.text and "LLMSCAN_ENV_ALLOWLIST" in r.text
        # nested anywhere, including headers and defaults
        for sneaky in (
            {"headers": {"X": "a-${DATABASE_URL}-b"}},
            {"headers": {"X": "${HOME:-nope}"}},
        ):
            assert (
                await c.post(
                    f"{P}/targets", json={"name": "x", "config": {**HTTP_TARGET, **sneaky}}
                )
            ).status_code == 422
        # updating an existing target and inline run targets go through the same gate
        tid = await new_target(c, HTTP_TARGET, "ok")
        assert (await c.put(f"{P}/targets/{tid}", json={"config": cfg})).status_code == 422
        assert (await c.post(f"{P}/runs", json={"target": cfg, "scan": {}})).status_code == 422


async def test_an_allowlisted_reference_is_expanded_and_nothing_else_is(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "tok-allowed-123")
    monkeypatch.setenv("OTHER_SECRET", "must-never-be-sent")
    app = make_app(tmp_path, queue=ManualQueue(), env_allowlist=["MY_TOKEN"])
    net = Recorder()
    async with client_for(app) as c:
        cfg = {**HTTP_TARGET, "auth": {"type": "bearer", "token": "${MY_TOKEN}"}}
        tid = await new_target(c, cfg, "allowed")
        assert (
            await c.post(
                f"{P}/targets",
                json={"name": "x", "config": {**HTTP_TARGET, "headers": {"X": "${OTHER_SECRET}"}}},
            )
        ).status_code == 422
        run = (
            await c.post(
                f"{P}/runs",
                json={
                    "target_id": tid,
                    "scan": {"seed": 1, "max_probes": 2, "judge": {"mode": "off"}},
                },
            )
        ).json()
        await asyncio.to_thread(
            execute_run,
            app.state.store,
            run["id"],
            transport=net.transport(),
            env=app.state.settings.allowed_env(),
        )
        assert (await c.get(f"{P}/runs/{run['id']}")).json()["status"] == "completed"
    assert net.requests and all(
        r.headers["authorization"] == "Bearer tok-allowed-123" for r in net.requests
    )
    assert "must-never-be-sent" not in net.header_values()


async def test_the_worker_refuses_references_even_if_validation_was_bypassed(tmp_path, monkeypatch):
    """Defence in depth: a config written straight into the database still cannot read the environment."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://svc:hunter2@db/llmscan")
    app = make_app(tmp_path, queue=ManualQueue())
    store, net = app.state.store, Recorder()
    project = store.ensure_project()
    sneaky = {**HTTP_TARGET, "headers": {"X-Leak": "${DATABASE_URL}"}}
    run = store.create_run(
        project.id,
        target_id=None,
        scan_config={"seed": 1, "max_probes": 1},
        target_summary={},
        target_config=sneaky,
    )
    await asyncio.to_thread(
        execute_run, store, run.id, transport=net.transport()
    )  # no env given: empty
    row = store.get_run(None, run.id)
    assert row.status == "failed" and "DATABASE_URL" in (row.error or "")
    assert net.requests == [], "nothing may be sent once a reference cannot be resolved"
    assert "hunter2" not in (row.error or "")


# ------------------------------------------------- 2. provider shorthands for judge / attacker


def probes_with_judge_criteria() -> list[str]:
    from scanner.probes import load_probes

    return [p.id for p in load_probes() if p.success_criteria.judge is not None][:2]


async def test_a_judge_shorthand_cannot_borrow_the_servers_provider_key(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    app = make_app(tmp_path, queue=ManualQueue())  # no allowlist
    net = Recorder()
    judge = {"mode": "llm", "target": "openai:gpt-4o-mini@https://judge.attacker.example/v1"}
    async with client_for(app) as c:
        tid = await new_target(c)
        r = await c.post(
            f"{P}/runs",
            json={
                "target_id": tid,
                "scan": {"seed": 1, "ids": probes_with_judge_criteria(), "judge": judge},
            },
        )
        assert r.status_code == 202, r.text
        await asyncio.to_thread(
            execute_run,
            app.state.store,
            r.json()["id"],
            judge_transport=net.transport(),
            env=app.state.settings.allowed_env(),
        )
    assert net.requests, "the judge was consulted, so the test is meaningful"
    assert all(str(req.url).startswith("https://judge.attacker.example/") for req in net.requests)
    assert SECRET not in net.header_values()


async def test_an_operator_can_opt_in_to_sharing_a_provider_key(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    app = make_app(tmp_path, queue=ManualQueue(), env_allowlist=["OPENAI_API_KEY"])
    net = Recorder()
    judge = {"mode": "llm", "target": "openai:gpt-4o-mini@https://api.openai.example/v1"}
    async with client_for(app) as c:
        tid = await new_target(c)
        r = await c.post(
            f"{P}/runs",
            json={
                "target_id": tid,
                "scan": {"seed": 1, "ids": probes_with_judge_criteria(), "judge": judge},
            },
        )
        assert r.status_code == 202, r.text
        await asyncio.to_thread(
            execute_run,
            app.state.store,
            r.json()["id"],
            judge_transport=net.transport(),
            env=app.state.settings.allowed_env(),
        )
    assert net.requests and all(
        req.headers["authorization"] == f"Bearer {SECRET}" for req in net.requests
    )


async def test_judge_and_attacker_targets_obey_the_host_policy(tmp_path):
    app = make_app(
        tmp_path, block_private_targets=True, target_allowlist=["*.acme.com"], queue=ManualQueue()
    )
    async with client_for(app) as c:
        tid = await new_target(c, {"type": "http", "url": "https://bot.acme.com/chat"}, "ok")
        for field, spec in (
            ("judge", "openai:x@http://169.254.169.254/v1"),  # cloud metadata service
            ("judge", "openai:x@https://evil.example.org/v1"),  # not on the allowlist
            ("attacker", "ollama:llama3@http://localhost:11434"),  # loopback
        ):
            scan = {field: {"mode": "llm", "target": spec}}
            r = await c.post(f"{P}/runs", json={"target_id": tid, "scan": scan})
            assert r.status_code == 403, (spec, r.status_code, r.text)
        bad = await c.post(
            f"{P}/runs",
            json={"target_id": tid, "scan": {"judge": {"mode": "llm", "target": "nonsense"}}},
        )
        assert bad.status_code == 422


def test_environment_is_an_explicit_input_to_provider_shorthands(monkeypatch):
    from scanner.config import ConfigError, model_target

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    assert model_target("openai:gpt-4o")["api_key"] == SECRET  # CLI behaviour is unchanged
    assert "api_key" not in model_target("openai:gpt-4o@http://x/v1", env={})
    with pytest.raises(ConfigError):
        model_target("openai:gpt-4o", env={})
