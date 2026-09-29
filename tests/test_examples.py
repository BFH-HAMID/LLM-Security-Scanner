"""The example configs are documentation, so they must keep working (against a real HTTP server)."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml
from typer.testing import CliRunner

from scanner.cli import app
from scanner.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
runner = CliRunner()


@pytest.fixture(scope="module")
def demo_url():
    """The vulnerable demo app on a real socket."""
    from targets.vulnerable_app.main import create_app

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if getattr(server, "started", False):
            break
        time.sleep(0.05)
    else:  # pragma: no cover
        raise RuntimeError("demo target did not start")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def scan(config: str, *args: str, tmp_path: Path) -> dict:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["run", str(EXAMPLES / config), "--no-save", "-q", "-o", str(out), *args]
    )
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text())


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")), ids=lambda p: p.name)
def test_every_example_config_loads(path, monkeypatch):
    for name, value in {
        "OPENAI_API_KEY": "sk-x",
        "ANTHROPIC_API_KEY": "sk-ant-x",
        "ANTHROPIC_MODEL": "claude-x",
    }.items():
        monkeypatch.setenv(name, value)
    cfg = load_config(path)
    assert cfg.target.canaries, "examples should show how to plant a canary"


PARITY = [
    (
        "demo-http.yaml",
        "demo:weak:chat",
        ["system_prompt_extraction", "sensitive_data_leakage"],
        ["base64", "roleplay"],
    ),
    ("demo-agent-http.yaml", "demo:medium:agent", ["excessive_agency"], []),
    ("demo-rag-http.yaml", "demo:weak:rag", ["indirect_injection"], []),
]


@pytest.mark.parametrize("config, spec, categories, mutators", PARITY, ids=[p[0] for p in PARITY])
def test_scanning_over_real_http_gives_the_same_verdicts_as_in_process(
    config, spec, categories, mutators, demo_url, monkeypatch, tmp_path
):
    """Request templates, JSONPath extraction, conversation ids, tool-call capture and RAG ingestion
    all sit between the scanner and the app; none of it may change a single verdict."""
    from scanner.models import Category
    from tests.conftest import run_demo

    monkeypatch.setenv("DEMO_URL", demo_url)
    args = [x for c in categories for x in ("-c", c)]
    over_http = {
        (r["probe_id"], r["mutator"]): r["status"]
        for r in scan(config, *args, tmp_path=tmp_path)["results"]
    }
    local = run_demo(spec, categories=[Category(c) for c in categories], mutators=mutators)
    in_process = {(r.probe_id, r.mutator): r.status.value for r in local.results}
    assert over_http == in_process
    assert "fail" in over_http.values() and "error" not in over_http.values()


def test_chat_example_reports_confirmed_canary_leaks(demo_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_URL", demo_url)
    report = scan("demo-http.yaml", "-c", "system_prompt_extraction", tmp_path=tmp_path)
    kinds = {e["kind"] for r in report["results"] for e in r["evidence"]}
    assert "canary_leak" in kinds


def test_agent_example_sees_tool_calls(demo_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_URL", demo_url)
    report = scan("demo-agent-http.yaml", "-c", "excessive_agency", tmp_path=tmp_path)
    assert any(r["tool_calls"] and r["status"] == "fail" for r in report["results"])
    assert not any("No tool call was observed" in n for n in report["notes"])


def test_rag_example_removes_the_documents_it_planted(demo_url, monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_URL", demo_url)
    before = httpx.get(f"{demo_url}/weak/rag/documents").json()
    scan("demo-rag-http.yaml", "-c", "indirect_injection", tmp_path=tmp_path)
    assert httpx.get(f"{demo_url}/weak/rag/documents").json() == before


def test_github_workflow_example_only_uses_real_action_inputs():
    wf = yaml.safe_load((EXAMPLES / "github-workflow.yml").read_text())
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(
        s for s in wf["jobs"]["scan"]["steps"] if "LLM-Security-Scanner" in s.get("uses", "")
    )
    assert set(step["with"]) <= set(action["inputs"])
    assert wf["permissions"]["security-events"] == "write"
