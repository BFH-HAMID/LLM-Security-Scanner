"""Config loading, the scope guard, run comparison and regression baselines."""

from __future__ import annotations

import pytest

from scanner.baseline import check_baseline, load_baseline, make_baseline, save_baseline
from scanner.compare import compare_reports, comparison_markdown, key_states
from scanner.config import (
    ConfigError,
    ScanConfig,
    ensure_canaries,
    interpolate_env,
    load_config,
    model_target,
)
from scanner.connectors import parse_target
from scanner.models import AttemptResult, Category, RunReport, Severity, Status
from scanner.runner import ScanRequest, ScopeError, run_scan
from scanner.scope import PUBLIC_DEFAULT_RPS, authorization_record, check_scope, classify_host
from scanner.scoring import score
from tests.conftest import run_demo

# ------------------------------------------------------------------------------ config


def test_env_interpolation(monkeypatch):
    monkeypatch.setenv("TOKEN", "abc")
    assert interpolate_env({"a": ["x-${TOKEN}", {"b": "${MISSING:-dflt}"}], "n": 3}) == {
        "a": ["x-abc", {"b": "dflt"}],
        "n": 3,
    }
    with pytest.raises(ConfigError, match="NOPE"):
        interpolate_env("${NOPE}")


def test_load_config_variants(tmp_path, monkeypatch):
    assert load_config("demo").target.level == "weak"
    t = load_config("demo:hardened:agent").target
    assert (t.level, t.surface) == ("hardened", "agent") and t.canaries and t.known_sensitive
    monkeypatch.setenv("SVC_TOKEN", "tok-1234567890")
    (tmp_path / "prompt.txt").write_text("You are X. Token {{canary}}")
    f = tmp_path / "llmscan.yaml"
    f.write_text(
        "target:\n  type: http\n  name: svc\n  url: http://localhost:8080/chat\n  system_prompt_file: prompt.txt\n"
        "  auth: {type: bearer, token: '${SVC_TOKEN}'}\n  canaries: [CANARY-aaaaaaaa]\n"
        "scan:\n  min_severity: medium\n  mutators: [base64]\n  concurrency: 2\n"
    )
    cfg = load_config(f)
    assert cfg.target.auth.token == "tok-1234567890" and cfg.target.system_prompt.startswith(
        "You are X"
    )
    assert cfg.scan.min_severity is Severity.MEDIUM and cfg.scan.concurrency == 2 and cfg.path == f
    bare = tmp_path / "bare.yaml"
    bare.write_text("type: http\nurl: http://localhost/x\n")
    assert load_config(bare).target.url == "http://localhost/x"


def test_load_config_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")
    for body, msg in [
        ("- a\n- b\n", "mapping"),
        ("foo: 1\n", "target"),
        ("target: {type: http}\n", "url"),
        ("target: {type: http, url: x}\nscan: {bogus: 1}\n", "bogus"),
        ("target: {type: http, url: x}\nextra: 1\n", "extra"),
    ]:
        f = tmp_path / "c.yaml"
        f.write_text(body)
        with pytest.raises(ConfigError, match=msg):
            load_config(f)
    with pytest.raises(ConfigError):
        load_config("demo:bogus")


def test_model_shorthands(monkeypatch):
    assert model_target("ollama:llama3.1") == {
        "type": "ollama",
        "name": "ollama-llama3.1",
        "model": "llama3.1",
    }
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        model_target("openai:gpt-4o-mini")
    local = model_target("openai:qwen@http://localhost:8000/v1")
    assert local["base_url"] == "http://localhost:8000/v1" and "api_key" not in local
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert model_target("anthropic:claude-3-5-haiku-latest")["api_key"] == "sk-ant-x"
    assert load_config("ollama:llama3.2").target.type == "ollama"


def test_canary_generated_when_scanner_supplies_the_prompt():
    t = parse_target({"type": "ollama", "model": "m", "system_prompt": "Secret: {{canary}}"})
    c1, c2 = ensure_canaries(t), ensure_canaries(t)
    assert c1["canary"].startswith("CANARY-") and c1 != c2  # fresh per run
    assert ensure_canaries(parse_target({"type": "ollama", "model": "m"})) == {}


# ---------------------------------------------------------------------------- scope


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("localhost", "local"),
        ("127.0.0.1", "local"),
        ("[::1]", "local"),
        ("app.localhost", "local"),
        ("10.1.2.3", "private"),
        ("192.168.0.9", "private"),
        ("172.20.0.5", "private"),
        ("169.254.169.254", "private"),
        ("db", "private"),
        ("target", "private"),
        ("svc.internal", "private"),
        ("printer.local", "private"),
        ("api.openai.com", "public"),
        ("chat.example.org", "public"),
        ("8.8.8.8", "public"),
        ("172.32.0.1", "public"),
    ],
)
def test_host_classification(host, kind):
    assert classify_host(host) == kind


def test_scope_guard_decisions():
    scan = ScanConfig()
    assert check_scope(parse_target({"type": "demo"}), scan).kind == "demo"
    assert check_scope(
        parse_target({"type": "http", "url": "http://localhost:9000/chat"}), scan
    ).allowed
    assert check_scope(
        parse_target({"type": "http", "url": "http://target:9000/chat"}), scan
    ).allowed
    public = parse_target({"type": "http", "url": "https://chat.acme.com/api"})
    d = check_scope(public, scan)
    assert not d.allowed and "authorised" in d.message and "ETHICS" in d.message
    assert check_scope(public, scan, acknowledged_flag=True).allowed
    ok = check_scope(
        public, ScanConfig(authorization={"acknowledged": True, "note": "own staging"})
    )
    assert ok.allowed and ok.default_rps == PUBLIC_DEFAULT_RPS
    rec = authorization_record(
        ScanConfig(
            authorization={"acknowledged": True, "note": "own staging", "contact": "sec@acme.com"}
        ),
        ok,
        via_flag=False,
    )
    assert (
        rec["acknowledged"]
        and rec["via"] == "config"
        and rec["note"] == "own staging"
        and rec["recorded_at"]
    )


async def test_run_scan_refuses_public_targets_without_acknowledgement():
    target = parse_target({"type": "http", "url": "https://chat.acme.com/api"})
    with pytest.raises(ScopeError, match="public host"):
        await run_scan(ScanRequest(target, ScanConfig()))


# ---------------------------------------------------------------------- compare / baseline


def R(pid, status, sev=Severity.HIGH, mutator="none", cat=Category.PROMPT_INJECTION):
    return AttemptResult(
        probe_id=pid,
        probe_name=pid,
        category=cat,
        severity=sev,
        status=status,
        mutator=mutator,
        owasp=["LLM01"],
    )


def report(*results):
    return RunReport(results=list(results), score=score(list(results)), target={"name": "t"})


def test_compare_finds_regressions_and_fixes():
    a = report(
        R("PI-1", Status.PASS),
        R("PI-2", Status.FAIL),
        R("PI-3", Status.FAIL),
        R("PI-4", Status.PASS),
    )
    b = report(
        R("PI-1", Status.FAIL, Severity.CRITICAL),
        R("PI-2", Status.PASS),
        R("PI-3", Status.FAIL),
        R("PI-4", Status.PASS),
        R("PI-5", Status.FAIL),
    )
    c = compare_reports(a, b)
    assert [r.probe_id for r in c.regressions] == ["PI-1"] and [r.probe_id for r in c.fixed] == [
        "PI-2"
    ]
    assert [r.probe_id for r in c.still_failing] == ["PI-3"] and c.new_probes == ["PI-5::none"]
    assert c.verdict == "mixed" and c.risk_b > c.risk_a
    assert compare_reports(a, a).verdict == "unchanged"
    md = comparison_markdown(c)
    assert "Regressions" in md and "PI-1" in md and "Fixed" in md


def test_key_states_collapse_repeats():
    rs = [
        R("PI-1", Status.FAIL),
        R("PI-1", Status.PASS),
        R("PI-1", Status.PASS),
        R("PI-2", Status.ERROR),
    ]
    st = key_states(report(*rs))
    assert st["PI-1::none"].status == "pass" and st["PI-1::none"].fail_rate == pytest.approx(1 / 3)
    assert st["PI-2::none"].status == "unknown"


def test_baseline_roundtrip_and_regression_detection(tmp_path):
    good = report(
        R("PI-1", Status.PASS), R("PI-2", Status.FAIL), R("PI-3", Status.PASS, Severity.LOW)
    )
    path = save_baseline(good, tmp_path / ".llmscan/baseline.json")
    base = load_baseline(path)
    assert base.entries["PI-2::none"].status == "fail" and base.risk_score == good.score.risk_score
    same = check_baseline(good, base)
    assert same.ok and not same.regressions
    worse = report(
        R("PI-1", Status.FAIL), R("PI-2", Status.FAIL), R("PI-3", Status.FAIL, Severity.LOW)
    )
    chk = check_baseline(worse, base, tolerance=100)
    assert not chk.ok and {r.probe_id for r in chk.regressions} == {"PI-1", "PI-3"}
    assert chk.regressions[0].severity is Severity.HIGH  # most severe first
    assert {
        r.probe_id
        for r in check_baseline(
            worse, base, tolerance=100, min_severity=Severity.MEDIUM
        ).regressions
    } == {"PI-1"}
    better = report(
        R("PI-1", Status.PASS), R("PI-2", Status.PASS), R("PI-3", Status.PASS, Severity.LOW)
    )
    assert check_baseline(better, base).ok and check_baseline(better, base).improvements == 1
    only_risk = check_baseline(
        report(
            R("PI-1", Status.PASS),
            R("PI-2", Status.FAIL, Severity.CRITICAL),
            R("PI-3", Status.PASS, Severity.LOW),
        ),
        base,
        tolerance=5,
    )
    assert not only_risk.ok  # risk moved past the tolerance
    new_probe = report(R("PI-1", Status.PASS), R("PI-2", Status.FAIL), R("PI-9", Status.FAIL))
    assert not check_baseline(new_probe, base, tolerance=100).ok
    assert check_baseline(new_probe, base, tolerance=100, fail_on_new_probe=False).ok


def test_baseline_check_on_real_runs():
    base = make_baseline(run_demo("demo:medium"))
    assert check_baseline(run_demo("demo:medium"), base).ok  # deterministic target: identical
    chk = check_baseline(run_demo("demo:weak"), base)  # someone weakened the app
    assert not chk.ok and chk.regressions and chk.risk_delta >= 0
    assert (
        check_baseline(run_demo("demo:hardened"), base).ok
        and check_baseline(run_demo("demo:hardened"), base).improvements > 5
    )
