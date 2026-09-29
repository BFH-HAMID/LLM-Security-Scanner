"""action.yml and the CI workflow: structure, injection-safety and a real execution of the scan step."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
WORKFLOWS = {
    p.name: yaml.safe_load(p.read_text()) for p in (ROOT / ".github" / "workflows").glob("*.yml")
}


def steps():
    return ACTION["runs"]["steps"]


def step(step_id):
    return next(s for s in steps() if s.get("id") == step_id)


# ------------------------------------------------------------------------- structure


def test_action_metadata():
    assert ACTION["name"] and ACTION["description"] and ACTION["branding"]["icon"]
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["inputs"]["target"]["required"] is True
    assert all(spec.get("description") for spec in ACTION["inputs"].values())
    assert all(spec.get("description") and spec.get("value") for spec in ACTION["outputs"].values())


def test_every_referenced_input_and_step_output_exists():
    text = (ROOT / "action.yml").read_text()
    for name in set(re.findall(r"inputs\.([a-z0-9-]+)", text)):
        assert name in ACTION["inputs"], f"undeclared input {name}"
    ids = {s["id"] for s in steps() if "id" in s}
    for sid, _out in set(re.findall(r"steps\.([a-z0-9-]+)\.outputs\.([a-z-]+)", text)):
        assert sid in ids, sid
    written = re.findall(r'echo "([a-z-]+)=', step("scan")["run"]) + re.findall(
        r'print\(f"([a-z-]+)=', step("scan")["run"]
    )
    for spec in ACTION["outputs"].values():
        assert re.search(r"steps\.scan\.outputs\.([a-z-]+)", spec["value"]).group(1) in written


def test_run_scripts_never_interpolate_expressions():
    """`${{ ... }}` inside a script is a shell-injection vector; inputs must arrive via env."""
    for s in steps():
        if "run" in s:
            assert "${{" not in s["run"], f"expression inside run: of step {s.get('name')}"
            assert s.get("shell") == "bash"


def test_third_party_actions_are_pinned_to_a_major_version():
    uses = [s["uses"] for s in steps() if "uses" in s]
    for wf in WORKFLOWS.values():
        for job in wf["jobs"].values():
            uses += [s["uses"] for s in job.get("steps", []) if "uses" in s]
    assert uses
    for u in uses:
        if not u.startswith("./"):
            assert re.fullmatch(r"[\w./-]+@v\d+(\.\d+){0,2}", u), u


def test_sarif_upload_is_optional_and_never_breaks_the_build():
    up = next(
        s for s in steps() if s.get("uses", "").startswith("github/codeql-action/upload-sarif")
    )
    assert (
        up["continue-on-error"] is True
        and "inputs.upload-sarif" in up["if"]
        and up["with"]["category"]
    )


def test_policy_step_runs_last_and_only_after_reports_were_published():
    names = [s.get("name") for s in steps()]
    assert names.index("Enforce policy") == len(names) - 1
    assert names.index("Upload reports") < names.index("Enforce policy")
    assert names.index("Upload SARIF to code scanning") < names.index("Enforce policy")


# ---------------------------------------------------------------------------- CI workflow


def test_ci_workflow_shape():
    wf = WORKFLOWS["ci.yml"]
    on = wf.get("on", wf.get(True))
    assert (
        "pull_request" in on and "pull_request_target" not in on
    )  # never run untrusted PR code with secrets
    assert wf["permissions"] == {"contents": "read"}
    assert {"lint", "test", "dashboard", "self-scan", "docker"} <= set(wf["jobs"])
    scan = wf["jobs"]["self-scan"]
    assert scan["permissions"]["security-events"] == "write"
    action_step = next(s for s in scan["steps"] if s.get("uses") == "./")
    assert action_step["with"]["baseline"] == ".llmscan/baseline.json"
    assert (ROOT / action_step["with"]["baseline"]).exists()
    assert wf["jobs"]["test"]["services"]["redis"]["image"].startswith("redis")


def test_files_referenced_by_ci_exist():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    referenced = (
        re.findall(r"file: (\S+)", text)
        + re.findall(r"sh (\S+\.sh)", text)
        + re.findall(r"python3 (\S+\.py)", text)
    )
    assert referenced, "the docker jobs should reference the files they need"
    for path in referenced:
        assert (ROOT / path).exists(), path
    assert (ROOT / "dashboard" / "package-lock.json").exists()
    scripts = json.loads((ROOT / "dashboard" / "package.json").read_text())["scripts"]
    assert {"build", "typecheck"} <= set(scripts)


# ----------------------------------------------------------------- run the scan step for real


def scan_env(tmp_path, **inputs):
    """The environment GitHub would build: each ``env:`` entry resolves to its input (or its default)."""
    env = {}
    for key, expr in step("scan")["env"].items():
        name = re.fullmatch(r"\$\{\{ inputs\.([a-z-]+) \}\}", expr).group(1)
        env[key] = str(ACTION["inputs"][name].get("default", ""))
    env.update({f"INPUT_{k.upper()}": v for k, v in inputs.items()})
    env |= {
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "github_output"),
    }
    return env


def run_step(tmp_path, **inputs):
    out = tmp_path / "github_output"
    out.unlink(missing_ok=True)
    proc = subprocess.run(
        ["bash", "-c", step("scan")["run"]],
        cwd=tmp_path,
        env=scan_env(tmp_path, **inputs),
        capture_output=True,
        text=True,
        timeout=120,
    )
    outputs = (
        dict(line.split("=", 1) for line in out.read_text().splitlines()) if out.exists() else {}
    )
    return proc, outputs


def test_scan_step_writes_reports_and_outputs(tmp_path):
    proc, out = run_step(
        tmp_path,
        target="demo:hardened",
        seed="1",
        categories="jailbreak, prompt_injection",
        fail_on="critical",
    )
    assert proc.returncode == 0, proc.stderr
    assert out["exit-code"] == "0" and out["grade"] in "ABCDF" and out["sarif-exists"] == "true"
    assert (
        float(out["risk-score"]) >= 0
        and int(out["findings"]) >= 0
        and out["report-dir"] == "llmscan-reports"
    )
    for name in ("json", "html", "sarif", "md"):
        assert (tmp_path / "llmscan-reports" / f"llmscan.{name}").stat().st_size > 100
    assert (
        json.loads((tmp_path / "llmscan-reports" / "llmscan.json").read_text())["score"]["total"]
        == 30
    )  # 14 + 16


def test_scan_step_records_policy_failures_without_failing_the_step(tmp_path):
    proc, out = run_step(
        tmp_path, target="demo:weak", seed="1", fail_on="high", categories="jailbreak"
    )
    assert proc.returncode == 0  # the *later* "Enforce policy" step fails the job, after uploads
    assert out["exit-code"] == "1" and int(out["findings"]) > 0


def test_scan_step_handles_regressions_and_probe_selection(tmp_path):
    env = scan_env(tmp_path)
    base = tmp_path / "base.json"
    subprocess.run(
        ["llmscan", "run", "demo:hardened", "--seed", "1", "-q", "--no-save", "-o", str(base)],
        check=True,
        env=env,
    )
    subprocess.run(
        ["llmscan", "baseline", "save", str(base), "-o", str(tmp_path / "b.json")],
        check=True,
        capture_output=True,
        env=env,
    )
    proc, out = run_step(
        tmp_path,
        target="demo:weak",
        seed="1",
        baseline="b.json",
        fail_on_regression="true",
        probes="PI-001,SP-001",
    )
    assert proc.returncode == 0 and out["exit-code"] in {"0", "1"}
    assert (
        json.loads((tmp_path / "llmscan-reports" / "llmscan.json").read_text())["score"]["total"]
        == 2
    )


def test_scan_step_survives_a_broken_configuration(tmp_path):
    proc, out = run_step(tmp_path, target="does-not-exist.yaml")
    assert proc.returncode == 0 and out["exit-code"] == "2" and out["sarif-exists"] == "false"
    assert "risk-score" not in out


def test_hostile_input_is_treated_as_data(tmp_path):
    marker = tmp_path / "pwned"
    proc, out = run_step(tmp_path, target=f"demo:weak; touch {marker}", extra_args="--seed 1")
    assert proc.returncode == 0 and not marker.exists() and out["exit-code"] == "2"
    proc, out = run_step(
        tmp_path, target="demo:weak", categories=f"jailbreak$(touch {marker})", seed="1"
    )
    assert not marker.exists()


@pytest.mark.parametrize("bad", ["", "  ", ","])
def test_empty_lists_are_ignored(tmp_path, bad):
    proc, out = run_step(
        tmp_path, target="demo:hardened", seed="1", categories=bad, probes="PI-001"
    )
    assert proc.returncode == 0 and out["exit-code"] == "0"
