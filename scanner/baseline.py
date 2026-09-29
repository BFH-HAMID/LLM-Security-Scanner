"""Regression baselines: commit a known-good scan and fail CI when a change makes things worse."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from scanner import __version__
from scanner.compare import FAIL_THRESHOLD, KeyState, key_states
from scanner.models import RunReport, Severity, utcnow


class BaselineEntry(BaseModel):
    status: str
    fail_rate: float
    attempts: int
    severity: Severity
    probe_id: str
    probe_name: str = ""
    mutator: str = "none"


class Baseline(BaseModel):
    schema_version: str = "1"
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())
    tool_version: str = __version__
    target: str = ""
    risk_score: float = 0.0
    category_asr: dict[str, float] = Field(default_factory=dict)
    entries: dict[str, BaselineEntry] = Field(default_factory=dict)


class RegressionItem(BaseModel):
    key: str
    probe_id: str
    probe_name: str
    mutator: str
    severity: Severity
    reason: str
    fail_rate_before: float | None
    fail_rate_after: float


class BaselineCheck(BaseModel):
    ok: bool
    risk_before: float
    risk_after: float
    risk_delta: float
    tolerance: float
    regressions: list[RegressionItem] = Field(default_factory=list)
    improvements: int = 0

    def summary(self) -> str:
        if self.ok:
            return (
                f"No regression vs baseline (risk {self.risk_before:.0f} → {self.risk_after:.0f}, "
                f"{self.improvements} improvement(s))."
            )
        return (
            f"{len(self.regressions)} regression(s) vs baseline; risk {self.risk_before:.0f} → {self.risk_after:.0f} "
            f"(tolerance {self.tolerance:.0f})."
        )


def make_baseline(report: RunReport, threshold: float = FAIL_THRESHOLD) -> Baseline:
    states = key_states(report, threshold)
    return Baseline(
        target=str(report.target.get("name", "")),
        risk_score=report.score.risk_score,
        category_asr={c: round(cs.asr, 4) for c, cs in report.score.categories.items()},
        entries={
            k: BaselineEntry(
                status=s.status,
                fail_rate=round(s.fail_rate, 4),
                attempts=s.attempts,
                severity=s.severity,
                probe_id=s.probe_id,
                probe_name=s.probe_name,
                mutator=s.mutator,
            )
            for k, s in sorted(states.items())
        },
    )


def save_baseline(report: RunReport, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(make_baseline(report).model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(path: str | Path) -> Baseline:
    return Baseline.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


def check_baseline(
    report: RunReport,
    baseline: Baseline,
    *,
    tolerance: float = 5.0,
    min_severity: Severity = Severity.LOW,
    threshold: float = FAIL_THRESHOLD,
    fail_on_new_probe: bool = True,
) -> BaselineCheck:
    """Regression = a (probe, mutator) that now fails but did not before, or a risk increase above
    ``tolerance``. Repeats are collapsed to a fail rate so flaky targets do not cause noise."""
    current: dict[str, KeyState] = key_states(report, threshold)
    regressions: list[RegressionItem] = []
    improvements = 0
    for key, state in current.items():
        if state.severity.rank < min_severity.rank:
            continue
        old = baseline.entries.get(key)
        if old is None:
            if state.status == "fail" and fail_on_new_probe:
                regressions.append(
                    RegressionItem(
                        key=key,
                        probe_id=state.probe_id,
                        probe_name=state.probe_name,
                        mutator=state.mutator,
                        severity=state.severity,
                        reason="new attack that succeeds (not in baseline)",
                        fail_rate_before=None,
                        fail_rate_after=state.fail_rate,
                    )
                )
            continue
        if state.status == "fail" and old.status != "fail":
            regressions.append(
                RegressionItem(
                    key=key,
                    probe_id=state.probe_id,
                    probe_name=state.probe_name,
                    mutator=state.mutator,
                    severity=state.severity,
                    reason="passed in baseline, now fails",
                    fail_rate_before=old.fail_rate,
                    fail_rate_after=state.fail_rate,
                )
            )
        elif state.status == "pass" and old.status == "fail":
            improvements += 1
    regressions.sort(key=lambda r: (-r.severity.rank, r.probe_id, r.mutator))
    delta = report.score.risk_score - baseline.risk_score
    ok = not regressions and delta <= tolerance
    return BaselineCheck(
        ok=ok,
        risk_before=baseline.risk_score,
        risk_after=report.score.risk_score,
        risk_delta=delta,
        tolerance=tolerance,
        regressions=regressions,
        improvements=improvements,
    )
