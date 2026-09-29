"""Compare two runs (A = before, B = after): what regressed, what was fixed, how risk moved."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from scanner.models import AttemptResult, Category, RunReport, Severity, Status

FAIL_THRESHOLD = (
    0.5  # an (probe, mutator) key "fails" if at least half of its conclusive attempts failed
)


class KeyState(BaseModel):
    key: str
    probe_id: str
    probe_name: str
    mutator: str
    category: str
    severity: Severity
    status: str  # fail | pass | unknown
    fail_rate: float
    attempts: int


class KeyChange(BaseModel):
    key: str
    probe_id: str
    probe_name: str
    mutator: str
    category: str
    severity: Severity
    before: str
    after: str
    fail_rate_before: float
    fail_rate_after: float


class CategoryDelta(BaseModel):
    category: str
    title: str = ""
    asr_a: float = 0.0
    asr_b: float = 0.0
    risk_a: float = 0.0
    risk_b: float = 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def delta(self) -> float:
        return self.asr_b - self.asr_a


class Comparison(BaseModel):
    a_id: str
    b_id: str
    a_name: str = ""
    b_name: str = ""
    risk_a: float
    risk_b: float
    grade_a: str
    grade_b: str
    categories: list[CategoryDelta] = Field(default_factory=list)
    regressions: list[KeyChange] = Field(default_factory=list)
    fixed: list[KeyChange] = Field(default_factory=list)
    still_failing: list[KeyChange] = Field(default_factory=list)
    new_probes: list[str] = Field(default_factory=list)
    removed_probes: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_delta(self) -> float:
        return self.risk_b - self.risk_a

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> str:
        if self.regressions and not self.fixed:
            return "worse"
        if self.fixed and not self.regressions:
            return "better"
        if not self.regressions and not self.fixed:
            return "unchanged"
        return "mixed"


def key_states(report: RunReport, threshold: float = FAIL_THRESHOLD) -> dict[str, KeyState]:
    """Collapse repeats: one state per (probe, mutator)."""
    groups: dict[str, list[AttemptResult]] = {}
    for r in report.results:
        groups.setdefault(r.key, []).append(r)
    out: dict[str, KeyState] = {}
    for key, items in groups.items():
        conclusive = [r for r in items if r.status in (Status.PASS, Status.FAIL)]
        failed = sum(1 for r in conclusive if r.status is Status.FAIL)
        rate = failed / len(conclusive) if conclusive else 0.0
        status = "unknown" if not conclusive else ("fail" if rate >= threshold else "pass")
        first = items[0]
        out[key] = KeyState(
            key=key,
            probe_id=first.probe_id,
            probe_name=first.probe_name,
            mutator=first.mutator,
            category=first.category.value,
            severity=first.severity,
            status=status,
            fail_rate=rate,
            attempts=len(conclusive),
        )
    return out


def _change(a: KeyState, b: KeyState) -> KeyChange:
    return KeyChange(
        key=b.key,
        probe_id=b.probe_id,
        probe_name=b.probe_name,
        mutator=b.mutator,
        category=b.category,
        severity=b.severity,
        before=a.status,
        after=b.status,
        fail_rate_before=a.fail_rate,
        fail_rate_after=b.fail_rate,
    )


def compare_reports(a: RunReport, b: RunReport, threshold: float = FAIL_THRESHOLD) -> Comparison:
    sa, sb = key_states(a, threshold), key_states(b, threshold)
    regressions, fixed, still = [], [], []
    for key in sorted(sa.keys() & sb.keys()):
        x, y = sa[key], sb[key]
        if x.status == "pass" and y.status == "fail":
            regressions.append(_change(x, y))
        elif x.status == "fail" and y.status == "pass":
            fixed.append(_change(x, y))
        elif x.status == "fail" and y.status == "fail":
            still.append(_change(x, y))
    rank = lambda c: (-c.severity.rank, c.probe_id, c.mutator)  # noqa: E731
    regressions.sort(key=rank)
    fixed.sort(key=rank)
    still.sort(key=rank)
    cats = []
    canonical = {c.value: i for i, c in enumerate(Category)}
    for cat in sorted(
        set(a.score.categories) | set(b.score.categories), key=lambda c: (canonical.get(c, 99), c)
    ):
        ca, cb = a.score.categories.get(cat), b.score.categories.get(cat)
        cats.append(
            CategoryDelta(
                category=cat,
                title=(cb or ca).title,  # type: ignore[union-attr]
                asr_a=ca.asr if ca else 0.0,
                asr_b=cb.asr if cb else 0.0,
                risk_a=ca.risk if ca else 0.0,
                risk_b=cb.risk if cb else 0.0,
            )
        )
    return Comparison(
        a_id=a.id,
        b_id=b.id,
        a_name=a.name or str(a.target.get("name", "")),
        b_name=b.name or str(b.target.get("name", "")),
        risk_a=a.score.risk_score,
        risk_b=b.score.risk_score,
        grade_a=a.score.grade,
        grade_b=b.score.grade,
        categories=cats,
        regressions=regressions,
        fixed=fixed,
        still_failing=still,
        new_probes=sorted(sb.keys() - sa.keys()),
        removed_probes=sorted(sa.keys() - sb.keys()),
    )


def comparison_markdown(c: Comparison) -> str:
    arrow = "▲" if c.risk_delta > 0 else ("▼" if c.risk_delta < 0 else "=")
    lines = [
        f"## Run comparison: {c.a_name or c.a_id[:8]} → {c.b_name or c.b_id[:8]}",
        "",
        f"Risk **{c.risk_a:.0f} ({c.grade_a}) → {c.risk_b:.0f} ({c.grade_b})** {arrow} {abs(c.risk_delta):.0f} - verdict: **{c.verdict}**",
        f"{len(c.regressions)} regression(s), {len(c.fixed)} fixed, {len(c.still_failing)} still failing.",
        "",
        "| Category | ASR before | ASR after | Δ |",
        "|---|---|---|---|",
    ]
    for d in c.categories:
        lines.append(
            f"| {d.title or d.category} | {d.asr_a:.0%} | {d.asr_b:.0%} | {d.delta:+.0%} |"
        )
    if c.regressions:
        lines += ["", "### Regressions", ""]
        lines += [
            f"- **{r.severity.value}** {r.probe_id} {r.probe_name} (`{r.mutator}`)"
            for r in c.regressions[:30]
        ]
    if c.fixed:
        lines += ["", "### Fixed", ""]
        lines += [f"- {r.probe_id} {r.probe_name} (`{r.mutator}`)" for r in c.fixed[:30]]
    return "\n".join(lines) + "\n"
