"""Compact Markdown summary (used for CI job summaries and PR comments)."""

from __future__ import annotations

from scanner.models import RunReport
from scanner.reporting.common import SEVERITY_ORDER, sorted_findings


def _cell(text: str, n: int = 90) -> str:
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= n else text[: n - 1] + "…"


def render_markdown(report: RunReport, *, max_findings: int = 25) -> str:
    s = report.score
    name = report.target.get("name") or report.target.get("url") or "target"
    lines = [
        f"## LLM security scan - {name}",
        "",
        f"**Risk score: {s.risk_score:.0f}/100 (grade {s.grade}, {s.band})** - "
        f"{s.failed} of {s.passed + s.failed} conclusive attacks succeeded "
        f"({s.asr:.0%} ASR); {s.errors} errors, {s.inconclusive} inconclusive.",
        "",
        "| Category | ASR | Failed | Risk |",
        "|---|---|---|---|",
    ]
    for cat, cs in s.categories.items():
        lines.append(
            f"| {cs.title or cat} | {cs.asr:.0%} | {cs.failed}/{cs.total} | {cs.risk:.0f} |"
        )
    if report.notes:
        lines += ["", "> **Coverage notes**"] + [f"> - {n}" for n in report.notes]
    findings = sorted_findings(report)
    if findings:
        lines += [
            "",
            f"### Findings ({len(findings)})",
            "",
            "| Severity | Probe | Mutator | OWASP | Why |",
            "|---|---|---|---|---|",
        ]
        for r in findings[:max_findings]:
            lines.append(
                f"| {r.severity.value} | {r.probe_id} {_cell(r.probe_name, 40)} | {r.mutator} | {', '.join(r.owasp)} | {_cell(r.reason)} |"
            )
        if len(findings) > max_findings:
            lines.append(f"\n_... and {len(findings) - max_findings} more (see the full report)._")
        top = findings[0]
        lines += [
            "",
            f"**Top fix ({top.probe_id}):** {_cell(top.remediation.splitlines()[0], 300)}",
        ]
    else:
        lines += ["", "No attack succeeded."]
    sev = [
        f"{n}: {s.severities[n].failed}/{s.severities[n].total}"
        for n in SEVERITY_ORDER
        if n in s.severities
    ]
    if sev:
        lines += ["", "Severity (succeeded/attempts) - " + ", ".join(sev)]
    lines += ["", f"<sub>Run `{report.id}` - authorised testing only.</sub>"]
    return "\n".join(lines) + "\n"
