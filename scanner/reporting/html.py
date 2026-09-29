"""Self-contained HTML report (Jinja2 with autoescape; charts are server-rendered SVG)."""

from __future__ import annotations

from types import SimpleNamespace

from jinja2 import Environment, PackageLoader

from scanner import __version__
from scanner.models import RunReport, Severity, Status
from scanner.reporting.common import (
    SEVERITY_COLOR,
    SEVERITY_ORDER,
    STATUS_COLOR,
    grade_color,
    heatmap,
    radar_points,
    remediation_blocks,
    sorted_findings,
    tag_links,
)
from scanner.taxonomy import ATLAS_VERSION, OWASP_EDITION

_env = Environment(
    loader=PackageLoader("scanner.reporting", "templates"),
    autoescape=True,  # every value is escaped; transcripts are attacker-controlled text
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(report: RunReport) -> str:
    heat_rows, mutators = heatmap(report)
    findings = []
    for r in sorted_findings(report):
        links = tag_links(r)
        findings.append(
            SimpleNamespace(
                **{
                    k: getattr(r, k)
                    for k in (
                        "probe_id",
                        "probe_name",
                        "severity",
                        "mutator",
                        "confidence",
                        "reason",
                        "evidence",
                        "transcript",
                        "tool_calls",
                    )
                },
                tags_owasp=links["owasp"],
                tags_atlas=links["atlas"],
                documents=r.meta.get("documents", []),
                fix_blocks=remediation_blocks(r.remediation),
            )
        )
    severities = []
    for name in SEVERITY_ORDER:
        c = report.score.severities.get(name)
        if c and c.total:
            severities.append(
                SimpleNamespace(
                    name=name,
                    weight=Severity(name).weight,
                    failed=c.failed,
                    total=c.total,
                    rate=c.rate,
                    color=SEVERITY_COLOR[name],
                )
            )
    categories = list(report.score.categories.values())
    others = [r for r in report.results if r.status in (Status.ERROR, Status.INCONCLUSIVE)]
    target = report.target
    template = _env.get_template("report.html.j2")
    return template.render(
        version=report.tool.version or __version__,
        target_name=target.get("name") or target.get("url") or target.get("model") or "target",
        started=report.started_at.strftime("%Y-%m-%d %H:%M UTC"),
        run_id=report.id,
        run_status=report.status,
        run_error=report.error,
        notes=report.notes,
        authorization_note=(report.authorization or {}).get("note", ""),
        score=report.score,
        grade_color=grade_color(report.score.grade),
        radar=radar_points(report),
        categories=categories,
        severities=severities,
        heat_rows=heat_rows,
        mutators=mutators,
        status_color=STATUS_COLOR,
        severity_color=SEVERITY_COLOR,
        findings=findings,
        others=others,
        owasp_edition=OWASP_EDITION,
        atlas_version=ATLAS_VERSION,
    )
