"""View-model helpers shared by the report renderers."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from scanner.models import AttemptResult, Category, RunReport, Status
from scanner.taxonomy import CATEGORIES, atlas_url, describe_atlas, describe_owasp, owasp_url

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOR = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}
STATUS_COLOR = {"fail": "#dc2626", "pass": "#16a34a", "error": "#9ca3af", "inconclusive": "#f59e0b"}
GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}


def sorted_findings(report: RunReport) -> list[AttemptResult]:
    """Failed attempts, most severe and most confident first."""
    fails = [r for r in report.results if r.status is Status.FAIL]
    return sorted(fails, key=lambda r: (-r.severity.rank, -r.confidence, r.probe_id, r.mutator))


@dataclass
class HeatCell:
    status: str  # fail | pass | error | inconclusive
    failed: int
    total: int


@dataclass
class HeatRow:
    probe_id: str
    name: str
    category: str
    severity: str
    cells: dict[str, HeatCell] = field(default_factory=dict)


def heatmap(report: RunReport) -> tuple[list[HeatRow], list[str]]:
    """Probe x mutator matrix. ``none`` (the unmodified probe) is always the first column."""
    rows: dict[str, HeatRow] = {}
    mutators: list[str] = []
    for r in report.results:
        if r.mutator not in mutators:
            mutators.append(r.mutator)
        row = rows.setdefault(
            r.probe_id, HeatRow(r.probe_id, r.probe_name, r.category.value, r.severity.value)
        )
        cell = row.cells.setdefault(r.mutator, HeatCell("pass", 0, 0))
        cell.total += 1
        if r.status is Status.FAIL:
            cell.failed += 1
    for row in rows.values():
        for m, cell in row.cells.items():
            results = [x for x in report.results if x.probe_id == row.probe_id and x.mutator == m]
            if cell.failed:
                cell.status = "fail"
            elif any(x.status is Status.ERROR for x in results):
                cell.status = "error"
            elif any(x.status is Status.INCONCLUSIVE for x in results):
                cell.status = "inconclusive"
            else:
                cell.status = "pass"
    mutators.sort(key=lambda m: (m != "none", m))
    order = {c.value: i for i, c in enumerate(Category)}
    ordered = sorted(rows.values(), key=lambda r: (order.get(r.category, 99), r.probe_id))
    return ordered, mutators


def radar_points(report: RunReport, size: int = 300, radius: int = 105) -> dict:
    """Geometry for a server-rendered SVG radar chart of ASR per category."""
    cx = cy = size / 2
    cats = [c for c in Category if c.value in report.score.categories]
    if len(cats) < 3:
        cats = list(Category)
    n = len(cats)
    axes = []
    poly = []
    for i, cat in enumerate(cats):
        angle = -math.pi / 2 + 2 * math.pi * i / n
        cs = report.score.categories.get(cat.value)
        value = cs.asr if cs else 0.0
        axes.append(
            {
                "label": CATEGORIES[cat].title,
                "x": cx + radius * math.cos(angle),
                "y": cy + radius * math.sin(angle),
                "lx": cx + (radius + 22) * math.cos(angle),
                "ly": cy + (radius + 22) * math.sin(angle),
                "anchor": "middle"
                if abs(math.cos(angle)) < 0.3
                else ("start" if math.cos(angle) > 0 else "end"),
                "value": value,
            }
        )
        poly.append((cx + radius * value * math.cos(angle), cy + radius * value * math.sin(angle)))
    rings = []
    for frac in (0.25, 0.5, 0.75, 1.0):
        pts = " ".join(
            f"{cx + radius * frac * math.cos(-math.pi / 2 + 2 * math.pi * i / n):.1f},"
            f"{cy + radius * frac * math.sin(-math.pi / 2 + 2 * math.pi * i / n):.1f}"
            for i in range(n)
        )
        rings.append({"frac": frac, "points": pts})
    return {
        "size": size,
        "cx": cx,
        "cy": cy,
        "axes": axes,
        "rings": rings,
        "polygon": " ".join(f"{x:.1f},{y:.1f}" for x, y in poly),
    }


def tag_links(result: AttemptResult) -> dict[str, list[dict[str, str]]]:
    return {
        "owasp": [{"id": o, "label": describe_owasp(o), "url": owasp_url(o)} for o in result.owasp],
        "atlas": [{"id": a, "label": describe_atlas(a), "url": atlas_url(a)} for a in result.atlas],
    }


def remediation_blocks(text: str) -> list[tuple[str, list[str] | str]]:
    """Split remediation text into ('p', str) and ('ul', [items]) blocks (no HTML, no escaping)."""
    blocks: list[tuple[str, list[str] | str]] = []
    bullets: list[str] = []
    para: list[str] = []

    def flush_para() -> None:
        if para:
            blocks.append(("p", " ".join(para)))
            para.clear()

    def flush_bullets() -> None:
        if bullets:
            blocks.append(("ul", list(bullets)))
            bullets.clear()

    for line in text.strip().splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            flush_para()
            bullets.append(stripped[2:].strip())
        elif not stripped:
            flush_para()
            flush_bullets()
        else:
            flush_bullets()
            para.append(stripped)
    flush_para()
    flush_bullets()
    return blocks


def grade_color(grade: str) -> str:
    return GRADE_COLOR.get(grade, "#64748b")
