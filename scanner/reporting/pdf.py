"""PDF report built with ReportLab (no external binaries; Helvetica, Latin-1 text)."""

from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.graphics.charts.spider import SpiderChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from scanner import __version__
from scanner.models import RunReport
from scanner.reporting.common import (
    SEVERITY_COLOR,
    grade_color,
    remediation_blocks,
    sorted_findings,
)
from scanner.taxonomy import atlas_url, describe_atlas, describe_owasp

MAX_FINDINGS = 60
MAX_TRANSCRIPT_CHARS = 1400


def pdf_safe(text: str) -> str:
    """Helvetica only covers Latin-1: replace anything else (and control chars) visibly."""
    text = "".join(ch if ch in "\n\t" or ord(ch) >= 32 else " " for ch in text)
    return text.encode("latin-1", "replace").decode("latin-1")


def _p(text: str) -> str:
    return escape(pdf_safe(text))


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, spaceAfter=4, alignment=0),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6
        ),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=10.5, spaceAfter=2),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9, leading=12),
        "small": ParagraphStyle(
            "s",
            parent=base["BodyText"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        ),
        "mono": ParagraphStyle(
            "m", parent=base["Code"], fontSize=7, leading=8.5, backColor=colors.HexColor("#f1f5f9")
        ),
    }


def _table(data: list[list], widths: list[float], header: bool = True) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(style))
    return t


def _radar(report: RunReport) -> Drawing:
    cats = list(report.score.categories.values())
    d = Drawing(300, 210)
    if len(cats) >= 3:
        chart = SpiderChart()
        chart.x, chart.y, chart.width, chart.height = 60, 20, 170, 170
        chart.data = [[c.asr * 100 for c in cats]]
        chart.labels = [pdf_safe(c.title.split(" ")[0]) for c in cats]
        chart.strands[0].fillColor = colors.Color(0.86, 0.15, 0.15, alpha=0.3)
        chart.strands[0].strokeColor = colors.HexColor("#dc2626")
        chart.strandLabels.fontSize = 6
        chart.spokeLabels.fontSize = 7
        d.add(chart)
    return d


def render_pdf(report: RunReport) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="LLM security scan report",
        author=f"llm-security-scanner {report.tool.version or __version__}",
    )
    s = report.score
    name = (
        report.target.get("name")
        or report.target.get("url")
        or report.target.get("model")
        or "target"
    )
    story: list = [
        Paragraph("LLM security scan report", st["title"]),
        Paragraph(
            f"Target <b>{_p(str(name))}</b> &nbsp;|&nbsp; {report.started_at:%Y-%m-%d %H:%M UTC} &nbsp;|&nbsp; "
            f"run {_p(report.id[:12])} &nbsp;|&nbsp; llm-security-scanner {_p(report.tool.version or __version__)}",
            st["small"],
        ),
        Spacer(1, 6),
        Paragraph(
            "Authorised testing only. Transcripts may contain sensitive data; handle accordingly.",
            st["small"],
        ),
        Spacer(1, 8),
    ]
    gcol = grade_color(s.grade)
    summary = Table(
        [
            [
                Paragraph(
                    f'<font size="26"><b>{s.risk_score:.0f}</b></font><font size="9"> / 100</font>',
                    st["body"],
                ),
                Paragraph(
                    f'<font size="22" color="{gcol}"><b>{_p(s.grade)}</b></font> {_p(s.band)}',
                    st["body"],
                ),
                Paragraph(
                    f"<b>{s.failed}</b> attacks succeeded<br/>of {s.passed + s.failed} conclusive ({s.asr:.0%} ASR)",
                    st["body"],
                ),
                Paragraph(
                    f"{s.total} attempts<br/>{s.errors} errors, {s.inconclusive} inconclusive",
                    st["body"],
                ),
            ]
        ],
        colWidths=[38 * mm, 36 * mm, 56 * mm, 46 * mm],
    )
    summary.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story += [summary, Paragraph("Attack success rate by category", st["h2"])]
    story.append(_radar(report))
    rows = [["Category", "OWASP", "ASR", "95% CI", "Failed", "Risk"]]
    for cs in s.categories.values():
        rows.append(
            [
                _p(cs.title),
                _p(", ".join(cs.owasp)),
                f"{cs.asr:.0%}",
                f"{cs.ci_low:.0%}-{cs.ci_high:.0%}",
                f"{cs.failed}/{cs.total}",
                f"{cs.risk:.0f}",
            ]
        )
    story.append(_table(rows, [58 * mm, 24 * mm, 16 * mm, 24 * mm, 20 * mm, 16 * mm]))
    sev_rows = [["Severity", "Succeeded", "Attempts"]]
    for name_, c in s.severities.items():
        sev_rows.append([name_, str(c.failed), str(c.total)])
    story += [
        Paragraph("Severity breakdown", st["h2"]),
        _table(sev_rows, [40 * mm, 30 * mm, 30 * mm]),
    ]

    findings = sorted_findings(report)
    story += [PageBreak(), Paragraph(f"Findings ({len(findings)})", st["h2"])]
    if not findings:
        story.append(Paragraph("No attack succeeded in this run.", st["body"]))
    for f in findings[:MAX_FINDINGS]:
        color = SEVERITY_COLOR[f.severity.value]
        block: list = [
            Paragraph(
                f'<font color="{color}"><b>[{f.severity.value.upper()}]</b></font> {_p(f.probe_id)} - {_p(f.probe_name)} '
                f'<font size="7" color="#64748b">(mutator {_p(f.mutator)}, confidence {f.confidence:.0%})</font>',
                st["h3"],
            ),
            Paragraph(
                "OWASP: "
                + _p("; ".join(describe_owasp(o) for o in f.owasp))
                + " | ATLAS: "
                + _p("; ".join(describe_atlas(a) for a in f.atlas)),
                st["small"],
            ),
            Paragraph(f"<b>Why it was flagged.</b> {_p(f.reason)}", st["body"]),
        ]
        for e in f.evidence[:3]:
            block.append(
                Paragraph(
                    f"&bull; {_p(e.description)}"
                    + (
                        f": <font face='Courier' size='7'>{_p(e.matched[:160])}</font>"
                        if e.matched
                        else ""
                    ),
                    st["body"],
                )
            )
        for m in f.transcript[-3:]:
            if m.role == "system":
                continue
            snippet = (
                m.content
                if len(m.content) <= MAX_TRANSCRIPT_CHARS
                else m.content[:MAX_TRANSCRIPT_CHARS] + " [...]"
            )
            block.append(Paragraph(f"<b>{_p(m.role)}</b>", st["small"]))
            block.append(Preformatted(pdf_safe(snippet), st["mono"], maxLineLength=110))
        fix = []
        for kind, body in remediation_blocks(f.remediation):
            if kind == "p":
                fix.append(Paragraph(_p(str(body)), st["body"]))
            else:
                fix += [Paragraph("&bull; " + _p(item), st["body"]) for item in body]
        block.append(Paragraph("<b>How to fix it</b>", st["body"]))
        block += fix[:8]
        block.append(Spacer(1, 8))
        story.append(KeepTogether(block[:3]))
        story += block[3:]
    if len(findings) > MAX_FINDINGS:
        story.append(
            Paragraph(
                f"... {len(findings) - MAX_FINDINGS} more findings omitted; see the JSON or HTML report.",
                st["small"],
            )
        )
    story.append(Spacer(1, 10))
    story.append(
        Paragraph(
            "Mappings: OWASP Top 10 for LLM Applications 2025; MITRE ATLAS. "
            "A resisted attack is not proof of safety; only successful attacks are reported as findings.",
            st["small"],
        )
    )
    doc.build(story)
    return buf.getvalue()


__all__ = ["atlas_url", "pdf_safe", "render_pdf"]
