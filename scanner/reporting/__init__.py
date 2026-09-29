"""Report exporters: JSON, Markdown, HTML, PDF and SARIF 2.1.0."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.models import RunReport
from scanner.reporting.html import render_html
from scanner.reporting.markdown import render_markdown
from scanner.reporting.pdf import render_pdf
from scanner.reporting.sarif import to_sarif

FORMATS = ("json", "html", "pdf", "sarif", "md")
EXTENSIONS = {"json": ".json", "html": ".html", "pdf": ".pdf", "sarif": ".sarif", "md": ".md"}


def render(report: RunReport, fmt: str, *, config_path: str | None = None) -> bytes:
    """Render ``report`` in ``fmt`` (json | html | pdf | sarif | md) as bytes."""
    fmt = fmt.lower()
    if fmt == "json":
        return (report.model_dump_json(indent=2) + "\n").encode()
    if fmt == "html":
        return render_html(report).encode()
    if fmt == "pdf":
        return render_pdf(report)
    if fmt == "sarif":
        return (json.dumps(to_sarif(report, config_path=config_path), indent=2) + "\n").encode()
    if fmt in ("md", "markdown"):
        return render_markdown(report).encode()
    raise ValueError(f"unknown report format {fmt!r}; choose from {', '.join(FORMATS)}")


def guess_format(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    for fmt, ext in EXTENSIONS.items():
        if suffix == ext:
            return fmt
    if suffix == ".sarif.json":
        return "sarif"
    raise ValueError(f"cannot infer report format from {path!r}; pass --format")


def write_report(
    report: RunReport, path: str | Path, fmt: str | None = None, *, config_path: str | None = None
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render(report, fmt or guess_format(path), config_path=config_path))
    return path


__all__ = [
    "EXTENSIONS",
    "FORMATS",
    "guess_format",
    "render",
    "render_html",
    "render_markdown",
    "render_pdf",
    "to_sarif",
    "write_report",
]
