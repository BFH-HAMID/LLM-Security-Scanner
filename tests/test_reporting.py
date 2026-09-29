"""Exporters: JSON round-trip, HTML safety, PDF, SARIF schema validity and Markdown."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest

from scanner.models import AttemptResult, Category, Message, RunReport, Severity, Status
from scanner.redact import redact_report, redact_text
from scanner.reporting import FORMATS, guess_format, render, to_sarif, write_report
from scanner.reporting.common import heatmap, radar_points, remediation_blocks, sorted_findings
from scanner.reporting.pdf import pdf_safe
from scanner.scoring import score

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())


def test_json_roundtrip(small_report):
    again = RunReport.model_validate_json(render(small_report, "json"))
    assert again.id == small_report.id and again.score == small_report.score
    assert [r.id for r in again.results] == [r.id for r in small_report.results]


def test_sarif_validates_against_the_official_schema(small_report, weak_report):
    for rep in (small_report, weak_report):
        doc = to_sarif(rep)
        errors = list(jsonschema.Draft7Validator(SCHEMA).iter_errors(doc))
        assert not errors, errors[:3]
    empty = RunReport(results=[], score=score([]))
    assert not list(jsonschema.Draft7Validator(SCHEMA).iter_errors(to_sarif(empty)))


def test_sarif_content(small_report):
    doc = to_sarif(small_report, config_path="ci/llmscan.yaml")
    run = doc["runs"][0]
    findings = [r for r in small_report.results if r.status is Status.FAIL]
    assert len(run["results"]) == len(findings) > 0
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "llm-security-scanner"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    res = run["results"][0]
    assert (
        res["ruleId"] in rule_ids
        and run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
    )
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "ci/llmscan.yaml"
    assert (
        res["level"] in {"error", "warning", "note"}
        and res["partialFingerprints"]["llmscan/finding/v1"]
    )
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == res["ruleId"])
    assert float(rule["properties"]["security-severity"]) > 0 and rule["help"]["text"]
    taxa = {t["name"]: {x["id"] for x in t["taxa"]} for t in run["taxonomies"]}
    assert "LLM01" in taxa["OWASP LLM Top 10"] and any(
        t.startswith("AML.T") for t in taxa["MITRE ATLAS"]
    )
    fp = [r["partialFingerprints"]["llmscan/finding/v1"] for r in run["results"]]
    assert len(fp) == len(set(fp))  # stable + unique per (target, probe, mutator)


def test_sarif_severity_levels():
    def result(sev):
        return AttemptResult(
            probe_id="PI-001",
            probe_name="p",
            category=Category.PROMPT_INJECTION,
            severity=sev,
            status=Status.FAIL,
            owasp=["LLM01"],
            atlas=["AML.T0051.000"],
        )

    for sev, level in [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
    ]:
        rep = RunReport(results=[result(sev)], score=score([result(sev)]))
        assert to_sarif(rep)["runs"][0]["results"][0]["level"] == level


def test_html_escapes_attacker_and_model_controlled_text():
    evil = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
    r = AttemptResult(
        probe_id="OH-001",
        probe_name=evil,
        category=Category.INSECURE_OUTPUT_HANDLING,
        severity=Severity.HIGH,
        status=Status.FAIL,
        mutator="none",
        reason=evil,
        response_text=evil,
        transcript=[Message(role="user", content=evil), Message(role="assistant", content=evil)],
        remediation=f"- {evil}\n\n{evil}",
        meta={"documents": [{"title": evil, "carrier": "email", "content": evil}]},
    )
    rep = RunReport(
        target={"name": evil},
        results=[r],
        score=score([r]),
        notes=[evil],
        authorization={"note": evil},
    )
    html = render(rep, "html").decode()
    assert (
        "<script" not in html.lower() and "<img src=x" not in html.lower()
    )  # markup is inert text
    assert html.count("&lt;script&gt;") >= 5
    assert "<body" in html and "</html>" in html.strip()[-10:]


def test_html_is_self_contained_and_has_all_sections(small_report):
    html = render(small_report, "html").decode()
    assert "<script" not in html and "https://cdn" not in html and 'rel="stylesheet"' not in html
    for section in (
        "Attack success rate by category",
        "Severity breakdown",
        "Probe x mutator heatmap",
        "How to fix it",
        "Why it was flagged",
        "Radar chart",
    ):
        assert section in html
    assert "atlas.mitre.org/techniques/AML.T" in html and "genai.owasp.org" in html


def test_pdf_is_a_valid_pdf_and_survives_non_latin_text():
    r = AttemptResult(
        probe_id="PI-001",
        probe_name="\u65e5\u672c\u8a9e \u0442\u0435\u0441\u0442 \U0001f600",
        category=Category.PROMPT_INJECTION,
        severity=Severity.HIGH,
        status=Status.FAIL,
        reason="<b>bold</b> & \u2603",
        response_text="\u4f60\u597d",
        transcript=[
            Message(role="user", content="\u4f60\u597d <x>"),
            Message(role="assistant", content="\u043f\u0440\u0438\u0432\u0435\u0442"),
        ],
        owasp=["LLM01"],
        atlas=["AML.T0051.000"],
        remediation="fix it",
    )
    pdf = render(RunReport(results=[r], score=score([r])), "pdf")
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF") and len(pdf) > 2000
    assert pdf_safe("a\u4f60b\x00c") == "a?b c"


def test_pdf_of_a_full_run(weak_report):
    pdf = render(weak_report, "pdf")
    assert pdf.startswith(b"%PDF-") and len(pdf) > 20_000


def test_markdown_summary(small_report):
    md = render(small_report, "md").decode()
    assert (
        md.startswith("## LLM security scan")
        and "| Category | ASR | Failed | Risk |" in md
        and "### Findings" in md
    )
    assert re.search(r"Risk score: \d+/100", md)


def test_format_helpers(tmp_path, small_report):
    assert [guess_format(f"x.{e}") for e in ("json", "html", "pdf", "sarif", "md")] == [
        "json",
        "html",
        "pdf",
        "sarif",
        "md",
    ]
    with pytest.raises(ValueError):
        guess_format("x.docx")
    with pytest.raises(ValueError):
        render(small_report, "docx")
    for fmt in FORMATS:
        p = write_report(small_report, tmp_path / f"nested/dir/r.{fmt}")
        assert p.exists() and p.stat().st_size > 100


def test_heatmap_radar_and_helpers(small_report):
    rows, mutators = heatmap(small_report)
    assert mutators[0] == "none" and {"base64", "roleplay"} <= set(mutators)
    assert len(rows) == 25 and all("none" in r.cells for r in rows)
    fails = sorted_findings(small_report)
    assert all(f.status is Status.FAIL for f in fails)
    assert [f.severity.rank for f in fails] == sorted(
        (f.severity.rank for f in fails), reverse=True
    )
    radar = radar_points(small_report)
    assert len(radar["axes"]) >= 3 and radar["polygon"]
    assert remediation_blocks("Intro line.\n\n- a\n- b\n\nTail") == [
        ("p", "Intro line."),
        ("ul", ["a", "b"]),
        ("p", "Tail"),
    ]


def test_redaction():
    text = "mail bob@example.com card 4111 1111 1111 1111 ssn 987-65-4320 key AKIAIOSFODNN7EXAMPLE phone +1-555-0100 order 1234 5678 9012 3456"
    out = redact_text(text)
    for leaked in (
        "bob@example.com",
        "4111 1111 1111 1111",
        "987-65-4320",
        "AKIAIOSFODNN7EXAMPLE",
        "555-0100",
    ):
        assert leaked not in out
    assert "1234 5678 9012 3456" in out  # not a valid card number: left alone
    assert redact_text("CANARY-xyz", extra=["CANARY-xyz"]) == "[REDACTED:known]"
    r = AttemptResult(
        probe_id="DL-001",
        probe_name="p",
        category=Category.SENSITIVE_DATA_LEAKAGE,
        severity=Severity.HIGH,
        status=Status.FAIL,
        response_text=text,
        transcript=[Message(role="assistant", content=text)],
        meta={"documents": [{"title": "t", "content": text}]},
    )
    clean = redact_report(RunReport(results=[r], score=score([r])))
    blob = clean.model_dump_json()
    assert "bob@example.com" not in blob and "987-65-4320" not in blob
    assert "bob@example.com" in r.response_text  # original object untouched
