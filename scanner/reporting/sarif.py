"""SARIF 2.1.0 export for GitHub code scanning and other CI viewers."""

from __future__ import annotations

import hashlib
from typing import Any

from scanner import __version__
from scanner.models import AttemptResult, RunReport, Severity, Status
from scanner.taxonomy import (
    ATLAS_TECHNIQUES,
    ATLAS_VERSION,
    OWASP_EDITION,
    OWASP_LLM_TOP10,
    atlas_url,
    owasp_url,
)

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/BFH-HAMID/LLM-Security-Scanner"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _fingerprint(report: RunReport, r: AttemptResult) -> str:
    target = str(
        report.target.get("name")
        or report.target.get("url")
        or report.target.get("model")
        or "target"
    )
    return hashlib.sha256(f"{target}|{r.probe_id}|{r.mutator}".encode()).hexdigest()[:32]


def _excerpt(text: str, n: int = 400) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def to_sarif(report: RunReport, *, config_path: str | None = None) -> dict[str, Any]:
    """Convert a run to SARIF. Only successful attacks (findings) become results.

    GitHub needs a file location per result, so findings point at the scan config file
    (``config_path``, default ``llmscan.yaml``); the probe id is the rule id.
    """
    uri = config_path or str(report.config.get("config_file") or "llmscan.yaml")
    findings = [r for r in report.results if r.status is Status.FAIL]

    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for r in findings:
        if r.probe_id in rule_index:
            continue
        rule_index[r.probe_id] = len(rules)
        rules.append(
            {
                "id": r.probe_id,
                "name": r.probe_name.title().replace(" ", "").replace("-", "")[:80],
                "shortDescription": {"text": r.probe_name},
                "fullDescription": {
                    "text": f"{r.probe_name} ({r.category.value.replace('_', ' ')})"
                },
                "help": {"text": r.remediation, "markdown": r.remediation},
                "helpUri": owasp_url(r.owasp[0]) if r.owasp else INFO_URI,
                "defaultConfiguration": {"level": _LEVEL[r.severity]},
                "properties": {
                    "tags": ["security", "llm", r.category.value, *r.owasp, *r.atlas],
                    "security-severity": r.severity.security_severity,
                    "precision": "high" if r.confidence >= 0.9 else "medium",
                    "problem.severity": _LEVEL[r.severity],
                },
                "relationships": [
                    {
                        "target": {
                            "id": oid,
                            "toolComponent": {"name": "OWASP LLM Top 10"},
                        },
                        "kinds": ["relevant"],
                    }
                    for oid in r.owasp
                ]
                + [
                    {
                        "target": {"id": aid, "toolComponent": {"name": "MITRE ATLAS"}},
                        "kinds": ["relevant"],
                    }
                    for aid in r.atlas
                ],
            }
        )

    used_owasp = sorted({o for r in findings for o in r.owasp})
    used_atlas = sorted({a for r in findings for a in r.atlas})
    taxonomies = []
    if used_owasp:
        taxonomies.append(
            {
                "name": "OWASP LLM Top 10",
                "version": OWASP_EDITION,
                "organization": "OWASP",
                "informationUri": "https://genai.owasp.org/llm-top-10/",
                "taxa": [
                    {"id": o, "name": OWASP_LLM_TOP10[o], "helpUri": owasp_url(o)}
                    for o in used_owasp
                ],
            }
        )
    if used_atlas:
        taxonomies.append(
            {
                "name": "MITRE ATLAS",
                "version": ATLAS_VERSION,
                "organization": "MITRE",
                "informationUri": "https://atlas.mitre.org/",
                "taxa": [
                    {"id": a, "name": ATLAS_TECHNIQUES[a], "helpUri": atlas_url(a)}
                    for a in used_atlas
                ],
            }
        )

    results = []
    for r in findings:
        why = r.reason or "attack succeeded"
        text = (
            f"{r.probe_name} succeeded against the target"
            + (f" (mutator: {r.mutator})" if r.mutator != "none" else "")
            + f". {why}"
        )
        results.append(
            {
                "ruleId": r.probe_id,
                "ruleIndex": rule_index[r.probe_id],
                "level": _LEVEL[r.severity],
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": r.probe_id,
                                "fullyQualifiedName": f"{report.target.get('name', 'target')}/{r.probe_id}/{r.mutator}",
                                "kind": "member",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {"llmscan/finding/v1": _fingerprint(report, r)},
                "taxa": [{"id": o, "toolComponent": {"name": "OWASP LLM Top 10"}} for o in r.owasp]
                + [{"id": a, "toolComponent": {"name": "MITRE ATLAS"}} for a in r.atlas],
                "properties": {
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "mutator": r.mutator,
                    "confidence": round(r.confidence, 3),
                    "owasp": r.owasp,
                    "atlas": r.atlas,
                    "response_excerpt": _excerpt(r.response_text),
                    "evidence": [e.description for e in r.evidence][:5],
                },
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "llm-security-scanner",
                "version": report.tool.version or __version__,
                "semanticVersion": report.tool.version or __version__,
                "informationUri": INFO_URI,
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": report.status == "completed",
                "startTimeUtc": report.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                **(
                    {"endTimeUtc": report.finished_at.strftime("%Y-%m-%dT%H:%M:%SZ")}
                    if report.finished_at
                    else {}
                ),
            }
        ],
        "properties": {
            "risk_score": report.score.risk_score,
            "grade": report.score.grade,
            "attempts": report.score.total,
            "failed": report.score.failed,
            "run_id": report.id,
        },
    }
    if taxonomies:
        run["taxonomies"] = taxonomies
    return {"$schema": SCHEMA_URI, "version": "2.1.0", "runs": [run]}
