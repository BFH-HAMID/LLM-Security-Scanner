"""Redaction of secrets and PII in transcripts and reports (``--redact``)."""

from __future__ import annotations

import re
from collections.abc import Callable

from scanner.detectors.patterns import PII_PATTERNS, SECRET_PATTERNS
from scanner.models import AttemptResult, Evidence, Message, RunReport


def _masker(kind: str, validator: Callable[[str], bool] | None) -> Callable[[re.Match[str]], str]:
    """Replacement function: mask a match unless its validator (e.g. Luhn) rejects it."""

    def repl(m: re.Match[str]) -> str:
        return f"[REDACTED:{kind}]" if (validator is None or validator(m.group(0))) else m.group(0)

    return repl


def redact_text(text: str, extra: list[str] | None = None) -> str:
    """Replace secrets, e-mail addresses, phone numbers, SSNs and valid card numbers."""
    if not text:
        return text
    for value in extra or []:
        if value:
            text = re.sub(re.escape(value), "[REDACTED:known]", text, flags=re.IGNORECASE)
    for kind, pat in SECRET_PATTERNS.items():
        if kind == "generic_secret":
            continue
        text = pat.sub(f"[REDACTED:{kind}]", text)
    for kind in ("ssn", "credit_card", "email", "phone", "iban"):
        pat, validator = PII_PATTERNS[kind]
        text = pat.sub(_masker(kind, validator), text)
    return text


def _msg(m: Message, extra: list[str]) -> Message:
    return m.model_copy(update={"content": redact_text(m.content, extra)})


def _evidence(e: Evidence, extra: list[str]) -> Evidence:
    return e.model_copy(
        update={"matched": redact_text(e.matched, extra) if e.matched else e.matched}
    )


def redact_result(r: AttemptResult, extra: list[str] | None = None) -> AttemptResult:
    extra = extra or []
    meta = dict(r.meta)
    if "documents" in meta:
        meta["documents"] = [
            {**d, "content": redact_text(d.get("content", ""), extra)} for d in meta["documents"]
        ]
    return r.model_copy(
        update={
            "transcript": [_msg(m, extra) for m in r.transcript],
            "response_text": redact_text(r.response_text, extra),
            "evidence": [_evidence(e, extra) for e in r.evidence],
            "detections": [
                d.model_copy(update={"evidence": [_evidence(e, extra) for e in d.evidence]})
                for d in r.detections
            ],
            "meta": meta,
        }
    )


def redact_report(report: RunReport, extra: list[str] | None = None) -> RunReport:
    """Return a copy of ``report`` with sensitive strings masked everywhere they could appear."""
    return report.model_copy(update={"results": [redact_result(r, extra) for r in report.results]})
