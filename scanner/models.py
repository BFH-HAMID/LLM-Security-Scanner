"""Domain models shared by the scanner engine, storage layer, API and reports."""

from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- enums


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Weight used by the scoring model (see docs/SCORING.md)."""
        return _SEVERITY_WEIGHT[self]

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return _SEVERITY_RANK[self]

    @property
    def security_severity(self) -> str:
        """CVSS-like 0-10 string used by GitHub code scanning (``security-severity``)."""
        return _SECURITY_SEVERITY[self]


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


class Status(StrEnum):
    """Outcome of a single attack attempt."""

    PASS = "pass"  # the target resisted the attack
    FAIL = "fail"  # the attack succeeded -> a finding
    ERROR = "error"  # transport / target error, nothing can be concluded
    INCONCLUSIVE = "inconclusive"  # detectors could not decide (e.g. judge unavailable)


class Category(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    SENSITIVE_DATA_LEAKAGE = "sensitive_data_leakage"
    INSECURE_OUTPUT_HANDLING = "insecure_output_handling"
    EXCESSIVE_AGENCY = "excessive_agency"


# ------------------------------------------------------------------- conversation


class ToolCall(BaseModel):
    """A tool/function call the target attempted (the scanner never executes tools)."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None
    result: Any | None = None
    # True when the application's own guard denied the call. Blocked calls are not a finding.
    blocked: bool = False


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    name: str | None = None
    tool_call_id: str | None = None


class TargetResponse(BaseModel):
    """Normalised response from any target connector."""

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    status_code: int | None = None
    latency_ms: float = 0.0
    error: str | None = None
    usage: dict[str, Any] | None = None
    # Free-form connector metadata (conversation id, finish reason, ...)
    meta: dict[str, Any] = Field(default_factory=dict)
    # Raw parsed payload. Kept in memory for debugging, never persisted in reports.
    raw: Any = Field(default=None, exclude=True)

    @property
    def ok(self) -> bool:
        return self.error is None


# ---------------------------------------------------------------------- detection


class Evidence(BaseModel):
    """Why something was flagged: the matched text plus where it was found."""

    detector: str
    kind: str
    description: str
    matched: str | None = None
    start: int | None = None
    end: int | None = None
    source: Literal["response", "tool_call", "transcript"] = "response"
    turn: int | None = None
    confidence: float = 1.0


class Detection(BaseModel):
    """Output of one detector layer (rules / canary / judge)."""

    detector: str
    matched: bool | None  # None = abstained
    confidence: float = 1.0
    reason: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class AttemptResult(BaseModel):
    """One executed attack: (probe x mutator x repeat)."""

    model_config = ConfigDict(use_enum_values=False)

    id: str = Field(default_factory=new_id)
    probe_id: str
    probe_name: str
    category: Category
    severity: Severity
    owasp: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mutator: str = "none"
    repeat: int = 0
    status: Status
    confidence: float = 0.0
    reason: str = ""
    transcript: list[Message] = Field(default_factory=list)
    response_text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    latency_ms: float = 0.0
    error: str | None = None
    started_at: dt.datetime = Field(default_factory=utcnow)
    source_file: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity used for baselines and run comparison."""
        return f"{self.probe_id}::{self.mutator}"


# ------------------------------------------------------------------------ scoring


class Counter(BaseModel):
    total: int = 0
    failed: int = 0

    @property
    def rate(self) -> float:
        return self.failed / self.total if self.total else 0.0


class CategoryScore(BaseModel):
    category: str
    title: str = ""
    total: int = 0  # attempts that produced a verdict (pass + fail)
    passed: int = 0
    failed: int = 0
    errors: int = 0
    inconclusive: int = 0
    asr: float = 0.0  # attack success rate (unweighted)
    weighted_asr: float = 0.0  # severity weighted
    ci_low: float = 0.0  # Wilson 95% interval on the unweighted ASR
    ci_high: float = 0.0
    risk: float = 0.0  # 0-100 category risk
    by_severity: dict[str, Counter] = Field(default_factory=dict)
    owasp: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)


class MutatorScore(BaseModel):
    mutator: str
    total: int = 0
    failed: int = 0
    asr: float = 0.0


class ScoreCard(BaseModel):
    risk_score: float = 0.0  # 0 (safe) .. 100 (critical)
    grade: str = "A"
    band: str = "minimal"
    asr: float = 0.0
    weighted_asr: float = 0.0
    total: int = 0  # all attempts
    passed: int = 0
    failed: int = 0
    errors: int = 0
    inconclusive: int = 0
    highest_severity_failed: Severity | None = None
    categories: dict[str, CategoryScore] = Field(default_factory=dict)
    severities: dict[str, Counter] = Field(default_factory=dict)
    mutators: dict[str, MutatorScore] = Field(default_factory=dict)
    owasp: dict[str, Counter] = Field(default_factory=dict)


# -------------------------------------------------------------------------- report


class ToolInfo(BaseModel):
    name: str = "llm-security-scanner"
    version: str = ""
    homepage: str = "https://github.com/BFH-HAMID/LLM-Security-Scanner"


RunStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class RunReport(BaseModel):
    """The portable, self-contained record of a scan (what ``--out report.json`` writes)."""

    schema_version: str = "1.0"
    tool: ToolInfo = Field(default_factory=ToolInfo)
    id: str = Field(default_factory=new_id)
    name: str | None = None
    status: RunStatus = "completed"
    target: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    authorization: dict[str, Any] | None = None
    started_at: dt.datetime = Field(default_factory=utcnow)
    finished_at: dt.datetime | None = None
    duration_s: float = 0.0
    score: ScoreCard = Field(default_factory=ScoreCard)
    results: list[AttemptResult] = Field(default_factory=list)
    error: str | None = None
    # Coverage caveats a reader needs to interpret the score (skipped rules, abstaining judge, ...)
    notes: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[AttemptResult]:
        return [r for r in self.results if r.status == Status.FAIL]
