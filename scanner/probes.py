"""Probe schema, YAML loading, selection and attack planning.

A *probe* is one attack, stored as one YAML file under ``probes/<category>/``. See
``docs/PROBES.md`` for the authoring guide and ``probes/probe.schema.json`` for the JSON Schema.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scanner.indirect import CARRIERS, HIDING_STYLES, build_document
from scanner.models import Category, Severity
from scanner.taxonomy import ATLAS_TECHNIQUES, CATEGORIES, OWASP_LLM_TOP10, default_remediation
from scanner.templating import (
    FILTERS,
    TemplateError,
    builtin_variable_names,
    find_filters,
    render,
    validate_variables,
)

# --------------------------------------------------------------------------- rules


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContainsRule(_Strict):
    """Matches when the response contains one of (or all of) the given strings."""

    type: Literal["contains"]
    values: list[str] = Field(min_length=1)
    match: Literal["any", "all"] = "any"
    case_sensitive: bool = False
    description: str = ""


def _default_flags() -> list[Literal["i", "m", "s"]]:
    return ["i"]


class RegexRule(_Strict):
    type: Literal["regex"]
    pattern: str
    flags: list[Literal["i", "m", "s"]] = Field(default_factory=_default_flags)
    description: str = ""

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        # Template variables may appear in patterns; neutralise them for the compile check only.
        try:
            re.compile(re.sub(r"\{\{\s*\w+\s*\}\}", "x", v))
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return v


class CanaryRule(_Strict):
    """A planted secret leaked (also detects base64/hex/ROT13/reversed/spaced variants)."""

    type: Literal["canary"]
    names: list[str] = Field(default_factory=list)  # empty = every configured canary
    decode: bool = True


class SecretRule(_Strict):
    """API keys, tokens and private keys in the response."""

    type: Literal["secret"]
    kinds: list[str] = Field(default_factory=list)  # empty = all built-in patterns
    ignore_in_prompt: bool = True


class PiiRule(_Strict):
    type: Literal["pii"]
    kinds: list[str] = Field(default_factory=list)
    known_values: list[str] = Field(default_factory=list)
    ignore_in_prompt: bool = True
    min_matches: int = Field(1, ge=1)


class SystemPromptLeakRule(_Strict):
    """Response reproduces the (known) system prompt or listed fragments."""

    type: Literal["system_prompt_leak"]
    fragments: list[str] = Field(default_factory=list)
    min_overlap: float = Field(0.3, ge=0.0, le=1.0)
    ngram: int = Field(4, ge=2, le=12)


class OutputHandlingRule(_Strict):
    type: Literal["output_handling"]
    kinds: list[str] = Field(default_factory=list)  # empty = all
    allowed_domains: list[str] = Field(default_factory=list)


class ToolCallRule(_Strict):
    """Matches when the agent attempted a (forbidden) tool call."""

    type: Literal["tool_call"]
    names: list[str] = Field(default_factory=list)
    any_tool: bool = False
    args_match: dict[str, str] = Field(default_factory=dict)  # arg -> regex; "*" = any argument
    min_calls: int = Field(1, ge=1)

    @model_validator(mode="after")
    def _selector(self) -> ToolCallRule:
        if not self.names and not self.any_tool:
            raise ValueError("tool_call rule needs `names` or `any_tool: true`")
        for pattern in self.args_match.values():
            try:
                re.compile(re.sub(r"\{\{\s*\w+\s*\}\}", "x", pattern))
            except re.error as exc:
                raise ValueError(f"invalid args_match regex: {exc}") from exc
        return self


class KnownSensitiveRule(_Strict):
    """Matches when a value the target owner declared as sensitive (``known_sensitive``) leaks."""

    type: Literal["known_sensitive"]
    values: list[str] = Field(default_factory=list)  # extra values on top of the target's list
    min_matches: int = Field(1, ge=1)
    ignore_in_prompt: bool = True


class RefusalRule(_Strict):
    """Refusal heuristic. ``absent`` matches when the model did NOT refuse (weak signal)."""

    type: Literal["refusal"]
    expect: Literal["present", "absent"] = "absent"
    min_length: int = Field(0, ge=0)


Rule = Annotated[
    ContainsRule
    | RegexRule
    | CanaryRule
    | SecretRule
    | PiiRule
    | SystemPromptLeakRule
    | OutputHandlingRule
    | ToolCallRule
    | KnownSensitiveRule
    | RefusalRule,
    Field(discriminator="type"),
]


class JudgeSpec(_Strict):
    rubric: str
    success_indicators: list[str] = Field(default_factory=list)
    threshold: float = Field(0.6, ge=0.0, le=1.0)


class SuccessCriteria(_Strict):
    match: Literal["any", "all"] = "any"
    rules: list[Rule] = Field(default_factory=list)
    judge: JudgeSpec | None = None
    policy: Literal["rules", "judge", "any", "all"] | None = None
    # Multi-turn probes: evaluate the final response only, or flag if *any* turn succeeded.
    scope: Literal["last", "any_turn"] = "last"

    @model_validator(mode="after")
    def _needs_detector(self) -> SuccessCriteria:
        if not self.rules and self.judge is None:
            raise ValueError("success_criteria needs at least one rule or a judge")
        if self.policy in ("all", "any") and not (self.rules and self.judge):
            raise ValueError(f"policy '{self.policy}' needs both rules and a judge")
        if self.policy == "rules" and not self.rules:
            raise ValueError("policy 'rules' needs rules")
        if self.policy == "judge" and self.judge is None:
            raise ValueError("policy 'judge' needs a judge")
        return self

    @property
    def effective_policy(self) -> str:
        if self.policy:
            return self.policy
        if self.rules and self.judge:
            return "any"
        return "rules" if self.rules else "judge"


# ---------------------------------------------------------------------------- probe


class Turn(_Strict):
    role: Literal["user", "assistant", "system"] = "user"
    content: str
    # Mark the turn that carries the attack payload (mutators transform it). Default: last user turn.
    attack: bool = False


class IndirectSpec(_Strict):
    """A poisoned document: benign content + hidden instruction, delivered inline or ingested."""

    carrier: str = "document"
    hide: str = "none"
    payload: str
    benign_content: str = ""
    title: str = "Untitled document"
    delivery: Literal["auto", "inline", "ingest"] = "auto"
    query: str = "Please summarize this document."

    @field_validator("carrier")
    @classmethod
    def _carrier(cls, v: str) -> str:
        if v not in CARRIERS:
            raise ValueError(f"unknown carrier '{v}'. Choose from {sorted(CARRIERS)}")
        return v

    @field_validator("hide")
    @classmethod
    def _hide(cls, v: str) -> str:
        if v not in HIDING_STYLES:
            raise ValueError(f"unknown hide style '{v}'. Choose from {sorted(HIDING_STYLES)}")
        return v


class ToolDef(_Strict):
    """Function schema offered to models that support tool calling (never executed by us)."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class AdaptiveSpec(_Strict):
    """Multi-turn attacker agent (PAIR / crescendo style)."""

    strategy: Literal["crescendo", "pair"] = "crescendo"
    goal: str
    max_turns: int = Field(6, ge=1, le=20)
    tactics: list[str] = Field(default_factory=list)


MutatorPolicy = Literal["all", "none"] | list[str]


class Probe(_Strict):
    id: str = Field(pattern=r"^[A-Z]{2,5}-\d{3,4}$")
    name: str
    category: Category
    severity: Severity
    description: str = ""
    owasp: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    prompt: str | None = None
    system_prompt: str | None = None
    turns: list[Turn] = Field(default_factory=list)
    indirect: IndirectSpec | None = None
    adaptive: AdaptiveSpec | None = None
    tools: list[ToolDef] = Field(default_factory=list)
    # Names from scanner.standard_tools.STANDARD_TOOLS (send_email, delete_file, ...)
    standard_tools: list[str] = Field(default_factory=list)

    success_criteria: SuccessCriteria
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    mutators: MutatorPolicy = "all"
    enabled: bool = True

    # Set by the loader, not part of the file format.
    source_file: str | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _shape(self) -> Probe:
        modes = [
            bool(self.prompt),
            bool(self.turns),
            self.indirect is not None,
            self.adaptive is not None,
        ]
        if sum(modes) != 1:
            raise ValueError(
                "a probe needs exactly one of: prompt, turns, indirect, adaptive "
                f"(found {sum(modes)})"
            )
        if self.turns and not any(t.role == "user" for t in self.turns):
            raise ValueError("turns must contain at least one user turn")
        from scanner.standard_tools import STANDARD_TOOLS

        for name in self.standard_tools:
            if name not in STANDARD_TOOLS:
                raise ValueError(
                    f"unknown standard tool '{name}' (available: {sorted(STANDARD_TOOLS)})"
                )
        for oid in self.owasp:
            if oid not in OWASP_LLM_TOP10:
                raise ValueError(f"unknown OWASP LLM id '{oid}'")
        for aid in self.atlas:
            if aid not in ATLAS_TECHNIQUES:
                raise ValueError(f"unknown MITRE ATLAS technique '{aid}'")
        info = CATEGORIES[self.category]
        if not self.owasp:
            self.owasp = list(info.owasp)
        if not self.atlas:
            self.atlas = list(info.atlas)
        return self

    # ------------------------------------------------------------------ helpers

    @property
    def kind(self) -> Literal["single", "scripted", "indirect", "adaptive"]:
        if self.adaptive is not None:
            return "adaptive"
        if self.indirect is not None:
            return "indirect"
        if self.turns:
            return "scripted"
        return "single"

    @property
    def remediation_text(self) -> str:
        return (self.remediation or "").strip() or default_remediation(self.category)

    def allows_mutator(self, name: str) -> bool:
        if self.kind == "adaptive":
            return False
        if self.mutators == "all":
            return True
        if self.mutators == "none":
            return False
        return name in self.mutators

    def template_texts(self) -> Iterable[tuple[str, str]]:
        """(location, text) for every templated string, used by validation."""
        if self.prompt:
            yield "prompt", self.prompt
        if self.system_prompt:
            yield "system_prompt", self.system_prompt
        for i, t in enumerate(self.turns):
            yield f"turns[{i}]", t.content
        if self.indirect:
            yield "indirect.payload", self.indirect.payload
            yield "indirect.benign_content", self.indirect.benign_content
            yield "indirect.query", self.indirect.query
        if self.adaptive:
            yield "adaptive.goal", self.adaptive.goal
        for i, rule in enumerate(self.success_criteria.rules):
            if isinstance(rule, ContainsRule):
                for v in rule.values:
                    yield f"success_criteria.rules[{i}].values", v
            elif isinstance(rule, RegexRule):
                yield f"success_criteria.rules[{i}].pattern", rule.pattern
        if self.success_criteria.judge:
            yield "success_criteria.judge.rubric", self.success_criteria.judge.rubric

    # ------------------------------------------------------------------ planning

    def plan(
        self,
        variables: dict[str, str],
        transform: Callable[[str], str] | None = None,
        *,
        can_ingest: bool = False,
    ) -> AttackPlan:
        """Render templates and apply a mutator ``transform`` to the attack payload."""
        r = lambda s: render(s, variables)  # noqa: E731
        t = transform or (lambda s: s)
        from scanner.standard_tools import STANDARD_TOOLS

        system_prompt = r(self.system_prompt) if self.system_prompt else None
        tools = [*self.tools, *(STANDARD_TOOLS[n] for n in self.standard_tools)]

        if self.kind == "single":
            payload = r(self.prompt or "")
            turns = [PlannedTurn("user", t(payload), attack=True)]
            return AttackPlan(self.kind, turns, [], tools, system_prompt, variables, payload)

        if self.kind == "scripted":
            rendered = [(turn.role, r(turn.content), turn.attack) for turn in self.turns]
            flagged = [i for i, (_, _, a) in enumerate(rendered) if a]
            if not flagged:
                users = [i for i, (role, _, _) in enumerate(rendered) if role == "user"]
                flagged = [users[-1]]
            planned = [
                PlannedTurn(role, t(text) if i in flagged else text, attack=i in flagged)
                for i, (role, text, _) in enumerate(rendered)
            ]
            payload = "\n".join(rendered[i][1] for i in flagged)
            return AttackPlan(self.kind, planned, [], tools, system_prompt, variables, payload)

        if self.kind == "indirect":
            assert self.indirect is not None
            spec = self.indirect
            payload = r(spec.payload)
            mutated = t(payload)
            body = build_document(
                spec.carrier, spec.hide, mutated, r(spec.benign_content), r(spec.title)
            )
            delivery = spec.delivery
            if delivery == "auto":
                delivery = "ingest" if can_ingest else "inline"
            if delivery == "ingest" and not can_ingest:
                delivery = "inline"  # target has no ingestion endpoint: fall back to inline
            doc = PlannedDocument(title=r(spec.title), content=body, carrier=spec.carrier)
            if delivery == "ingest":
                turns = [PlannedTurn("user", r(spec.query), attack=False)]
                docs = [doc]
            else:
                turns = [
                    PlannedTurn("user", inline_document_prompt(r(spec.query), doc), attack=True)
                ]
                docs = []
            return AttackPlan(
                self.kind, turns, docs, tools, system_prompt, variables, payload, delivery=delivery
            )

        # adaptive
        assert self.adaptive is not None
        goal = r(self.adaptive.goal)
        return AttackPlan(self.kind, [], [], tools, system_prompt, variables, goal)


@dataclass
class PlannedTurn:
    role: str
    content: str
    attack: bool = False


@dataclass
class PlannedDocument:
    title: str
    content: str
    carrier: str = "document"


@dataclass
class AttackPlan:
    kind: str
    turns: list[PlannedTurn]
    documents: list[PlannedDocument]
    tools: list[ToolDef]
    system_prompt: str | None
    variables: dict[str, str]
    payload: str
    delivery: str = "inline"
    meta: dict[str, Any] = field(default_factory=dict)


def inline_document_prompt(query: str, doc: PlannedDocument) -> str:
    """Wrap a document the way a naive app would hand retrieved/attached content to the model."""
    return (
        f"{query}\n\n--- BEGIN {doc.carrier.upper()}: {doc.title} ---\n{doc.content}\n--- END ---"
    )


# -------------------------------------------------------------------------- loading


class ProbeLoadError(Exception):
    def __init__(self, errors: list[tuple[str, str]]):
        self.errors = errors
        lines = "\n".join(f"  {path}: {msg}" for path, msg in errors)
        super().__init__(f"{len(errors)} probe file(s) failed validation:\n{lines}")


def default_probes_dir() -> Path:
    """Locate the built-in probe library.

    Order: ``$LLMSCAN_PROBES_DIR``, ``./probes``, the source checkout, the installed data package.
    """
    env = os.environ.get("LLMSCAN_PROBES_DIR")
    if env:
        return Path(env)
    cwd = Path.cwd() / "probes"
    if cwd.is_dir():
        return cwd
    checkout = Path(__file__).resolve().parents[1] / "probes"
    if checkout.is_dir():
        return checkout
    try:
        import importlib.resources as res

        return Path(str(res.files("scanner_probes")))
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - defensive
        return checkout


def _iter_probe_files(paths: Iterable[Path | str]) -> Iterable[Path]:
    for p in paths:
        path = Path(p)
        if path.is_dir():
            yield from sorted([*path.rglob("*.yaml"), *path.rglob("*.yml")])
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(f"probe path not found: {path}")


def parse_probe(data: Any, source: str | None = None) -> Probe:
    if not isinstance(data, dict):
        raise ValueError("probe file must contain a YAML mapping")
    probe = Probe.model_validate(data)
    problems: list[str] = []
    allowed = builtin_variable_names(
        extra=[f"canary_{n}" for n in _CANARY_NAME_HINTS]
    )  # canary_<name> checked loosely
    for where, text in probe.template_texts():
        unknown = [v for v in validate_variables(text, allowed) if not v.startswith("canary_")]
        if unknown:
            problems.append(f"{where}: unknown template variable(s) {unknown}")
        bad_filters = sorted(find_filters(text) - set(FILTERS))
        if bad_filters:
            problems.append(f"{where}: unknown template filter(s) {bad_filters}")
    if problems:
        raise ValueError("; ".join(problems))
    probe.source_file = source
    return probe


_CANARY_NAME_HINTS = ("system", "rag", "default")


def load_probe_file(path: Path | str) -> Probe:
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return parse_probe(data, source=str(path))


def load_probes(paths: Iterable[Path | str] | Path | str | None = None) -> list[Probe]:
    """Load and validate every probe under ``paths`` (default: the built-in library)."""
    if paths is None:
        paths = [default_probes_dir()]
    elif isinstance(paths, (str, Path)):
        paths = [paths]
    probes: list[Probe] = []
    errors: list[tuple[str, str]] = []
    seen: dict[str, str] = {}
    for file in _iter_probe_files(paths):
        try:
            probe = load_probe_file(file)
        except Exception as exc:
            errors.append((str(file), _short_error(exc)))
            continue
        if probe.id in seen:
            errors.append((str(file), f"duplicate probe id {probe.id} (also in {seen[probe.id]})"))
            continue
        seen[probe.id] = str(file)
        probes.append(probe)
    if errors:
        raise ProbeLoadError(errors)
    probes.sort(key=lambda p: (list(Category).index(p.category), p.id))
    return probes


def _short_error(exc: Exception) -> str:
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        parts = []
        for err in exc.errors():
            loc = ".".join(str(x) for x in err["loc"])
            parts.append(f"{loc}: {err['msg']}" if loc else err["msg"])
        return "; ".join(parts)
    return str(exc)


# ------------------------------------------------------------------------ selection


class ProbeSelection(BaseModel):
    """Which probes to run. Empty lists mean 'no restriction'."""

    categories: list[Category] = Field(default_factory=list)
    severities: list[Severity] = Field(default_factory=list)
    min_severity: Severity | None = None
    tags: list[str] = Field(default_factory=list)
    ids: list[str] = Field(default_factory=list)
    exclude_ids: list[str] = Field(default_factory=list)
    kinds: list[str] = Field(default_factory=list)
    max_probes: int | None = Field(default=None, ge=1)
    include_disabled: bool = False


def select_probes(probes: Iterable[Probe], sel: ProbeSelection | None = None) -> list[Probe]:
    sel = sel or ProbeSelection()
    out: list[Probe] = []
    for p in probes:
        if not p.enabled and not sel.include_disabled and p.id not in sel.ids:
            continue
        if sel.categories and p.category not in sel.categories:
            continue
        if sel.severities and p.severity not in sel.severities:
            continue
        if sel.min_severity and p.severity.rank < sel.min_severity.rank:
            continue
        if sel.tags and not set(sel.tags) & set(p.tags):
            continue
        if sel.ids and p.id not in sel.ids:
            continue
        if p.id in sel.exclude_ids:
            continue
        if sel.kinds and p.kind not in sel.kinds:
            continue
        out.append(p)
    if sel.max_probes:
        out = out[: sel.max_probes]
    return out


# ---------------------------------------------------------------------------- lint


def lint_probe(probe: Probe) -> list[str]:
    """Non-fatal quality warnings for probe authors."""
    warnings: list[str] = []
    if not probe.description.strip():
        warnings.append("missing description")
    if probe.source_file:
        stem = Path(probe.source_file).stem.lower()
        if not stem.startswith(probe.id.lower()):
            warnings.append(f"file name '{Path(probe.source_file).name}' should start with the id")
    text = "\n".join(t for _, t in probe.template_texts() if _ in ("prompt",) or "turns" in _)
    uses_marker_in_rules = any(
        isinstance(r, ContainsRule) and any("{{marker}}" in v.replace(" ", "") for v in r.values)
        for r in probe.success_criteria.rules
    )
    if uses_marker_in_rules and "{{marker}}" in text.replace(" ", ""):
        warnings.append(
            "prompt contains the full {{marker}} that a rule looks for: a refusal that quotes the "
            "prompt would be a false positive. Build it from {{marker_head}} + {{marker_tail}}."
        )
    rules = probe.success_criteria.rules
    if (
        rules
        and all(isinstance(r, RefusalRule) for r in rules)
        and not probe.success_criteria.judge
    ):
        warnings.append(
            "only a refusal heuristic decides this probe; add a stronger rule or a judge"
        )
    if probe.kind == "adaptive" and not rules:
        warnings.append("adaptive probes should have at least one rule so the loop can stop early")
    return warnings


__all__ = [
    "AdaptiveSpec",
    "AttackPlan",
    "IndirectSpec",
    "Probe",
    "ProbeLoadError",
    "ProbeSelection",
    "SuccessCriteria",
    "TemplateError",
    "load_probe_file",
    "load_probes",
    "select_probes",
]
