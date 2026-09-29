"""Tiny, safe ``{{variable}}`` template engine used for probes and target configs.

Deliberately *not* Jinja: probe files are data, and may come from third parties. Only plain
variable substitution is supported, so a probe can never execute code. To emit a literal
``{{name}}`` (e.g. for server-side-template-injection probes) escape it as ``\\{{name}}``.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import re
import secrets
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from typing import Any

_VAR = re.compile(r"(?<!\\)\{\{\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*\|\s*([a-z0-9_]+))?\s*\}\}")
_ESCAPED = re.compile(r"\\(\{\{)")

# Pure string filters: ``{{marker|b64}}``. No arbitrary code, no arguments.
FILTERS: dict[str, Callable[[str], str]] = {
    "b64": lambda v: base64.b64encode(v.encode()).decode(),
    "hex": lambda v: v.encode().hex(),
    "rot13": lambda v: codecs.encode(v, "rot13"),
    "rev": lambda v: v[::-1],
    "upper": str.upper,
    "lower": str.lower,
    "urlenc": lambda v: urllib.parse.quote(v, safe=""),
    "spaced": lambda v: " ".join(v),
}

_BUILTIN_VARS = frozenset(
    {
        "nonce",
        "marker",
        "marker_head",
        "marker_tail",
        "canary",
        "target",
        "prompt",
        "conversation_id",
    }
)


class TemplateError(ValueError):
    pass


def find_variables(template: str) -> set[str]:
    return {name for name, _ in _VAR.findall(template)}


def find_filters(template: str) -> set[str]:
    return {flt for _, flt in _VAR.findall(template) if flt}


def render(template: str, variables: Mapping[str, Any], *, strict: bool = True) -> str:
    """Substitute ``{{name}}`` placeholders. Unknown names raise unless ``strict=False``."""

    def repl(match: re.Match[str]) -> str:
        name, flt = match.group(1), match.group(2)
        if flt and flt not in FILTERS:
            raise TemplateError(
                f"unknown template filter |{flt} (available: {', '.join(sorted(FILTERS))})"
            )
        if name in variables:
            value = str(variables[name])
            return FILTERS[flt](value) if flt else value
        if strict:
            raise TemplateError(f"unknown template variable {{{{{name}}}}}")
        return match.group(0)

    out = _VAR.sub(repl, template)
    return _ESCAPED.sub(r"\1", out)


def validate_variables(template: str, allowed: Iterable[str]) -> list[str]:
    """Return the variable names used in ``template`` that are not in ``allowed``."""
    allowed_set = set(allowed)
    return sorted(v for v in find_variables(template) if v not in allowed_set)


def builtin_variable_names(extra: Iterable[str] = ()) -> set[str]:
    return set(_BUILTIN_VARS) | set(extra)


def make_variables(
    *,
    probe_id: str,
    mutator: str,
    repeat: int,
    seed: int | None,
    canaries: Mapping[str, str] | None = None,
    target: str = "",
) -> dict[str, str]:
    """Per-attempt template variables.

    ``nonce`` is unique per attempt (deterministic when ``seed`` is given) so a marker echoed by a
    *previous* attempt on a stateful target can never be mistaken for the current one.
    ``marker_head`` + ``marker_tail`` == ``marker``: probes build the marker from the two halves so
    a refusal that quotes the prompt cannot contain the whole marker (echo-safe).
    """
    if seed is None:
        nonce = secrets.token_hex(4)
    else:
        nonce = hashlib.sha256(f"{seed}|{probe_id}|{mutator}|{repeat}".encode()).hexdigest()[:8]
    marker = f"LLMSCAN-{nonce}"
    variables = {
        "nonce": nonce,
        "marker": marker,
        "marker_head": "LLM",
        "marker_tail": f"SCAN-{nonce}",
        "target": target,
    }
    canary_map = dict(canaries or {})
    for i, (name, value) in enumerate(canary_map.items()):
        if i == 0:
            variables["canary"] = value
        variables[f"canary_{name}"] = value
    variables.setdefault("canary", "")
    return variables
