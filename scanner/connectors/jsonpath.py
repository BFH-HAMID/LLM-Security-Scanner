"""A deliberately small JSONPath subset for pulling the reply out of arbitrary chat APIs.

Supported: ``$``, ``.key``, ``['key']``, ``["key"]``, ``[0]``, ``[-1]``, ``[*]`` and ``.*``.
A leading ``$`` is optional (``choices[0].message.content`` works). A path that contains a
wildcard returns a list of every match.
"""

from __future__ import annotations

import json
import re
from typing import Any

_TOKEN = re.compile(
    r"""
    \.\*                          # .*
    | \.\s*(?P<dot>[^.\[\]\s]+)   # .key
    | \[\s*(?P<idx>-?\d+)\s*\]    # [0]
    | \[\s*\*\s*\]                # [*]
    | \[\s*'(?P<sq>[^']*)'\s*\]   # ['key']
    | \[\s*"(?P<dq>[^"]*)"\s*\]   # ["key"]
    """,
    re.VERBOSE,
)


class JSONPathError(ValueError):
    pass


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover
        return "MISSING"


MISSING = _Missing()  # pass ``default=MISSING`` to get a sentinel back instead of a KeyError
_RAISE = object()


def _tokenize(path: str) -> list[tuple[str, Any]]:
    path = path.strip()
    if path.startswith("$"):
        path = path[1:]
    elif path and not path.startswith((".", "[")):
        path = "." + path
    tokens: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(path):
        m = _TOKEN.match(path, pos)
        if not m:
            raise JSONPathError(f"cannot parse JSONPath near {path[pos:]!r}")
        if m.group(0) in (".*",) or m.group(0).replace(" ", "") == "[*]":
            tokens.append(("wild", None))
        elif m.group("dot") is not None:
            tokens.append(("key", m.group("dot")))
        elif m.group("idx") is not None:
            tokens.append(("idx", int(m.group("idx"))))
        else:
            tokens.append(("key", m.group("sq") if m.group("sq") is not None else m.group("dq")))
        pos = m.end()
    return tokens


def extract(data: Any, path: str, default: Any = _RAISE) -> Any:
    """Return the value at ``path`` or ``default`` (raises ``KeyError`` if no default given)."""
    tokens = _tokenize(path)
    current: list[Any] = [data]
    wildcard = False
    for kind, arg in tokens:
        nxt: list[Any] = []
        for node in current:
            if kind == "key":
                if isinstance(node, dict) and arg in node:
                    nxt.append(node[arg])
            elif kind == "idx":
                if isinstance(node, list) and -len(node) <= arg < len(node):
                    nxt.append(node[arg])
            else:  # wild
                wildcard = True
                if isinstance(node, list):
                    nxt.extend(node)
                elif isinstance(node, dict):
                    nxt.extend(node.values())
        current = nxt
        if not current:
            break
    if not current:
        if default is _RAISE:
            raise KeyError(path)
        return default
    return current if wildcard else current[0]


def as_text(value: Any) -> str:
    """Flatten an extracted value into reply text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(t for t in (as_text(v) for v in value) if t)
    if isinstance(value, (dict, bool, int, float)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)
