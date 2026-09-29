"""Normalise tool/function-call payloads from different providers into :class:`ToolCall`."""

from __future__ import annotations

import json
from typing import Any

from scanner.models import ToolCall


def _args(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}
    if value is None:
        return {}
    return {"_value": value}


def parse_tool_calls(items: Any) -> list[ToolCall]:
    """Accepts OpenAI, Ollama, Anthropic and simple custom shapes."""
    if not items:
        return []
    if isinstance(items, dict):
        items = [items]
    calls: list[ToolCall] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else None
        name = (
            (fn or {}).get("name")
            or item.get("name")
            or item.get("tool")
            or item.get("tool_name")
            or item.get("function_name")
        )
        if not name:
            continue
        raw_args = (
            (fn or {}).get("arguments")
            if fn is not None
            else item.get("arguments", item.get("args", item.get("input", item.get("parameters"))))
        )
        status = str(item.get("status", "")).lower()
        calls.append(
            ToolCall(
                name=str(name),
                arguments=_args(raw_args),
                id=item.get("id"),
                result=item.get("result", item.get("output")),
                blocked=bool(item.get("blocked") or item.get("denied"))
                or status in {"blocked", "denied"},
            )
        )
    return calls
