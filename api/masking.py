"""Never return stored credentials: mask secret-looking values in target configs."""

from __future__ import annotations

import re
from typing import Any

from scanner.connectors.base import mask_secret

_SECRET_KEY = re.compile(
    r"(?i)(token|password|passwd|secret|api[_-]?key|authorization|cookie|credential|^value$)"
)


def mask_config(obj: Any, key: str = "") -> Any:
    """Copy of ``obj`` with secret-looking string values masked (``${ENV}`` references stay visible)."""
    if isinstance(obj, dict):
        return {k: mask_config(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_config(v, key) for v in obj]
    if isinstance(obj, str) and _SECRET_KEY.search(key):
        return mask_secret(obj)
    return obj


def merge_masked(old: Any, new: Any, key: str = "") -> Any:
    """On update, a client that sends back a masked value keeps the stored secret."""
    if isinstance(new, dict) and isinstance(old, dict):
        return {k: merge_masked(old.get(k), v, k) for k, v in new.items()}
    if isinstance(new, list) and isinstance(old, list) and len(new) == len(old):
        return [merge_masked(o, n, key) for o, n in zip(old, new, strict=True)]
    if (
        isinstance(new, str)
        and isinstance(old, str)
        and _SECRET_KEY.search(key)
        and new == mask_secret(old)
    ):
        return old
    return new
