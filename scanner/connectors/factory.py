"""Build a connector (optionally wrapped with rate-limit/retry policy) from a target config."""

from __future__ import annotations

from typing import Any

import httpx

from scanner.connectors.base import Connector, PolicyConnector, RetryPolicy
from scanner.connectors.configs import (
    AnthropicTarget,
    DemoTarget,
    HTTPTarget,
    OllamaTarget,
    OpenAITarget,
    TargetBase,
    parse_target,
)


def build_connector(
    target: dict[str, Any] | TargetBase,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    rps: float | None = None,
    concurrency: int | None = None,
    retries: int = 3,
) -> Connector:
    """Create the connector for ``target``.

    ``transport`` lets tests route requests into an in-process ASGI app. When ``rps`` or
    ``concurrency`` is given, the connector is wrapped in a :class:`PolicyConnector`.
    """
    cfg = parse_target(target)
    inner: Connector
    if isinstance(cfg, HTTPTarget):
        from scanner.connectors.http import HTTPConnector

        inner = HTTPConnector(cfg, transport=transport)
    elif isinstance(cfg, OpenAITarget):
        from scanner.connectors.openai_compat import OpenAIConnector

        inner = OpenAIConnector(cfg, transport=transport)
    elif isinstance(cfg, AnthropicTarget):
        from scanner.connectors.anthropic import AnthropicConnector

        inner = AnthropicConnector(cfg, transport=transport)
    elif isinstance(cfg, OllamaTarget):
        from scanner.connectors.ollama import OllamaConnector

        inner = OllamaConnector(cfg, transport=transport)
    elif isinstance(cfg, DemoTarget):
        from scanner.connectors.demo import DemoConnector

        inner = DemoConnector(cfg)
    else:  # pragma: no cover - exhaustive over the union
        raise ValueError(f"unsupported target type: {type(cfg).__name__}")
    if rps is None and concurrency is None and retries == 0:
        return inner
    return PolicyConnector(
        inner,
        rps=rps,
        concurrency=concurrency or 4,
        retry=RetryPolicy(max_retries=retries),
    )
