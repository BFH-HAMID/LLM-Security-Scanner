"""Connector interface plus the rate-limit / retry policy wrapper.

A connector turns a list of chat messages into a :class:`TargetResponse`. Connectors never raise
for transport problems: they return a response with ``error`` set (and ``meta['retryable']`` when
a retry might help). :class:`PolicyConnector` adds concurrency limits, request spacing and
exponential backoff around any connector.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scanner.models import Message, TargetResponse

if TYPE_CHECKING:
    from scanner.probes import ToolDef

_SECRET_KEY = re.compile(r"(?i)(authorization|api[-_]?key|token|secret|password|cookie|credential)")


def mask_secret(value: str) -> str:
    if not value:
        return value
    if value.startswith("${") and value.endswith("}"):
        return value  # environment reference, not a secret
    return "***" if len(value) <= 8 else f"{value[:3]}***{value[-2:]}"


def mask_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {k: (mask_secret(str(v)) if _SECRET_KEY.search(k) else v) for k, v in mapping.items()}


class Connector(ABC):
    """Common interface: ``send(messages) -> response``."""

    kind: str = "base"
    name: str = "target"
    supports_history = True  # can prior assistant turns be replayed (many-shot / prefill)?
    supports_tools = False  # can tool schemas be offered to the model?
    supports_ingest = False  # is there a document-ingestion endpoint (RAG)?

    @abstractmethod
    async def send(
        self,
        messages: list[Message],
        *,
        tools: list[ToolDef] | None = None,
        conversation_id: str | None = None,
    ) -> TargetResponse: ...

    async def ingest(
        self, title: str, content: str, *, conversation_id: str | None = None
    ) -> str | None:
        """Add a document to the target's knowledge base. Returns a document id (or None)."""
        raise NotImplementedError(f"{self.kind} connector has no ingestion endpoint")

    async def remove_document(self, document_id: str) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def describe(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name}

    async def __aenter__(self) -> Connector:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class CallableConnector(Connector):
    """Wrap a Python callable — handy for tests and for embedding the scanner in your own app.

    ``fn`` may be sync or async and returns either a string or a :class:`TargetResponse`.
    """

    kind = "callable"

    def __init__(
        self,
        fn: Callable[[list[Message]], Any],
        *,
        name: str = "callable",
        supports_history: bool = True,
        supports_tools: bool = True,
    ):
        self._fn = fn
        self.name = name
        self.supports_history = supports_history
        self.supports_tools = supports_tools
        self.calls: list[list[Message]] = []

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        self.calls.append(list(messages))
        start = time.perf_counter()
        try:
            out = self._fn(messages)
            if asyncio.iscoroutine(out):
                out = await out
        except Exception as exc:
            return TargetResponse(error=f"{type(exc).__name__}: {exc}")
        resp = out if isinstance(out, TargetResponse) else TargetResponse(text=str(out))
        if not resp.latency_ms:
            resp.latency_ms = (time.perf_counter() - start) * 1000
        return resp


# ------------------------------------------------------------------------- policies


class RateLimiter:
    """Spaces requests at least ``1/rps`` seconds apart (leaky-bucket style)."""

    def __init__(
        self,
        rps: float | None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._next_slot = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.interval
            delay = slot - now
        if delay > 0:
            await self._sleep(delay)


@dataclass
class RetryPolicy:
    max_retries: int = 3
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    jitter: float = 0.25

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), 60.0)
        base = min(self.backoff_max, self.backoff_base * (2**attempt))
        return base * (1 + random.uniform(-self.jitter, self.jitter))


class PolicyConnector(Connector):
    """Decorator adding concurrency cap, request spacing and retries to another connector."""

    def __init__(
        self,
        inner: Connector,
        *,
        rps: float | None = None,
        concurrency: int = 4,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.inner = inner
        self.kind = inner.kind
        self.name = inner.name
        self.supports_history = inner.supports_history
        self.supports_tools = inner.supports_tools
        self.supports_ingest = inner.supports_ingest
        self._limiter = RateLimiter(rps, sleep=sleep)
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._retry = retry or RetryPolicy()
        self._sleep = sleep
        self.total_requests = 0
        self.total_retries = 0

    async def send(self, messages, *, tools=None, conversation_id=None) -> TargetResponse:
        async with self._sem:
            attempt = 0
            while True:
                await self._limiter.acquire()
                self.total_requests += 1
                resp = await self.inner.send(messages, tools=tools, conversation_id=conversation_id)
                retryable = resp.error is not None and bool(resp.meta.get("retryable"))
                if not retryable or attempt >= self._retry.max_retries:
                    resp.meta["attempts"] = attempt + 1
                    return resp
                self.total_retries += 1
                await self._sleep(self._retry.delay(attempt, resp.meta.get("retry_after")))
                attempt += 1

    async def ingest(
        self, title: str, content: str, *, conversation_id: str | None = None
    ) -> str | None:
        async with self._sem:
            await self._limiter.acquire()
            return await self.inner.ingest(title, content, conversation_id=conversation_id)

    async def remove_document(self, document_id: str) -> None:
        async with self._sem:
            await self._limiter.acquire()
            await self.inner.remove_document(document_id)

    async def aclose(self) -> None:
        await self.inner.aclose()

    def describe(self) -> dict[str, Any]:
        return self.inner.describe()


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
