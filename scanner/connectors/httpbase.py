"""Shared HTTP plumbing for connectors that talk to web APIs."""

from __future__ import annotations

import time
from typing import Any

import httpx

from scanner.connectors.base import Connector, parse_retry_after
from scanner.models import TargetResponse


class HTTPConnectorBase(Connector):
    def __init__(
        self,
        *,
        name: str,
        timeout: float,
        verify_tls: bool = True,
        headers: dict[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        max_response_chars: int = 20_000,
    ):
        self.name = name
        self._timeout = timeout
        self._verify = verify_tls
        self._headers = dict(headers or {})
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self.max_response_chars = max_response_chars

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            kwargs: dict[str, Any] = {
                "timeout": httpx.Timeout(self._timeout),
                "follow_redirects": False,
                "headers": {"User-Agent": "llm-security-scanner/0.1 (+authorized-testing)"},
            }
            if self._transport is not None:
                kwargs["transport"] = self._transport
            else:
                kwargs["verify"] = self._verify
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def truncate(self, text: str) -> str:
        if len(text) > self.max_response_chars:
            return text[: self.max_response_chars] + "\n[... truncated by scanner ...]"
        return text

    async def _do(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        data: dict[str, Any] | None = None,
        content: str | None = None,
    ) -> tuple[httpx.Response | None, TargetResponse | None, float]:
        """Perform a request. Returns ``(response, None, ms)`` or ``(None, error_response, ms)``."""
        merged = {**self._headers, **(headers or {})}
        start = time.perf_counter()
        try:
            resp = await self.client.request(
                method,
                url,
                headers=merged,
                params=params,
                json=json_body,
                data=data,
                content=content,
            )
        except httpx.TimeoutException:
            ms = (time.perf_counter() - start) * 1000
            return (
                None,
                TargetResponse(
                    error=f"timeout after {self._timeout:g}s calling {method} {url}",
                    latency_ms=ms,
                    meta={"retryable": True},
                ),
                ms,
            )
        except httpx.TransportError as exc:
            ms = (time.perf_counter() - start) * 1000
            return (
                None,
                TargetResponse(
                    error=f"connection error calling {method} {url}: {type(exc).__name__}: {exc}",
                    latency_ms=ms,
                    meta={"retryable": True},
                ),
                ms,
            )
        ms = (time.perf_counter() - start) * 1000
        if resp.status_code >= 400:
            snippet = resp.text.strip().replace("\n", " ")[:300]
            retryable = resp.status_code in (408, 425, 429) or resp.status_code >= 500
            return (
                None,
                TargetResponse(
                    error=f"HTTP {resp.status_code} from {url}: {snippet}",
                    status_code=resp.status_code,
                    latency_ms=ms,
                    meta={
                        "retryable": retryable,
                        "retry_after": parse_retry_after(resp.headers.get("retry-after")),
                    },
                ),
                ms,
            )
        if 300 <= resp.status_code < 400:
            return (
                None,
                TargetResponse(
                    error=f"unexpected redirect (HTTP {resp.status_code}) from {url}; "
                    "point the target at the final URL",
                    status_code=resp.status_code,
                    latency_ms=ms,
                ),
                ms,
            )
        return resp, None, ms
