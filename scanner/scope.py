"""Scope guard: only test systems you own or are authorised to test (docs/ETHICS.md).

Local and private-network targets and the bundled demo run freely. A target on a public host
requires an explicit, recorded authorisation acknowledgement, and gets a polite default rate limit.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from scanner.config import ScanConfig
from scanner.connectors.configs import (
    AnthropicTarget,
    DemoTarget,
    HTTPTarget,
    OllamaTarget,
    OpenAITarget,
    TargetBase,
)
from scanner.models import utcnow

PUBLIC_DEFAULT_RPS = 2.0
_PRIVATE_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
    ".lan",
    ".home.arpa",
    ".test",
    ".example",
    ".invalid",
)
_KNOWN_PUBLIC_APIS = ("api.openai.com", "api.anthropic.com")


@dataclass
class ScopeDecision:
    allowed: bool
    host: str | None
    kind: str  # demo | local | private | public
    message: str = ""
    default_rps: float | None = None


def target_url(target: TargetBase) -> str | None:
    if isinstance(target, HTTPTarget):
        return target.url
    if isinstance(target, (OpenAITarget, AnthropicTarget, OllamaTarget)):
        return target.base_url
    return None


def classify_host(host: str | None) -> str:
    """``local`` (loopback), ``private`` (RFC1918/link-local/internal names) or ``public``."""
    if not host:
        return "local"
    host = host.strip("[]").lower()
    if host in ("localhost", "0.0.0.0") or host.endswith(".localhost"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            return "private"  # single-label names: docker/k8s service names, intranet hosts
        if host.endswith(_PRIVATE_SUFFIXES):
            return "private"
        return "public"
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


def check_scope(
    target: TargetBase, scan: ScanConfig, *, acknowledged_flag: bool = False
) -> ScopeDecision:
    if isinstance(target, DemoTarget):
        return ScopeDecision(True, None, "demo", "in-process demo target")
    url = target_url(target)
    host = urlparse(url).hostname if url else None
    kind = classify_host(host)
    if kind in ("local", "private"):
        return ScopeDecision(True, host, kind, f"{kind} target ({host})")
    if scan.authorization.acknowledged or acknowledged_flag:
        return ScopeDecision(
            True,
            host,
            "public",
            f"public target {host}: authorisation acknowledged",
            default_rps=PUBLIC_DEFAULT_RPS,
        )
    return ScopeDecision(
        False,
        host,
        "public",
        (
            f"{host} is a public host. llmscan only tests systems you own or are authorised to test.\n"
            "If that applies, confirm with --i-am-authorized or set `scan.authorization.acknowledged: true` "
            "(and describe the authorisation in `scan.authorization.note`). See docs/ETHICS.md."
        ),
        default_rps=PUBLIC_DEFAULT_RPS,
    )


def authorization_record(scan: ScanConfig, decision: ScopeDecision, *, via_flag: bool) -> dict:
    """What gets stored in the report so there is an audit trail."""
    acknowledged = (
        scan.authorization.acknowledged or via_flag or decision.kind in ("demo", "local", "private")
    )
    return {
        "acknowledged": acknowledged,
        "scope": decision.kind,
        "host": decision.host,
        "via": "flag"
        if via_flag
        else ("config" if scan.authorization.acknowledged else "not-required"),
        "note": scan.authorization.note,
        "contact": scan.authorization.contact,
        "recorded_at": utcnow().isoformat(),
    }
