"""Scan configuration: what to run, how hard to push, and how to load it from a YAML file."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from scanner.connectors.configs import TargetBase, parse_target
from scanner.models import Category, Severity
from scanner.probes import ProbeSelection


class ConfigError(ValueError):
    pass


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class JudgeConfig(_Cfg):
    """LLM-as-judge settings. ``target`` is a connector config (or ``ollama:MODEL`` shorthand)."""

    mode: Literal["auto", "llm", "heuristic", "off"] = "auto"
    target: dict[str, Any] | str | None = None
    votes: int = Field(1, ge=1, le=9)
    max_chars: int = Field(6000, ge=500)


class AttackerConfig(_Cfg):
    """Attacker LLM for adaptive multi-turn probes (PAIR / crescendo)."""

    mode: Literal["auto", "llm", "heuristic"] = "auto"
    target: dict[str, Any] | str | None = None


class AuthorizationConfig(_Cfg):
    """Recorded acknowledgement that you are allowed to test this target (see docs/ETHICS.md)."""

    acknowledged: bool = False
    note: str = ""
    contact: str = ""


class ScanConfig(_Cfg):
    name: str | None = None
    # probe selection
    categories: list[Category] = Field(default_factory=list)
    severities: list[Severity] = Field(default_factory=list)
    min_severity: Severity | None = None
    tags: list[str] = Field(default_factory=list)
    ids: list[str] = Field(default_factory=list)
    exclude_ids: list[str] = Field(default_factory=list)
    max_probes: int | None = Field(default=None, ge=1)
    probe_paths: list[str] = Field(default_factory=list)  # extra probe files / directories
    builtin_probes: bool = True  # include the bundled probe library
    # mutation
    mutators: list[str] = Field(default_factory=list)
    include_original: bool = True
    # execution
    repeats: int = Field(1, ge=1, le=50)
    concurrency: int = Field(4, ge=1, le=64)
    rps: float | None = Field(default=None, gt=0)
    retries: int = Field(3, ge=0, le=10)
    timeout: float | None = Field(default=None, gt=0)
    seed: int | None = None
    max_consecutive_errors: int = Field(8, ge=1)
    # analysis
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    attacker: AttackerConfig = Field(default_factory=AttackerConfig)
    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    redact: bool = False

    def selection(self) -> ProbeSelection:
        return ProbeSelection(
            categories=self.categories,
            severities=self.severities,
            min_severity=self.min_severity,
            tags=self.tags,
            ids=self.ids,
            exclude_ids=self.exclude_ids,
            max_probes=self.max_probes,
        )


@dataclass
class LoadedConfig:
    target: TargetBase
    scan: ScanConfig
    path: Path | None = None


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate_env(obj: Any, env: dict[str, str] | None = None) -> Any:
    """Replace ``${VAR}`` / ``${VAR:-default}`` in every string. Missing variables raise."""
    env = os.environ if env is None else env  # type: ignore[assignment]
    if isinstance(obj, str):

        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in env:  # type: ignore[operator]
                return env[name]  # type: ignore[index]
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is not set (referenced as ${{{name}}})")

        return _ENV.sub(repl, obj)
    if isinstance(obj, dict):
        return {k: interpolate_env(v, env) for k, v in obj.items()}  # type: ignore[arg-type]
    if isinstance(obj, list):
        return [interpolate_env(v, env) for v in obj]  # type: ignore[arg-type]
    return obj


DEMO_SHORTHAND = re.compile(r"^demo(?::(weak|medium|hardened))?(?::(chat|rag|agent))?$")


def demo_target(spec: str) -> dict[str, Any]:
    """``demo`` / ``demo:weak`` / ``demo:hardened:agent`` -> in-process demo target config."""
    m = DEMO_SHORTHAND.match(spec)
    if not m:
        raise ConfigError(
            f"bad demo target {spec!r}; use demo[:weak|medium|hardened][:chat|rag|agent]"
        )
    level, surface = m.group(1) or "weak", m.group(2) or "chat"
    from targets.vulnerable_app import data

    return {
        "type": "demo",
        "name": f"demo-{surface}-{level}",
        "level": level,
        "surface": surface,
        "canaries": {"system": data.CANARY, "rag": data.RAG_CANARY},
        "system_prompt_fragments": data.SYSTEM_PROMPT_FRAGMENTS,
        "known_sensitive": [v for c in data.CUSTOMERS for v in (c["email"], c["ssn"], c["card"])]
        + ["BLUE HARBOR", "AKIAIOSFODNN7EXAMPLE"],
    }


MODEL_SHORTHAND = re.compile(r"^(ollama|openai|anthropic):(?P<model>[^@\s]+)(?:@(?P<url>\S+))?$")


def model_target(spec: str) -> dict[str, Any]:
    """``ollama:llama3.1`` / ``openai:gpt-4o-mini[@http://host/v1]`` / ``anthropic:MODEL`` -> config."""
    m = MODEL_SHORTHAND.match(spec)
    if not m:
        raise ConfigError(
            f"bad model spec {spec!r}; use ollama:MODEL, openai:MODEL[@BASE_URL] or anthropic:MODEL"
        )
    kind, model, url = spec.split(":", 1)[0], m.group("model"), m.group("url")
    cfg: dict[str, Any] = {"type": kind, "name": f"{kind}-{model}", "model": model}
    if url:
        cfg["base_url"] = url
    if kind in ("openai", "anthropic"):
        var = "OPENAI_API_KEY" if kind == "openai" else "ANTHROPIC_API_KEY"
        key = os.environ.get(var)
        if key:
            cfg["api_key"] = key
        elif not url:
            raise ConfigError(f"{var} is not set (needed for {spec})")
    return cfg


def resolve_target_spec(spec: str | dict[str, Any]) -> dict[str, Any]:
    """Accept a mapping, a ``demo:`` shorthand or a ``provider:model`` shorthand."""
    if isinstance(spec, dict):
        return spec
    if spec.startswith("demo"):
        return demo_target(spec)
    return model_target(spec)


def looks_like_shorthand(spec: str) -> bool:
    return (spec.startswith("demo") and DEMO_SHORTHAND.match(spec) is not None) or bool(
        MODEL_SHORTHAND.match(spec)
    )


def load_config(source: str | Path) -> LoadedConfig:
    """Load a scan config from a YAML file, or a ``demo:...`` / ``ollama:MODEL`` shorthand."""
    if isinstance(source, str) and looks_like_shorthand(source):
        return LoadedConfig(parse_target(resolve_target_spec(source)), ScanConfig())
    path = Path(source)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    raw = interpolate_env(raw)
    if "target" in raw:
        target_raw = raw["target"]
        scan_raw = raw.get("scan", {})
        unknown = set(raw) - {"target", "scan"}
        if unknown:
            raise ConfigError(
                f"{path}: unknown top-level keys {sorted(unknown)} (use `target:` and `scan:`)"
            )
    elif "type" in raw:
        target_raw, scan_raw = raw, {}
    else:
        raise ConfigError(f"{path}: no `target:` section (or top-level `type:`) found")
    target_raw = dict(resolve_target_spec(target_raw))
    spf = target_raw.pop("system_prompt_file", None)
    if spf:
        sp_path = (path.parent / spf).resolve()
        if not sp_path.is_file():
            raise ConfigError(f"{path}: system_prompt_file not found: {sp_path}")
        target_raw["system_prompt"] = sp_path.read_text(encoding="utf-8")
    try:
        target = parse_target(target_raw)
        scan = ScanConfig.model_validate(scan_raw or {})
    except Exception as exc:
        raise ConfigError(f"{path}: {_fmt_error(exc)}") from exc
    return LoadedConfig(target, scan, path)


def _fmt_error(exc: Exception) -> str:
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
    return str(exc)


def ensure_canaries(target: TargetBase) -> dict[str, str]:
    """Canaries for a run. If the scanner supplies the system prompt and it references
    ``{{canary}}`` but none is configured, generate a fresh random one."""
    canaries = dict(target.canaries)
    if not canaries and target.system_prompt and "{{canary" in target.system_prompt:
        canaries["canary"] = f"CANARY-{secrets.token_hex(6)}"
    return canaries
