"""Pydantic models describing a scan target (what to attack and how to talk to it)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthConfig(_Cfg):
    """How to authenticate against a custom HTTP target."""

    type: Literal["none", "bearer", "basic", "header"] = "none"
    token: str | None = None  # bearer
    username: str | None = None  # basic
    password: str | None = None
    header: str | None = None  # header name for type=header
    value: str | None = None


class IngestConfig(_Cfg):
    """Optional RAG ingestion endpoint used by indirect-injection probes."""

    url: str
    method: Literal["POST", "PUT"] = "POST"
    body: Any = Field(default_factory=lambda: {"title": "{{title}}", "content": "{{content}}"})
    headers: dict[str, str] = Field(default_factory=dict)
    id_path: str | None = None  # JSONPath to the created document id
    delete_url: str | None = None  # may contain {{document_id}}
    delete_method: Literal["DELETE", "POST"] = "DELETE"


class TargetBase(_Cfg):
    name: str = "target"
    description: str = ""
    # Planted secrets: a list, or a mapping of name -> value. Names are used in probe rules.
    canaries: dict[str, str] = Field(default_factory=dict)
    # Test-time system prompt for raw model endpoints (templated with {{canary}}).
    system_prompt: str | None = None
    system_prompt_file: str | None = None  # resolved by the config loader
    # Known fragments of your (app's) real system prompt, used to detect leakage.
    system_prompt_fragments: list[str] = Field(default_factory=list)
    # Values you seeded in test data that must never appear in a response (PII, secrets, ...).
    known_sensitive: list[str] = Field(default_factory=list)
    timeout: float = Field(60.0, gt=0)
    max_response_chars: int = Field(20_000, ge=100)

    @field_validator("canaries", mode="before")
    @classmethod
    def _canaries(cls, v: Any) -> Any:
        if v is None:
            return {}
        if isinstance(v, (list, tuple)):
            return {("canary" if i == 0 else f"canary_{i + 1}"): str(x) for i, x in enumerate(v)}
        if isinstance(v, str):
            return {"canary": v}
        return v


class HTTPTarget(TargetBase):
    """Any HTTP chat endpoint, described by a request template."""

    type: Literal["http"]
    url: str
    method: Literal["POST", "PUT", "PATCH", "GET"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    auth: AuthConfig | None = None
    # JSON body template. Placeholders: {{prompt}} {{messages}} {{system}} {{conversation_id}} {{tools}}
    body: Any = Field(default_factory=lambda: {"message": "{{prompt}}"})
    body_format: Literal["json", "form", "text"] = "json"
    response_format: Literal["json", "text", "sse"] = "json"
    response_path: str = "$"  # JSONPath of the reply text
    tool_calls_path: str | None = None
    conversation_id_path: str | None = None  # capture a server-issued conversation id
    verify_tls: bool = True
    ingest: IngestConfig | None = None

    @property
    def sends_history(self) -> bool:
        return "messages" in _flatten_placeholders(self.body) or "history" in _flatten_placeholders(
            self.body
        )


class OpenAITarget(TargetBase):
    """OpenAI or any OpenAI-compatible server (vLLM, LM Studio, Ollama /v1, Together, Groq, ...)."""

    type: Literal["openai"]
    base_url: str = "https://api.openai.com/v1"
    api_key: str | None = None
    model: str
    temperature: float | None = None
    max_tokens: int | None = 512
    max_tokens_param: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    headers: dict[str, str] = Field(default_factory=dict)
    extra_body: dict[str, Any] = Field(default_factory=dict)
    verify_tls: bool = True


class AnthropicTarget(TargetBase):
    type: Literal["anthropic"]
    base_url: str = "https://api.anthropic.com"
    api_key: str | None = None
    model: str
    max_tokens: int = 1024
    temperature: float | None = None
    anthropic_version: str = "2023-06-01"
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True


class OllamaTarget(TargetBase):
    type: Literal["ollama"]
    base_url: str = "http://localhost:11434"
    model: str
    options: dict[str, Any] = Field(default_factory=dict)
    timeout: float = Field(120.0, gt=0)
    verify_tls: bool = True


class DemoTarget(TargetBase):
    """The built-in deliberately vulnerable app, run in-process (no server needed)."""

    type: Literal["demo"]
    level: Literal["weak", "medium", "hardened"] = "weak"
    surface: Literal["chat", "rag", "agent"] = "chat"


TargetConfig = Annotated[
    HTTPTarget | OpenAITarget | AnthropicTarget | OllamaTarget | DemoTarget,
    Field(discriminator="type"),
]

_TYPE_ALIASES = {
    "openai_compat": "openai",
    "openai-compatible": "openai",
    "openai_compatible": "openai",
}


def _flatten_placeholders(obj: Any) -> set[str]:
    from scanner.templating import find_variables

    found: set[str] = set()
    if isinstance(obj, str):
        found |= find_variables(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            found |= _flatten_placeholders(v)
    elif isinstance(obj, list):
        for v in obj:
            found |= _flatten_placeholders(v)
    return found


def parse_target(data: dict[str, Any] | TargetBase) -> TargetBase:
    """Validate a target mapping into the right config class."""
    from pydantic import TypeAdapter

    if isinstance(data, TargetBase):
        return data
    data = dict(data)
    t = str(data.get("type", "")).lower()
    data["type"] = _TYPE_ALIASES.get(t, t)
    return TypeAdapter(TargetConfig).validate_python(data)


def canary_variables(canaries: dict[str, str]) -> dict[str, str]:
    """Template variables for canaries: ``canary`` (first) and ``canary_<name>`` for each."""
    out: dict[str, str] = {}
    for i, (name, value) in enumerate(canaries.items()):
        if i == 0:
            out["canary"] = value
        out[f"canary_{name}"] = value
    out.setdefault("canary", "")
    return out
