"""Everything a detector needs to know about one attack attempt."""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.models import Message, ToolCall
from scanner.probes import Probe


@dataclass
class DetectionContext:
    probe: Probe
    response_text: str  # the assistant response being judged
    transcript: list[Message] = field(default_factory=list)  # conversation up to and incl. response
    tool_calls: list[ToolCall] = field(default_factory=list)
    canaries: dict[str, str] = field(default_factory=dict)
    system_prompt: str | None = None  # prompt we supplied (raw model endpoints)
    system_prompt_fragments: list[str] = field(default_factory=list)  # known app prompt fragments
    known_sensitive: list[str] = field(default_factory=list)  # seeded values that must not leak
    variables: dict[str, str] = field(default_factory=dict)  # nonce / marker / canary_* ...
    turn: int | None = None  # index of the assistant turn (multi-turn)

    @property
    def user_text(self) -> str:
        """All user/system-authored text in the conversation (for echo suppression)."""
        return "\n".join(m.content for m in self.transcript if m.role in ("user", "system"))
