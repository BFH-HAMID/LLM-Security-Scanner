"""Mutator interface: transform an attack payload to evade naive defences.

Mutators wrap or obfuscate the *attack text* of a probe. Character-level mutators leave quoted
strings, URLs, e-mail addresses and marker/nonce tokens untouched so success markers stay exact.
"""

from __future__ import annotations

import random
import re
from abc import ABC, abstractmethod
from collections.abc import Callable

# Spans character-level mutators must not touch.
PROTECTED = re.compile(
    r"""(
        "[^"\n]{1,200}" | (?<![\w])'[^'\n]{1,200}'(?![\w]) | `[^`\n]{1,200}` | “[^”\n]{1,200}”
        | https?://\S+ | [\w.+-]+@[\w-]+\.[\w.-]+
        | \b[A-Za-z]+-[0-9a-f]{6,}\b | \b[0-9a-f]{8,}\b
    )""",
    re.VERBOSE,
)


def map_unprotected(text: str, fn: Callable[[str], str]) -> str:
    """Apply ``fn`` to the parts of ``text`` outside protected spans."""
    parts = PROTECTED.split(text)
    return "".join(fn(p) if i % 2 == 0 else p for i, p in enumerate(parts))


class Mutator(ABC):
    name: str = "mutator"
    description: str = ""
    atlas: tuple[str, ...] = ("AML.T0068",)  # LLM Prompt Obfuscation

    @abstractmethod
    def transform(self, text: str, rng: random.Random) -> str: ...

    async def mutate(self, text: str, rng: random.Random) -> str:
        return self.transform(text, rng)

    def __repr__(self) -> str:
        return f"<Mutator {self.name}>"


class ChainMutator(Mutator):
    """Apply several mutators left to right (``a+b`` = ``b(a(text))``)."""

    def __init__(self, parts: list[Mutator]):
        self.parts = parts
        self.name = "+".join(p.name for p in parts)
        self.description = " then ".join(p.name for p in parts)

    def transform(self, text: str, rng: random.Random) -> str:  # pragma: no cover - async only
        for p in self.parts:
            text = p.transform(text, rng)
        return text

    async def mutate(self, text: str, rng: random.Random) -> str:
        for p in self.parts:
            text = await p.mutate(text, rng)
        return text
