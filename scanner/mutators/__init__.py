"""Mutators: transform attack payloads (encodings, obfuscation, framing, language switching)."""

from __future__ import annotations

from scanner.mutators.base import ChainMutator, Mutator, map_unprotected
from scanner.mutators.encoding import Base64Mutator, HexMutator, ReverseMutator, Rot13Mutator
from scanner.mutators.language import TranslateMutator
from scanner.mutators.obfuscation import (
    CharSpacingMutator,
    HomoglyphMutator,
    LeetspeakMutator,
    ZeroWidthMutator,
)
from scanner.mutators.structure import (
    ManyShotMutator,
    PayloadSplitMutator,
    PrefixInjectionMutator,
    RefusalSuppressionMutator,
    RoleplayMutator,
    RoleSpoofMutator,
)

REGISTRY: dict[str, type[Mutator]] = {
    cls.name: cls
    for cls in (
        Base64Mutator,
        Rot13Mutator,
        HexMutator,
        ReverseMutator,
        LeetspeakMutator,
        HomoglyphMutator,
        ZeroWidthMutator,
        CharSpacingMutator,
        PayloadSplitMutator,
        TranslateMutator,
        RoleplayMutator,
        RoleSpoofMutator,
        PrefixInjectionMutator,
        RefusalSuppressionMutator,
        ManyShotMutator,
    )
}

# Sensible default when the user asks for "all" mutators.
DEFAULT_SET = list(REGISTRY)


class UnknownMutatorError(ValueError):
    pass


def get_mutator(name: str, **kwargs: object) -> Mutator:
    """Instantiate a mutator by name. ``a+b`` builds a chain (a first)."""
    name = name.strip().lower()
    if "+" in name:
        return ChainMutator([get_mutator(part, **kwargs) for part in name.split("+")])
    cls = REGISTRY.get(name)
    if cls is None:
        raise UnknownMutatorError(
            f"unknown mutator {name!r}. Available: {', '.join(sorted(REGISTRY))}"
        )
    if cls is TranslateMutator:
        return TranslateMutator(**{k: v for k, v in kwargs.items() if k in ("llm", "languages")})  # type: ignore[arg-type]
    return cls()


def resolve_mutators(names: list[str] | str | None, **kwargs: object) -> list[Mutator]:
    if not names:
        return []
    if isinstance(names, str):
        names = DEFAULT_SET if names == "all" else [n for n in names.split(",") if n.strip()]
    if len(names) == 1 and names[0] == "all":
        names = DEFAULT_SET
    return [get_mutator(n, **kwargs) for n in names]


__all__ = [
    "DEFAULT_SET",
    "REGISTRY",
    "ChainMutator",
    "Mutator",
    "UnknownMutatorError",
    "get_mutator",
    "map_unprotected",
    "resolve_mutators",
]
