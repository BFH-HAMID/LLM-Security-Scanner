"""Character-level obfuscation: leetspeak, homoglyphs, zero-width characters, letter spacing."""

from __future__ import annotations

import random
import re

from scanner.mutators.base import Mutator, map_unprotected

_LEET = str.maketrans(
    {
        "a": "4",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "5",
        "t": "7",
        "A": "4",
        "E": "3",
        "I": "1",
        "O": "0",
        "S": "5",
        "T": "7",
    }
)

# Latin -> visually identical Cyrillic / Greek
_HOMOGLYPHS = str.maketrans(
    {
        "a": "а",
        "e": "е",
        "o": "о",
        "p": "р",
        "c": "с",
        "x": "х",
        "y": "у",
        "i": "і",
        "s": "ѕ",
        "A": "А",
        "E": "Е",
        "O": "О",
        "P": "Р",
        "C": "С",
        "X": "Х",
        "B": "В",
        "H": "Н",
        "K": "К",
        "M": "М",
        "T": "Т",
    }
)
ZWSP = "\u200b"


class LeetspeakMutator(Mutator):
    name = "leetspeak"
    description = "Replace letters with look-alike digits (a→4, e→3, i→1, o→0, s→5, t→7)."

    def transform(self, text: str, rng: random.Random) -> str:
        return map_unprotected(text, lambda s: s.translate(_LEET))


class HomoglyphMutator(Mutator):
    name = "homoglyph"
    description = "Swap Latin letters for identical-looking Cyrillic/Greek characters."

    def transform(self, text: str, rng: random.Random) -> str:
        return map_unprotected(text, lambda s: s.translate(_HOMOGLYPHS))


class ZeroWidthMutator(Mutator):
    name = "zero_width"
    description = "Insert zero-width spaces inside words so keyword filters no longer match."

    def transform(self, text: str, rng: random.Random) -> str:
        def fn(s: str) -> str:
            return re.sub(r"[A-Za-z]{4,}", lambda m: ZWSP.join(m.group(0)), s)

        return map_unprotected(text, fn)


class CharSpacingMutator(Mutator):
    name = "char_spacing"
    description = "Space out the letters of every word (i g n o r e)."

    def transform(self, text: str, rng: random.Random) -> str:
        def fn(segment: str) -> str:
            # letters of a word are separated by one space, words by three
            out = []
            for part in re.split(r"(\s+)", segment):
                if part.isspace():
                    out.append("   ")
                elif len(part) >= 3 and any(c.isalpha() for c in part):
                    out.append(re.sub(r"[A-Za-z]", lambda m: m.group(0) + " ", part).rstrip())
                else:
                    out.append(part)
            return "".join(out)

        return map_unprotected(text, fn)
