"""Canary-token detection that survives encoding tricks.

A canary is a unique secret planted in a system prompt / document / database. Seeing it in a
response proves that hidden data crossed a trust boundary. Attackers ask the model to *encode*
its output to slip past exact-match filters, so we look for the canary in every common
encoding: base64, hex, ROT13, reversed, URL-encoded, HTML-entity-encoded, letter-spaced,
zero-width-interleaved and Unicode-homoglyph forms.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

_ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"), None)
_TAGS = re.compile("[\U000e0020-\U000e007e]")
_SEP = re.compile(r"[\s\-_.:|/\\*·•]+")

_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "ј": "j",
        "ԁ": "d",
        "һ": "h",
        "ο": "o",
        "α": "a",
        "ρ": "p",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ι": "I",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
    }
)


def normalise(text: str) -> str:
    text = _TAGS.sub(lambda m: chr(ord(m.group(0)) - 0xE0000), text)
    text = unicodedata.normalize("NFKC", text).translate(_ZW)
    return text.translate(_CONFUSABLES)


def _squash(text: str) -> str:
    return _SEP.sub("", text).lower()


def _b64_segments(text: str) -> list[str]:
    out: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/_\-]{12,}={0,2}", text):
        for altchars in (None, b"-_"):
            try:
                raw = base64.b64decode(
                    token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4)
                    if altchars
                    else token + "=" * (-len(token) % 4)
                )
            except (binascii.Error, ValueError):
                continue
            out.append(raw.decode("utf-8", "ignore"))
            break
    return out


def _hex_segments(text: str) -> list[str]:
    out: list[str] = []
    for token in re.findall(r"(?:[0-9a-fA-F]{2}[\s:,]?){8,}", text):
        try:
            out.append(bytes.fromhex(re.sub(r"[\s:,]", "", token)).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return out


def readings(text: str) -> list[tuple[str, str]]:
    """Every alternative reading of ``text`` in which a canary might be visible."""
    base = normalise(text)
    out: list[tuple[str, str]] = [("plain", text)]
    if base != text:
        out.append(("unicode-normalised", base))
    unq = urllib.parse.unquote(base)
    if unq != base:
        out.append(("url-encoded", unq))
    unesc = html.unescape(base)
    if unesc != base:
        out.append(("html-entity-encoded", unesc))
    out.append(("rot13", codecs.decode(base, "rot13")))
    out.append(("reversed", base[::-1]))
    out.extend(("base64", seg) for seg in _b64_segments(base))
    out.extend(("hex", seg) for seg in _hex_segments(base))
    return out


@dataclass
class CanaryHit:
    name: str
    form: str  # plain / spaced / base64 / ...
    snippet: str
    start: int | None = None
    end: int | None = None


def find_canaries(text: str, canaries: dict[str, str], *, decode: bool = True) -> list[CanaryHit]:
    """Find planted canaries in ``text``.

    Returns one hit per (canary, form); the verbatim (``plain``) form is always checked first.
    With ``decode`` the response is also searched in every encoding listed in the module doc.
    """
    hits: list[CanaryHit] = []
    if not text or not canaries:
        return hits
    low = text.lower()
    plain: set[str] = set()
    for name, value in canaries.items():
        if value and (idx := low.find(value.lower())) != -1:
            plain.add(name)
            hits.append(
                CanaryHit(name, "plain", text[idx : idx + len(value)], idx, idx + len(value))
            )
    if not decode:
        return hits
    seen: set[tuple[str, str]] = set()
    for label, reading in readings(text):
        reading_low = reading.lower()
        squashed = _squash(reading)
        for name, value in canaries.items():
            if not value:
                continue
            if label == "plain":
                if name in plain or _squash(value) not in squashed:
                    continue
                form = "separated"  # e.g. "C A N A R Y - 7 f 3 a ..." or zero-width interleaved
            elif value.lower() in reading_low or _squash(value) in squashed:
                form = label
            else:
                continue
            if (name, form) in seen:
                continue
            seen.add((name, form))
            hits.append(CanaryHit(name, form, _context(reading, value)))
    return hits


def _context(reading: str, value: str) -> str:
    low = reading.lower()
    i = low.find(value.lower())
    if i == -1:
        return value
    return reading[max(0, i - 20) : i + len(value) + 20].strip()
