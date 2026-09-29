"""Policy tests for the probe library (docs/ETHICS.md): probes test control, never solicit harm.

They also guard the "every finding is mapped and actionable" promise, so a contributed probe that
skips its OWASP / ATLAS tags or its remediation text fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from scanner.probes import Probe, default_probes_dir
from scanner.taxonomy import ATLAS_TECHNIQUES
from scanner.taxonomy import OWASP_LLM_TOP10 as OWASP_LLM

PROBE_DIR = default_probes_dir()
FILES = sorted(PROBE_DIR.glob("*/*.yaml"))

# Topics no probe may ask a model about. Probes steer behaviour towards harmless markers and planted
# canaries; they must never need real harmful content to demonstrate a weakness.
FORBIDDEN_TOPICS = re.compile(
    r"\b(bomb|explosive|napalm|nerve agent|bioweapon|chemical weapon|malware|ransomware|keylogger|"
    r"zero-day|suicide|self-harm|child (abuse|porn)|csam|how to (make|build|hack|kill|synthesi[sz]e)|"
    r"synthesi[sz]e (a |the )?(drug|poison)|meth(amphetamine)?)\b",
    re.I,
)
TRUSTED_REFERENCE_HOSTS = (
    "arxiv.org",
    "genai.owasp.org",
    "owasp.org",
    "anthropic.com",
    "atlas.mitre.org",
    "github.com",
)
# Payload URLs must be inert: reserved documentation domains, loopback, or the cloud metadata address
# (the SSRF probes make a model *write* it; nothing ever fetches it).
INERT_HOSTS = re.compile(
    r"(\.example|\.test|\.invalid|^localhost|^127\.0\.0\.1|^169\.254\.169\.254)$"
)


def test_the_library_is_where_we_expect_it():
    assert len(FILES) >= 80


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_probe_solicits_harmful_content(path: Path):
    match = FORBIDDEN_TOPICS.search(path.read_text(encoding="utf-8"))
    assert match is None, f"{path.name}: forbidden topic {match.group(0)!r}; see docs/ETHICS.md"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_url_is_either_a_trusted_reference_or_an_inert_payload(path: Path):
    text = path.read_text(encoding="utf-8")
    refs = re.findall(r"^\s*-\s+(https?://\S+)\s*$", text, re.M)  # the `references:` list
    for url in refs:
        assert url.startswith("https://"), url
        host = urlparse(url).hostname or ""
        assert host.endswith(TRUSTED_REFERENCE_HOSTS), f"{path.name}: untrusted reference {url}"
    for url in set(re.findall(r"https?://[^\s\"'<>)\]]+", text)) - set(refs):
        host = (urlparse(url).hostname or "").lower()
        assert INERT_HOSTS.search(host), f"{path.name}: payload URL {url} points at a real host"


def test_every_probe_is_mapped_to_owasp_and_atlas_and_carries_remediation(probes: list[Probe]):
    assert len(probes) >= 80
    for p in probes:
        assert p.owasp and set(p.owasp) <= set(OWASP_LLM), f"{p.id}: bad OWASP tags {p.owasp}"
        assert p.atlas and set(p.atlas) <= set(ATLAS_TECHNIQUES), (
            f"{p.id}: unknown ATLAS ids {p.atlas}"
        )
        assert len(p.remediation_text.strip()) > 80, f"{p.id}: remediation is missing or too thin"
        assert p.description.strip(), f"{p.id}: needs a description"


def test_ids_are_unique_and_match_their_file_names(probes: list[Probe]):
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids))
    for p in probes:
        assert Path(p.source_file or "").name.lower().startswith(p.id.lower()), p.id


def test_the_library_covers_every_attack_family_in_the_spec(probes: list[Probe]):
    from collections import Counter

    per_category = Counter(p.category.value for p in probes)
    assert set(per_category) == {
        "prompt_injection",
        "indirect_injection",
        "jailbreak",
        "system_prompt_extraction",
        "sensitive_data_leakage",
        "insecure_output_handling",
        "excessive_agency",
    }
    assert all(n >= 10 for n in per_category.values()), per_category
    kinds = {p.kind for p in probes}
    assert {"single", "scripted", "adaptive", "indirect"} <= kinds, kinds
