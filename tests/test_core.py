"""Templating, JSONPath, taxonomy, scoring and the probe library itself."""

from __future__ import annotations

import json
import re

import pytest
import yaml

from scanner.connectors.jsonpath import MISSING, as_text, extract
from scanner.models import AttemptResult, Category, Severity, Status
from scanner.probes import (
    Probe,
    ProbeLoadError,
    ProbeSelection,
    lint_probe,
    load_probes,
    parse_probe,
    select_probes,
)
from scanner.scoring import band_for, score, wilson_interval
from scanner.taxonomy import ATLAS_TECHNIQUES, CATEGORIES, OWASP_LLM_TOP10, default_remediation
from scanner.templating import TemplateError, make_variables, render

# ------------------------------------------------------------------------ templating


def test_render_substitutes_and_filters():
    v = make_variables(
        probe_id="PI-001", mutator="none", repeat=0, seed=1, canaries={"system": "CANARY-abc"}
    )
    assert (
        render("{{ marker }} / {{marker_head}}{{marker_tail}}", v)
        == f"{v['marker']} / {v['marker']}"
    )
    assert render("{{marker|upper}}", v) == v["marker"].upper()
    assert render("{{marker|b64}}", v) != v["marker"]
    assert v["canary"] == "CANARY-abc" and v["canary_system"] == "CANARY-abc"


def test_render_unknown_variable_and_filter():
    with pytest.raises(TemplateError):
        render("{{nope}}", {})
    with pytest.raises(TemplateError):
        render("{{marker|evil}}", {"marker": "x"})
    assert render("{{nope}}", {}, strict=False) == "{{nope}}"


def test_render_is_not_a_template_engine():
    # Jinja-style expressions are not evaluated, so probe files cannot execute code.
    assert render("{{7*7}} {{ config }}", {"config": "X"}) == "{{7*7}} X"
    assert (
        render("{% for i in range(3) %}x{% endfor %}", {}) == "{% for i in range(3) %}x{% endfor %}"
    )
    assert render(r"\{{config}}", {"config": "X"}) == "{{config}}"


def test_nonce_is_deterministic_per_seed_and_unique_per_attempt():
    a = make_variables(probe_id="PI-001", mutator="none", repeat=0, seed=5)
    b = make_variables(probe_id="PI-001", mutator="none", repeat=0, seed=5)
    c = make_variables(probe_id="PI-001", mutator="none", repeat=1, seed=5)
    d = make_variables(probe_id="PI-001", mutator="none", repeat=0, seed=None)
    assert a["nonce"] == b["nonce"] != c["nonce"]
    assert len(d["nonce"]) == 8


# -------------------------------------------------------------------------- jsonpath


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("$.reply", "hi"),
        ("reply", "hi"),
        ("$.choices[0].message.content", "yo"),
        ("$['odd key']", "spaced"),
        ("$.items[-1]", 3),
        ("$.items[*]", [1, 2, 3]),
        ("$.nested.a.b", 7),
    ],
)
def test_jsonpath(path, expected):
    doc = {
        "reply": "hi",
        "choices": [{"message": {"content": "yo"}}],
        "odd key": "spaced",
        "items": [1, 2, 3],
        "nested": {"a": {"b": 7}},
    }
    assert extract(doc, path) == expected


def test_jsonpath_missing_and_text():
    assert extract({}, "$.a", default=None) is None
    with pytest.raises(KeyError):
        extract({}, "$.a")
    assert extract({"a": 1}, "$.b", default=MISSING) is MISSING
    assert as_text(["a", "b"]) == "a\nb" and as_text(None) == "" and as_text({"k": 1}) == '{"k": 1}'


# -------------------------------------------------------------------------- taxonomy


def test_taxonomy_ids_are_well_formed():
    assert set(OWASP_LLM_TOP10) == {f"LLM{i:02d}" for i in range(1, 11)}
    assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", t) for t in ATLAS_TECHNIQUES)
    for info in CATEGORIES.values():
        assert set(info.owasp) <= set(OWASP_LLM_TOP10)
        assert set(info.atlas) <= set(ATLAS_TECHNIQUES)
        assert info.remediation.steps and default_remediation(info.key)


# ------------------------------------------------------------------- probe library


def test_library_size_and_shape(probes):
    assert 50 <= len(probes) <= 100
    assert len({p.id for p in probes}) == len(probes)
    assert {p.category for p in probes} == set(Category)
    kinds = {p.kind for p in probes}
    assert {"single", "scripted", "indirect", "adaptive"} <= kinds


def test_every_probe_is_tagged_and_lint_clean(probes):
    for p in probes:
        assert p.owasp and p.atlas, p.id
        assert set(p.owasp) <= set(OWASP_LLM_TOP10) and set(p.atlas) <= set(ATLAS_TECHNIQUES)
        assert lint_probe(p) == [], (p.id, lint_probe(p))
        assert p.description.strip(), p.id


def test_probe_ids_match_category_prefix(probes):
    prefix = {
        Category.PROMPT_INJECTION: "PI",
        Category.INDIRECT_INJECTION: "II",
        Category.JAILBREAK: "JB",
        Category.SYSTEM_PROMPT_EXTRACTION: "SP",
        Category.SENSITIVE_DATA_LEAKAGE: "DL",
        Category.INSECURE_OUTPUT_HANDLING: "OH",
        Category.EXCESSIVE_AGENCY: "EA",
    }
    for p in probes:
        # II-014 / SP-008 style cross-category probes are allowed only when documented
        if p.id.split("-")[0] != prefix[p.category]:
            pytest.fail(f"{p.id} lives in {p.category}")


def test_every_probe_renders_without_error(probes):
    v = make_variables(
        probe_id="X-000", mutator="none", repeat=0, seed=0, canaries={"system": "CANARY-1"}
    )
    for p in probes:
        plan = p.plan(v, can_ingest=True)
        if p.kind != "adaptive":
            assert plan.turns and all(t.content.strip() for t in plan.turns), p.id
        assert "{{" not in "".join(t.content for t in plan.turns).replace("{{7*7}}", ""), p.id


def test_marker_probes_are_echo_safe(probes):
    """A refusal that merely quotes the prompt must not contain the full marker."""
    v = make_variables(probe_id="X-000", mutator="none", repeat=0, seed=0)
    for p in probes:
        if p.kind == "adaptive":
            continue
        prompt = "\n".join(t.content for t in p.plan(v).turns)
        assert v["marker"] not in prompt, f"{p.id} leaks the full marker in its prompt"


def test_probe_json_schema_is_committed_and_current():
    from pathlib import Path

    committed = json.loads(Path("probes/probe.schema.json").read_text())
    assert committed == Probe.model_json_schema(), (
        "regenerate with: llmscan probes schema > probes/probe.schema.json"
    )


def test_loader_reports_every_bad_file(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "id: PI-901\nname: x\ncategory: nope\nseverity: high\nprompt: hi\nsuccess_criteria: {rules: [{type: canary}]}\n"
    )
    (tmp_path / "b.yaml").write_text("id: not-an-id\n")
    (tmp_path / "c.yaml").write_text("- just a list\n")
    with pytest.raises(ProbeLoadError) as exc:
        load_probes(tmp_path)
    assert len(exc.value.errors) == 3


def test_loader_rejects_duplicates_and_unknown_fields(tmp_path):
    good = "id: PI-900\nname: n\ncategory: prompt_injection\nseverity: low\nprompt: hi\nsuccess_criteria: {rules: [{type: canary}]}\n"
    (tmp_path / "a.yaml").write_text(good)
    (tmp_path / "b.yaml").write_text(good)
    with pytest.raises(ProbeLoadError, match="duplicate"):
        load_probes(tmp_path)
    (tmp_path / "b.yaml").write_text(good.replace("id: PI-900", "id: PI-902") + "surprise: 1\n")
    with pytest.raises(ProbeLoadError, match=r"surprise|Extra"):
        load_probes(tmp_path)


def test_probe_validation_rules():
    base = {
        "id": "PI-950",
        "name": "n",
        "category": "prompt_injection",
        "severity": "low",
        "success_criteria": {"rules": [{"type": "canary"}]},
    }
    with pytest.raises(ValueError, match="exactly one"):
        parse_probe({**base})
    with pytest.raises(ValueError, match="exactly one"):
        parse_probe({**base, "prompt": "a", "turns": [{"role": "user", "content": "b"}]})
    with pytest.raises(ValueError, match="unknown template variable"):
        parse_probe({**base, "prompt": "hello {{typo}}"})
    with pytest.raises(ValueError, match="ATLAS"):
        parse_probe({**base, "prompt": "a", "atlas": ["AML.T9999"]})
    with pytest.raises(ValueError, match="OWASP"):
        parse_probe({**base, "prompt": "a", "owasp": ["LLM99"]})
    with pytest.raises(ValueError, match="tool_call"):
        parse_probe({**base, "prompt": "a", "success_criteria": {"rules": [{"type": "tool_call"}]}})
    with pytest.raises(ValueError, match="invalid regex"):
        parse_probe(
            {
                **base,
                "prompt": "a",
                "success_criteria": {"rules": [{"type": "regex", "pattern": "("}]},
            }
        )
    p = parse_probe({**base, "prompt": "a"})
    assert p.owasp == ["LLM01"] and p.atlas  # inherited from the category defaults


def test_selection_filters(probes):
    crit = select_probes(probes, ProbeSelection(min_severity=Severity.CRITICAL))
    assert crit and all(p.severity is Severity.CRITICAL for p in crit)
    ea = select_probes(probes, ProbeSelection(categories=[Category.EXCESSIVE_AGENCY]))
    assert all(p.category is Category.EXCESSIVE_AGENCY for p in ea)
    assert [p.id for p in select_probes(probes, ProbeSelection(ids=["PI-001"]))] == ["PI-001"]
    assert "PI-001" not in [
        p.id for p in select_probes(probes, ProbeSelection(exclude_ids=["PI-001"]))
    ]
    assert len(select_probes(probes, ProbeSelection(max_probes=5))) == 5
    assert all(
        "encoding" in p.tags for p in select_probes(probes, ProbeSelection(tags=["encoding"]))
    )


def test_probe_yaml_files_are_plain_data():
    """No YAML tags / python objects: files load with safe_load only."""
    from pathlib import Path

    for f in Path("probes").rglob("*.yaml"):
        text = f.read_text()
        assert "!!python" not in text, f
        yaml.safe_load(text)


# ---------------------------------------------------------------------------- scoring


def _r(
    sev: Severity, status: Status, cat=Category.PROMPT_INJECTION, mutator="none"
) -> AttemptResult:
    return AttemptResult(
        probe_id="PI-001",
        probe_name="p",
        category=cat,
        severity=sev,
        status=status,
        mutator=mutator,
        owasp=["LLM01"],
    )


def test_wilson_interval_properties():
    assert wilson_interval(0, 0) == (0.0, 0.0)
    lo, hi = wilson_interval(5, 10)
    assert lo < 0.5 < hi
    lo0, hi0 = wilson_interval(0, 10)
    assert lo0 == 0.0 and hi0 > 0
    assert wilson_interval(50, 100)[1] - wilson_interval(50, 100)[0] < hi - lo


def test_score_excludes_errors_and_inconclusive_from_asr():
    card = score(
        [
            _r(Severity.HIGH, Status.FAIL),
            _r(Severity.HIGH, Status.PASS),
            _r(Severity.HIGH, Status.ERROR),
            _r(Severity.HIGH, Status.INCONCLUSIVE),
        ]
    )
    assert (card.failed, card.passed, card.errors, card.inconclusive, card.total) == (1, 1, 1, 1, 4)
    assert card.asr == 0.5


def test_score_severity_weighting_and_floor():
    # 1 critical failure among 99 passing low probes: weighted ASR is tiny, yet risk must not be "low"
    results = [_r(Severity.LOW, Status.PASS) for _ in range(99)] + [
        _r(Severity.CRITICAL, Status.FAIL)
    ]
    card = score(results)
    assert card.weighted_asr < 0.05
    assert card.risk_score == 60.0 and card.grade == "D"
    assert card.highest_severity_failed is Severity.CRITICAL


def test_score_all_pass_and_all_fail():
    assert score([_r(Severity.HIGH, Status.PASS)] * 5).risk_score == 0.0
    all_fail = score([_r(s, Status.FAIL) for s in Severity])
    assert all_fail.risk_score == 100.0 and all_fail.grade == "F"
    assert score([]).risk_score == 0.0


def test_score_breakdowns():
    card = score(
        [
            _r(Severity.HIGH, Status.FAIL, mutator="base64"),
            _r(Severity.HIGH, Status.PASS, mutator="base64"),
            _r(Severity.LOW, Status.PASS, Category.JAILBREAK),
        ]
    )
    assert card.categories["prompt_injection"].asr == 0.5
    assert card.categories["jailbreak"].asr == 0.0
    assert card.mutators["base64"].asr == 0.5
    assert card.owasp["LLM01"].total == 3 and card.owasp["LLM01"].failed == 1
    assert card.severities["high"].total == 2


@pytest.mark.parametrize(
    ("risk", "grade"),
    [
        (0, "A"),
        (9.9, "A"),
        (10, "B"),
        (24, "B"),
        (25, "C"),
        (49, "C"),
        (50, "D"),
        (74, "D"),
        (75, "F"),
        (100, "F"),
    ],
)
def test_bands(risk, grade):
    assert band_for(risk)[0] == grade
