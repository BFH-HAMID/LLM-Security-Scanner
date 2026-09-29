"""The judge-evaluation harness: metrics maths, abstention handling and dataset hygiene."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.detectors.judge import Judge, JudgeVerdict
from scanner.judge_eval import (
    Counts,
    LabeledExample,
    _finish,
    evaluate,
    format_evaluation,
    load_dataset,
    sample_from_report,
)

SEED = Path(__file__).resolve().parents[1] / "benchmarks" / "judge_eval" / "seed.jsonl"


class ScriptedJudge(Judge):
    """Returns pre-set verdicts keyed by response text."""

    name = "scripted"

    def __init__(self, table):
        self.table = table

    async def evaluate(self, inp):
        ok, conf = self.table[inp.response]
        return JudgeVerdict(succeeded=ok, confidence=conf, rationale="scripted")


def ex(i, response, label, category="jailbreak"):
    return LabeledExample(
        id=i, category=category, rubric="r", prompt="p", response=response, label=label
    )


def test_metric_maths():
    c = _finish(Counts(tp=8, fp=2, tn=85, fn=5))
    assert c.n == 100 and c.precision == 0.8 and c.recall == pytest.approx(8 / 13)
    assert c.f1 == pytest.approx(2 * 0.8 * (8 / 13) / (0.8 + 8 / 13)) and c.accuracy == 0.93
    assert c.false_positive_rate == pytest.approx(2 / 87)
    lo, hi = c.precision_ci
    assert lo < 0.8 < hi and lo >= 0 and hi <= 1
    empty = _finish(Counts())
    assert empty.precision is None and empty.recall is None and empty.f1 is None


async def test_confusion_matrix_thresholding_and_abstention():
    rows = [
        ex("a", "tp", True),
        ex("b", "fn", True),
        ex("c", "fp", False),
        ex("d", "tn", False),
        ex("e", "abstain", True),
        ex("f", "weak-yes", True, "sensitive_data_leakage"),
    ]
    judge = ScriptedJudge(
        {
            "tp": (True, 0.9),
            "fn": (False, 0.9),
            "fp": (True, 0.95),
            "tn": (False, 0.9),
            "abstain": (None, 0.0),
            "weak-yes": (True, 0.3),
        }
    )
    ev = await evaluate(rows, judge, "scripted", threshold=0.6)
    o = ev.overall
    assert (o.tp, o.fn, o.fp, o.tn, o.abstained) == (
        1,
        3,
        1,
        1,
        2,
    )  # abstentions and low-confidence 'yes' are misses, not hits
    assert o.precision == 0.5 and o.recall == 0.25
    assert ev.by_category["sensitive_data_leakage"].fn == 1 and ev.by_category["jailbreak"].tp == 1
    assert {d.id for d in ev.disagreements} == {"b", "c", "e", "f"}
    assert "precision" in format_evaluation(ev).lower()
    lenient = await evaluate(rows, judge, "scripted", threshold=0.2)
    assert lenient.overall.tp == 2


def test_dataset_loading_rules(tmp_path):
    good = tmp_path / "g.jsonl"
    good.write_text("# comment\n" + json.dumps(ex("a", "r", True).model_dump()) + "\n\n")
    assert len(load_dataset(good)) == 1
    unlabelled = tmp_path / "u.jsonl"
    unlabelled.write_text(json.dumps({**ex("a", "r", True).model_dump(), "label": None}) + "\n")
    with pytest.raises(ValueError, match="no label"):
        load_dataset(unlabelled)
    broken = tmp_path / "b.jsonl"
    broken.write_text("{not json}\n")
    with pytest.raises(ValueError, match=r"b\.jsonl:1"):
        load_dataset(broken)


def test_seed_dataset_is_balanced_unique_and_honestly_labelled():
    rows = load_dataset(SEED)
    assert len(rows) == 100 and len({r.id for r in rows}) == 100
    assert sum(bool(r.label) for r in rows) == 50
    assert {r.source for r in rows} == {"synthetic-seed"}  # never passed off as human labels
    assert len({r.category for r in rows}) >= 6
    assert all(r.response.strip() and r.rubric.strip() for r in rows)


async def test_offline_judge_never_cries_wolf_on_the_seed_set():
    from scanner.detectors.judge import HeuristicJudge

    ev = await evaluate(load_dataset(SEED), HeuristicJudge(), "heuristic")
    assert ev.overall.fp == 0 and ev.overall.precision in (None, 1.0)
    assert ev.overall.abstained >= 50  # documented: it abstains rather than guess


def test_sampling_from_a_report_is_reproducible(weak_report):
    a = sample_from_report(weak_report, n=30, seed=7)
    b = sample_from_report(weak_report, n=30, seed=7)
    assert [x.id for x in a] == [x.id for x in b] and len(a) == 30
    assert {x.label for x in a} == {None}
    assert (
        len({x.id for x in sample_from_report(weak_report, n=30, seed=8)} ^ {x.id for x in a}) > 0
    )
