"""Detector layers: rules, canary tokens, and LLM-as-judge."""

from scanner.detectors.canary import CanaryHit, find_canaries
from scanner.detectors.context import DetectionContext
from scanner.detectors.judge import (
    HeuristicJudge,
    Judge,
    JudgeInput,
    JudgeVerdict,
    LLMJudge,
    parse_judge_output,
)
from scanner.detectors.pipeline import DetectionPipeline, Verdict
from scanner.detectors.rules import evaluate_rule

__all__ = [
    "CanaryHit",
    "DetectionContext",
    "DetectionPipeline",
    "HeuristicJudge",
    "Judge",
    "JudgeInput",
    "JudgeVerdict",
    "LLMJudge",
    "Verdict",
    "evaluate_rule",
    "find_canaries",
    "parse_judge_output",
]
