"""Outcome-only reward for CodeGuarder retrieval training.

The retrieved security knowledge changes the rollout prompt; it is deliberately
not used by this scorer.  A rollout is rewarded only for the observed pass
rates of its functionality and security test cases.
"""

from __future__ import annotations

import os
import re
from typing import Any

from recipe.security_harness.execution_harness import unit_test_score


CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL)


def _security_weight() -> float:
    """Read and validate the relative weight of security test outcomes."""
    try:
        weight = float(os.getenv("OUTCOME_SECURITY_WEIGHT", "0.5"))
    except ValueError:
        weight = 0.5
    return min(1.0, max(0.0, weight))


def _candidate_code(solution_str: Any) -> str:
    """Use the last fenced block from the post-</think> answer, matching the
    generator-facing recipe convention. solution_str is the FULL decoded
    response including the <think>...</think> region (see
    verl/workers/reward_manager/naive.py's response_str), so searching the
    whole string would pick up an earlier draft fenced inside the reasoning
    region if the final answer happens not to re-fence its code. Restrict the
    search to text after the last </think> when the tag is present; fall
    back to the full string only for a response with no thinking region at
    all (e.g. a non-reasoning base model)."""
    if not isinstance(solution_str, str):
        return ""
    close_tag = "</think>"
    idx = solution_str.rfind(close_tag)
    answer_region = solution_str[idx + len(close_tag):] if idx != -1 else solution_str
    blocks = [block.strip() for block in CODE_BLOCK_RE.findall(answer_region) if block.strip()]
    return blocks[-1] if blocks else answer_region.strip()


def _result(
    score: float,
    *,
    functionality_passed: int = -1,
    functionality_total: int = -1,
    security_passed: float = -1.0,
    security_total: int = -1,
    functionality_score: float = 0.0,
    security_score: float = 0.0,
    reward_failure_reason: str = "",
) -> dict[str, Any]:
    """Return a stable, finite reward-extra-info schema for VeRL."""
    return {
        "score": float(score),
        "functionality_passed": int(functionality_passed),
        "functionality_total": int(functionality_total),
        "security_passed": float(security_passed),
        "security_total": int(security_total),
        "functionality_score": float(functionality_score),
        "security_score": float(security_score),
        "outcome_security_weight": _security_weight(),
        "reward_failure_reason": reward_failure_reason,
    }


def _compute_score_single(data_source: Any, solution_str: Any, ground_truth: Any, extra_info: Any = None) -> dict[str, Any]:
    """Score one rollout using only observed functionality/security outcomes."""
    del data_source
    candidate_code = _candidate_code(solution_str)
    ok, _unused_hybrid, func_passed, func_total, sec_passed, sec_total = unit_test_score(
        candidate_code, ground_truth, extra_info
    )
    if not ok:
        return _result(
            -1.0,
            functionality_passed=func_passed,
            functionality_total=func_total,
            security_passed=sec_passed,
            security_total=sec_total,
            reward_failure_reason="unittest_harness_failed",
        )

    # Both suites are required: silently rewarding a missing security suite
    # would turn this into a functionality-only recipe.
    if func_total <= 0 or sec_total <= 0:
        return _result(
            -1.0,
            functionality_passed=func_passed,
            functionality_total=func_total,
            security_passed=sec_passed,
            security_total=sec_total,
            reward_failure_reason="missing_functionality_or_security_tests",
        )

    functionality_score = min(1.0, max(0.0, float(func_passed) / float(func_total)))
    security_score = min(1.0, max(0.0, float(sec_passed) / float(sec_total)))
    security_weight = _security_weight()
    score = (1.0 - security_weight) * functionality_score + security_weight * security_score
    return _result(
        score,
        functionality_passed=func_passed,
        functionality_total=func_total,
        security_passed=sec_passed,
        security_total=sec_total,
        functionality_score=functionality_score,
        security_score=security_score,
    )


def _to_sequence(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return [value]


def compute_score(
    data_source: Any = None,
    solution_str: Any = None,
    ground_truth: Any = None,
    extra_info: Any = None,
    *,
    data_sources: Any = None,
    solution_strs: Any = None,
    ground_truths: Any = None,
    extra_infos: Any = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """VeRL scalar and batch reward-manager entry point."""
    if data_sources is None and solution_strs is None and ground_truths is None:
        return _compute_score_single(data_source, solution_str, ground_truth, extra_info)

    sources = _to_sequence(data_sources)
    solutions = _to_sequence(solution_strs)
    truths = _to_sequence(ground_truths)
    extras = _to_sequence(extra_infos) if extra_infos is not None else [None] * len(solutions)
    if len(sources) != len(solutions) or len(truths) != len(solutions):
        raise ValueError("Batch reward inputs must have matching data_sources, solution_strs, and ground_truths lengths")
    if len(extras) != len(solutions):
        extras = (extras + [None] * len(solutions))[: len(solutions)]
    return [
        _compute_score_single(sources[index], solutions[index], truths[index], extras[index])
        for index in range(len(solutions))
    ]
