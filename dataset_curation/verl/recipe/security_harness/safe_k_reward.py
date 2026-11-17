"""Aggregate execution, quality, and LLM-judge scores for GRPO training."""

from __future__ import annotations

import ast
import math
import os
import re
import sys
import threading
from typing import Any
## sanity check for CWE-601
import defusedxml

_PKG_DIR = __file__
import pathlib as _pathlib
_PKG_DIR = str(_pathlib.Path(__file__).resolve().parent)
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

try:
    from recipe.security_harness.reward_config import (
        IS_COT_MODEL,
        TOKENIZER_MODEL,
        LLM_JUDGE_ENABLED,
        LLM_JUDGE_RATIO,
        PRM_JUDGE_ENABLED,
        SECURITY_RATIO,
        UT_RATIO,
        USE_REAL_DETECTOR_HARNESS,
        debug,
        log_reward_components,
        normalize_extra_info,
    )
    from recipe.security_harness.execution_harness import (
        expected_unittest_totals,
        simple_gen_language,
        unittest_metrics,
    )
    if USE_REAL_DETECTOR_HARNESS:
        from recipe.security_harness.execution_harness_real import (
            combine_functionality_and_detector_scores,
            unit_test_score,
        )
    else:
        from recipe.security_harness.execution_harness import unit_test_score
    from recipe.security_harness.llm_judge import (
        extract_model_guideline_sections,
        llm_triple_guideline_judge_score,
        reference_guidelines_from_extra,
    )
    from recipe.security_harness.prm_judge import prm_guideline_judge_score
except ImportError:
    from reward_config import (
        IS_COT_MODEL,
        TOKENIZER_MODEL,
        LLM_JUDGE_ENABLED,
        LLM_JUDGE_RATIO,
        PRM_JUDGE_ENABLED,
        SECURITY_RATIO,
        UT_RATIO,
        USE_REAL_DETECTOR_HARNESS,
        debug,
        log_reward_components,
        normalize_extra_info,
    )
    from execution_harness import (
        expected_unittest_totals,
        simple_gen_language,
        unittest_metrics,
    )
    if USE_REAL_DETECTOR_HARNESS:
        from execution_harness_real import (
            combine_functionality_and_detector_scores,
            unit_test_score,
        )
    else:
        from execution_harness import unit_test_score
    from llm_judge import (
        extract_model_guideline_sections,
        llm_triple_guideline_judge_score,
        reference_guidelines_from_extra,
    )
    from prm_judge import prm_guideline_judge_score

CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)


_HIGH_LEVEL_CLOSE_RE = re.compile(r"</high_level>", re.IGNORECASE)
_IMPL_CLOSE_RE = re.compile(r"</implementation>", re.IGNORECASE)
_HIGH_LEVEL_BLOCK_RE = re.compile(r"<high_level>[\s\S]*?</high_level>", re.IGNORECASE)
_IMPL_BLOCK_RE = re.compile(r"<implementation>[\s\S]*?</implementation>", re.IGNORECASE)
_FUNCTIONALITY_EDGE_CASES_BLOCK_RE = re.compile(
    r"<functionality_edge_cases>[\s\S]*?</functionality_edge_cases>", re.IGNORECASE
)

_TOKENIZER = None
_TOKENIZER_NAME: str | None = None
_TOKENIZER_LOCK = threading.Lock()


def _extract_non_reasoning_candidate_code(solution_str: str) -> str:
    if not isinstance(solution_str, str):
        return ""
    text = solution_str or ""
    
    matches = [m.strip() for m in CODE_BLOCK_RE.findall(text) if isinstance(m, str) and m.strip()]
    if matches:
        return matches[-1]
    return text.strip()


def _extract_reasoning_candidate_code(solution_str: str) -> str:
    if not isinstance(solution_str, str):
        return ""
    text = solution_str or ""

    # If a known closing thinking tag exists, parse code only after the last one (ignore
    # fenced blocks inside thinking). Otherwise use the full string (no CoT, different
    # tag names, or thinking only in special tokens).
    lowered = text.lower()
    last_close = -1
    for close_tag in ("</think>", "</thinking>", "</analysis>"):
        idx = lowered.rfind(close_tag)
        if idx != -1:
            last_close = max(last_close, idx + len(close_tag))
    if last_close != -1:
        text = text[last_close:]
    if last_close == -1:
        return ""

    matches = [m.strip() for m in CODE_BLOCK_RE.findall(text) if isinstance(m, str) and m.strip()]
    if matches:
        return matches[-1]
    return text.strip()


def _extract_candidate_code(solution_str: str) -> str:
    if IS_COT_MODEL:
        return _extract_reasoning_candidate_code(solution_str)
    return _extract_non_reasoning_candidate_code(solution_str)


# def _extract_guidelines(solution_str: str) -> str:
#     if not isinstance(solution_str, str):
#         return ""
#     matches = re.findall(r"<GUIDELINES>([\s\S]*?)</GUIDELINES>", solution_str, flags=re.IGNORECASE)
#     cleaned = [m.strip() for m in matches if isinstance(m, str) and m.strip()]
#     return "\n\n".join(cleaned)


def _validate_guideline_tag_syntax(solution_str: str) -> str | None:
    """Return a failure reason if required guideline XML blocks are missing."""
    if not isinstance(solution_str, str) or not solution_str.strip():
        return "empty_response"
    if not _HIGH_LEVEL_BLOCK_RE.search(solution_str):
        return "missing_high_level_tags"
    if not _IMPL_BLOCK_RE.search(solution_str):
        return "missing_implementation_tags"
    if not _FUNCTIONALITY_EDGE_CASES_BLOCK_RE.search(solution_str):
        return "missing_functionality_edge_cases_tags"
    return None


def _span_boundaries_from_solution(solution_str: str, extra_info: Any) -> tuple[int, int]:
    """Inclusive response token end indices for high-level and implementation spans."""
    details = normalize_extra_info(extra_info)
    text = solution_str or ""
    hl_close = _HIGH_LEVEL_CLOSE_RE.search(text)
    im_close = _IMPL_CLOSE_RE.search(text)
    if not hl_close and not im_close:
        return -1, -1

    token_ids = details.get("response_token_ids")
    valid_len = details.get("valid_response_length")
    try:
        valid_len = int(valid_len)
    except (TypeError, ValueError):
        valid_len = 0

    if token_ids and valid_len > 0:
        try:
            from verl.utils.span_credit import token_ends_from_solution

            ids = [int(x) for x in token_ids]
            tok = _get_tokenizer()
            if tok is not None:
                return token_ends_from_solution(text, ids[:valid_len], tok)
        except Exception:
            pass

    text_len = max(len(text), 1)
    high_end, impl_end = -1, -1
    if valid_len > 0:
        if hl_close:
            high_end = min(int(hl_close.end() / text_len * valid_len), valid_len - 1)
        if im_close:
            impl_end = min(int(im_close.end() / text_len * valid_len), valid_len - 1)
    return high_end, impl_end

    # blob = _extract_guidelines(solution_str)
    # if not blob.strip():
    #     return "", ""
    # try:
    #     obj = json.loads(blob.strip())
    #     if isinstance(obj, dict):
    #         h = str(obj.get("high_level_guidelines", "")).strip()
    #         i = str(obj.get("implementational", "")).strip()
    #         if h or i:
    #             return h, i
    # except Exception:
    #     pass
    # return blob.strip(), ""


def _get_tokenizer():
    """Lazy-load tokenizer for span-credit boundaries; returns None if TOKENIZER_MODEL unset."""
    global _TOKENIZER, _TOKENIZER_NAME
    if not TOKENIZER_MODEL:
        return None
    with _TOKENIZER_LOCK:
        if _TOKENIZER is not None and _TOKENIZER_NAME == TOKENIZER_MODEL:
            return _TOKENIZER
        from transformers import AutoTokenizer

        _TOKENIZER = AutoTokenizer.from_pretrained(TOKENIZER_MODEL, trust_remote_code=True)
        _TOKENIZER_NAME = TOKENIZER_MODEL
        return _TOKENIZER


def _default_reward_extra_fields() -> dict[str, Any]:
    """Stable keys for ``reward_extra_info`` (agent loop requires identical keys across rollouts).

    All numeric fields must be finite: NaNs in span_reward_* propagate through GRPO span
    credit and produce NaN policy gradients.
    """
    return {
        "functionality_passed": -1,
        "functionality_total": -1,
        "security_passed": -1.0,
        "security_total": -1,
        "real_detector_vulnerability_count": -1,
        "ut_score": 0.0,
        "exec_score": 0.0,
        "llm_judge_score": 0.0,
        "llm_judge_high_level_security_relevance": -1,
        "llm_judge_implementation_supports_high_level": -1,
        "llm_judge_explanations": "",
        "guideline_alignment_epsilon": 0.0,
        "format_reward": 0.0,
        "reward_failure_reason": "",
        "span_reward_high": 0.0,
        "span_reward_impl": 0.0,
        "span_reward_code": 0.0,
        "span_high_end": -1,
        "span_impl_end": -1,
    }


def _reward_result(score: float, **overrides: Any) -> dict[str, Any]:
    out = _default_reward_extra_fields()
    out["score"] = float(score)
    out.update(overrides)
    return out


def _cascade_span_judge_scores(s1: float, s2: float) -> tuple[float, float]:
    """Hierarchical judge scores: s1=0 forces s2=0. Preserves 0.5."""
    s1_f = float(s1) if float(s1) > 0 else 0.0
    s2_f = float(s2) if float(s2) > 0 else 0.0
    if s1_f == 0.0:
        s2_f = 0.0
    return s1_f, s2_f


def _compute_span_rewards(
    s1: float,
    s2: float,
    exec_score: float,
    lam: float = LLM_JUDGE_RATIO,
) -> tuple[float, float, float]:
    """Per-span outcome rewards for GRPO span credit.

    high←λ·s1, impl←λ·s2 (no exec blend); code←exec only.
    """
    lam = float(lam)
    exec_score = float(exec_score)
    span_high = lam * s1
    span_impl = lam * s2
    span_code = exec_score
    return span_high, span_impl, span_code


def _span_rewards_from_components(
    *,
    exec_score: float,
    llm_b1: float = 0.0,
    llm_b2: float = 0.0,
    llm_b3: float = 0.0,
) -> tuple[float, float, float]:
    """Build span rewards from exec + judge bits (never use scalar score as a shortcut)."""
    del llm_b3  # code-consistency judge disabled
    s1, s2 = _cascade_span_judge_scores(
        llm_b1 if llm_b1 >= 0 else 0.0,
        llm_b2 if llm_b2 >= 0 else 0.0,
    )
    if PRM_JUDGE_ENABLED:
        # Additive / gated: high/impl get full PRM bits (already 0 when gated off).
        return _compute_span_rewards(s1, s2, exec_score, lam=1.0)
    return _compute_span_rewards(s1, s2, exec_score, lam=LLM_JUDGE_RATIO)


def _unittest_counts_for_log(
    ground_truth: Any,
    extra_info: Any,
    functionality_passed: int,
    functionality_total: int,
    security_passed: float,
    security_total: int,
) -> tuple[int, int, float, int]:
    """Fill unknown denominators from test_spec for stderr logs (reward_extra_info keeps -1)."""
    if functionality_total >= 0 and security_total >= 0:
        return functionality_passed, functionality_total, security_passed, security_total
    exp_func, exp_sec = expected_unittest_totals(ground_truth, extra_info)
    return (
        functionality_passed,
        functionality_total if functionality_total >= 0 else (exp_func if exp_func is not None else -1),
        security_passed,
        security_total if security_total >= 0 else (exp_sec if exp_sec is not None else -1),
    )


def _log_reward(
    *,
    ground_truth: Any,
    extra_info: Any = None,
    **kwargs: Any,
) -> None:
    fp, ft, sp, st = _unittest_counts_for_log(
        ground_truth,
        extra_info,
        kwargs["functionality_passed"],
        kwargs["functionality_total"],
        kwargs["security_passed"],
        kwargs["security_total"],
    )
    log_reward_components(
        functionality_passed=fp,
        functionality_total=ft,
        security_passed=sp,
        security_total=st,
        **{k: v for k, v in kwargs.items() if k not in ("functionality_passed", "functionality_total", "security_passed", "security_total")},
    )


def _reward_result_with_spans(
    score: float,
    *,
    exec_score: float,
    llm_b1: float = 0.0,
    llm_b2: float = 0.0,
    llm_b3: float = 0.0,
    llm_judge_score: float | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    """Return reward dict with span_reward_* derived from exec and judge components."""
    span_high, span_impl, span_code = _span_rewards_from_components(
        exec_score=exec_score, llm_b1=llm_b1, llm_b2=llm_b2, llm_b3=llm_b3
    )
    if llm_judge_score is None:
        llm_judge_score = (
            float(llm_b1 + llm_b2) / 2.0 if min(llm_b1, llm_b2) >= 0 else 0.0
        )
    return _reward_result(
        score,
        exec_score=float(exec_score),
        llm_judge_score=float(llm_judge_score),
        llm_judge_high_level_security_relevance=float(llm_b1),
        llm_judge_implementation_supports_high_level=float(llm_b2),
        span_reward_high=float(span_high),
        span_reward_impl=float(span_impl),
        span_reward_code=float(span_code),
        **overrides,
    )


def _compute_score_single(data_source, solution_str, ground_truth, extra_info=None):
    del data_source
    language = simple_gen_language(ground_truth, extra_info)

    tag_syntax_err = _validate_guideline_tag_syntax(solution_str or "")
    # PRM mode: binary format reward (1=both guideline blocks present, else 0).
    # Missing tags do NOT short-circuit — exec still runs; only format_reward is 0.
    format_reward = 0.0
    if PRM_JUDGE_ENABLED:
        format_reward = 0.0 if tag_syntax_err is not None else 1.0
        if tag_syntax_err is not None:
            debug(f"guideline format reward=0 ({tag_syntax_err}); continuing to exec")
    elif LLM_JUDGE_ENABLED and tag_syntax_err is not None:
        debug(f"guideline tag syntax invalid: {tag_syntax_err}")
        _log_reward(
            ground_truth=ground_truth,
            extra_info=extra_info,
            functionality_passed=-1,
            functionality_total=-1,
            security_passed=-1.0,
            security_total=-1,
            ut_score=-1.0,
            exec_score=-1.0,
            llm_judge_score=0.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            final_score=-1.0,
            reward_failure_reason=tag_syntax_err,
        )
        return _reward_result_with_spans(
            -1.0,
            exec_score=-1.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            llm_judge_score=0.0,
            format_reward=0.0,
            reward_failure_reason=tag_syntax_err,
            **unittest_metrics(),
        )

    candidate_code = _extract_candidate_code(solution_str)
    if not candidate_code:
        debug("candidate code extraction failed (empty)")
        span_high_end, span_impl_end = _span_boundaries_from_solution(solution_str or "", extra_info)
        _log_reward(
            ground_truth=ground_truth,
            extra_info=extra_info,
            functionality_passed=-1,
            functionality_total=-1,
            security_passed=-1.0,
            security_total=-1,
            ut_score=-1.0,
            exec_score=-1.0,
            llm_judge_score=0.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            final_score=-1.0,
            reward_failure_reason="empty_code",
        )
        return _reward_result_with_spans(
            -1.0,
            exec_score=-1.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            llm_judge_score=0.0,
            format_reward=float(format_reward),
            reward_failure_reason="empty_code",
            span_high_end=int(span_high_end),
            span_impl_end=int(span_impl_end),
            **unittest_metrics(),
        )

    if language == "python":
        try:
            ast.parse(candidate_code)
        except SyntaxError:
            debug("candidate code has syntax error")
            span_high_end, span_impl_end = _span_boundaries_from_solution(solution_str or "", extra_info)
            _log_reward(
                ground_truth=ground_truth,
                extra_info=extra_info,
                functionality_passed=-1,
                functionality_total=-1,
                security_passed=-1.0,
                security_total=-1,
                ut_score=-1.0,
                exec_score=-1.0,
                llm_judge_score=0.0,
                llm_b1=0,
                llm_b2=0,
                llm_b3=0,
                final_score=-1.0,
                reward_failure_reason="syntax_error",
            )
            return _reward_result_with_spans(
                -1.0,
                exec_score=-1.0,
                ut_score=-1.0,
                llm_b1=0,
                llm_b2=0,
                llm_b3=0,
                llm_judge_score=0.0,
                format_reward=float(format_reward),
                reward_failure_reason="syntax_error",
                span_high_end=int(span_high_end),
                span_impl_end=int(span_impl_end),
                **unittest_metrics(),
            )

    (
        ut_ok,
        ut_score,
        functionality_passed,
        functionality_total,
        security_passed,
        security_total,
    ) = unit_test_score(candidate_code, ground_truth, extra_info)
    functionality_score = float(ut_score)
    if USE_REAL_DETECTOR_HARNESS:
        if math.isclose(float(security_passed), -0.5, rel_tol=0.0, abs_tol=1e-9):
            ut_score = -0.5
        elif security_passed >= 0:
            ut_score = combine_functionality_and_detector_scores(
                functionality_score,
                float(security_passed),
            )
        else:
            ut_score = functionality_score
        debug(
            "real_detector harness blend: "
            f"functionality={functionality_score:.4f}, security={security_passed:.4f}, "
            f"SECURITY_RATIO={SECURITY_RATIO:.4f}, ut_score={ut_score:.4f}"
        )
    unittest_fields = unittest_metrics(
        functionality_passed=functionality_passed,
        functionality_total=functionality_total,
        security_passed=security_passed,
        security_total=security_total,
    )
    if not ut_ok:
        debug("unittest evaluation failed; returning -1.0")
        span_high_end, span_impl_end = _span_boundaries_from_solution(solution_str or "", extra_info)
        _log_reward(
            ground_truth=ground_truth,
            extra_info=extra_info,
            functionality_passed=functionality_passed,
            functionality_total=functionality_total,
            security_passed=security_passed,
            security_total=security_total,
            ut_score=-1.0,
            exec_score=-1.0,
            llm_judge_score=0.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            final_score=-1.0,
            reward_failure_reason="unittest_harness_failed",
        )
        return _reward_result_with_spans(
            -1.0,
            exec_score=-1.0,
            ut_score=-1.0,
            llm_b1=0,
            llm_b2=0,
            llm_b3=0,
            llm_judge_score=0.0,
            format_reward=float(format_reward),
            reward_failure_reason="unittest_harness_failed",
            span_high_end=int(span_high_end),
            span_impl_end=int(span_impl_end),
            **unittest_fields,
        )

    details = normalize_extra_info(extra_info)
    user_prompt = details.get("user_prompt", "")
    reference_guidelines = reference_guidelines_from_extra(details)
    model_hl, model_im = extract_model_guideline_sections(solution_str or "")

    # Fully secure + correct: all functionality tests pass AND all security tests pass.
    func_ok = (
        int(functionality_total) > 0
        and int(functionality_passed) >= int(functionality_total)
    )
    sec_ok = (
        int(security_total) > 0
        and float(security_passed) + 1e-9 >= float(security_total)
    )
    secure_and_correct = bool(func_ok and sec_ok)

    llm_judge_score = 0.0
    llm_b1 = 0.0
    llm_b2 = 0.0
    _llm_b3 = 0.0
    llm_judge_explanations = ""
    judge_backend = "none"

    if PRM_JUDGE_ENABLED:
        # PRM replaces the LLM judge. Only add PRM signal when secure+correct
        # and guideline tags are present (format_reward=1).
        if secure_and_correct and format_reward >= 1.0:
            llm_judge_score, llm_b1, llm_b2, _llm_b3, llm_judge_explanations = (
                prm_guideline_judge_score(
                    cwe=str(details.get("cwe", "")),
                    user_prompt=user_prompt,
                    reference_guidelines=reference_guidelines,
                    model_high_level=model_hl,
                    model_implementational=model_im,
                    code=candidate_code,
                )
            )
            judge_backend = "prm"
        else:
            llm_judge_explanations = (
                f"[prm] gated_off format={format_reward:g} "
                f"func_ok={func_ok} sec_ok={sec_ok} "
                f"func={functionality_passed}/{functionality_total} "
                f"sec={security_passed}/{security_total}"
            )
            judge_backend = "prm_gated"
            debug(llm_judge_explanations)
    elif LLM_JUDGE_ENABLED:
        llm_judge_score, llm_b1, llm_b2, _llm_b3, llm_judge_explanations = (
            llm_triple_guideline_judge_score(
                cwe=str(details.get("cwe", "")),
                user_prompt=user_prompt,
                reference_guidelines=reference_guidelines,
                model_high_level=model_hl,
                model_implementational=model_im,
                code=candidate_code,
            )
        )
        judge_backend = "llm"
    else:
        # With both judge backends disabled, the rollout is scored only by the
        # unit-test harness. Keep the judge fields populated for stable logging.
        llm_judge_explanations = "[judge] disabled"
        judge_backend = "none"

    exec_score = float(UT_RATIO * ut_score)
    if PRM_JUDGE_ENABLED:
        # ReCode-style CG-GRPO: R = format + R_out + I(secure∧correct) · R_proc.
        base_score = float(format_reward) + exec_score + float(llm_judge_score)
        judge_w = 1.0 if secure_and_correct else 0.0
        exec_w = 1.0
    elif LLM_JUDGE_ENABLED:
        judge_w = float(LLM_JUDGE_RATIO)
        exec_w = max(0.0, 1.0 - judge_w)
        base_score = exec_w * exec_score + judge_w * llm_judge_score
    else:
        judge_w = 0.0
        exec_w = 1.0
        base_score = exec_score

    # Tied to code-consistency (s3); disabled with that judge.
    guideline_alignment_epsilon = 0.0
    final_score = base_score + guideline_alignment_epsilon
    debug(
        "final score components: "
        f"backend={judge_backend} secure_and_correct={secure_and_correct} "
        f"ut={ut_score:.4f}*{UT_RATIO}, "
        f"exec={exec_score:.4f}"
        + (
            f" + format={format_reward:g} + prm={llm_judge_score:.4f} (gated sum)"
            if PRM_JUDGE_ENABLED
            else (
                f"*{exec_w:.4f} + judge={llm_judge_score:.4f}*{judge_w:.4f}"
                if LLM_JUDGE_ENABLED
                else " (unit-test only; judges disabled)"
            )
        )
        + f", base={base_score:.4f}"
        f", guideline_epsilon={guideline_alignment_epsilon:.4f}, final={final_score:.4f}"
    )

    try:
        idx = int(details.get("index", -1))
    except Exception:
        idx = -1

    span_high_end, span_impl_end = _span_boundaries_from_solution(solution_str or "", extra_info)
    span_reward_high, span_reward_impl, span_reward_code = _span_rewards_from_components(
        exec_score=exec_score,
        llm_b1=llm_b1,
        llm_b2=llm_b2,
    )
    s1, s2 = _cascade_span_judge_scores(
        llm_b1 if llm_b1 >= 0 else 0,
        llm_b2 if llm_b2 >= 0 else 0,
    )
    debug(
        "span rewards: "
        f"s1={s1:g} s2={s2:g} exec={exec_score:.4f} "
        f"lambda={(1.0 if PRM_JUDGE_ENABLED else LLM_JUDGE_RATIO if LLM_JUDGE_ENABLED else 0.0):.4f} "
        f"high={span_reward_high:.4f} impl={span_reward_impl:.4f} code={span_reward_code:.4f} "
        f"ends=({span_high_end},{span_impl_end})"
    )

    _log_reward(
        ground_truth=ground_truth,
        extra_info=extra_info,
        index=idx,
        functionality_passed=functionality_passed,
        functionality_total=functionality_total,
        security_passed=security_passed,
        security_total=security_total,
        ut_score=float(ut_score),
        exec_score=float(exec_score),
        llm_judge_score=float(llm_judge_score),
        llm_b1=float(llm_b1),
        llm_b2=float(llm_b2),
        final_score=float(final_score),
    )

    return _reward_result(
        final_score,
        ut_score=float(ut_score),
        exec_score=float(exec_score),
        llm_judge_score=float(llm_judge_score),
        llm_judge_high_level_security_relevance=float(llm_b1),
        llm_judge_implementation_supports_high_level=float(llm_b2),
        llm_judge_explanations=str(llm_judge_explanations or ""),
        guideline_alignment_epsilon=float(guideline_alignment_epsilon),
        format_reward=float(format_reward),
        span_reward_high=float(span_reward_high),
        span_reward_impl=float(span_reward_impl),
        span_reward_code=float(span_reward_code),
        span_high_end=int(span_high_end),
        span_impl_end=int(span_impl_end),
        **unittest_fields,
    )


def _to_sequence(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    try:
        return list(value)
    except Exception:
        return [value]


def compute_score(
    data_source=None,
    solution_str=None,
    ground_truth=None,
    extra_info=None,
    *,
    data_sources=None,
    solution_strs=None,
    ground_truths=None,
    extra_infos=None,
):
    # Batch interface used by reward_manager=batch
    if data_sources is not None or solution_strs is not None or ground_truths is not None:
        sources = _to_sequence(data_sources)
        solutions = _to_sequence(solution_strs)
        truths = _to_sequence(ground_truths)
        extras = _to_sequence(extra_infos) if extra_infos is not None else [None] * len(solutions)

        n = len(solutions)
        if len(sources) != n or len(truths) != n:
            raise ValueError(
                "Batch reward inputs length mismatch: "
                f"len(data_sources)={len(sources)}, len(solution_strs)={n}, len(ground_truths)={len(truths)}"
            )
        if len(extras) != n:
            extras = (extras + [None] * n)[:n]

        debug(f"batch reward scoring: {n} samples")
        scores = [
            _compute_score_single(
                data_source=sources[i],
                solution_str=solutions[i],
                ground_truth=truths[i],
                extra_info=extras[i],
            )
            for i in range(n)
        ]
        print(
            f"batch reward scores: {[s['score'] for s in scores]}",
            file=sys.stderr,
            flush=True,
        )
        return scores

    # Scalar interface used by reward_manager=naive
    return _compute_score_single(
        data_source=data_source,
        solution_str=solution_str,
        ground_truth=ground_truth,
        extra_info=extra_info,
    )
