"""Language-dispatching simple_gen execution harness."""

from __future__ import annotations

from typing import Any

try:
    from recipe.security_harness.execution_harness_c import run_simple_gen_c_harness_unittest
    from recipe.security_harness.execution_harness_cpp import run_simple_gen_cpp_harness_unittest
    from recipe.security_harness.execution_harness_js import run_simple_gen_js_harness_unittest
    from recipe.security_harness.execution_harness_python import run_simple_gen_python_harness_unittest
    from recipe.security_harness.reward_config import SECURITY_RATIO, debug
except ImportError:
    from execution_harness_c import run_simple_gen_c_harness_unittest
    from execution_harness_cpp import run_simple_gen_cpp_harness_unittest
    from execution_harness_js import run_simple_gen_js_harness_unittest
    from execution_harness_python import run_simple_gen_python_harness_unittest
    from reward_config import SECURITY_RATIO, debug


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_language(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    lang = value.strip().lower().replace("_", "-")
    if not lang:
        return None
    if lang in {"python", "python3", "py"}:
        return "python"
    if lang in {"c", "c11", "gnu11"}:
        return "c"
    if lang in {"cpp", "c++", "cxx", "cc", "cplusplus", "c++17", "gnu++17"}:
        return "cpp"
    if lang in {"javascript", "js", "node", "nodejs", "ecmascript"}:
        return "javascript"
    return None


def simple_gen_language(ground_truth: Any, extra_info: Any = None) -> str:
    """Best-effort language lookup for mixed simple_gen datasets."""
    details = _dict_or_empty(extra_info)
    truth = _dict_or_empty(ground_truth)
    for source in (details, truth):
        for key in ("lang", "language", "programming_language"):
            lang = _normalize_language(source.get(key))
            if lang is not None:
                return lang

    # Some intermediate simple_gen rows carry only language-specific candidate fields.
    if any(key in truth for key in ("candidate_cpp", "generated_cpp")):
        return "cpp"
    if any(key in truth for key in ("candidate_c", "generated_c")):
        return "c"
    if any(key in truth for key in ("candidate_js", "candidate_javascript", "generated_js", "generated_javascript")):
        return "javascript"
    return "python"


def compute_hybrid_score(
    functionality_passed: int | float,
    security_passed: int | float,
    total_functionality: int,
    total_security: int,
) -> float:
    if total_functionality <= 0 or total_security <= 0:
        return 0.0
    utility_score = float(functionality_passed) / total_functionality
    security_score = float(security_passed) / total_security
    return float(SECURITY_RATIO * security_score + (1.0 - SECURITY_RATIO) * utility_score)


def expected_unittest_totals(
    ground_truth: Any, extra_info: Any = None
) -> tuple[int | None, int | None]:
    """Denominators from test_spec without running the harness (for logging when ut_ok is False)."""
    del extra_info
    try:
        from recipe.security_harness.execution_harness_python import (
            count_totals_from_test_spec,
            extract_harness_bundle,
        )
    except ImportError:
        from execution_harness_python import count_totals_from_test_spec, extract_harness_bundle

    _harness, test_spec = extract_harness_bundle(ground_truth)
    if test_spec is None:
        return None, None
    func_total, sec_total = count_totals_from_test_spec(test_spec)
    return (
        func_total if func_total > 0 else None,
        sec_total if sec_total > 0 else None,
    )


def unittest_metrics(
    functionality_passed: int = -1,
    functionality_total: int = -1,
    security_passed: float = -1.0,
    security_total: int = -1,
) -> dict[str, Any]:
    """Per-sample unittest counts for reward_extra_info (-1 means not evaluated)."""
    return {
        "functionality_passed": int(functionality_passed),
        "functionality_total": int(functionality_total),
        "security_passed": float(security_passed),
        "security_total": int(security_total),
    }


def unit_test_score(
    candidate_code: str, ground_truth: Any, extra_info: dict[str, Any] | None
) -> tuple[bool, float, int, int, float, int]:
    language = simple_gen_language(ground_truth, extra_info)
    if language == "c":
        ut_ok, ut_result = run_simple_gen_c_harness_unittest(candidate_code, ground_truth)
    elif language == "cpp":
        ut_ok, ut_result = run_simple_gen_cpp_harness_unittest(candidate_code, ground_truth)
    elif language == "javascript":
        ut_ok, ut_result = run_simple_gen_js_harness_unittest(candidate_code, ground_truth)
    else:
        ut_ok, ut_result = run_simple_gen_python_harness_unittest(candidate_code, ground_truth)

    if not ut_ok:
        debug(f"{language} unittest harness failed")
        return False, -0.5, -1, -1, -1.0, -1

    functionality_passed, functionality_total = ut_result.get("functionality", (0, 0))
    security_passed, security_total = ut_result.get("security", (0, 0))

    if functionality_total <= 0 or security_total <= 0:
        debug(f"{language} unittest totals missing; returning ut_score=0.0")
        return True, 0.0, 0, 0, 0.0, 0

    ut_score = compute_hybrid_score(functionality_passed, security_passed, functionality_total, security_total)
    debug(
        "unittest score computed: "
        f"language={language}, functionality={functionality_passed}/{functionality_total}, "
        f"security={security_passed}/{security_total}, score={ut_score:.4f}"
    )
    return (
        True,
        ut_score,
        int(functionality_passed),
        int(functionality_total),
        float(security_passed),
        int(security_total),
    )
