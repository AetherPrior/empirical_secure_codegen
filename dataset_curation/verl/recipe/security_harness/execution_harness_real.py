"""Execution harness with functionality unittest score and real_detector security score."""

from __future__ import annotations

from typing import Any

try:
    from recipe.security_harness.execution_harness import compute_hybrid_score, simple_gen_language
    from recipe.security_harness.execution_harness_c import run_simple_gen_c_harness_unittest
    from recipe.security_harness.execution_harness_cpp import run_simple_gen_cpp_harness_unittest
    from recipe.security_harness.execution_harness_js import run_simple_gen_js_harness_unittest
    from recipe.security_harness.execution_harness_python import run_simple_gen_python_harness_unittest
    from recipe.security_harness.real_detector import run_all_detectors
    from recipe.security_harness.reward_config import debug
except ImportError:
    from execution_harness import compute_hybrid_score, simple_gen_language
    from execution_harness_c import run_simple_gen_c_harness_unittest
    from execution_harness_cpp import run_simple_gen_cpp_harness_unittest
    from execution_harness_js import run_simple_gen_js_harness_unittest
    from execution_harness_python import run_simple_gen_python_harness_unittest
    from real_detector import run_all_detectors
    from reward_config import debug


def combine_functionality_and_detector_scores(
    functionality_score: float,
    security_score: float,
) -> float:
    """Blend functionality and real_detector scores using SECURITY_RATIO."""
    if security_score < 0:
        return float(functionality_score)
    return compute_hybrid_score(
        functionality_score,
        security_score,
        total_functionality=1,
        total_security=1,
    )


def compute_functionality_score(functionality_passed: int | float, functionality_total: int) -> float:
    if functionality_total <= 0:
        return 0.0
    return float(functionality_passed) / float(functionality_total)


def compute_real_detector_security_score(candidate_code: str) -> tuple[bool, float, int]:
    """Run static detectors and return a binary score in {0.0, 1.0}.

    Returns:
        (detector_ok, security_score, vulnerability_count)
        detector_ok=False means the code could not be analyzed (syntax/parse failure).
    """
    code = candidate_code.strip()
    if not code:
        return False, -0.5, 0

    try:
        vulnerabilities = run_all_detectors(code)
    except Exception as exc:
        debug(f"real_detector failed: {type(exc).__name__}: {exc}")
        return False, -0.5, 0

    vuln_count = len(vulnerabilities)
    security_score = 1.0 if vuln_count == 0 else 0.0
    return True, float(security_score), int(vuln_count)


def unittest_metrics(
    functionality_passed: int = -1,
    functionality_total: int = -1,
    security_score: float = -1.0,
    vulnerability_count: int = -1,
) -> dict[str, Any]:
    """Per-sample metrics for reward logging (-1 means not evaluated)."""
    return {
        "functionality_passed": int(functionality_passed),
        "functionality_total": int(functionality_total),
        "security_passed": float(security_score),
        "security_total": 1,
        "real_detector_vulnerability_count": int(vulnerability_count),
    }


def _run_language_harness(
    candidate_code: str, ground_truth: Any, extra_info: dict[str, Any] | None
) -> tuple[bool, dict[str, tuple[int | float, int]]]:
    language = simple_gen_language(ground_truth, extra_info)
    if language == "c":
        return run_simple_gen_c_harness_unittest(candidate_code, ground_truth)
    if language == "cpp":
        return run_simple_gen_cpp_harness_unittest(candidate_code, ground_truth)
    if language == "javascript":
        return run_simple_gen_js_harness_unittest(candidate_code, ground_truth)
    return run_simple_gen_python_harness_unittest(candidate_code, ground_truth)


def unit_test_score(
    candidate_code: str, ground_truth: Any, extra_info: dict[str, Any] | None
) -> tuple[bool, float, int, int, float, int]:
    """Score candidate code with functionality tests and real_detector security.

    Returns:
        (ok, ut_score, functionality_passed, functionality_total, security_score, security_total)

    ut_score is functionality_passed / functionality_total.
    security_score is 1.0 if real_detector finds no issues else 0.0 (Python only).
    security_total is 1 when detector runs, else -1.
    """
    language = simple_gen_language(ground_truth, extra_info)
    ut_ok, ut_result = _run_language_harness(candidate_code, ground_truth, extra_info)
    if not ut_ok:
        debug(f"{language} unittest harness failed")
        return False, -0.5, -1, -1, -1.0, -1

    functionality_passed, functionality_total = ut_result.get("functionality", (0, 0))
    if functionality_total <= 0:
        debug(f"{language} functionality totals missing; returning ut_score=0.0")
        ut_score = 0.0
    else:
        ut_score = compute_functionality_score(functionality_passed, functionality_total)

    if language != "python":
        debug(
            "real_detector skipped for non-python language: "
            f"language={language}, ut_score={ut_score:.4f}"
        )
        return (
            True,
            ut_score,
            int(functionality_passed),
            int(functionality_total),
            -1.0,
            -1,
        )

    detector_ok, security_score, vulnerability_count = compute_real_detector_security_score(
        candidate_code
    )
    if not detector_ok:
        debug(
            "real_detector analysis failed after successful unittest harness: "
            f"ut_score={ut_score:.4f}"
        )
        return (
            True,
            ut_score,
            int(functionality_passed),
            int(functionality_total),
            -0.5,
            -1,
        )

    debug(
        "real harness score computed: "
        f"language={language}, functionality={functionality_passed}/{functionality_total}, "
        f"ut_score={ut_score:.4f}, security_score={security_score:.4f}, "
        f"vulnerabilities={vulnerability_count}"
    )
    return (
        True,
        ut_score,
        int(functionality_passed),
        int(functionality_total),
        float(security_score),
        1,
    )
