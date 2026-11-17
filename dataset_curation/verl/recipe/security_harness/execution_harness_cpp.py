"""C++ simple_gen execution harness."""

from __future__ import annotations

from typing import Any

try:
    from recipe.security_harness.execution_harness_native import run_simple_gen_native_harness_unittest
except ImportError:
    from execution_harness_native import run_simple_gen_native_harness_unittest


def run_simple_gen_cpp_harness_unittest(
    candidate_code: str, ground_truth: Any
) -> tuple[bool, dict[str, tuple[int | float, int]]]:
    return run_simple_gen_native_harness_unittest(candidate_code, ground_truth, language="cpp")
