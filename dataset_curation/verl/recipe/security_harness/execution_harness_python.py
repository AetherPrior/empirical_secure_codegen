"""Python simple_gen execution harness."""

from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import textwrap
from typing import Any

try:
    from recipe.security_harness.reward_config import (
        REWARD_DEBUG,
        UNITTEST_TIMEOUT_SECONDS,
        debug,
    )
except ImportError:
    from reward_config import REWARD_DEBUG, UNITTEST_TIMEOUT_SECONDS, debug

SIMPLE_GEN_TESTING_HARNESS = r"""
import builtins

def _expects_exception_value(expected):
    return expected is Exception or str(expected).lower() == "exception"

def _output_matches_expectation(actual, expected):
    # Recursively match testcase ``output`` to a return value.
    # - If expected is a type (e.g. str, dict), require isinstance(actual, expected).
    # - If expected is a container (dict/list/tuple) that contains types, treat those
    #   types as wildcards for the corresponding positions.
    if _expects_exception_value(expected):
        return False
    if isinstance(expected, tuple) and expected and all(isinstance(t, type) for t in expected):
        try:
            return isinstance(actual, expected)
        except TypeError:
            return False
    if isinstance(expected, type):
        try:
            return isinstance(actual, expected)
        except TypeError:
            return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        if set(actual.keys()) != set(expected.keys()):
            return False
        for k, vexp in expected.items():
            if not _output_matches_expectation(actual.get(k), vexp):
                return False
        return True
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if len(actual) != len(expected):
            return False
        for a, e in zip(actual, expected):
            if not _output_matches_expectation(a, e):
                return False
        return True
    if isinstance(expected, tuple):
        if not isinstance(actual, tuple):
            return False
        if len(actual) != len(expected):
            return False
        for a, e in zip(actual, expected):
            if not _output_matches_expectation(a, e):
                return False
        return True
    return actual == expected

def run_tests(candidate_code: str, test_spec: dict):
    # Barebones, non-sandbox harness for simple_gen-style tasks.
    #
    # test_spec expects:
    #   - setup_for_harness: code executed before everything else (optional)
    #   - setup_tests: code that prepares tests globals (optional)
    #   - test_code: code that defines a dict named `tests`
    #   - function_name: function to call
    #   - testcases: {"functionality": [...], "security": [...]} (optional; if missing we read from tests)
    namespace = {"__builtins__": builtins.__dict__}

    setup_for_harness = test_spec.get("setup_for_harness", "")
    setup_tests = test_spec.get("setup_tests", "")
    test_code = test_spec.get("test_code", "")
    function_name = test_spec.get("function_name")

    if not isinstance(function_name, str) or not function_name.strip():
        raise ValueError("test_spec['function_name'] missing or invalid")

    if not isinstance(setup_for_harness, str):
        setup_for_harness = ""
    if not isinstance(setup_tests, str):
        setup_tests = ""
    if not isinstance(test_code, str):
        test_code = ""

    if setup_for_harness.strip():
        exec(setup_for_harness, namespace, namespace)
    if setup_tests.strip():
        exec(setup_tests, namespace, namespace)
    if test_code.strip():
        exec(test_code, namespace, namespace)

    tests = namespace.get("tests")
    if not isinstance(tests, dict):
        raise ValueError("test_code did not define a dict named 'tests'")

    security_properties = namespace.get("security_properties", {})
    if not isinstance(security_properties, dict):
        security_properties = {}

    # Prefer explicit testcases passed via test_spec (SDPO style), otherwise map from simple_gen keys.
    testcases = test_spec.get("testcases")
    if isinstance(testcases, dict):
        functionality_cases = testcases.get("functionality", [])
        security_cases = testcases.get("security", [])
    else:
        functionality_cases = tests.get("functionality", [])
        security_cases = tests.get("security", [])

    if not isinstance(functionality_cases, list):
        raise ValueError("functionality testcases is not a list")
    if not isinstance(security_cases, list):
        raise ValueError("security testcases is not a list")

    # Load candidate code after trusted test setup is in place.
    exec(candidate_code, namespace, namespace)
    func = namespace.get(function_name)
    if not callable(func):
        raise ValueError(f"Function {function_name!r} not defined")

    def _run_one(case):
        expected = case.get("output")
        kwargs = case.get("input")
        if not isinstance(kwargs, dict):
            raise TypeError("Test input must be a dict of keyword args")

        security_property = case.get("security_property")
        has_output_expectation = expected is not None or "output" in case
        try:
            actual = func(**kwargs)

            if has_output_expectation:
                if _expects_exception_value(expected):
                    output_pass = False
                else:
                    output_pass = _output_matches_expectation(actual, expected)
            else:
                output_pass = None

            has_property_check = isinstance(security_property, str) and security_property
            if has_property_check:
                checker = security_properties.get(security_property)
                if not callable(checker):
                    property_pass = False
                else:
                    try:
                        property_pass = bool(checker(actual, kwargs, candidate_code))
                    except Exception:
                        property_pass = False
                if output_pass is None:
                    return 1.0 if property_pass else 0.0
                return 0.5 * (float(output_pass) + float(property_pass))

            if output_pass is None:
                return 0.0
            return output_pass
        except Exception:
            has_property_check = isinstance(security_property, str) and security_property
            if has_property_check:
                if not has_output_expectation:
                    return 0.0
                output_pass = _expects_exception_value(expected)
                return 0.5 * float(output_pass)
            if not has_output_expectation:
                return 0.0
            return _expects_exception_value(expected)

    functionality_passed = 0
    for case in functionality_cases:
        if isinstance(case, dict) and _run_one(case):
            functionality_passed += 1

    security_passed = 0.0
    for case in security_cases:
        if isinstance(case, dict):
            result = _run_one(case)
            if isinstance(result, (int, float)):
                security_passed += float(result)

    return {
        "functionality_passed": int(functionality_passed),
        "security_passed": float(security_passed),
        "functionality_total": int(len(functionality_cases)),
        "security_total": int(len(security_cases)),
    }
"""


def maybe_simple_gen_bundle(ground_truth: Any) -> tuple[str | None, dict[str, Any] | None]:
    """If `ground_truth` looks like a simple_gen task row, synthesize a GRPO-style harness bundle."""
    if not isinstance(ground_truth, dict):
        return None, None

    fn = ground_truth.get("function_name")
    test_code = ground_truth.get("test_code")
    setup_tests = ground_truth.get("setup_tests")
    setup_code = ground_truth.get("setup_code")

    if not isinstance(fn, str) or not fn.strip():
        return None, None
    if not isinstance(test_code, str) or not test_code.strip():
        return None, None
    if setup_tests is not None and not isinstance(setup_tests, str):
        return None, None
    if setup_code is not None and not isinstance(setup_code, str):
        return None, None

    # Map simple_gen -> SDPO test_spec.
    # Do not set empty ``testcases`` here: ``run_tests`` must fall back to
    # ``tests["functionality"]`` / ``tests["security"]`` from executed test_code.
    test_spec = {
        "function_name": fn,
        "setup_for_harness": setup_code or "",
        "setup_tests": setup_tests or "",
        "test_code": test_code,
    }
    return SIMPLE_GEN_TESTING_HARNESS, test_spec


def extract_harness_bundle(ground_truth: Any) -> tuple[str | None, dict[str, Any] | None]:
    # Security-harness training always uses simple_gen-style ground_truth.
    return maybe_simple_gen_bundle(ground_truth)


def count_totals_from_test_spec(test_spec: dict[str, Any]) -> tuple[int, int]:
    testcases = test_spec.get("testcases")
    if not isinstance(testcases, dict):
        return 0, 0

    functionality_cases = testcases.get("functionality", [])
    security_cases = testcases.get("security", [])

    total_functionality = len(functionality_cases) if isinstance(functionality_cases, list) else 0
    total_security = len(security_cases) if isinstance(security_cases, list) else 0
    return total_functionality, total_security


def validate_summary(summary: Any) -> tuple[bool, float, float, int | None, int | None]:
    if not isinstance(summary, dict):
        return False, 0, 0, None, None

    functionality_passed = summary.get("functionality_passed")
    security_passed = summary.get("security_passed")
    if not isinstance(functionality_passed, (int, float)) or not isinstance(security_passed, (int, float)):
        return False, 0, 0, None, None
    if functionality_passed < 0 or security_passed < 0:
        return False, 0, 0, None, None

    functionality_total = summary.get("functionality_total")
    security_total = summary.get("security_total")
    if not isinstance(functionality_total, int) or functionality_total < 0:
        functionality_total = None
    if not isinstance(security_total, int) or security_total < 0:
        security_total = None
    return True, functionality_passed, security_passed, functionality_total, security_total


def run_simple_gen_python_harness_unittest(
    candidate_code: str, ground_truth: Any
) -> tuple[bool, dict[str, tuple[int | float, int]]]:
    testing_harness, test_spec = extract_harness_bundle(ground_truth)
    if testing_harness is None or test_spec is None:
        debug("simple_gen Python harness unavailable: missing testing_harness/test_spec")
        if REWARD_DEBUG:
            try:
                debug(
                    f"simple_gen Python harness ground_truth type={type(ground_truth).__name__} "
                    f"repr={repr(ground_truth)[:400]}"
                )
            except Exception:
                debug("simple_gen Python harness debug dump failed")
        return False, {}

    total_functionality, total_security = count_totals_from_test_spec(test_spec)
    payload = {
        "testing_harness": testing_harness,
        "test_spec": test_spec,
        "candidate_code": candidate_code,
    }
    runner_script = textwrap.dedent(
        """
        import json
        import sys

        data = json.loads(sys.stdin.read())
        namespace = {}
        try:
            exec(data["testing_harness"], namespace, namespace)
            runner = namespace.get("run_tests")
            if not callable(runner):
                print("SAFE_K_ERROR=run_tests_not_callable")
                raise SystemExit(2)
            summary = runner(data["candidate_code"], data["test_spec"])
            print("SAFE_K_SUMMARY=" + json.dumps(summary, default=str))
        except Exception as exc:
            print(f"SAFE_K_ERROR={type(exc).__name__}: {exc}")
            raise
        """
    )

    def limit_child():
        limit = int(os.environ.get("SAFE_K_RLIMIT_AS_MIB", "1024")) * 1024 * 1024  # 1 GiB
        fsize = int(os.environ.get("SAFE_K_RLIMIT_FSIZE_MIB", "4")) * 1024 * 1024
        cpu = int(os.environ.get("SAFE_K_RLIMIT_CPU_SECONDS", "3"))
        stack = int(os.environ.get("SAFE_K_RLIMIT_STACK_MIB", "64")) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_STACK, (stack, stack))

    proc = None
    output_text = ""
    try:
        with tempfile.TemporaryDirectory(prefix="safe_k_simple_gen_python_") as tmp_cwd:
            # A regular file enforces RLIMIT_FSIZE and avoids retaining unbounded
            # child output in this worker's memory.
            with tempfile.TemporaryFile(mode="w+b", dir=tmp_cwd) as output:
                proc = subprocess.Popen(
                    [sys.executable, "-c", runner_script],
                    preexec_fn=limit_child,
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    cwd=tmp_cwd,
                    start_new_session=True,
                )
                try:
                    proc.communicate(
                        input=json.dumps(payload, ensure_ascii=False).encode(),
                        timeout=UNITTEST_TIMEOUT_SECONDS,
                    )
                except subprocess.TimeoutExpired:
                    debug(f"simple_gen Python harness timed out after {UNITTEST_TIMEOUT_SECONDS}s")
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.communicate()
                    return False, {}

                output.seek(0)
                output_text = output.read(64 * 1024).decode("utf-8", errors="replace")
    except Exception as exc:
        debug(f"simple_gen Python harness subprocess launch failed: {type(exc).__name__}: {exc}")
        return False, {}

    if proc.returncode != 0:
        output_preview = output_text.strip().replace("\n", "\\n")[:400]
        debug(
            "simple_gen Python harness execution failed in subprocess: "
            f"rc={proc.returncode}, output={output_preview!r}"
        )
        return False, {}

    summary = None
    for line in output_text.splitlines():
        if line.startswith("SAFE_K_SUMMARY="):
            try:
                summary = json.loads(line[len("SAFE_K_SUMMARY=") :])
            except Exception:
                summary = None
            break
    if summary is None:
        output_preview = output_text.strip().replace("\n", "\\n")[:400]
        debug(f"simple_gen Python harness missing summary output; output={output_preview!r}")
        return False, {}

    ok, functionality_passed, security_passed, summary_func_total, summary_sec_total = validate_summary(summary)
    if not ok:
        debug("simple_gen Python harness failed: invalid summary format")
        return False, {}

    # For simple_gen tasks, totals come from executed test_code (summary_*_total), not test_spec["testcases"].
    if total_functionality <= 0 and summary_func_total is not None:
        total_functionality = summary_func_total
    if total_security <= 0 and summary_sec_total is not None:
        total_security = summary_sec_total

    functionality_passed = min(functionality_passed, total_functionality) if total_functionality > 0 else 0
    security_passed = min(security_passed, total_security) if total_security > 0 else 0
    debug(
        "simple_gen Python harness succeeded: "
        f"functionality={functionality_passed}/{total_functionality}, security={security_passed}/{total_security}"
    )
    return True, {
        "functionality": (int(functionality_passed), int(total_functionality)),
        "security": (float(security_passed), int(total_security)),
    }
