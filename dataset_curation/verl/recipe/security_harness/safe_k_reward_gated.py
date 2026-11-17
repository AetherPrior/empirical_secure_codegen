import ast
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from collections import defaultdict
CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)
_ROLLOUT_GROUP = defaultdict(list)
_ROLLOUT_CODE_GROUP = defaultdict(list)
_ROLLOUT_LOCK = threading.Lock()
_ROLLOUT_N = int(os.getenv("ROLLOUT_N", "8"))

def _env_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        return int(value)
    except Exception:
        return default


SECURITY_RATIO = float(os.getenv("SECURITY_RATIO", "0.5"))
UT_RATIO = float(os.getenv("UT_RATIO", "0.7"))
UNITTEST_TIMEOUT_SECONDS = float(os.getenv("UNITTEST_TIMEOUT_SECONDS", "5.0"))
REWARD_DEBUG = os.getenv("REWARD_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}
REWARD_DEBUG_CODE_MAX_CHARS = _env_int("REWARD_DEBUG_CODE_MAX_CHARS", 1200)

SIMPLE_GEN_TESTING_HARNESS = r"""
import builtins

def _expects_exception_value(expected):
    return expected is Exception or str(expected).lower() == "exception"

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
        try:
            actual = func(**kwargs)
            if _expects_exception_value(expected):
                return False
            return actual == expected
        except Exception:
            return _expects_exception_value(expected)

    functionality_passed = 0
    for case in functionality_cases:
        if isinstance(case, dict) and _run_one(case):
            functionality_passed += 1

    security_passed = 0
    for case in security_cases:
        if isinstance(case, dict) and _run_one(case):
            security_passed += 1

    return {
        "functionality_passed": int(functionality_passed),
        "security_passed": int(security_passed),
        "functionality_total": int(len(functionality_cases)),
        "security_total": int(len(security_cases)),
    }
"""


def _debug(msg: str) -> None:
    if REWARD_DEBUG:
        print(f"[safe_k_reward] {msg}", file=sys.stderr, flush=True)


def _debug_code_block(label: str, code: str) -> None:
    if not REWARD_DEBUG:
        return
    if not isinstance(code, str):
        # _debug(f"{label}: <non-string code>")
        return

    text = code
    truncated = False
    if REWARD_DEBUG_CODE_MAX_CHARS > 0 and len(text) > REWARD_DEBUG_CODE_MAX_CHARS:
        text = text[:REWARD_DEBUG_CODE_MAX_CHARS]
        truncated = True

    suffix = " (truncated)" if truncated else ""
    # _debug(f"{label}{suffix}:\n```python\n{text}\n```")


def _normalize_code_for_similarity(code: str) -> str:
    """Whitespace-normalized fingerprint for comparing rollouts (not semantic)."""
    if not isinstance(code, str):
        return ""
    return " ".join(code.split())


def _pairwise_similarity_stats(normalized_codes: list[str]) -> dict[str, float | int]:
    """Mean/min/max SequenceMatcher ratio over all unordered pairs; also unique count."""
    n = len(normalized_codes)
    if n < 2:
        return {
            "n": n,
            "unique_normalized": len(set(normalized_codes)),
            "pairwise_mean": 1.0 if n <= 1 else float("nan"),
            "pairwise_min": 1.0 if n <= 1 else float("nan"),
            "pairwise_max": 1.0 if n <= 1 else float("nan"),
            "identical_pair_fraction": float("nan"),
        }
    ratios: list[float] = []
    identical_pairs = 0
    total_pairs = 0
    for i in range(n):
        for j in range(i + 1, n):
            a, b = normalized_codes[i], normalized_codes[j]
            total_pairs += 1
            if a == b:
                identical_pairs += 1
                ratios.append(1.0)
            else:
                ratios.append(difflib.SequenceMatcher(None, a, b).ratio())
    return {
        "n": n,
        "unique_normalized": len(set(normalized_codes)),
        "pairwise_mean": sum(ratios) / len(ratios),
        "pairwise_min": min(ratios),
        "pairwise_max": max(ratios),
        "identical_pair_fraction": identical_pairs / total_pairs if total_pairs else 0.0,
    }


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    path.mkdir(parents=True, exist_ok=True)
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _extract_candidate_code(solution_str: str) -> str:
    if not isinstance(solution_str, str):
        return ""
    text = solution_str or ""
    matches = [m.strip() for m in CODE_BLOCK_RE.findall(text) if isinstance(m, str) and m.strip()]
    # Prefer a fenced block that parses as valid python
    for block in matches:
        try:
            ast.parse(block)
            # _debug("selected code block that parses as valid Python")
            return block
        except Exception:
            continue

    # If no fenced block parses, prefer a block that contains a likely function/class definition
    for block in matches:
        lower = block.lower()
        if re.search(r"\bdef\s+[a-zA-Z_]", lower) or re.search(r"\bclass\s+[A-Za-z_]", lower) or "return" in lower:
            # _debug("selected code block by heuristic (contains def/class/return)")
            return block

    # If fenced blocks exist but none matched heuristics, return the first fenced block
    if matches:
        # _debug("falling back to first fenced code block")
        return matches[0]

    # No fenced code blocks: try to extract python-like tail from the text
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if re.match(r"\s*(from\s+\w+\s+import|import\s+\w+|class\s+\w+|def\s+\w+|if\s+__name__\s*==|@\w+|\w+\s*=)", line):
            candidate = "\n".join(lines[idx:]).strip()
            try:
                ast.parse(candidate)
                # _debug("extracted python fallback from plain text")
                return candidate
            except Exception:
                # _debug("python fallback found but parsing failed; returning fallback anyway")
                return candidate

    # As a last resort, return the whole text
    # _debug("no code blocks or python-like tail found; returning full text")
    return text.strip()


def _to_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def _maybe_simple_gen_bundle(ground_truth: Any) -> tuple[str | None, dict[str, Any] | None]:
    """If `ground_truth` looks like a simple_gen task row, synthesize a SDPO-style harness bundle."""
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


def _extract_harness_bundle(ground_truth: Any) -> tuple[str | None, dict[str, Any] | None]:
    # Security-harness training always uses simple_gen-style ground_truth.
    return _maybe_simple_gen_bundle(ground_truth)


def _normalize_extra_info(extra_info: Any) -> dict[str, Any]:
    details = _to_dict(extra_info)
    if details is None:
        return {}

    nested = _to_dict(details.get("extra_info"))
    if nested is not None:
        return nested

    return details


def _count_totals_from_test_spec(test_spec: dict[str, Any]) -> tuple[int, int]:
    testcases = test_spec.get("testcases")
    if not isinstance(testcases, dict):
        return 0, 0

    functionality_cases = testcases.get("functionality", [])
    security_cases = testcases.get("security", [])

    total_functionality = len(functionality_cases) if isinstance(functionality_cases, list) else 0
    total_security = len(security_cases) if isinstance(security_cases, list) else 0
    return total_functionality, total_security


def _validate_summary(summary: Any) -> tuple[bool, int, int, int | None, int | None]:
    if not isinstance(summary, dict):
        return False, 0, 0, None, None

    functionality_passed = summary.get("functionality_passed")
    security_passed = summary.get("security_passed")
    if not isinstance(functionality_passed, int) or not isinstance(security_passed, int):
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


def _compute_hybrid_score(functionality_passed: int, security_passed: int, total_functionality: int, total_security: int) -> tuple[float, float, float]:
    if total_functionality <= 0 or total_security <= 0:
        return 0.0, 0.0, 0.0
    utility_score = functionality_passed / total_functionality
    security_score = security_passed / total_security

    ut_score = utility_score * security_score

    return UT_RATIO * ut_score, utility_score, security_score


def _run_simple_gen_harness_unittest(candidate_code: str, ground_truth: Any) -> tuple[bool, dict[str, tuple[int, int]]]:
    testing_harness, test_spec = _extract_harness_bundle(ground_truth)
    if testing_harness is None or test_spec is None:
        _debug("simple_gen harness unavailable: missing testing_harness/test_spec")
        if REWARD_DEBUG:
            try:
                _debug(
                    f"simple_gen _run_simple_gen_harness_unittest ground_truth type={type(ground_truth).__name__} "
                    f"repr={repr(ground_truth)[:400]}"
                )
            except Exception:
                _debug("simple_gen harness debug dump failed")
        return False, {}

    total_functionality, total_security = _count_totals_from_test_spec(test_spec)
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

    try:
        proc = subprocess.run(
            [sys.executable, "-c", runner_script],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            timeout=UNITTEST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        _debug(f"simple_gen harness timed out after {UNITTEST_TIMEOUT_SECONDS}s")
        return False, {}
    except Exception as exc:
        _debug(f"simple_gen harness subprocess launch failed: {type(exc).__name__}: {exc}")
        return False, {}

    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "").strip().replace("\n", "\\n")[:400]
        stdout_preview = (proc.stdout or "").strip().replace("\n", "\\n")[:400]
        _debug(
            "simple_gen harness execution failed in subprocess: "
            f"rc={proc.returncode}, stdout={stdout_preview!r}, stderr={stderr_preview!r}"
        )
        return False, {}

    summary = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("SAFE_K_SUMMARY="):
            try:
                summary = json.loads(line[len("SAFE_K_SUMMARY=") :])
            except Exception:
                summary = None
            break
    if summary is None:
        stdout_preview = (proc.stdout or "").strip().replace("\n", "\\n")[:400]
        _debug(f"simple_gen harness missing summary output; stdout={stdout_preview!r}")
        return False, {}

    ok, functionality_passed, security_passed, summary_cap_total, summary_safe_total = _validate_summary(summary)
    if not ok:
        _debug("simple_gen harness failed: invalid summary format")
        return False, {}

    # For simple_gen tasks, totals come from executed test_code (summary_*_total), not test_spec["testcases"].
    if total_functionality <= 0 and summary_cap_total is not None:
        total_functionality = summary_cap_total
    if total_security <= 0 and summary_safe_total is not None:
        total_security = summary_safe_total

    functionality_passed = min(functionality_passed, total_functionality) if total_functionality > 0 else 0
    security_passed = min(security_passed, total_security) if total_security > 0 else 0
    _debug(
        "simple_gen harness succeeded: "
        f"functionality={functionality_passed}/{total_functionality}, security={security_passed}/{total_security}"
    )
    return True, {
        "functionality": (functionality_passed, total_functionality),
        "security": (security_passed, total_security),
    }


def _unit_test_score(candidate_code: str, ground_truth: Any, extra_info: dict[str, Any] | None) -> tuple[bool, float]:
    details = _normalize_extra_info(extra_info)

    # _debug("starting unittest evaluation via dataset harness")
    ut_ok, ut_result = _run_simple_gen_harness_unittest(candidate_code, ground_truth)
    if not ut_ok:
        # _debug("all unittest paths failed")
        return False, -0.5, 0.0, 0.0

    functionality_passed, functionality_total = ut_result.get("functionality", (0, 0))
    security_passed, security_total = ut_result.get("security", (0, 0))

    if functionality_total <= 0 or security_total <= 0:
        # _debug("unittest totals missing; returning ut_score=0.0")
        return True, 0.0, 0.0, 0.0

    hybrid_ut_score, functionality_score, security_score = _compute_hybrid_score(functionality_passed, security_passed, functionality_total, security_total)
    _debug(
        "unittest score computed: "
        f"functionality={functionality_passed}/{functionality_total}, security={security_passed}/{security_total}, "
        f"score={hybrid_ut_score:.4f}"
    )
    return True, hybrid_ut_score, functionality_score, security_score


def _compute_score_single(data_source, solution_str, ground_truth, extra_info=None):
    del data_source

    candidate_code = _extract_candidate_code(solution_str)
    if not candidate_code:
        _debug("candidate code extraction failed (empty)")
        return -1.0
    # _debug_code_block("candidate code for scoring", candidate_code)

    try:
        ast.parse(candidate_code)
    except SyntaxError:
        _debug("candidate code has syntax error")
        return -1.0

    ut_ok, weighted_ut_score, functionality_score, security_score = _unit_test_score(candidate_code, ground_truth, extra_info)
    if not ut_ok:
        _debug("unittest evaluation failed; returning -1.0")
        return -1.0

    final_score = float(weighted_ut_score)
    _debug(
        "final score components: "
        f"ut={weighted_ut_score:.4f}, final={final_score:.4f}"
    )

    # # --- Debug: per-prompt rollout stats ---
    # try:
    #     details = _normalize_extra_info(extra_info)
    #     idx = int(details.get("index", -1))
    # except Exception:
    #     idx = -1

    # if idx >= 0:
    #     # Serialize per-index rollout aggregation: concurrent reward calls can share the
    #     # same list from defaultdict; one thread may flush+pop while another still holds
    #     # that list and appends again, then hits KeyError on del.
    #     with _ROLLOUT_LOCK:
    #         group = _ROLLOUT_GROUP[idx]
    #         group.append(float(final_score))
    #         code_group = _ROLLOUT_CODE_GROUP[idx]
    #         code_group.append(_normalize_code_for_similarity(candidate_code))

    #         # When we've seen all rollouts for this prompt, log stats once
    #         if len(group) >= _ROLLOUT_N:
    #             vals = list(group)
    #             mean = sum(vals) / len(vals)
    #             var = sum((v - mean) ** 2 for v in vals) / len(vals) if len(vals) > 1 else 0.0
    #             print(
    #                 f"[rollout_rewards] index={idx} n={len(vals)} "
    #                 f"mean={mean:.4f} var={var:.4f} "
    #                 f"min={min(vals):.4f} max={max(vals):.4f} "
    #                 f"scores={[round(v, 4) for v in vals]}",
    #                 flush=True,
    #             )
    #             sim = _pairwise_similarity_stats(code_group[: len(vals)])
    #             pm = sim["pairwise_mean"]
    #             pmin = sim["pairwise_min"]
    #             pmax = sim["pairwise_max"]
    #             pm_s = f"{pm:.4f}" if isinstance(pm, float) and pm == pm else str(pm)
    #             pmin_s = f"{pmin:.4f}" if isinstance(pmin, float) and pmin == pmin else str(pmin)
    #             pmax_s = f"{pmax:.4f}" if isinstance(pmax, float) and pmax == pmax else str(pmax)
    #             _debug(
    #                 f"[rollout_code_similarity] index={idx} n={sim['n']} "
    #                 f"unique_normalized={sim['unique_normalized']} "
    #                 f"pairwise_mean={pm_s} pairwise_min={pmin_s} pairwise_max={pmax_s} "
    #                 f"identical_pair_fraction={sim['identical_pair_fraction']:.4f}"
    #             )
    #             _ROLLOUT_GROUP.pop(idx, None)
    #             _ROLLOUT_CODE_GROUP.pop(idx, None)

    return final_score


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

        _debug(f"batch reward scoring: {n} samples")
        scores =[
            _compute_score_single(
                data_source=sources[i],
                solution_str=solutions[i],
                ground_truth=truths[i],
                extra_info=extras[i],
            )
            for i in range(n)
        ]
        print(f"batch reward scores: {scores}", file=sys.stderr, flush=True)
        return scores

    # Scalar interface used by reward_manager=naive
    return _compute_score_single(
        data_source=data_source,
        solution_str=solution_str,
        ground_truth=ground_truth,
        extra_info=extra_info,
    )
