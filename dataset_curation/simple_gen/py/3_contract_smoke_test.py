#!/usr/bin/env python3
from __future__ import annotations

"""
Contract smoke test (non-generation dependent).

The evaluator calls the generated function as:

    func(**case["input"])

So, for each testcase row:
  - every top-level key in each test case's input dict must match a real
    parameter name in the function signature (derived from `row["arguments"]`)
  - each case's input must be a dict (otherwise it's a harness contract error)

This script defines a deterministic dummy function with the exact parameter
names declared in each row's `arguments`, then attempts to call it for every
test case input. It reports any TypeErrors caused by unexpected/missing kwargs.

It does not run or verify the real generated implementation logic.

Note: ``parse_tests`` executes ``setup_tests`` and ``test_code`` with ``exec``. Any
expensive work encoded *inside* the ``tests = {...}`` literal (for example
``"output": brute_reference("x" * 2000)``) runs at import time and can make this
script appear to hang even though the dummy function calls themselves are cheap.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tqdm import tqdm

from utils import read_jsonl, parse_tests

_WORKER_ENV = "CONTRACT_SMOKE_ROW_WORKER"


def _build_dummy_function_source(function_name: str, param_names: List[str]) -> str:
    params = ", ".join(param_names)
    # Keep the body extremely small; we only care about signature compatibility.
    return f"def {function_name}({params}):\n    return None\n"


def _dummy_call_signature_mismatch(
    *,
    function_name: str,
    param_names: List[str],
    setup_tests: Any,
    test_code: Any,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Returns (mismatch_rows, total_checked_cases).
    Each mismatch entry describes a single failing test case input.
    """
    src = _build_dummy_function_source(function_name, param_names)

    env: Dict[str, Any] = {}
    try:
        exec(src, env, env)
    except Exception as e:
        # If the dummy cannot be defined (invalid function name or params), treat
        # all cases as contract failures with one error marker.
        return (
            [
                {
                    "kind": "dummy_definition_error",
                    "error": f"{type(e).__name__}: {e}",
                }
            ],
            0,
        )

    func = env.get(function_name)
    if not callable(func):
        return (
            [{"kind": "dummy_definition_error", "error": "function not callable"}],
            0,
        )

    try:
        # breakpoint()
        tests = parse_tests(setup_tests, test_code)
    except Exception as e:
        return (
            [
                {
                    "kind": "test_parse_error",
                    "error": f"{type(e).__name__}: {e}",
                }
            ],
            0,
        )

    mismatches: List[Dict[str, Any]] = []
    total = 0

    try:
        # parse_tests executes setup_tests + test_code and expects it to define
        # a dict named `tests` in that code.
        for category in ("functionality", "security"):
            cases = tests.get(category) or []
            for idx, case in enumerate(cases):
                total += 1
                case_input = None
                try:
                    case_input = case["input"]
                except Exception:
                    mismatches.append(
                        {
                            "category": category,
                            "case_index": idx,
                            "kind": "invalid_case_input_shape",
                            "error": "case['input'] missing or unreadable",
                        }
                    )
                    continue

                if not isinstance(case_input, dict):
                    mismatches.append(
                        {
                            "category": category,
                            "case_index": idx,
                            "kind": "harness_error",
                            "error": 'case["input"] must be a dict',
                        }
                    )
                    continue

                try:
                    _ = func(**case_input)
                except TypeError as e:
                    mismatches.append(
                        {
                            "category": category,
                            "case_index": idx,
                            "kind": "kwargs_contract_error",
                            "error": str(e),
                            "case_input_keys": sorted(list(case_input.keys())),
                            "expected_param_names": sorted(param_names),
                        }
                    )
                except Exception as e:
                    # Dummy should not raise except for signature mismatch, but keep a
                    # catch-all marker to avoid hiding issues.
                    mismatches.append(
                        {
                            "category": category,
                            "case_index": idx,
                            "kind": "dummy_runtime_error",
                            "error": f"{type(e).__name__}: {e}",
                            "case_input_keys": sorted(list(case_input.keys())),
                            "expected_param_names": sorted(param_names),
                        }
                    )
    except Exception as e:
        mismatches.append(
            {
                "kind": "test_parse_error",
                "error": f"{type(e).__name__}: {e}",
            }
        )

    return mismatches, total


def _worker_row_check_from_stdin() -> None:
    """Child entry: read one JSON payload from stdin, write mismatches JSON to stdout."""
    payload = json.loads(sys.stdin.read())
    mismatches, total = _dummy_call_signature_mismatch(
        function_name=payload["function_name"],
        param_names=payload["param_names"],
        setup_tests=payload.get("setup_tests"),
        test_code=payload.get("test_code"),
    )
    json.dump({"mismatches": mismatches, "total": total}, sys.stdout, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def _dummy_call_signature_mismatch_subprocess(
    *,
    function_name: str,
    param_names: List[str],
    setup_tests: Any,
    test_code: Any,
    timeout: float,
) -> Tuple[List[Dict[str, Any]], int]:
    """Run contract check in a fresh process; kill it after ``timeout`` seconds."""
    payload = {
        "function_name": function_name,
        "param_names": param_names,
        "setup_tests": setup_tests,
        "test_code": test_code,
    }
    try:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve())],
            input=json.dumps(payload, ensure_ascii=False, default=str),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, _WORKER_ENV: "1"},
            cwd=str(Path(__file__).resolve().parent),
        )
    except subprocess.TimeoutExpired:
        return (
            [
                {
                    "kind": "row_timeout",
                    "error": f"row check exceeded {timeout} seconds (likely slow exec() in setup_tests/test_code)",
                }
            ],
            0,
        )
    except Exception as e:
        return (
            [
                {
                    "kind": "subprocess_error",
                    "error": f"{type(e).__name__}: {e}",
                }
            ],
            0,
        )

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:2000]
        return (
            [
                {
                    "kind": "subprocess_error",
                    "error": f"exit {proc.returncode}: {err}",
                }
            ],
            0,
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        return (
            [{"kind": "subprocess_error", "error": "empty worker stdout"}],
            0,
        )
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as e:
        return (
            [
                {
                    "kind": "subprocess_error",
                    "error": f"invalid worker JSON: {e}; stdout head={raw[:400]!r}",
                }
            ],
            0,
        )
    mismatches = decoded.get("mismatches")
    total = decoded.get("total")
    if not isinstance(mismatches, list) or not isinstance(total, int):
        return (
            [{"kind": "subprocess_error", "error": "worker returned unexpected shape"}],
            0,
        )
    return mismatches, total


def _extract_param_names(row: Dict[str, Any]) -> List[str]:
    args = row.get("arguments") or []
    out: List[str] = []
    for a in args:
        if not isinstance(a, dict):
            continue
        name = a.get("name")
        if isinstance(name, str) and name:
            out.append(name)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Non-generation contract smoke test")
    parser.add_argument("--input-jsonl", type=Path, required=True, help="Task JSONL with setup_tests/test_code")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--filtered-jsonl",
        type=Path,
        default=None,
        help="Optional output JSONL containing only rows with zero contract mismatches.",
    )
    parser.add_argument("--max-mismatches-per-row", type=int, default=20)
    parser.add_argument(
        "--row-timeout-seconds",
        type=float,
        default=5.0,
        help="Kill the per-row harness check after this many seconds (subprocess). "
        "Use 0 to disable (run in-process; may hang on pathological test_code).",
    )
    args = parser.parse_args()

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    report_rows: List[Dict[str, Any]] = []
    kept_rows: List[Dict[str, Any]] = []

    total_mismatches = 0
    total_checked = 0

    for row_index, row in tqdm(enumerate(rows), total=len(rows), desc="Checking rows"):
        fn = row.get("function_name") or "<unknown>"
        param_names = _extract_param_names(row)

        if args.row_timeout_seconds and args.row_timeout_seconds > 0:
            mismatches, total = _dummy_call_signature_mismatch_subprocess(
                function_name=str(fn),
                param_names=param_names,
                setup_tests=row.get("setup_tests"),
                test_code=row.get("test_code"),
                timeout=float(args.row_timeout_seconds),
            )
        else:
            mismatches, total = _dummy_call_signature_mismatch(
                function_name=str(fn),
                param_names=param_names,
                setup_tests=row.get("setup_tests"),
                test_code=row.get("test_code"),
            )

        # Cap detail size; still count totals precisely.
        capped = mismatches[: args.max_mismatches_per_row]

        kinds = [m.get("kind") for m in mismatches if isinstance(m, dict)]
        total_kwargs_contract_errors = sum(1 for k in kinds if k == "kwargs_contract_error")
        total_harness_input_errors = sum(1 for k in kinds if k == "harness_error")
        total_test_parse_errors = sum(1 for k in kinds if k == "test_parse_error")
        total_row_timeouts = sum(1 for k in kinds if k == "row_timeout")

        row_entry = {
            "row_index": row_index,
            "function_name": fn,
            "expected_param_names": param_names,
            "total_checked_cases": total,
            "contract_mismatches_count": len(mismatches),
            "total_kwargs_contract_errors": total_kwargs_contract_errors,
            "total_harness_input_errors": total_harness_input_errors,
            "total_test_parse_errors": total_test_parse_errors,
            "total_row_timeouts": total_row_timeouts,
            "contract_mismatches": capped,
        }
        report_rows.append(row_entry)

        if len(mismatches) == 0:
            kept_rows.append(row)

        total_mismatches += len(mismatches)
        total_checked += total
        # tqdm.write(f"Row {row_index} checked {total} cases, {len(mismatches)} mismatches")
        # tqdm.write(f"Mismatches: {mismatches}")

    summary = {
        "rows_checked": len(rows),
        "rows_kept": len(kept_rows),
        "rows_dropped": len(rows) - len(kept_rows),
        "total_checked_cases": total_checked,
        "total_contract_mismatches": total_mismatches,
        "total_kwargs_contract_errors": sum(
            r.get("total_kwargs_contract_errors", 0) for r in report_rows
        ),
        "total_harness_input_errors": sum(
            r.get("total_harness_input_errors", 0) for r in report_rows
        ),
        "total_test_parse_errors": sum(r.get("total_test_parse_errors", 0) for r in report_rows),
        "rows_with_mismatches": sum(1 for r in report_rows if r["contract_mismatches_count"] > 0),
        "details": report_rows,
    }

    if args.filtered_jsonl is not None:
        args.filtered_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.filtered_jsonl.open("w", encoding="utf-8") as f:
            for r in kept_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(f"Kept {len(kept_rows)}/{len(rows)} rows with zero contract mismatches in {args.filtered_jsonl}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    else:
        # Small console summary.
        print(
            f"rows_checked={summary['rows_checked']} "
            f"total_checked_cases={summary['total_checked_cases']} "
            f"total_contract_mismatches={summary['total_contract_mismatches']} "
            f"rows_with_mismatches={summary['rows_with_mismatches']} "
            f"total_row_timeouts={summary['total_row_timeouts']}"
        )


if __name__ == "__main__":
    if os.environ.get(_WORKER_ENV) == "1":
        _worker_row_check_from_stdin()
    else:
        main()

