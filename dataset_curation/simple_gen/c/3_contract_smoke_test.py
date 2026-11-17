#!/usr/bin/env python3
"""Static contract checks for **pytest** harness rows (C tasks).

Each row is expected to contain:
- ``setup_tests`` (optional): python prelude
- ``test_code`` (required): pytest module body

Validates harness shape with ``parse_and_validate_pytest``. Full compile+pytest
evaluation happens in stage 5 (``4_filter_valid_samples.py``).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from tqdm import tqdm

from c_utils import parse_and_validate_pytest, read_jsonl


def _synthetic_md(setup_tests: Any, test_code: Any) -> str:
    setup = setup_tests if isinstance(setup_tests, str) else ""
    tests = test_code if isinstance(test_code, str) else ""
    return (
        "## test setup\n```python\n"
        f"{setup.strip()}\n"
        "```\n\n"
        "## pytest tests\n```python\n"
        f"{tests.strip()}\n"
        "```\n"
    )


def _validate_row(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    mismatches: List[Dict[str, Any]] = []
    test_code = row.get("test_code")
    if not isinstance(test_code, str) or not test_code.strip():
        mismatches.append({"kind": "missing_test_code", "error": "row.test_code must be a non-empty string"})
        return mismatches

    try:
        md = _synthetic_md(row.get("setup_tests"), test_code)
        parse_and_validate_pytest(md)
    except Exception as e:
        mismatches.append({"kind": "pytest_harness_invalid", "error": f"{type(e).__name__}: {e}"})
    return mismatches


def main() -> None:
    p = argparse.ArgumentParser(description="Static contract checks for C JSONL pytest harness rows")
    p.add_argument("--input-jsonl", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=-1)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--filtered-jsonl", type=Path, default=None)
    p.add_argument("--max-mismatches-per-row", type=int, default=20)
    args = p.parse_args()

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    report_rows: List[Dict[str, Any]] = []
    kept_rows: List[Dict[str, Any]] = []
    total_mismatches = 0

    for row_index, row in tqdm(enumerate(rows), total=len(rows), desc="Checking rows"):
        mismatches = _validate_row(row)
        capped = mismatches[: int(args.max_mismatches_per_row)]
        kinds = [m.get("kind") for m in mismatches if isinstance(m, dict)]

        row_entry = {
            "row_index": row_index,
            "function_name": row.get("function_name"),
            "contract_mismatches_count": len(mismatches),
            "total_pytest_harness_invalid": sum(1 for k in kinds if k == "pytest_harness_invalid"),
            "contract_mismatches": capped,
        }
        report_rows.append(row_entry)

        if not mismatches:
            kept_rows.append(row)

        total_mismatches += len(mismatches)
        tqdm.write(f"Row {row_index}: mismatches={len(mismatches)}")

    summary = {
        "rows_checked": len(rows),
        "rows_kept": len(kept_rows),
        "rows_dropped": len(rows) - len(kept_rows),
        "total_contract_mismatches": total_mismatches,
        "rows_with_mismatches": sum(1 for r in report_rows if r["contract_mismatches_count"] > 0),
        "details": report_rows,
    }

    if args.filtered_jsonl is not None:
        args.filtered_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.filtered_jsonl.open("w", encoding="utf-8") as f:
            for r in kept_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Kept {len(kept_rows)}/{len(rows)} rows with zero mismatches in {args.filtered_jsonl}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    else:
        print(
            f"rows_checked={summary['rows_checked']} "
            f"total_contract_mismatches={summary['total_contract_mismatches']} "
            f"rows_with_mismatches={summary['rows_with_mismatches']}"
        )


if __name__ == "__main__":
    main()
