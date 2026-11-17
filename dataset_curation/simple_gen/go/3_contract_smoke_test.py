#!/usr/bin/env python3
"""Static (+ optional pytest) contract checks for Go simple_gen rows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from tqdm import tqdm

from go_utils import harness_fully_passes, parse_and_validate_pytest, read_jsonl, write_jsonl

VERL_ROOT = Path(__file__).resolve().parents[2] / "verl"
if str(VERL_ROOT) not in sys.path:
    sys.path.insert(0, str(VERL_ROOT))

try:
    from recipe.security_harness.execution_harness_go import run_simple_gen_go_harness_unittest
except ImportError:
    from execution_harness_go import run_simple_gen_go_harness_unittest


def _validate_row(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    mismatches: List[Dict[str, Any]] = []
    try:
        setup = row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else ""
        tests = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
        md = (
            "## test setup\n```python\n"
            + setup.strip()
            + "\n```\n\n## pytest tests\n```python\n"
            + tests.strip()
            + "\n```\n"
        )
        parse_and_validate_pytest(md)
    except Exception as e:
        mismatches.append({"kind": "pytest_harness_invalid", "error": f"{type(e).__name__}: {e}"})
    return mismatches


def _go_smoke(row: Dict[str, Any], *, candidate_field: str) -> List[Dict[str, Any]]:
    raw = row.get(candidate_field)
    if not isinstance(raw, str) or not raw.strip():
        return [{"kind": "missing_candidate", "error": f"missing candidate field {candidate_field!r}"}]
    ok, result = run_simple_gen_go_harness_unittest(raw, row)
    if harness_fully_passes(ok, result):
        return []
    return [{"kind": "go_smoke_failed", "error": json.dumps(result, ensure_ascii=False, default=str)}]


def main() -> None:
    p = argparse.ArgumentParser(description="Contract checks for Go simple_gen JSONL rows")
    p.add_argument("--input-jsonl", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=-1)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--filtered-jsonl", type=Path, default=None)
    p.add_argument("--max-mismatches-per-row", type=int, default=20)
    p.add_argument(
        "--go-smoke",
        action="store_true",
        help="Run candidate Go through the Go harness after static validation.",
    )
    p.add_argument("--candidate-field", type=str, default="candidate_go")
    args = p.parse_args()

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    report_rows: List[Dict[str, Any]] = []
    kept_rows: List[Dict[str, Any]] = []
    total_mismatches = 0

    for row_index, row in tqdm(enumerate(rows), total=len(rows), desc="Checking rows"):
        mismatches = _validate_row(row)
        if args.go_smoke and not mismatches:
            mismatches.extend(_go_smoke(row, candidate_field=args.candidate_field))

        capped = mismatches[: int(args.max_mismatches_per_row)]
        kinds = [m.get("kind") for m in mismatches if isinstance(m, dict)]
        entry = {
            "row_index": row_index,
            "function_name": row.get("function_name"),
            "contract_mismatches_count": len(mismatches),
            "total_pytest_harness_invalid": sum(1 for k in kinds if k == "pytest_harness_invalid"),
            "total_go_smoke_failed": sum(1 for k in kinds if k == "go_smoke_failed"),
            "contract_mismatches": capped,
        }
        report_rows.append(entry)
        if not mismatches:
            kept_rows.append(row)
        total_mismatches += len(mismatches)

    summary = {
        "rows_checked": len(rows),
        "rows_kept": len(kept_rows),
        "rows_dropped": len(rows) - len(kept_rows),
        "total_contract_mismatches": total_mismatches,
        "rows_with_mismatches": sum(1 for r in report_rows if r["contract_mismatches_count"] > 0),
        "details": report_rows,
    }

    if args.filtered_jsonl is not None:
        write_jsonl(args.filtered_jsonl, kept_rows)
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
