#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from safe_k_reward import compute_score


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run safe_k_reward on simple_gen task JSONL")
    parser.add_argument("--tasks-jsonl", type=Path, required=True, help="simple_gen tasks JSONL (rows with setup_code/setup_tests/test_code/function_name)")
    parser.add_argument("--row-index", type=int, default=0, help="Row index to evaluate (0-based)")
    parser.add_argument("--solution-file", type=Path, default=None, help="Path to a python file (candidate solution)")
    parser.add_argument("--solution-text", type=str, default="", help="Raw solution text (may include ``` fenced code)")
    args = parser.parse_args()

    rows = read_jsonl(args.tasks_jsonl)
    if args.row_index < 0 or args.row_index >= len(rows):
        raise SystemExit(f"--row-index out of range: {args.row_index} (len={len(rows)})")

    row = rows[args.row_index]

    if args.solution_file is not None:
        solution_str = args.solution_file.read_text(encoding="utf-8")
    else:
        solution_str = args.solution_text

    score = compute_score(
        data_source=None,
        solution_str=solution_str,
        ground_truth=row,
        extra_info=None,
    )
    print(score)


if __name__ == "__main__":
    main()

