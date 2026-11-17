#!/usr/bin/env python3
"""Stage 6: LLM audit + harness filter on ``4_valid.jsonl`` rows.

Uses rubrics in ``simple_gen/c/rubrics_c/`` and audit logic from ``data_annotation_files/c/prompt_c.py``.
Writes harness-kept rows to ``5_rewritten.jsonl`` (updated ``test_code`` / ``candidate_c`` when rewritten).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from tqdm import tqdm

from c_utils import read_jsonl
from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


def _setup_annotation_imports():
    c_dir = Path(__file__).resolve().parent
    ann_dir = c_dir.parents[1] / "data_annotation_files" / "c"
    for p in (c_dir, ann_dir):
        ps = str(p)
        if ps not in sys.path:
            sys.path.insert(0, ps)
    from prompt_c import normalize_cwe, parse_cwe_list, process_row  # type: ignore

    return process_row, normalize_cwe, parse_cwe_list


process_row, normalize_cwe, parse_cwe_list = _setup_annotation_imports()


def _load_filter_module():
    import importlib.util

    path = Path(__file__).resolve().parent / "4_filter_valid_samples.py"
    spec = importlib.util.spec_from_file_location("_c_filter_for_rewrites", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_FILTER = _load_filter_module()
load_dotenv_for_script = _FILTER.load_dotenv_for_script


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def row_to_task(row: dict[str, Any]) -> dict[str, Any]:
    prompt = row.get("prompt") or row.get("user_prompt") or ""
    if not isinstance(prompt, str):
        prompt = str(prompt)
    ground_truth = row.get("candidate_c") or row.get("generated_code") or ""
    if not isinstance(ground_truth, str):
        ground_truth = str(ground_truth)
    return {
        "language": "c",
        "cwe": str(row.get("cwe") or ""),
        "function_name": str(row.get("function_name") or ""),
        "user_prompt": prompt,
        "setup_tests": row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row.get("setup_code") if isinstance(row.get("setup_code"), str) else "",
        "test_code": row.get("test_code") if isinstance(row.get("test_code"), str) else "",
        "ground_truth_solution": ground_truth,
    }


def apply_kept_row(orig: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    out = dict(orig)
    parsed = result.get("model_parsed") or {}
    change = str(parsed.get("change") or "")

    if change == "rewrite":
        out["test_code"] = result.get("final_test_code") or out.get("test_code")
        code = result.get("final_ground_truth_solution") or out.get("candidate_c")
        out["candidate_c"] = code
        out["generated_code"] = code

    for key in ("high_level_guidelines", "implementational", "sample_guidelines", "guidelines_skipped"):
        out.pop(key, None)

    out["annotation_change"] = change
    out["annotation_issues"] = parsed.get("issues")
    out["annotation_analysis"] = parsed.get("analysis")
    out["annotation_harness_passed"] = bool(result.get("harness_passed"))
    return out


def _audit_record(row: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    parsed = result.get("model_parsed") or {}
    return {
        "function_name": row.get("function_name"),
        "cwe": row.get("cwe"),
        "change": parsed.get("change"),
        "issues": parsed.get("issues"),
        "analysis": parsed.get("analysis"),
        "kept": result.get("kept"),
        "rejected": result.get("rejected"),
        "fix_error": result.get("fix_error"),
        "test_parse_error": result.get("test_parse_error"),
        "harness_passed": result.get("harness_passed"),
        "harness_error": (result.get("harness_error") or "")[:2000],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 6: audit 4_valid.jsonl; keep harness-passing rows.")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--audit-jsonl", type=Path, default=None, help="Optional per-row audit log.")
    parser.add_argument("--model", default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    args = parser.parse_args()

    load_dotenv_for_script(__file__)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")
    client = OpenAI(api_key=api_key, base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]
    print(f"input {len(rows)} rows from {args.input_jsonl}")

    results: list[dict[str, Any] | None] = [None] * len(rows)
    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {
            ex.submit(
                process_row,
                client,
                args.model,
                row_to_task(row),
                max_retries=args.retries,
                max_output_tokens=args.max_output_tokens,
            ): i
            for i, row in enumerate(rows)
        }
        for fut in tqdm(as_completed(futures), total=len(futures), desc="rewrites"):
            results[futures[fut]] = fut.result()

    kept_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for row, result in zip(rows, results):
        if result is None:
            continue
        audit_rows.append(_audit_record(row, result))
        if result.get("kept"):
            kept_rows.append(apply_kept_row(row, result))

    write_jsonl(args.output_jsonl, kept_rows)
    n_rewrite = sum(
        1 for r in results if r and r.get("kept") and (r.get("model_parsed") or {}).get("change") == "rewrite"
    )
    print(f"wrote {len(kept_rows)} kept rows ({n_rewrite} rewrites) -> {args.output_jsonl}")

    if args.audit_jsonl is not None:
        write_jsonl(args.audit_jsonl, audit_rows)
        print(f"wrote audit {len(audit_rows)} rows -> {args.audit_jsonl}")


if __name__ == "__main__":
    main()
