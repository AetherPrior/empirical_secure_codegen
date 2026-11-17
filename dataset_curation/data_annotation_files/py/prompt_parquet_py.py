#!/usr/bin/env python3
"""Audit and rewrite test cases from RL parquet rows (no pre-existing annotations).

Reads VeRL / GRPO parquet (e.g. ``python_cwe_GRPO.parquet``), runs the same LLM
audit as ``prompt_py.py``, and writes a plain CSV with original fields plus
rewritten ``test_code`` / ``ground_truth_solution``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from tqdm import tqdm

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL
from prompt_py import (
    extract_solution_code,
    format_test_code,
    model_slug,
    normalize_cwe,
    parse_cwe_list,
    process_row,
)

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


OUTPUT_FIELDS = [
    "language",
    "cwe",
    "source_index",
    "function_name",
    "user_prompt",
    "setup_tests",
    "test_code",
    "ground_truth_solution",
    "new_test_code",
    "new_ground_truth_solution",
    "change",
    "issues",
    "analysis",
    "fix_error",
    "test_parse_error",
]


def _user_prompt_from_chat(prompt: Any) -> str:
    if not isinstance(prompt, list):
        return ""
    for msg in prompt:
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content
    return ""


def _task_from_fields(
    *,
    language: str,
    cwe: str,
    function_name: str,
    user_prompt: str,
    test_code: str,
    ground_truth_solution: str,
    setup_tests: str = "",
    setup_code: str = "",
) -> dict[str, Any] | None:
    if language and cwe and function_name and user_prompt.strip() and test_code.strip():
        return {
            "language": language,
            "cwe": cwe,
            "function_name": function_name,
            "user_prompt": user_prompt,
            "setup_tests": setup_tests,
            "setup_code": setup_code,
            "test_code": test_code,
            "ground_truth_solution": ground_truth_solution,
        }
    return None


def load_pairs_from_parquet(input_parquet: Path) -> list[tuple[dict[str, str], dict[str, Any]]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("pyarrow is required to read parquet (pip install pyarrow)") from exc

    pairs: list[tuple[dict[str, str], dict[str, Any]]] = []
    for row in pq.read_table(input_parquet).to_pylist():
        extra = row.get("extra_info") if isinstance(row.get("extra_info"), dict) else {}
        gt = row.get("reward_model", {}).get("ground_truth") if isinstance(row.get("reward_model"), dict) else {}
        if not isinstance(gt, dict):
            gt = {}

        lang = str(extra.get("language") or row.get("lang") or gt.get("language") or "python").strip()
        if lang == "py":
            lang = "python"
        cwe = str(extra.get("cwe") or gt.get("cwe") or "").strip()
        fn = str(extra.get("function_name") or gt.get("function_name") or "").strip()
        user_prompt = str(extra.get("user_prompt") or gt.get("prompt") or _user_prompt_from_chat(row.get("prompt")) or "")
        test_code = str(gt.get("test_code") or "")
        ground_truth_solution = str(extra.get("generated_code") or "")
        setup_tests = str(gt.get("setup_tests") or "")
        setup_code = str(gt.get("setup_code") or "")

        src = {
            "language": lang,
            "cwe": cwe,
            "source_index": str(extra.get("index", "")),
            "function_name": fn,
            "user_prompt": user_prompt,
            "test_code": test_code,
            "ground_truth_solution": ground_truth_solution,
        }
        task = _task_from_fields(
            language=lang,
            cwe=cwe,
            function_name=fn,
            user_prompt=user_prompt,
            test_code=test_code,
            ground_truth_solution=ground_truth_solution,
            setup_tests=setup_tests,
            setup_code=setup_code,
        )
        if task is not None:
            pairs.append((src, task))
    return pairs


def rewrite_output_path(output_dir: Path, model: str, cwe: str, stamp: str) -> Path:
    tag = normalize_cwe(cwe).lower().replace("-", "")
    return output_dir / f"data_annotation_{model_slug(model)}_{stamp}_{tag}_rewrites.csv"


def beautify_code(code: str) -> str:
    code = (code or "").strip()
    if not code:
        return ""
    return format_test_code(code)


def build_output_row(
    src: dict[str, str],
    task: dict[str, object],
    result: dict[str, object],
) -> dict[str, str]:
    parsed = result.get("model_parsed") or {}
    change = parsed.get("change") or ""
    if result.get("rejected"):
        change = "reject"

    orig_test = str(task["test_code"])
    orig_gt = str(task["ground_truth_solution"])
    new_test = ""
    new_gt = ""

    if result.get("kept"):
        new_test = str(result.get("final_test_code") or "")
        new_gt = str(result.get("final_ground_truth_solution") or "")
    elif change == "UNCHANGED":
        new_test = orig_test
        new_gt = orig_gt
    elif change == "rewrite":
        new_test = str(parsed.get("test_code") or "")
        new_gt = extract_solution_code(str(parsed.get("ground_truth_solution") or ""))
        if new_test.strip().upper() == "UNCHANGED":
            new_test = orig_test
        if not new_gt.strip() or new_gt.strip().upper() == "UNCHANGED":
            new_gt = orig_gt

    issues = parsed.get("issues")
    return {
        "language": str(task["language"]),
        "cwe": str(task["cwe"]),
        "source_index": str(src.get("source_index") or ""),
        "function_name": str(task["function_name"]),
        "user_prompt": str(task["user_prompt"]),
        "setup_tests": str(task.get("setup_tests") or ""),
        "test_code": beautify_code(orig_test),
        "ground_truth_solution": beautify_code(orig_gt),
        "new_test_code": beautify_code(new_test),
        "new_ground_truth_solution": beautify_code(new_gt),
        "change": change,
        "issues": "" if issues is None else str(issues),
        "analysis": str(parsed.get("analysis") or ""),
        "fix_error": "" if result.get("fix_error") is None else str(result.get("fix_error")),
        "test_parse_error": str(result.get("test_parse_error") or ""),
    }


def run_cwe_rewrite(
    client: OpenAI,
    model: str,
    cwe: str,
    pairs: list[tuple[dict[str, str], dict[str, object]]],
    *,
    max_rows: int,
    max_workers: int,
    retries: int,
    max_output_tokens: int,
    output_path: Path,
    audit_jsonl: Path | None,
) -> None:
    cwe_pairs = [(src, task) for src, task in pairs if normalize_cwe(str(task["cwe"])) == cwe]
    if max_rows > 0:
        cwe_pairs = cwe_pairs[:max_rows]
    print(f"{cwe}: {len(cwe_pairs)} rows")
    if not cwe_pairs:
        return

    results: list[dict[str, object] | None] = [None] * len(cwe_pairs)
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = {
            ex.submit(
                process_row,
                client,
                model,
                task,
                max_retries=retries,
                max_output_tokens=max_output_tokens,
            ): i
            for i, (_, task) in enumerate(cwe_pairs)
        }
        for fut in tqdm(as_completed(futures), total=len(futures), desc=cwe):
            results[futures[fut]] = fut.result()

    out_rows: list[dict[str, str]] = []
    audit_records: list[dict[str, object]] = []
    for (src, task), result in zip(cwe_pairs, results):
        if result is None:
            continue
        out_rows.append(build_output_row(src, task, result))
        if audit_jsonl is not None:
            parsed = result.get("model_parsed") or {}
            audit_records.append(
                {
                    "cwe": cwe,
                    "function_name": task["function_name"],
                    "source_index": src.get("source_index"),
                    "fix_error": result.get("fix_error"),
                    "change": parsed.get("change"),
                    "issues": parsed.get("issues"),
                    "analysis": parsed.get("analysis"),
                    "rejected": result.get("rejected"),
                    "test_parse_error": result.get("test_parse_error"),
                    "kept": result.get("kept"),
                }
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)

    kept_n = sum(1 for result in results if result and result.get("kept"))
    print(f"wrote {len(out_rows)} rows ({kept_n} kept) -> {output_path}")

    if audit_jsonl is not None:
        audit_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with audit_jsonl.open("w", encoding="utf-8") as f:
            for rec in audit_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"wrote audit log -> {audit_jsonl}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rewrite test cases from RL parquet (plain CSV output, no compare columns)."
    )
    parser.add_argument(
        "--input-parquet",
        type=str,
        required=True,
        help="Local parquet path or HF dataset id (e.g. anonymous/python_cwe_GRPO).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory for per-CWE *_rewrites.csv outputs.",
    )
    parser.add_argument(
        "--cwes",
        nargs="+",
        default=["CWE-78"],
        help="CWE ids to process. Example: --cwes CWE-78 CWE-89",
    )
    parser.add_argument("--model", default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1, help="Cap rows per CWE (-1 = all).")
    parser.add_argument("--max-workers", type=int, default=16)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument(
        "--audit-jsonl",
        type=Path,
        default=None,
        help="Optional audit JSONL path prefix; writes <prefix>_cweNNN.audit.jsonl per CWE.",
    )
    args = parser.parse_args()

    cwes = parse_cwe_list(args.cwes)
    if not cwes:
        raise SystemExit("no CWEs to process")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")
    client = OpenAI(api_key=api_key, base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))

    input_path = Path(args.input_parquet)
    if not input_path.is_file() and "/" in args.input_parquet and not args.input_parquet.endswith(".parquet"):
        from huggingface_hub import hf_hub_download
        name = args.input_parquet.split("/")[-1]
        input_path = Path(hf_hub_download(repo_id=args.input_parquet, filename=f"{name}.parquet", repo_type="dataset"))
    pairs = load_pairs_from_parquet(input_path.resolve())
    print(f"loaded {len(pairs)} processable rows from {input_path}")
    print(f"CWES: {', '.join(cwes)}")

    output_dir = args.output_dir.resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    for cwe in cwes:
        out_path = rewrite_output_path(output_dir, args.model, cwe, stamp)
        audit_path = None
        if args.audit_jsonl is not None:
            prefix = args.audit_jsonl.resolve()
            tag = normalize_cwe(cwe).lower().replace("-", "")
            audit_path = prefix.parent / f"{prefix.stem}_{tag}{prefix.suffix or '.jsonl'}"
        run_cwe_rewrite(
            client,
            args.model,
            cwe,
            pairs,
            max_rows=args.max_rows,
            max_workers=args.max_workers,
            retries=args.retries,
            max_output_tokens=args.max_output_tokens,
            output_path=out_path,
            audit_jsonl=audit_path,
        )


if __name__ == "__main__":
    main()
