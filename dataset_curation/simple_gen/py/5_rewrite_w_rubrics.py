#!/usr/bin/env python3
"""Audit-rewrite ``4_valid.jsonl`` rows and re-run the reward harness.

For each pipeline row (passing oracle + authoring guidelines), this script:

1. Builds an audit task from ``prompt``, ``test_code``, ``generated_code``, etc.
2. Calls an LLM audit using CWE rubrics from ``rubrics_py/rubrics.py``.
3. Applies rewritten ``test_code`` / ``generated_code`` onto the existing row keys when the harness passes.
4. Runs ``run_simple_gen_python_harness_unittest`` on the result.
5. Writes ``5_rewritten.jsonl`` — harness-passing rows only, same key set as step 5 input.

**Expected pipeline input:** ``<run-dir>/4_valid.jsonl``  
**Output:** ``<run-dir>/5_rewritten.jsonl`` (optional ``--all-output-jsonl`` for full audit metadata)
"""

from __future__ import annotations

import argparse
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tqdm import tqdm

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL
from fix_test_case_parquet import (
    ISSUE_ANTI_SECURITY,
    ISSUE_CWE_IRRELEVANT,
    SERVICE_TIER,
    _FIX_DECISION_BLOCK,
    _FIX_OUTPUT_BLOCK,
    _import_run_harness_unittest,
    _resolved_revision,
    cwe_description,
    evaluate_harness,
    extract_python_from_response,
    load_dotenv_for_script,
    normalize_cwe,
    parse_model_result,
    validate_and_normalize_test_code,
)
from rubrics_py.rubrics import rubrics
from utils import read_jsonl

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


DEFAULT_CWE_REWRITE_RUBRIC = """- **reject:** prompt requires vulnerable behavior or lacks the CWE mitigation boundary.
- **UNCHANGED:** security cases already defeat naive insecure implementations.
- **rewrite:** tests reward the exploit, wrong category, or security does not test this CWE."""

REWRITE_METADATA_KEYS = frozenset(
    {
        "original_test_code",
        "original_generated_code",
        "rewrite_change",
        "rewrite_issues",
        "rewrite_analysis",
        "rewrite_error",
        "rewrite_test_parse_error",
        "rewrite_rejected",
        "rewrite_harness_error",
        "harness_passed",
        "harness_summary_ok",
        "harness_ut_result",
    }
)


def parse_cwe_list(values: List[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        for part in value.split(","):
            cwe = normalize_cwe(part)
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def cwe_rewrite_rubric(cwe: str) -> str:
    return rubrics.get(normalize_cwe(cwe), DEFAULT_CWE_REWRITE_RUBRIC)


def build_fix_instruction(task: Dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    cwe_rubric = cwe_rewrite_rubric(cwe)
    setup_tests = task.get("setup_tests") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI_SECURITY,
        irrelevant=ISSUE_CWE_IRRELEVANT,
    )
    return f"""Audit one **{cwe}** secure-coding datapoint ({task.get("function_name", "")}, {task.get("language", "")}).

{cwe_desc}

**Harness:** run ``setup_tests``, then solution, then ``test_code`` (`functionality` + `security` cases with `input` / `output` or Exception).

## Checklist — {cwe}
{cwe_rubric}

{decision}

{output_rules}


## prompt
```
{task.get("user_prompt", "")}
```

## setup_tests (cannot be changed)
```python
{setup_tests}
```

## test_code
```python
{task.get("test_code", "")}
```

## oracle (may share test bugs)
```python
{task.get("ground_truth_solution", "")}
```
"""


def audit_process_row(
    client: OpenAI,
    model: str,
    task: Dict[str, Any],
    run_unittest: Any,
    *,
    max_retries: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "model_parsed": None,
        "fix_error": None,
        "test_parse_error": "",
        "final_test_code": "",
        "final_ground_truth_solution": "",
        "kept": False,
        "rejected": False,
        "harness_passed": False,
        "harness_ut_result": {},
        "harness_error": "",
    }

    instruction = build_fix_instruction(task)
    parsed: Optional[Dict[str, Any]] = None
    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a security benchmark auditor. "
                    "Return only one JSON object. "
                    "For every test case, audit each input field against expected output for raw preserved attacker substrings. "
                    "Rewrite on partial sanitization, prompt/test contradictions, or misplaced security tests. "
                    "When change is rewrite, test_code must fix every security case you criticized — do not echo the same bad expected outputs. "
                    "Do not rewrite for task-design debates alone."
                ),
                input=instruction,
                max_output_tokens=max_output_tokens,
                service_tier=SERVICE_TIER,
            )
            parsed_obj, err = parse_model_result((resp.output_text or "").strip())
            out["model_parsed"] = parsed_obj or None
            out["fix_error"] = err
            if err is None:
                parsed = parsed_obj
                break
            last_err = err
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    if parsed is None:
        out["fix_error"] = last_err or out.get("fix_error") or "no valid output after retries"
        return out

    if parsed.get("change") == "reject":
        out["rejected"] = True
        return out

    final_tests, _ = _resolved_revision(parsed["test_code"], task["test_code"])
    final_gt, _ = _resolved_revision(parsed["ground_truth_solution"], task["ground_truth_solution"])
    out["final_test_code"] = final_tests
    out["final_ground_truth_solution"] = extract_python_from_response(final_gt)

    final_tests, parse_err = validate_and_normalize_test_code(task["setup_tests"], final_tests)
    out["final_test_code"] = final_tests
    if parse_err:
        out["test_parse_error"] = parse_err
        return out

    passed, ut_result, harness_err = evaluate_harness(
        final_gt,
        task,
        test_code=final_tests,
        run_unittest=run_unittest,
    )
    out["harness_passed"] = passed
    out["harness_ut_result"] = {
        k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()
    }
    out["harness_error"] = harness_err
    if passed:
        out["kept"] = True
    return out


def row_to_audit_task(row: Dict[str, Any], *, language: str = "python") -> Optional[Dict[str, Any]]:
    fn = str(row.get("function_name") or "").strip()
    prompt = str(row.get("prompt") or "").strip()
    test_code = str(row.get("test_code") or "").strip()
    ground_truth = str(row.get("generated_code") or "").strip()
    cwe = str(row.get("cwe") or "").strip()
    if not (fn and prompt and test_code and ground_truth and cwe):
        return None
    return {
        "language": language,
        "cwe": cwe,
        "function_name": fn,
        "user_prompt": prompt,
        "setup_tests": str(row.get("setup_tests") or ""),
        "setup_code": str(row.get("setup_code") or ""),
        "test_code": test_code,
        "ground_truth_solution": ground_truth,
    }


def apply_rewrite(row: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """Merge audit metadata; update existing ``test_code`` / ``generated_code`` only when harness passes."""
    out = dict(row)
    parsed = result.get("model_parsed") or {}
    change = parsed.get("change") or ""
    if result.get("rejected"):
        change = "reject"

    harness_passed = bool(result.get("harness_passed"))
    original_test_code = row.get("test_code") or ""
    original_generated_code = row.get("generated_code") or ""

    out["original_test_code"] = original_test_code
    out["original_generated_code"] = original_generated_code
    out["rewrite_change"] = change
    out["rewrite_issues"] = parsed.get("issues")
    out["rewrite_analysis"] = parsed.get("analysis") or ""
    out["rewrite_error"] = result.get("fix_error")
    out["rewrite_test_parse_error"] = result.get("test_parse_error") or ""
    out["rewrite_rejected"] = bool(result.get("rejected"))
    out["rewrite_harness_error"] = result.get("harness_error") or ""
    out["harness_passed"] = harness_passed
    out["harness_summary_ok"] = harness_passed
    out["harness_ut_result"] = result.get("harness_ut_result") or {}

    if harness_passed:
        out["test_code"] = result.get("final_test_code") or original_test_code
        out["generated_code"] = result.get("final_ground_truth_solution") or original_generated_code

    return out


def row_for_output(row: Dict[str, Any]) -> Dict[str, Any]:
    """Same schema as ``4_valid.jsonl`` — drop step-6 audit metadata keys."""
    return {k: v for k, v in row.items() if k not in REWRITE_METADATA_KEYS}


def process_row(
    client: OpenAI,
    model: str,
    row: Dict[str, Any],
    *,
    language: str,
    max_retries: int,
    max_output_tokens: int,
    run_unittest: Any,
) -> Dict[str, Any]:
    task = row_to_audit_task(row, language=language)
    if task is None:
        out = dict(row)
        out["rewrite_error"] = "skipped: missing prompt/test_code/generated_code/function_name/cwe"
        out["rewrite_change"] = "skip"
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        return out

    audit_result = audit_process_row(
        client,
        model,
        task,
        run_unittest,
        max_retries=max_retries,
        max_output_tokens=max_output_tokens,
    )
    return apply_rewrite(row, audit_result)


def discover_guidelines_paths(
    run_root: Path,
    *,
    language: str,
    cwes: Optional[List[str]],
) -> List[Tuple[Path, Path]]:
    """Return ``(input_jsonl, output_jsonl)`` pairs under ``run_root/<language>/cwe-*``."""
    lang_dir = run_root / language
    if not lang_dir.is_dir():
        raise FileNotFoundError(f"language directory not found: {lang_dir}")

    wanted = {normalize_cwe(c) for c in cwes} if cwes else None
    pairs: List[Tuple[Path, Path]] = []
    for cwe_dir in sorted(lang_dir.glob("cwe-*")):
        if not cwe_dir.is_dir():
            continue
        m = re.search(r"cwe[-_]?(\d+)", cwe_dir.name, re.I)
        cwe_id = f"CWE-{m.group(1)}" if m else normalize_cwe(cwe_dir.name)
        if wanted is not None and cwe_id not in wanted:
            continue
        inp = cwe_dir / "4_valid.jsonl"
        if not inp.is_file():
            continue
        pairs.append((inp, cwe_dir / "5_rewritten.jsonl"))
    return pairs


def run_file(
    client: OpenAI,
    model: str,
    input_jsonl: Path,
    output_jsonl: Path,
    *,
    language: str,
    max_rows: int,
    max_workers: int,
    retries: int,
    max_output_tokens: int,
    run_unittest: Any,
    all_output_jsonl: Optional[Path],
) -> None:
    rows = read_jsonl(input_jsonl)
    if max_rows > 0:
        rows = rows[:max_rows]
    if not rows:
        print(f"{input_jsonl}: no rows, skipping")
        return

    results: List[Optional[Dict[str, Any]]] = [None] * len(rows)

    def _one(i: int, r: Dict[str, Any]) -> Dict[str, Any]:
        return process_row(
            client,
            model,
            r,
            language=language,
            max_retries=retries,
            max_output_tokens=max_output_tokens,
            run_unittest=run_unittest,
        )

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = {ex.submit(_one, i, rows[i]): i for i in range(len(rows))}
        desc = input_jsonl.parent.name
        for fut in tqdm(as_completed(futures), total=len(futures), desc=desc):
            results[futures[fut]] = fut.result()

    evaluated = [r for r in results if r is not None]
    passing = [r for r in evaluated if r.get("harness_passed")]

    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with output_jsonl.open("w", encoding="utf-8") as f:
        for r in passing:
            f.write(json.dumps(row_for_output(r), ensure_ascii=False) + "\n")

    if all_output_jsonl is not None:
        all_output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with all_output_jsonl.open("w", encoding="utf-8") as f:
            for r in evaluated:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_pass = len(passing)
    n_reject = sum(1 for r in evaluated if r.get("rewrite_rejected"))
    msg = (
        f"{input_jsonl.name}: wrote {n_pass} passing rows -> {output_jsonl} "
        f"(input {len(rows)}, harness_passed {n_pass}, rewrite_rejected {n_reject})"
    )
    if all_output_jsonl is not None:
        msg += f"; all eval -> {all_output_jsonl}"
    print(msg)


def main() -> None:
    load_dotenv_for_script()
    parser = argparse.ArgumentParser(
        description="Rewrite 4_valid.jsonl rows via rubrics_py audit and re-run harness"
    )
    parser.add_argument(
        "--input-jsonl",
        type=Path,
        default=None,
        help="Single input JSONL (default when not using --run-root).",
    )
    parser.add_argument(
        "--output-jsonl",
        type=Path,
        default=None,
        help="Single output JSONL (default: sibling 5_rewritten.jsonl).",
    )
    parser.add_argument(
        "--run-root",
        type=Path,
        default=None,
        help="Process every <run-root>/<language>/cwe-*/4_valid.jsonl.",
    )
    parser.add_argument("--language", type=str, default="python")
    parser.add_argument(
        "--cwes",
        nargs="+",
        default=None,
        help="Optional CWE filter when using --run-root (e.g. CWE-1333 CWE-78).",
    )
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=120.0,
        help="Timeout (seconds) for each OpenAI API call.",
    )
    parser.add_argument(
        "--all-output-jsonl",
        type=Path,
        default=None,
        help="Optional path for every evaluated row with rewrite/harness metadata.",
    )
    args = parser.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL),
        timeout=args.request_timeout,
    )
    run_unittest = _import_run_harness_unittest(args.language)

    cwes = parse_cwe_list(args.cwes) if args.cwes else None

    if args.run_root is not None:
        pairs = discover_guidelines_paths(args.run_root.resolve(), language=args.language, cwes=cwes)
        if not pairs:
            raise SystemExit(f"no 4_valid.jsonl files under {args.run_root}/{args.language}")
        for inp, out in pairs:
            run_file(
                client,
                args.model,
                inp,
                out,
                language=args.language,
                max_rows=args.max_rows,
                max_workers=args.max_workers,
                retries=args.retries,
                max_output_tokens=args.max_output_tokens,
                run_unittest=run_unittest,
                all_output_jsonl=args.all_output_jsonl,
            )
        return

    if args.input_jsonl is None:
        raise SystemExit("provide --input-jsonl or --run-root")

    input_jsonl = args.input_jsonl.resolve()
    output_jsonl = args.output_jsonl or input_jsonl.with_name("5_rewritten.jsonl")
    run_file(
        client,
        args.model,
        input_jsonl,
        output_jsonl.resolve(),
        language=args.language,
        max_rows=args.max_rows,
        max_workers=args.max_workers,
        retries=args.retries,
        max_output_tokens=args.max_output_tokens,
        run_unittest=run_unittest,
        all_output_jsonl=args.all_output_jsonl.resolve() if args.all_output_jsonl else None,
    )


if __name__ == "__main__":
    main()
