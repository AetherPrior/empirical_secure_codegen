#!/usr/bin/env python3
"""Audit and rewrite misaligned security test cases from annotation CSVs."""

from __future__ import annotations

import argparse
import ast
import csv
import importlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from tqdm import tqdm

from const_cwe_id_desc import CWE_ID_DESC, DEFAULT_OPENAI_BASE_URL
from utils_py import get_test_cases_node, parse_blocks, validate_test_cases_dict

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


SERVICE_TIER = "flex"
_FORMAT_LOCK = threading.Lock()
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```(?:.*)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

ISSUE_ANTI = "anti_security_tests"
ISSUE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INVALID = "prompt_requests_invalid_behavior"
ALLOWED_ISSUES = {ISSUE_ANTI, ISSUE_IRRELEVANT, ISSUE_PROMPT_INVALID}


COMPARE_FIELDS = [
    "bucket",
    "human_invalid",
    "change",
    "language",
    "cwe",
    "source_index",
    "function_name",
    "user_prompt",
    "original_test_code",
    "rewritten_test_code",
    "original_ground_truth_solution",
    "rewritten_ground_truth_solution",
    "issues",
    "analysis",
    "fix_error",
    "test_parse_error",
    "annotator_c_is_valid?",
    "annotator_c_comments?",
    "annotator_d_is_valid",
    "annotator_d_comments",
    "final_annotation",
]

_FIX_DECISION_BLOCK = """## Decide `change`
| value | when |
| **reject** | Prompt cannot be a valid **{cwe}** task without replacing it → `issues`: `["prompt_requests_invalid_behavior"]` only |
| **rewrite** | Prompt OK; tests/oracle wrong (anti-security expectations, wrong category, missing security cases) |
| **UNCHANGED** | Prompt + tests already enforce secure behavior; insecure shortcuts would fail |

Check: attack payload in **functionality**? benign-only **security**? naive insecure code would pass a **security** case?"""
_FIX_OUTPUT_BLOCK = """## Output — JSON only, no markdown wrapper
{{
"issues": [...], 
"analysis": "...", 
"change": "reject"|"rewrite"|"UNCHANGED", 
"test_code": "...", 
"ground_truth_solution": "..."
}}
- **reject**: `issues` exactly `["prompt_requests_invalid_behavior"]`; both code fields `UNCHANGED`
- **UNCHANGED**: `issues` `[]`; both code fields must be the literal string `UNCHANGED` (do not paste test/oracle bodies)
- **rewrite**: `issues` only `{anti}`, `{irrelevant}`, or `prompt_requests_invalid_behavior`; full revised `test_code` + oracle (≥2 functionality, ≥2 security); use `Exception` not `"Exception"`; every case you criticize must have **corrected** expected outputs — do not copy the same bad expectations into `test_code`"""

RUBRICS_DIR = Path(__file__).resolve().parent / "rubrics_py"


def normalize_cwe(cwe: str) -> str:
    cwe = (cwe or "").strip().upper()
    if not cwe.startswith("CWE-"):
        m = re.search(r"(\d+)", cwe)
        if m:
            cwe = f"CWE-{m.group(1)}"
    return cwe


def parse_cwe_list(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for part in value.split(","):
            cwe = normalize_cwe(part)
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def model_slug(model: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", model.lower())


def compare_output_path(output_dir: Path, model: str, cwe: str, stamp: str) -> Path:
    tag = normalize_cwe(cwe).lower().replace("-", "")
    return output_dir / f"data_annotation_{model_slug(model)}_{stamp}_{tag}_rewrites_compare.csv"


def cwe_description(cwe: str) -> str:
    cwe = normalize_cwe(cwe)
    return CWE_ID_DESC.get(cwe)


def load_rubric(cwe: str) -> str:
    m = re.search(r"(\d+)", normalize_cwe(cwe))
    if not m:
        return ""
    path = RUBRICS_DIR / f"{m.group(1)}.txt"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def build_fix_instruction(task: dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    cwe_rubric = load_rubric(cwe)
    setup_tests = task.get("setup_tests") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI,
        irrelevant=ISSUE_IRRELEVANT,
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
```
{setup_tests}
```

## test_code
```
{task.get("test_code", "")}
```

## oracle (may share test bugs)
```
{task.get("ground_truth_solution", "")}
```
"""


def parse_model_result(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    text = (raw or "").strip()
    m = JSON_FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None, "no JSON object in model output"
    try:
        obj = json.loads(text[i : j + 1])
    except json.JSONDecodeError as e:
        return None, str(e)
    if not isinstance(obj, dict):
        return None, "JSON root must be an object"

    issues = obj.get("issues") or []
    if not isinstance(issues, list):
        return None, "issues must be a list"
    issues = [str(x) for x in issues]

    raw_change = obj.get("change", obj.get("needs_rewrite"))
    if isinstance(raw_change, bool):
        change = "rewrite" if raw_change else "UNCHANGED"
    elif isinstance(raw_change, str):
        key = raw_change.strip().lower()
        if key == "reject":
            change = "reject"
        elif raw_change.strip().upper() == "UNCHANGED" or key in {"false", "no", "unchanged"}:
            change = "UNCHANGED"
        elif key in {"rewrite", "true", "yes"}:
            change = "rewrite"
        else:
            return None, "change must be reject, rewrite, or UNCHANGED"
    else:
        return None, "change must be reject, rewrite, or UNCHANGED"

    for field in ("test_code", "ground_truth_solution"):
        if not isinstance(obj.get(field), str) or not str(obj[field]).strip():
            return None, f"missing or empty {field}"

    if [x for x in issues if x not in ALLOWED_ISSUES]:
        return None, f"unknown issue ids: {issues}"
    if change == "reject":
        if ISSUE_PROMPT_INVALID not in issues:
            return None, "change=reject requires prompt_requests_invalid_behavior in issues"
        issues = [ISSUE_PROMPT_INVALID]
    elif change == "UNCHANGED" and issues:
        return None, "change=UNCHANGED but issues non-empty"
    elif change == "rewrite" and not issues:
        return None, "change=rewrite but issues empty"

    return {
        "issues": issues,
        "change": change,
        "analysis": (obj.get("analysis") or "").strip() if isinstance(obj.get("analysis"), str) else "",
        "test_code": obj["test_code"].strip(),
        "ground_truth_solution": obj["ground_truth_solution"].strip(),
    }, None


def final_annotation_label(src: dict[str, str]) -> str:
    final_annotation = (src.get("final_annotation") or "").strip().upper()
    if final_annotation in ("Y", "N"):
        return final_annotation
    else:
        raise ValueError(f"invalid or no final annotation: {final_annotation}")


def audit_bucket(final_annotation: str, change: str) -> str:
    human_bad = final_annotation == "N"
    model_bad = change in ("reject", "rewrite")
    if human_bad and model_bad:
        return "TP (human invalid, model changed)"
    if not human_bad and change == "UNCHANGED":
        return "TN (human valid, model unchanged)"
    if human_bad and change == "UNCHANGED":
        return "FN (human invalid, model unchanged)"
    return "FP (human valid, model changed)"


def extract_solution_code(raw: str) -> str:
    m = CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return (raw or "").strip()


def build_compare_row(
    src: dict[str, str],
    task: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, str]:
    parsed = result.get("model_parsed") or {}
    change = parsed.get("change") or ""
    if result.get("rejected"):
        change = "reject"

    orig_test = task["test_code"]
    orig_gt = task["ground_truth_solution"]
    rew_test = ""
    rew_gt = ""
    if result.get("kept"):
        rew_test = result.get("final_test_code") or orig_test
        rew_gt = result.get("final_ground_truth_solution") or orig_gt
    elif change == "UNCHANGED":
        rew_test = orig_test
        rew_gt = orig_gt
    elif change == "rewrite":
        rew_test = parsed.get("test_code") or ""
        rew_gt = parsed.get("ground_truth_solution") or ""
        if rew_test.strip().upper() == "UNCHANGED":
            rew_test = orig_test
        if rew_gt.strip().upper() == "UNCHANGED":
            rew_gt = orig_gt
        rew_gt = extract_solution_code(rew_gt)

    final_annotation = final_annotation_label(src)
    issues = parsed.get("issues")
    fix_error = result.get("fix_error")
    return {
        "bucket": audit_bucket(final_annotation, change),
        "final_annotation": final_annotation,
        "human_invalid": "True" if final_annotation == "N" else "False",
        "change": change,
        "language": task["language"],
        "cwe": task["cwe"],
        "source_index": str(src.get("source_index") or ""),
        "function_name": task["function_name"],
        "annotator_c_is_valid?": src.get("annotator_c_is_valid?", ""),
        "annotator_c_comments?": src.get("annotator_c_comments?", ""),
        "annotator_d_is_valid": src.get("annotator_d_is_valid", ""),
        "annotator_d_comments": src.get("annotator_d_comments", ""),
        "user_prompt": task["user_prompt"],
        "original_test_code": orig_test,
        "rewritten_test_code": rew_test,
        "original_ground_truth_solution": orig_gt,
        "rewritten_ground_truth_solution": rew_gt,
        "issues": "" if issues is None else str(issues),
        "analysis": parsed.get("analysis") or "",
        "fix_error": "" if fix_error is None else str(fix_error),
        "test_parse_error": result.get("test_parse_error") or "",
    }


def format_test_code(test_code: str) -> str:
    with _FORMAT_LOCK:
        try:
            black = importlib.import_module("black")
            return black.format_str(test_code, mode=black.FileMode(line_length=100)).strip()
        except Exception:
            pass
    try:
        return ast.unparse(ast.parse(test_code)).strip()
    except SyntaxError:
        return test_code.strip()


def process_row(
    client: OpenAI,
    model: str,
    task: dict[str, Any],
    *,
    max_retries: int,
    max_output_tokens: int,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "model_parsed": None,
        "fix_error": None,
        "test_parse_error": "",
        "final_test_code": "",
        "final_ground_truth_solution": "",
        "kept": False,
        "rejected": False,
    }
    parsed = None
    last_err = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a security auditor. "
                    "Return only one JSON object. "
                    "For every test case, audit each input, output and the ground truth solution."
                    "Rewrite any invalid (or partially valid) security tests. "
                    "the new tests must fix every security case you criticized — do not echo the same bad expected outputs. "
                ),
                input=build_fix_instruction(task),
                max_output_tokens=max_output_tokens,
                service_tier=SERVICE_TIER,
            )
            parsed, err = parse_model_result((resp.output_text or "").strip())
            if err is None:
                break
            last_err = err
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out["model_parsed"] = parsed
    if parsed is None:
        out["fix_error"] = last_err or "no valid output after retries"
        return out
    if parsed["change"] == "reject":
        out["rejected"] = True
        return out

    def pick(val: str, original: str) -> str:
        v = (val or "").strip()
        return original if not v or v.upper() == "UNCHANGED" else v

    final_tests = pick(parsed["test_code"], task["test_code"])
    final_gt = pick(parsed["ground_truth_solution"], task["ground_truth_solution"])
    try:
        _, test_ast = parse_blocks("", final_tests)
        validate_test_cases_dict(get_test_cases_node(test_ast))
    except ValueError as e:
        out["test_parse_error"] = str(e)
        out["final_test_code"] = final_tests
        return out

    out["final_test_code"] = format_test_code(final_tests)
    out["final_ground_truth_solution"] = extract_solution_code(final_gt)
    out["kept"] = True
    return out


def load_pairs(input_csv: Path) -> list[tuple[dict[str, str], dict[str, Any]]]:
    pairs: list[tuple[dict[str, str], dict[str, Any]]] = []
    with input_csv.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            lang = str(row.get("language") or "").strip()
            cwe = str(row.get("cwe") or "").strip()
            fn = str(row.get("function_name") or "").strip()
            prompt = row.get("user_prompt") if isinstance(row.get("user_prompt"), str) else ""
            tests = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
            sol = (
                row.get("ground_truth_solution")
                if isinstance(row.get("ground_truth_solution"), str)
                else ""
            )
            if lang and cwe and fn and prompt.strip() and tests.strip():
                pairs.append((row, {
                    "language": lang,
                    "cwe": cwe,
                    "function_name": fn,
                    "user_prompt": prompt,
                    "setup_tests": "",
                    "setup_code": "",
                    "test_code": tests,
                    "ground_truth_solution": sol,
                }))
    return pairs


def run_cwe_audit(
    client: OpenAI,
    model: str,
    cwe: str,
    pairs: list[tuple[dict[str, str], dict[str, Any]]],
    *,
    max_rows: int,
    max_workers: int,
    retries: int,
    max_output_tokens: int,
    output_path: Path,
    audit_jsonl: Path | None,
) -> None:
    cwe_pairs = [(src, task) for src, task in pairs if normalize_cwe(task["cwe"]) == cwe]
    if max_rows > 0:
        cwe_pairs = cwe_pairs[:max_rows]
    print(f"{cwe}: {len(cwe_pairs)} rows")
    if not cwe_pairs:
        return

    results: list[dict[str, Any] | None] = [None] * len(cwe_pairs)
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

    compare_rows: list[dict[str, str]] = []
    audit_records: list[dict[str, Any]] = []
    for (src, task), result in zip(cwe_pairs, results):
        if result is None:
            continue
        compare_rows.append(build_compare_row(src, task, result))
        if audit_jsonl is not None:
            parsed = result.get("model_parsed") or {}
            audit_records.append({
                "cwe": cwe,
                "function_name": task["function_name"],
                "fix_error": result.get("fix_error"),
                "change": parsed.get("change"),
                "issues": parsed.get("issues"),
                "analysis": parsed.get("analysis"),
                "rejected": result.get("rejected"),
                "test_parse_error": result.get("test_parse_error"),
                "kept": result.get("kept"),
            })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COMPARE_FIELDS)
        w.writeheader()
        w.writerows(compare_rows)
    kept_n = sum(1 for _, result in zip(cwe_pairs, results) if result and result.get("kept"))
    print(f"wrote {len(compare_rows)} compare rows ({kept_n} kept) -> {output_path}")

    if audit_jsonl is not None:
        audit_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with audit_jsonl.open("w", encoding="utf-8") as f:
            for rec in audit_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"wrote audit log -> {audit_jsonl}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit annotation CSVs and rewrite test cases.")
    parser.add_argument("--input-csv", type=Path, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory for per-CWE *_rewrites_compare.csv outputs.",
    )
    parser.add_argument(
        "--cwes",
        nargs="+",
        default=["CWE-78"],
        help="CWE ids to process (default: CWE-78). Example: --cwes CWE-78 CWE-89",
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

    pairs = load_pairs(args.input_csv.resolve())
    print(f"loaded {len(pairs)} processable rows from {args.input_csv}")
    print(f"CWES: {', '.join(cwes)}")

    output_dir = args.output_dir.resolve()
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    for cwe in cwes:
        out_path = compare_output_path(output_dir, args.model, cwe, stamp)
        audit_path = None
        if args.audit_jsonl is not None:
            prefix = args.audit_jsonl.resolve()
            tag = normalize_cwe(cwe).lower().replace("-", "")
            audit_path = prefix.parent / f"{prefix.stem}_{tag}{prefix.suffix or '.jsonl'}"
        run_cwe_audit(
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
