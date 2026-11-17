#!/usr/bin/env python3
"""Audit and rewrite misaligned JavaScript security test cases (GRPO / simple_gen rows)."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from tqdm import tqdm

from const_cwe_id_desc import CWE_ID_DESC, DEFAULT_OPENAI_BASE_URL, enforce_openai_model, openai_service_tier
from utils_js import format_tests_json, validate_rewritten_tests

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```(?:.*)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

ISSUE_ANTI = "anti_security_tests"
ISSUE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INVALID = "prompt_requests_invalid_behavior"
ISSUE_BROKEN_SETUP = "broken_setup_code"
ALLOWED_ISSUES = {ISSUE_ANTI, ISSUE_IRRELEVANT, ISSUE_PROMPT_INVALID, ISSUE_BROKEN_SETUP}

RUBRICS_DIR = Path(__file__).resolve().parent / "rubrics_js"

_SETUP_AUDIT_BLOCK = """## Also audit `setup_code`
`setup_code` runs **before** the oracle and must be Node-harness runnable. Flag **`broken_setup_code`** and **rewrite** (fix setup) when it would crash or break the harness, including:
- `const { DOMParser } = require('jsdom')` / `new DOMParser().parseFromString(...)` — **jsdom does not export DOMParser**. Use `const { JSDOM } = require('jsdom');` and `new JSDOM(xml, { contentType: 'text/xml' }).window.document`.
- CWE-89: fake JS-array "DB", on-disk sqlite paths, or reopening `':memory:'` instead of one shared setup global + `__setup` / `__harnessSetup`.
- `require` of packages outside the allowlist, or setup that never defines globals the oracle needs.
If setup is fine, output the literal `UNCHANGED` for `setup_code`."""

_FIX_DECISION_BLOCK = """## Decide `change`
| value | when |
| **reject** | Prompt cannot be a valid **{cwe}** task without replacing it → `issues`: `["prompt_requests_invalid_behavior"]` only |
| **rewrite** | Prompt OK; tests/oracle/setup wrong (anti-security expectations, wrong category, missing security cases, **or broken setup_code**) |
| **UNCHANGED** | Prompt + setup + tests already enforce secure behavior; insecure shortcuts would fail |

Check: attack payload in **functionality**? benign-only **security**? naive insecure code would pass a **security** case? **does setup_code crash under Node / wrong jsdom API?**"""

_FIX_OUTPUT_BLOCK = """## Output — JSON only, no markdown wrapper
{{
"issues": [...],
"analysis": "...",
"change": "reject"|"rewrite"|"UNCHANGED",
"setup_code": "...",
"test_code": "...",
"ground_truth_solution": "..."
}}
- **reject**: `issues` exactly `["prompt_requests_invalid_behavior"]`; `setup_code`, `test_code`, and `ground_truth_solution` all `UNCHANGED`
- **UNCHANGED**: `issues` `[]`; `setup_code`, `test_code`, and `ground_truth_solution` must be the literal string `UNCHANGED` (do not paste bodies)
- **rewrite**: `issues` only `{anti}`, `{irrelevant}`, `{setup}`; include full revised fields you fix, or the literal `UNCHANGED` for fields that are already fine. If setup is broken, `setup_code` must be full revised JavaScript that runs in the harness. Revised `test_code` JSON (≥2 functionality, ≥2 security) when tests change; revised **JavaScript** oracle when the solution changes; use the string `"Exception"` (not bare Exception) for rejected cases; fix every case you criticized — do not copy the same bad expectations"""


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


def cwe_description(cwe: str) -> str:
    return CWE_ID_DESC.get(normalize_cwe(cwe), "")


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
    setup_code = task.get("setup_code") or ""
    setup_tests = task.get("setup_tests") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI, irrelevant=ISSUE_IRRELEVANT, setup=ISSUE_BROKEN_SETUP
    )
    return f"""Audit one **{cwe}** secure-coding datapoint ({task.get("function_name", "")}, javascript).

{cwe_desc}

**Harness:** Node.js JSON harness. Run optional `setup_code` (await `__setup` / `__harnessSetup` when present), then solution, then JSON tests
(`tests.functionality` / `tests.security` with `input` object + `output` value or `"Exception"`). Promises returned by the target are awaited.
For CWE-89, prefer shared sqlite3 `:memory:` via setup globals (no on-disk DB files).

## Checklist — {cwe}
{cwe_rubric}

{_SETUP_AUDIT_BLOCK}

{decision}

{output_rules}

## prompt
```
{task.get("user_prompt", "")}
```

## setup_code (rewrite if broken; else UNCHANGED)
```
{setup_code}
```

## setup_tests (cannot be changed)
```
{setup_tests}
```

## test_code (JSON — may rewrite)
```
{task.get("test_code", "")}
```

## oracle candidate_js (may share test bugs)
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

    for field in ("setup_code", "test_code", "ground_truth_solution"):
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
        "setup_code": obj["setup_code"].strip(),
        "test_code": obj["test_code"].strip(),
        "ground_truth_solution": obj["ground_truth_solution"].strip(),
    }, None


def extract_solution_code(raw: str) -> str:
    m = CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return (raw or "").strip()


def format_test_code(test_code: str) -> str:
    return format_tests_json(test_code)


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
        "final_setup_code": "",
        "final_test_code": "",
        "final_ground_truth_solution": "",
        "kept": False,
        "rejected": False,
    }
    parsed = None
    last_err = None
    service_tier = openai_service_tier()
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a security auditor for JavaScript GRPO harnesses. "
                    "Return only one JSON object. "
                    "Audit each functionality/security case, the candidate_js oracle, and setup_code. "
                    "Flag broken_setup_code when setup would crash under Node (e.g. invalid jsdom DOMParser import). "
                    "Rewrite invalid or partially valid security tests and fix broken setup. "
                    "New tests must fix every security case you criticized — do not echo the same bad expected outputs."
                ),
                input=build_fix_instruction(task),
                max_output_tokens=max_output_tokens,
                service_tier=service_tier,
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

    final_setup = pick(parsed.get("setup_code") or "UNCHANGED", task.get("setup_code") or "")
    final_tests = pick(parsed["test_code"], task["test_code"])
    final_gt = pick(parsed["ground_truth_solution"], task["ground_truth_solution"])
    try:
        validate_rewritten_tests(final_tests, arguments=task.get("arguments"))
    except ValueError as e:
        out["test_parse_error"] = str(e)
        out["final_setup_code"] = final_setup
        out["final_test_code"] = final_tests
        return out

    out["final_setup_code"] = final_setup
    out["final_test_code"] = format_test_code(final_tests)
    out["final_ground_truth_solution"] = extract_solution_code(final_gt)
    out["kept"] = True
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit JS annotation CSV rows (legacy). Prefer prompt_parquet_js.py.")
    parser.add_argument("--input-csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--cwes", nargs="+", default=["CWE-22"])
    parser.add_argument("--model", default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=10)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    args = parser.parse_args()
    args.model = enforce_openai_model(args.model)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")
    client = OpenAI(api_key=api_key, base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))
    print(f"service_tier={openai_service_tier()}")

    pairs: list[tuple[dict[str, str], dict[str, Any]]] = []
    with args.input_csv.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            lang = str(row.get("language") or "javascript").strip()
            cwe = str(row.get("cwe") or "").strip()
            fn = str(row.get("function_name") or "").strip()
            prompt = row.get("user_prompt") if isinstance(row.get("user_prompt"), str) else ""
            tests = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
            sol = row.get("ground_truth_solution") if isinstance(row.get("ground_truth_solution"), str) else ""
            if lang and cwe and fn and prompt.strip() and tests.strip():
                pairs.append(
                    (
                        row,
                        {
                            "language": lang,
                            "cwe": cwe,
                            "function_name": fn,
                            "user_prompt": prompt,
                            "setup_tests": row.get("setup_tests") or "",
                            "setup_code": row.get("setup_code") or "",
                            "test_code": tests,
                            "ground_truth_solution": sol,
                            "arguments": [],
                        },
                    )
                )

    cwes = parse_cwe_list(args.cwes)
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    for cwe in cwes:
        cwe_pairs = [(s, t) for s, t in pairs if normalize_cwe(str(t["cwe"])) == cwe]
        if args.max_rows > 0:
            cwe_pairs = cwe_pairs[: args.max_rows]
        print(f"{cwe}: {len(cwe_pairs)} rows")
        if not cwe_pairs:
            continue
        results: list[dict[str, Any] | None] = [None] * len(cwe_pairs)
        with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
            futs = {
                ex.submit(
                    process_row,
                    client,
                    args.model,
                    task,
                    max_retries=args.retries,
                    max_output_tokens=args.max_output_tokens,
                ): i
                for i, (_, task) in enumerate(cwe_pairs)
            }
            for fut in tqdm(as_completed(futs), total=len(futs), desc=cwe):
                results[futs[fut]] = fut.result()
        out_path = args.output_dir / f"data_annotation_{model_slug(args.model)}_{stamp}_{cwe.lower().replace('-', '')}_rewrites.csv"
        print(f"done {cwe} -> {out_path} (kept {sum(1 for r in results if r and r.get('kept'))})")


if __name__ == "__main__":
    main()
