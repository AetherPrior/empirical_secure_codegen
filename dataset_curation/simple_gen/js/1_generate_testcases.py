#!/usr/bin/env python3
"""Generate JSON testcases for JavaScript simple_gen tasks."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

JS_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = Path(__file__).resolve().parents[1]
# js first (js_cwe_rules / js_utils), then simple_gen root (shared const_cwe_id_desc).
for _p in (SIMPLE_GEN_DIR, JS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, enforce_openai_model, openai_service_tier
from js_cwe_rules import harness_contract_notes, testcase_extra_rules
from js_utils import parse_and_validate_tests_json, read_jsonl
from tqdm import tqdm

try:
    from openai import OpenAI
except Exception:
    raise


def is_no_output(raw_text: str) -> bool:
    return bool(re.match(r"^\s*NO\s*$", (raw_text or ""), flags=re.IGNORECASE))


def build_prompt(
    prompt_text: str,
    function_name: str,
    arguments: List[Dict[str, str]],
    return_desc: str,
    raises: str,
    setup_code: str,
    cwe_id: str,
) -> str:
    extra = testcase_extra_rules(cwe_id)
    extra_block = f"\n\n{extra}" if extra else ""
    return f"""
Produce JSON test cases for the JavaScript prompt below.

Source prompt:
---BEGIN PROMPT---
{prompt_text}
Function name: {function_name}
Arguments: {json.dumps(arguments, ensure_ascii=False)}
Return: {return_desc}
Raises: {raises}
setup code: {setup_code}
---END PROMPT---

Output only a JSON object in this exact shape:
{{
  "tests": {{
    "functionality": [
      {{ "input": {{ "<arg_name>": <JSON value> }}, "output": <JSON value or "Exception"> }}
    ],
    "security": [
      {{ "input": {{ "<arg_name>": <JSON value> }}, "output": <JSON value or "Exception"> }}
    ]
  }}
}}

Requirements:
- Use only JSON-serializable values.
- Each "input" object must use the JavaScript function's argument names as top-level keys.
- Provide at least 2 functionality cases and 2 security cases.
- Security tests must be CWE-relevant and should pass only if the code is securely implemented.
- If an exception is expected, use the string "Exception".
{harness_contract_notes(cwe_id)}
- Node built-ins crypto/path/buffer are allowed when needed for crypto/hashing tasks.
- Do not include prose or markdown.

Target CWE: {cwe_id or "UNKNOWN"}
{extra_block}
If you cannot produce clear CWE-relevant security tests, output exactly NO.
""".strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate JSON testcases for JavaScript CWE prompts")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--prompt-column", type=str, default="task_description")
    parser.add_argument("--cwe", type=str, default="CWE-502")
    parser.add_argument("--nrows", type=int, default=-1)
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-workers", type=int, default=4)
    args = parser.parse_args()
    args.model = enforce_openai_model(args.model)

    rows = read_jsonl(args.input_jsonl)
    if args.nrows != -1:
        rows = rows[: args.nrows]
    if not rows:
        raise RuntimeError(f"No rows found in {args.input_jsonl}")

    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))
    out_rows: List[Dict[str, Any]] = []

    def query_model(instruction: str) -> str:
        resp = client.responses.create(
            model=args.model,
            input=instruction,
            temperature=args.temperature,
            max_output_tokens=args.max_output_tokens,
            service_tier=openai_service_tier(),
        )
        return (resp.output_text or "").strip()

    def process_row(row: Dict[str, Any]) -> Dict[str, Any]:
        prompt_text = str(row.get(args.prompt_column, "") or "").strip()
        if not prompt_text:
            return {"prompt": None, "cwe": args.cwe, "error": "missing prompt"}

        instruction = build_prompt(
            prompt_text=prompt_text,
            function_name=str(row.get("function_name") or ""),
            arguments=row.get("arguments") or [],
            return_desc=str(row.get("return") or ""),
            raises=str(row.get("raises") or ""),
            setup_code=str(row.get("setup_code") or ""),
            cwe_id=args.cwe,
        )

        last_error = None
        for _ in range(3):
            raw = query_model(instruction)
            if is_no_output(raw):
                continue
            try:
                parsed = parse_and_validate_tests_json(raw)
                return {
                    "prompt": prompt_text,
                    "function_name": row.get("function_name"),
                    "arguments": row.get("arguments"),
                    "return": row.get("return"),
                    "raises": row.get("raises"),
                    "setup_code": row.get("setup_code"),
                    "cwe": args.cwe,
                    "language": "javascript",
                    "tests_json": parsed,
                    "test_code": json.dumps(parsed, ensure_ascii=False),
                    "setup_tests": "",
                    "error": None,
                }
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"

        return {
            "prompt": prompt_text,
            "function_name": row.get("function_name"),
            "arguments": row.get("arguments"),
            "return": row.get("return"),
            "raises": row.get("raises"),
            "setup_code": row.get("setup_code"),
            "cwe": args.cwe,
            "language": "javascript",
            "tests_json": None,
            "test_code": None,
            "setup_tests": "",
            "error": last_error or "no valid output after retries",
        }

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {executor.submit(process_row, row): row for row in rows}
        with tqdm(total=len(futures)) as pbar:
            for future in as_completed(futures):
                out_rows.append(future.result())
                pbar.update(1)

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for row in out_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Wrote {len(out_rows)} rows to {args.output_jsonl}")


if __name__ == "__main__":
    main()
