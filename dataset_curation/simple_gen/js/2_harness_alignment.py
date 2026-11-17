#!/usr/bin/env python3
"""Rewrite JavaScript prompts + JSON tests so they match the Node harness contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tqdm import tqdm

JS_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = Path(__file__).resolve().parents[1]
# js first (js_cwe_rules / js_utils), then simple_gen root (shared const_cwe_id_desc).
for _p in (SIMPLE_GEN_DIR, JS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, enforce_openai_model, openai_service_tier  # noqa: E402
from js_utils import (  # noqa: E402
    extract_param_names,
    parse_and_validate_tests_json,
    read_jsonl,
    tests_json_from_row,
    write_jsonl,
)
from js_cwe_rules import harness_contract_notes, testcase_extra_rules  # noqa: E402

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


ALIGN_MD_RE = re.compile(
    r"(?:##\s*prompt\s*(.*?))?"
    r"##\s*tests\s*json\s*```(?:json)?\s*(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def load_dotenv_file(path: Path, *, override: bool = False) -> None:
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value


def load_dotenv_for_script(script_path: str) -> None:
    base = Path(script_path).resolve().parent
    for candidate in (base / ".env", Path.cwd() / ".env"):
        load_dotenv_file(candidate)


def _harness_rules(cwe: str) -> str:
    return f"""
## Evaluation harness

- The JavaScript solution is run with Node.js.
{harness_contract_notes(cwe)}
- Node built-ins crypto/path/buffer are allowed when needed for crypto/hashing tasks.
- Do not require or mention any other external package.
- The harness evaluates ``setup_code`` first (awaiting ``__setup`` / ``__harnessSetup`` when present), then the candidate source.
- It resolves ``function_name`` and calls it with positional arguments in the order of ``arguments`` (Promises are awaited).
- Every testcase must be JSON:
  ``{{"input": {{"arg_name": <JSON value>, ...}}, "output": <JSON value or "Exception">}}``.
- Every testcase ``input`` object must use exactly the declared argument names as top-level keys.
- Preserve at least 2 ``functionality`` cases and 2 ``security`` cases.
- Security tests must be {cwe}-relevant and pass only for secure implementations.
- Output only the requested markdown sections.
"""


def _tests_blob(row: Dict[str, Any]) -> str:
    try:
        return json.dumps(tests_json_from_row(row), ensure_ascii=False, indent=2)
    except Exception:
        raw = row.get("test_code") or row.get("tests_json") or ""
        if isinstance(raw, str):
            return raw
        return json.dumps(raw, ensure_ascii=False, indent=2, default=str)


def build_alignment_instruction(row: Dict[str, Any]) -> str:
    prompt = row.get("prompt", "")
    fn = row.get("function_name", "")
    arguments = json.dumps(row.get("arguments"), ensure_ascii=False, indent=2)
    ret = json.dumps(row.get("return"), ensure_ascii=False)
    raises = row.get("raises", "")
    setup_code = row.get("setup_code", "")
    cwe = row.get("cwe", "")
    extra = testcase_extra_rules(str(cwe))
    extra_block = f"\n{extra}\n" if extra else ""

    return f"""You fix alignment between a JavaScript function task, its JSON tests, and a Node.js execution harness.

{_harness_rules(str(cwe))}
{extra_block}
## Current task

**Target CWE:** {cwe}
**function_name:** {fn}
**arguments:**
{arguments}
**return:** {ret}
**raises:** {raises}

**setup_code available to the generated JavaScript solution:**
```javascript
{setup_code}
```

**Current prompt:**
{prompt}

**Current tests_json / test_code:**
```json
{_tests_blob(row)}
```

---

## Output format

## prompt
<single revised task description in plain text, OR the single word UNCHANGED to keep the prompt text above>

## tests json
```json
{{
  "tests": {{
    "functionality": [
      {{ "input": {{ "<arg_name>": "<JSON value>" }}, "output": "<JSON value or Exception>" }}
    ],
    "security": [
      {{ "input": {{ "<arg_name>": "<JSON value>" }}, "output": "<JSON value or Exception>" }}
    ]
  }}
}}
```"""


def extract_alignment_blocks(raw: str) -> Tuple[Optional[str], str]:
    m = ALIGN_MD_RE.search(raw)
    if not m:
        raise ValueError("missing ## prompt / ## tests json markdown blocks")

    prompt_chunk = (m.group(1) or "").strip()
    tests_json = m.group(2).strip()
    if not prompt_chunk or prompt_chunk.upper() == "UNCHANGED":
        prompt_out: Optional[str] = None
    else:
        prompt_out = re.sub(r"^```[^\n]*\n|```\s*$", "", prompt_chunk).strip()
    return prompt_out, tests_json


def process_row(client: OpenAI, model: str, row: Dict[str, Any], max_retries: int) -> Dict[str, Any]:
    base = dict(row)
    try:
        current = tests_json_from_row(row)
    except Exception as e:
        base["harness_alignment_error"] = f"skipped: invalid existing tests: {type(e).__name__}: {e}"
        return base
    if not current:
        base["harness_alignment_error"] = "skipped: empty tests_json"
        return base

    last_err: Optional[str] = None
    param_names = extract_param_names(row)
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a careful JavaScript test author. "
                    "Follow the markdown output structure exactly."
                ),
                service_tier=openai_service_tier(),
                input=build_alignment_instruction(row),
            )
            raw = (resp.output_text or "").strip()
            prompt_new, tests_raw = extract_alignment_blocks(raw)
            parsed = parse_and_validate_tests_json(tests_raw, param_names=param_names)

            out = dict(base)
            if prompt_new:
                out["prompt"] = prompt_new
            out["tests_json"] = parsed
            out["test_code"] = json.dumps(parsed, ensure_ascii=False)
            out["setup_tests"] = ""
            out["harness_alignment_error"] = None
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out = dict(base)
    out["harness_alignment_error"] = last_err or "no valid output after retries"
    return out


def main() -> None:
    load_dotenv_for_script(__file__)

    parser = argparse.ArgumentParser(description="Align JavaScript testcase JSONL with Node harness contract")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()
    args.model = enforce_openai_model(args.model)

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))
    out_rows: List[Optional[Dict[str, Any]]] = [None] * len(rows)

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(process_row, client, args.model, rows[i], args.retries): i for i in range(len(rows))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="aligning"):
            out_rows[futures[fut]] = fut.result()

    final = [r for r in out_rows if r is not None]
    write_jsonl(args.output_jsonl, final)
    ok = sum(1 for r in final if r.get("harness_alignment_error") is None)
    bad = len(final) - ok
    print(f"wrote {len(final)} rows to {args.output_jsonl}")
    print(f"aligned OK: {ok}, with harness_alignment_error set: {bad}")


if __name__ == "__main__":
    main()
