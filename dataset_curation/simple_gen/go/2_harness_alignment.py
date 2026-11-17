#!/usr/bin/env python3
"""Rewrite Go prompts + CWEval-style pytest harness for alignment."""

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

_SIMPLE_GEN_DIR = Path(__file__).resolve().parents[1]
if str(_SIMPLE_GEN_DIR) not in sys.path:
    sys.path.insert(0, str(_SIMPLE_GEN_DIR))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL  # noqa: E402
from go_utils import parse_and_validate_pytest, read_jsonl, write_jsonl  # noqa: E402

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


ALIGN_MD_RE = re.compile(
    r"(?:##\s*prompt\s*(.*?))?"
    r"##\s*test setup\s*```python(.*?)```\s*"
    r"##\s*pytest tests\s*```python(.*?)```",
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


HARNESS_RULES = """
## Evaluation harness

- The Go solution is compiled to a native binary under ``compiled/`` next to the test file.
- The Go solution is a CLI program: it must define ``main`` and parse argv per the task/arguments contract.
- Tests are Python pytest code that invoke the binary with ``subprocess.run([TASK_BIN, ...], ...)``.
- In ``## test setup``, define at minimum:
  - ``COMPILED_DIR = os.path.join(os.path.dirname(__file__), "compiled")``
  - ``TASK_BIN = os.path.join(COMPILED_DIR, "<task_binary_name>")`` matching the compiled binary filename.
- Preserve >=2 ``pytest.mark.functionality`` and >=2 ``pytest.mark.security`` cases.
- CRITICAL: Security-marked tests must assert secure/deny behavior. Do NOT require exploitation to succeed.
- Output only the requested markdown sections.
"""

def build_alignment_instruction(row: Dict[str, Any]) -> str:
    prompt = row.get("prompt", "")
    fn = row.get("function_name", "")
    cwe = row.get("cwe", "")
    setup_tests = row.get("setup_tests", "") if isinstance(row.get("setup_tests"), str) else ""
    test_code = row.get("test_code", "") if isinstance(row.get("test_code"), str) else ""

    return f"""You fix alignment between a Go CLI task, its pytest harness, and the evaluator contract.

{HARNESS_RULES.replace("{cwe}", str(cwe))}

## Current task

**Target CWE:** {cwe}
**task id / function_name:** {fn}

**Current prompt:**
{prompt}

**Current pytest harness:**
## test setup
```python
{setup_tests}
```

## pytest tests
```python
{test_code}
```

---

## Output format

## prompt
<single revised task description in plain text, OR the single word UNCHANGED to keep the prompt text above>

## test setup
```python
<updated setup_tests>
```

## pytest tests
```python
<updated test_code>
```"""


def extract_alignment_blocks(raw: str) -> Tuple[Optional[str], str, str]:
    m = ALIGN_MD_RE.search(raw)
    if not m:
        raise ValueError("missing required markdown blocks (## test setup / ## pytest tests)")

    prompt_chunk = (m.group(1) or "").strip()
    setup_tests = (m.group(2) or "").strip()
    test_code = (m.group(3) or "").strip()
    if not prompt_chunk or prompt_chunk.upper() == "UNCHANGED":
        prompt_out: Optional[str] = None
    else:
        prompt_out = re.sub(r"^```[^\n]*\n|```\s*$", "", prompt_chunk).strip()
    return prompt_out, setup_tests, test_code


def process_row(client: OpenAI, model: str, row: Dict[str, Any], max_retries: int) -> Dict[str, Any]:
    base = dict(row)
    if not (isinstance(base.get("test_code"), str) and base.get("test_code", "").strip()):
        base["harness_alignment_error"] = "skipped: missing test_code"
        return base

    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a careful Go pytest harness author. "
                    "Follow the markdown output structure exactly."
                ),
                service_tier="flex",
                input=build_alignment_instruction(row),
            )
            raw = (resp.output_text or "").strip()
            prompt_new, setup_tests, test_code = extract_alignment_blocks(raw)
            parsed = parse_and_validate_pytest(
                "## test setup\n```python\n"
                + setup_tests.strip()
                + "\n```\n\n## pytest tests\n```python\n"
                + test_code.strip()
                + "\n```\n"
            )

            out = dict(base)
            if prompt_new:
                out["prompt"] = prompt_new
            out["setup_tests"] = parsed.get("test_setup", "")
            out["test_code"] = parsed.get("pytest_code", "")
            out["harness_alignment_error"] = None
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out = dict(base)
    out["harness_alignment_error"] = last_err or "no valid output after retries"
    return out


def main() -> None:
    load_dotenv_for_script(__file__)

    parser = argparse.ArgumentParser(description="Align Go testcase JSONL with Go harness contract")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

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
