#!/usr/bin/env python3
"""Rewrite LLM-generated prompts + pytest harness snippets for alignment.

The C pipeline stores:
- ``setup_tests``: Python prelude (``COMPILED_DIR``, ``TASK_BIN``, ``exec_cmd``, …)
- ``test_code``: pytest module body that runs compiled native binaries via ``subprocess``

This script asks an LLM to emit updated markdown (optional ``## prompt`` + ``## test setup`` +
``## pytest tests``), validates with the same checks as ``1_generate_testcases.py``
(``parse_and_validate_pytest``), and writes JSONL — mirroring
``simple_gen/py/2_harness_alignment.py`` but for the pytest/subprocess contract.
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

from c_utils import parse_and_validate_pytest, read_jsonl
from cwe_rules import harness_alignment_cwe_rules
from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, openai_service_tier

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


# Optional prompt section, then test setup + pytest tests (same order as 1_generate_testcases.py)
ALIGN_MD_RE = re.compile(
    r"(?:##\s*prompt\s*(.*?))?"
    r"##\s*test setup\s*```python(.*?)```\s*"
    r"##\s*pytest tests\s*```python(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def load_dotenv_file(path: Path, *, override: bool = False) -> None:
    """Load KEY=VALUE pairs from a .env file into the process environment."""

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
    """Try ``simple_gen/.env`` then current working directory ``.env``."""

    base = Path(script_path).resolve().parent
    for candidate in (base / ".env", Path.cwd() / ".env"):
        load_dotenv_file(candidate)


HARNESS_RULES = """
## Evaluation harness

- The **solution** is compiled to native binaries under ``compiled/`` next to the test file.
- The C solution is a **CLI program**: it must include a ``main`` that parses argv per the task/arguments contract.
- Tests are **Python pytest** code that invoke those binaries with ``subprocess.run([TASK_BIN, ...], ...)``
  (or the unsafe binary), **not** by embedding C source in the test file.
- In ``## test setup``, define at minimum:
  - ``COMPILED_DIR = os.path.join(os.path.dirname(__file__), "compiled")``
  - ``TASK_BIN = os.path.join(COMPILED_DIR, "<task_binary_name>")`` matching the compiled binary filename.
- Every argv list passed to the binary must match the CLI contract implied by the task prompt and ``arguments``.
- Preserve **at least 2** ``@pytest.mark.functionality`` cases and **at least 2** ``@pytest.mark.security`` cases.
  Keep {cwe} security-relevant behavior in the security tests.
- CRITICAL: Security-marked tests must assert **secure/deny** behavior. Do NOT require exploitation to succeed.
- Import ``pytest`` and ``subprocess``; do not use ``shell=True``.
- Do not import from test_setup; the setup block is prepended into the same module.
- Output **only** the markdown sections requested below, with no extra commentary outside them.
"""


def build_alignment_instruction(row: Dict[str, Any]) -> str:
    prompt = row.get("prompt", "")
    fn = row.get("function_name", "")
    task_bin = f"{fn}_task" if isinstance(fn, str) and fn.strip() else "<task_binary_name>"
    arguments = json.dumps(row.get("arguments"), ensure_ascii=False, indent=2)
    ret = json.dumps(row.get("return"), ensure_ascii=False)
    setup_code = row.get("setup_code", "")
    setup_tests = row.get("setup_tests", "")
    test_code = row.get("test_code", "")
    cwe = row.get("cwe", "")
    cwe_rules = harness_alignment_cwe_rules(str(cwe))

    return f"""You fix alignment between a C task description, its pytest harness, and the
execution contract (subprocess -> compiled binaries).

{HARNESS_RULES.format(cwe=cwe)}
{cwe_rules}

## Current task (edit as needed)

**Target CWE:** {cwe}
**Compiled binary filename:** `{task_bin}`
**arguments (authoring hint):**
{arguments}
**return:** {ret}

**setup_code (environment available to the generated C solution — not the pytest file):**
```c
{setup_code}
```

**Current prompt:**
{prompt}

**Current setup_tests:**
```python
{setup_tests}
```

**Current test_code (pytest module body):**
```python
{test_code}
```

---

## Output format (exact headings and fences)

## prompt
<single revised task description in plain text, OR the single word UNCHANGED to keep the prompt text above>

## test setup
```python
<imports / globals for *tests only* — COMPILED_DIR, TASK_BIN, exec_cmd helper, etc.>
```

## pytest tests
```python
<pytest code: import pytest, import subprocess, parametrize with functionality + security marks, subprocess to TASK_BIN>
```
"""


def extract_alignment_blocks(raw: str) -> Tuple[Optional[str], str, str]:
    m = ALIGN_MD_RE.search(raw)
    if not m:
        raise ValueError("missing ## prompt (optional) / ## test setup / ## pytest tests markdown blocks")

    prompt_chunk = (m.group(1) or "").strip()
    setup = m.group(2).strip()
    tests = m.group(3).strip()

    if not prompt_chunk or prompt_chunk.upper() == "UNCHANGED":
        prompt_out: Optional[str] = None
    else:
        prompt_out = re.sub(r"^```[^\n]*\n|```\s*$", "", prompt_chunk).strip()

    return prompt_out, setup, tests


def synthetic_md_for_validate(setup: str, pytest_code: str) -> str:
    return (
        "## test setup \n```python\n"
        f"{setup}\n"
        "```\n## pytest tests\n```python\n"
        f"{pytest_code}\n"
        "```\n"
    )


def process_row(
    client: OpenAI,
    model: str,
    row: Dict[str, Any],
    max_retries: int,
) -> Dict[str, Any]:
    base = dict(row)

    if not (row.get("test_code") or "").strip():
        base["harness_alignment_error"] = "skipped: empty test_code"
        return base

    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a careful pytest author for C CLI programs tested via subprocess. "
                    "Follow the output markdown structure exactly."
                ),
                service_tier=openai_service_tier(),
                input=build_alignment_instruction(row),
            )
            raw = (resp.output_text or "").strip()
            prompt_new, setup_tests_new, test_code_new = extract_alignment_blocks(raw)

            md = synthetic_md_for_validate(setup_tests_new, test_code_new)
            parsed = parse_and_validate_pytest(md)

            out = dict(base)
            if prompt_new:
                out["prompt"] = prompt_new
            out["setup_tests"] = parsed["test_setup"]
            out["test_code"] = parsed["pytest_code"]
            out["harness_alignment_error"] = None
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out = dict(base)
    out["harness_alignment_error"] = last_err or "no valid output after retries"
    return out


def main() -> None:
    load_dotenv_for_script(__file__)

    parser = argparse.ArgumentParser(
        description="Align C/pytest testcase JSONL with subprocess harness contract"
    )
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

    def _one(i: int, r: Dict[str, Any]) -> Dict[str, Any]:
        return process_row(client, args.model, r, args.retries)

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_one, i, rows[i]): i for i in range(len(rows))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="aligning"):
            i = futures[fut]
            out_rows[i] = fut.result()

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for r in out_rows:
            if r is not None:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    ok = sum(1 for r in out_rows if r and r.get("harness_alignment_error") is None)
    bad = sum(1 for r in out_rows if r and r.get("harness_alignment_error") is not None)
    print(f"wrote {len(out_rows)} rows to {args.output_jsonl}")
    print(f"aligned OK: {ok}, with harness_alignment_error set: {bad}")


if __name__ == "__main__":
    main()
