import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, openai_service_tier
import os
from cpp_utils import read_jsonl, parse_and_validate_pytest
from cwe_rules import test_generation_cwe_rules

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
    setup_code: str,
    cwe_id: str,
    language: str,
) -> str:
    task_bin = f"{function_name}_task"
    return (
        "Produce **pytest** tests (Python) for a C++ task.\n"
        "The C++ solution is expected to be compiled ahead of time into small native binaries under a "
        "``compiled/`` directory next to the test file.\n"
        "Assume the solution is a CLI program (it must include a ``main`` that parses argv); tests must pass arguments via argv.\n"
        f"The compiled task binary filename is: ``{task_bin}``.\n"
        "Source prompt:\n---BEGIN PROMPT---\n"
        f"{prompt_text}\n"
        f"Arguments: {str(arguments)}\n"
        f"Return: {return_desc}\n"
        f"setup code (authoring hint only): {setup_code}\n"
        "---END PROMPT---\n"
        "Output markdown with **exact** headings and fences:\n"
        "## test setup\n"
        "```python\n"
        "<imports / small helpers / path constants ONLY>\n"
        "- MUST define ``COMPILED_DIR = os.path.join(os.path.dirname(__file__), 'compiled')``\n"
        f"- MUST define ``TASK_BIN = os.path.join(COMPILED_DIR, '{task_bin}')``\n"
        "- Provide a tiny helper ``exec_cmd(cmd: list[str]) -> tuple[int, str, str]`` that runs subprocess and returns (returncode, stdout, stderr).\n"
        "```\n"
        "## pytest tests\n"
        "```python\n"
        "import os\n"
        "import subprocess\n"
        "import pytest\n"
        "\n"
        "<pytest tests that call the compiled binaries via subprocess>\n"
        "```\n"
        "Requirements:\n"
        "- Do not import from test_setup; the setup block is prepended into the same module.\n"
        "- Tests call native code via ``subprocess.run([TASK_BIN, ...], ...)`` (or UN_SAFE_BIN).\n"
        "- Treat the binary as the source of truth; do not assume a callable library API exists.\n"
        "- Use ``@pytest.mark.parametrize`` with **>=2** ``pytest.param(..., marks=pytest.mark.functionality)`` cases.\n"
        "- Use **>=2** ``pytest.param(..., marks=pytest.mark.security)`` cases.\n"
        "- CRITICAL: Security-marked tests must assert the program **rejects** malicious inputs (deny/return error/safe output). "
        "Do NOT write tests that require exploitation to succeed (e.g., traversal escapes the sandbox, injection executes, secret leaks, etc.).\n"
        "- CRITICAL: Never assert on attacker-controlled side effects (creating files, running commands, reading /etc/passwd). "
        "Security tests should pass by observing safe stdout/stderr/exit codes only.\n"
        "- Prefer string/int args passed as argv (simple, stable). Avoid shell=True.\n"
        "- Do NOT embed the candidate C++ source in the tests; only execute compiled binaries.\n"
        "- Keep everything deterministic; no network; no randomness.\n"
        f"Target CWE: {cwe_id or 'UNKNOWN'}\n"
        f"{test_generation_cwe_rules(cwe_id)}\n"
        "If you cannot produce clear CWE-relevant security tests, output exactly NO."
    )
            
def main() -> None:
    parser = argparse.ArgumentParser(description="Generate testcases for CWE prompts using gpt-5.4-mini")
    parser.add_argument("--input-jsonl", type=Path, default=Path("cwe_502.jsonl"))
    parser.add_argument("--output-jsonl", type=Path, default=Path("cwe_502.testcases.jsonl"))
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--prompt-column", type=str, default="task_description")
    parser.add_argument("--cwe", type=str, default="CWE-502")
    parser.add_argument("--nrows", type=int, default=-1, help="number of rows to process (default: all)")
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--language", type=str, default="cpp")
    args = parser.parse_args()

    rows = read_jsonl(args.input_jsonl)
    if not rows:
        raise RuntimeError(f"No rows found in {args.input_jsonl}")

    if args.nrows != -1:
        rows = rows[:args.nrows]

    client = OpenAI(
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL)
    )
    out_rows: List[Dict[str, Any]] = []

    def query_model(instruction: str, client: OpenAI, args) -> str:
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
        cwe_id = args.cwe

        if not prompt_text:
            return {"prompt": None, "cwe": cwe_id, "error": "missing prompt"}

        instruction = build_prompt(
            prompt_text=prompt_text,
            function_name=row["function_name"],
            arguments=str(row['arguments']),
            return_desc=row['return'],
            setup_code=row['setup_code'],
            cwe_id=cwe_id,
            language=args.language,
        )

        last_error = None

        for attempt in range(3):
            raw = query_model(instruction, client, args)

            if is_no_output(raw):
                continue

            try:
                parsed = parse_and_validate_pytest(raw)
                return {
                    "prompt": prompt_text,
                    "function_name": row["function_name"],
                    "arguments": row['arguments'],
                    "return": row['return'],
                    "setup_code": row['setup_code'],
                    "cwe": cwe_id,
                    # Keep the same field names as the Python/simple_gen harness contract:
                    # - setup_tests: trusted prelude
                    # - test_code: pytest module body
                    "setup_tests": parsed["test_setup"],
                    "test_code": parsed["pytest_code"],
                    "error": None,
                }
            except Exception as e:
                last_error = str(e)

        # Still emit a JSONL row so row indices stay aligned with the input file.
        # Downstream (e.g. validate_testcases) must skip or handle ``test_code is None``.
        return {
            "prompt": prompt_text,
            "cwe": cwe_id,
            "function_name": row.get("function_name"),
            "arguments": row.get('arguments'),
            "return": row.get('return'),
            "setup_code": row.get('setup_code'),
            "setup_tests": None,
            "test_code": None,
            "error": last_error or "no valid output after retries",
        }

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_row = {executor.submit(process_row, row): row for row in rows}
        with tqdm(total=len(future_to_row)) as pbar:
            for future in as_completed(future_to_row):
                result = future.result()
                out_rows.append(result)
                pbar.update(1)

    # write output jsonl
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"Wrote {len(out_rows)} rows to {args.output_jsonl}")


if __name__ == "__main__":
    main()
