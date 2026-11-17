#!/usr/bin/env python3
"""Audit and rewrite misaligned C++ security pytest harnesses (GRPO / simple_gen rows)."""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import os
import re
import threading
from typing import Any

from const_cwe_id_desc import CWE_ID_DESC, DEFAULT_OPENAI_BASE_URL
from rubrics_cpp.rubrics import load_rubric
from utils_cpp import evaluate_cpp_harness, validate_cpp_harness_structure

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


SERVICE_TIER = "flex"
_FORMAT_LOCK = threading.Lock()
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```(?:c|cpp)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

ISSUE_ANTI = "anti_security_tests"
ISSUE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INVALID = "prompt_requests_invalid_behavior"
ALLOWED_ISSUES = {ISSUE_ANTI, ISSUE_IRRELEVANT, ISSUE_PROMPT_INVALID}

_FIX_DECISION_BLOCK = """## Decide `change`
| value | when |
| **reject** | Prompt cannot be a valid **{cwe}** C++ CLI task without replacing it → `issues`: `["prompt_requests_invalid_behavior"]` only |
| **rewrite** | Prompt OK; pytest harness and/or `candidate_cpp` oracle wrong (anti-security expectations, wrong category, missing security cases) |
| **UNCHANGED** | Prompt + tests + oracle already enforce secure behavior; naive insecure C++ would fail security cases |

Check: attack payload in **functionality**? benign-only **security**? would insecure C++ pass a **security** case?"""
_FIX_OUTPUT_BLOCK = """## Output — JSON only, no markdown wrapper
{{
"issues": [...],
"analysis": "...",
"change": "reject"|"rewrite"|"UNCHANGED",
"test_code": "...",
"ground_truth_solution": "..."
}}
- **reject**: `issues` exactly `["prompt_requests_invalid_behavior"]`; both code fields `UNCHANGED`
- **UNCHANGED**: `issues` `[]`; both code fields must be the literal string `UNCHANGED` (do not paste bodies)
- **rewrite**: `issues` only `{anti}`, `{irrelevant}`; full revised pytest `test_code` (>=2 `@pytest.mark.functionality`, >=2 `@pytest.mark.security`, uses `TASK_BIN` via `exec_cmd`) plus revised **C++** `candidate_cpp` source in `ground_truth_solution`; fix every case you criticized — do not copy the same bad assertions"""


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


def build_fix_instruction(task: dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    cwe_rubric = load_rubric(cwe)
    setup_tests = task.get("setup_tests") or ""
    setup_code = task.get("setup_code") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI,
        irrelevant=ISSUE_IRRELEVANT,
    )
    setup_code_block = ""
    if setup_code.strip():
        setup_code_block = f"""
## setup_code (C++ headers/snippets — may extend in oracle)
```
{setup_code}
```
"""
    return f"""Audit one **{cwe}** secure-coding datapoint ({task.get("function_name", "")}, C++ CLI binary).

{cwe_desc}

**Harness:** compile `candidate_cpp` to a binary with g++ (`-std=c++17`), run ``setup_tests`` helpers, then pytest ``test_code``. Tests use ``exec_cmd([TASK_BIN, ...])`` and ``@pytest.mark.functionality`` / ``@pytest.mark.security`` (not input/output dicts). Security oracles are stdout/stderr/returncode (and JSON parse for CWE-347).

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
{setup_code_block}
## test_code (pytest — may rewrite)
```
{task.get("test_code", "")}
```

## oracle candidate_cpp (C++ source — may share test bugs)
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


def extract_solution_code(raw: str) -> str:
    m = CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return (raw or "").strip()


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


def format_cpp_solution(code: str) -> str:
    return extract_solution_code(code).strip()


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
        "harness_error": "",
        "harness_ut_result": {},
        "harness_passed": False,
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
                    "You are a security auditor for C++ CLI programs tested via pytest subprocess harnesses. "
                    "Return only one JSON object. "
                    "Audit each functionality and security pytest case and the C++ candidate_cpp oracle. "
                    "Rewrite invalid security tests and fix the C++ oracle when it shares the same bugs."
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
        validate_cpp_harness_structure(str(task.get("setup_tests") or ""), final_tests)
    except ValueError as e:
        out["test_parse_error"] = str(e)
        out["final_test_code"] = final_tests
        return out

    if parsed["change"] == "rewrite":
        passed, ut_result, herr = evaluate_cpp_harness(
            format_cpp_solution(final_gt),
            task,
            test_code=final_tests,
        )
        out["harness_ut_result"] = {
            k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()
        }
        out["harness_passed"] = passed
        if not passed:
            out["harness_error"] = herr
            out["final_test_code"] = final_tests
            out["final_ground_truth_solution"] = format_cpp_solution(final_gt)
            return out

    out["final_test_code"] = format_test_code(final_tests)
    out["final_ground_truth_solution"] = format_cpp_solution(final_gt)
    out["kept"] = True
    return out
