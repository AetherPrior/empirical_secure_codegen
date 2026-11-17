#!/usr/bin/env python3
"""Extract functionality and vulnerability/fix patterns with gpt-5.4-mini."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from semantic_slicing import rescue_style_semantic_slice


MODEL = "gpt-5.4-mini"
SERVICE_TIER = os.getenv("OPENAI_SERVICE_TIER", "flex")
_CLIENTS = threading.local()

BASE_SCHEMA = {
    "type": "object",
    "properties": {
        "functionality": {"type": "string"},
        "root_cause": {
            "type": "object",
            "properties": {"description": {"type": "string"}},
            "required": ["description"],
            "additionalProperties": False,
        },
        "fixing_pattern": {
            "type": "object",
            "properties": {"description": {"type": "string"}},
            "required": ["description"],
            "additionalProperties": False,
        },
    },
    "required": ["functionality", "root_cause", "fixing_pattern"],
    "additionalProperties": False,
}

EXTRACTION_SYSTEM_PROMPT = """Analyze paired vulnerable and secure implementations for security research.
Return only the requested JSON. The input contains an exact function-level diff and
 paired security-focused language slices. Describe the shared functionality, the concrete root cause of the
stated CWE, and the general fixing pattern. Code snippets are derived
deterministically by the pipeline; do not return code or Markdown fences."""


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def completed_attempt_keys(path: Path) -> set[str]:
    """Return checkpointed Stage 2 records that should not be repeated."""
    if not path.exists():
        return set()
    completed: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            attempt_key = row.get("attempt_key")
            if isinstance(attempt_key, str) and attempt_key:
                completed.add(attempt_key)
    return completed


def extraction_input(row: dict[str, Any]) -> dict[str, str]:
    materialized_fields = ("prompt", "vulnerable_code", "secure_code", "cwe")
    if all(isinstance(row.get(field), str) and row[field].strip() for field in materialized_fields):
        item = {field: row[field] for field in materialized_fields}
        if isinstance(row.get("language"), str) and row["language"].strip():
            item["language"] = row["language"]
        return item

    source = row["source_row"]
    ground = source["reward_model"]["ground_truth"]
    extra = source["extra_info"]
    language = row.get("language") or ground.get("language")
    field = {"c": "candidate_c", "cpp": "candidate_cpp", "javascript": "candidate_js"}.get(language)
    secure_code = (extra.get(field) if field else None) or extra["generated_code"]
    return {
        "prompt": ground["prompt"],
        "vulnerable_code": row["candidate"],
        "secure_code": secure_code,
        "cwe": row["cwe"],
        "language": language or "python",
    }


def deterministic_security_diff(item: dict[str, str], context_lines: int = 3) -> dict[str, Any]:
    """Produce an exact diff plus RESCUE-style paired semantic slices."""
    vulnerable_lines = item["vulnerable_code"].splitlines(keepends=True)
    secure_lines = item["secure_code"].splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=vulnerable_lines, b=secure_lines, autojunk=False)
    groups = list(matcher.get_grouped_opcodes(n=context_lines))
    if not groups:
        raise ValueError("vulnerable and secure implementations have no diff")

    hunks = []
    removed_lines: list[str] = []
    added_lines: list[str] = []
    for group in groups:
        vulnerable_start, vulnerable_end = group[0][1], group[-1][2]
        secure_start, secure_end = group[0][3], group[-1][4]
        for tag, old_start, old_end, new_start, new_end in group:
            if tag in {"replace", "delete"}:
                removed_lines.extend(vulnerable_lines[old_start:old_end])
            if tag in {"replace", "insert"}:
                added_lines.extend(secure_lines[new_start:new_end])
        hunks.append(
            {
                "vulnerable": "".join(vulnerable_lines[vulnerable_start:vulnerable_end]),
                "secure": "".join(secure_lines[secure_start:secure_end]),
            }
        )

    unified_diff = "".join(
        difflib.unified_diff(
            vulnerable_lines,
            secure_lines,
            fromfile="vulnerable.py",
            tofile="secure.py",
            n=context_lines,
        )
    )
    semantic_slice = rescue_style_semantic_slice(
        item["vulnerable_code"],
        item["secure_code"],
        item.get("language", "python"),
    )
    return {
        "unified": unified_diff,
        "hunks": hunks,
        "removed": "".join(removed_lines),
        "added": "".join(added_lines),
        "semantic_slice": semantic_slice,
    }


def semantic_snippets(diff: dict[str, Any]) -> tuple[str, str]:
    """Return the paired Python dependence slices used as KB code examples."""
    semantic_slice = diff.get("semantic_slice", {})
    if semantic_slice.get("method") != "rescue_style_pdg_slice":
        raise ValueError("Python semantic slicing did not produce a PDG slice")
    return semantic_slice["vulnerable"]["code"], semantic_slice["secure"]["code"]


def raw_pair_prompt(item: dict[str, str], diff: dict[str, Any]) -> str:
    semantic_slice = diff.get("semantic_slice", {})
    if semantic_slice.get("method") == "rescue_style_pdg_slice":
        language = semantic_slice.get("language", item.get("language", "python"))
        slice_context = f"""\n\nPaired security-focused code slices (changed statements plus two-hop data/control dependencies):
Vulnerable slice, source lines {semantic_slice['vulnerable']['line_numbers']}:
```{language}
{semantic_slice['vulnerable']['code']}
```
Secure slice, source lines {semantic_slice['secure']['line_numbers']}:
```{language}
{semantic_slice['secure']['code']}
```"""
    else:
        raise ValueError("Python semantic slicing did not produce a PDG slice")
    return f"""CWE: {item['cwe']}

Prompt:
{item['prompt']}

Deterministic security diff (vulnerable -> secure):
```diff
{diff['unified']}
```{slice_context}"""


def extraction_prompt(item: dict[str, str], diff: dict[str, Any]) -> str:
    return raw_pair_prompt(item, diff)


def client_for_thread():
    client = getattr(_CLIENTS, "client", None)
    if client is None:
        from openai import OpenAI

        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        client = OpenAI(api_key=key, base_url=os.getenv("OPENAI_BASE_URL") or None)
        _CLIENTS.client = client
    return client


def attach_deterministic_hunks(
    extraction: dict[str, Any], item: dict[str, str], diff: dict[str, Any]
) -> None:
    """Attach deterministic RESCUE-style slices while retaining the KB schema."""
    vulnerable_snippet, secure_snippet = semantic_snippets(diff)
    extraction["root_cause"]["vulnerable_code_snippet"] = vulnerable_snippet
    extraction["fixing_pattern"]["secure_code_snippet"] = secure_snippet
    extraction["security_diff"] = diff

    semantic_slice = diff.get("semantic_slice", {})
    if semantic_slice.get("method") == "rescue_style_pdg_slice":
        vulnerable_lines = item["vulnerable_code"].splitlines()
        secure_lines = item["secure_code"].splitlines()
        expected_vulnerable = "\n".join(
            vulnerable_lines[line - 1] for line in semantic_slice["vulnerable"]["line_numbers"]
        )
        expected_secure = "\n".join(
            secure_lines[line - 1] for line in semantic_slice["secure"]["line_numbers"]
        )
        if vulnerable_snippet != expected_vulnerable or secure_snippet != expected_secure:
            raise ValueError("semantic slice does not match its source lines")


def response_usage(response: Any) -> Any:
    return response.usage.model_dump() if response.usage else None


def extract_security_pattern(
    item: dict[str, str], diff: dict[str, Any]
) -> tuple[dict[str, Any], Any]:
    response = client_for_thread().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": extraction_prompt(item, diff)},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "security_pattern", "strict": True, "schema": BASE_SCHEMA},
        },
        # temperature=0,
        # max_completion_tokens=1600,
        service_tier=SERVICE_TIER,
    )
    extraction = json.loads(response.choices[0].message.content or "")
    attach_deterministic_hunks(extraction, item, diff)
    return extraction, response


def extract_one(index: int, row: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    item = extraction_input(row)
    base = {
        "attempt_key": row.get("attempt_key"),
        "task_id": row.get("task_id"),
        "source_index": row.get("source_index"),
        **item,
        "model": MODEL,
        "service_tier": SERVICE_TIER,
    }
    try:
        diff = deterministic_security_diff(item)
        extraction, extraction_response = extract_security_pattern(item, diff)
        result = {
            **base,
            "extraction": extraction,
            "provider_model": extraction_response.model,
            "usage": response_usage(extraction_response),
        }
    except Exception as exc:
        result = {**base, "extraction": None, "error": f"{type(exc).__name__}: {exc}"}
    return index, result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="append checkpointed results and skip attempt keys already in --output",
    )
    args = parser.parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")

    rows = load_jsonl(args.input)
    if args.limit is not None:
        rows = rows[: args.limit]
    completed = completed_attempt_keys(args.output) if args.resume else set()
    if completed:
        rows = [row for row in rows if row.get("attempt_key") not in completed]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.resume else "w"
    succeeded = failed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(extract_one, index, row)
            for index, row in enumerate(rows)
        ]
        with args.output.open(mode, encoding="utf-8") as handle:
            for future in as_completed(futures):
                _, result = future.result()
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
                if result["extraction"] is None:
                    failed += 1
                else:
                    succeeded += 1
    print(
        f"processed={len(rows)} succeeded={succeeded} failed={failed} "
        f"resumed={len(completed)} output={args.output}"
    )


if __name__ == "__main__":
    main()
