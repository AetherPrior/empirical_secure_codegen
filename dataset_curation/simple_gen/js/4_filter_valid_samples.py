#!/usr/bin/env python3
"""Generate JavaScript solutions, then keep rows whose code passes the Node harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from tqdm import tqdm

JS_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = Path(__file__).resolve().parents[1]
# js first (js_cwe_rules / js_utils), then simple_gen root (shared const_cwe_id_desc).
for _p in (SIMPLE_GEN_DIR, JS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, enforce_openai_model, openai_service_tier  # noqa: E402
from js_utils import (  # noqa: E402
    extract_js_source_from_markdown,
    harness_fully_passes,
    prompt_to_text,
    read_jsonl,
    tests_json_from_row,
    write_jsonl,
)
from js_cwe_rules import solution_async_rules, solution_extra_hints  # noqa: E402

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

VERL_ROOT = Path(__file__).resolve().parents[2] / "verl"
if str(VERL_ROOT) not in sys.path:
    sys.path.insert(0, str(VERL_ROOT))

try:
    from recipe.security_harness.execution_harness_js import run_simple_gen_js_harness_unittest
except ImportError:
    from execution_harness_js import run_simple_gen_js_harness_unittest

_CACHE_WRITE_LOCK = threading.Lock()


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


def is_no_output(raw_text: str) -> bool:
    return bool(re.match(r"^\s*(NO|REJECT)\s*$", (raw_text or ""), flags=re.IGNORECASE))


def _rl_ground_truth_bundle(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rm = row.get("reward_model")
    if not isinstance(rm, dict):
        return None
    gt = rm.get("ground_truth")
    if not isinstance(gt, dict):
        return None
    fn = gt.get("function_name")
    if not isinstance(fn, str) or not fn.strip():
        return None
    if not isinstance(gt.get("tests_json"), dict) and not (isinstance(gt.get("test_code"), str) and gt.get("test_code").strip()):
        return None
    out = {
        "function_name": fn.strip(),
        "tests_json": gt.get("tests_json"),
        "test_code": gt.get("test_code"),
        "setup_tests": gt.get("setup_tests") if isinstance(gt.get("setup_tests"), str) else "",
        "setup_code": gt.get("setup_code") if isinstance(gt.get("setup_code"), str) else "",
        "arguments": gt.get("arguments") if isinstance(gt.get("arguments"), list) else [],
        "return": gt.get("return", ""),
        "raises": gt.get("raises", ""),
        "cwe": gt.get("cwe", ""),
    }
    return out


def task_row_for_filter(row: Dict[str, Any]) -> Dict[str, Any]:
    bundled = _rl_ground_truth_bundle(row)
    if bundled is not None:
        task = dict(bundled)
        task["prompt"] = prompt_to_text(row.get("prompt")) or prompt_to_text(bundled.get("prompt"))
        ei = row.get("extra_info")
        if isinstance(ei, dict):
            task["cwe"] = task.get("cwe") or ei.get("cwe", "")
        return task
    out = dict(row)
    out["prompt"] = prompt_to_text(out.get("prompt"))
    return out


def harness_ground_row(row: Dict[str, Any]) -> Dict[str, Any]:
    bundled = _rl_ground_truth_bundle(row)
    if bundled is not None:
        return bundled
    return {
        "function_name": row.get("function_name"),
        "tests_json": row.get("tests_json"),
        "test_code": row.get("test_code"),
        "setup_tests": row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row.get("setup_code") if isinstance(row.get("setup_code"), str) else "",
        "arguments": row.get("arguments") if isinstance(row.get("arguments"), list) else [],
    }


def _tests_preview(row: Dict[str, Any]) -> tuple[str, Optional[str]]:
    try:
        tests = tests_json_from_row(row)
        return json.dumps(tests, ensure_ascii=False, indent=2), None
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"


def build_solution_instruction(row: Dict[str, Any]) -> str:
    tests_blob, parse_err = _tests_preview(row)
    if parse_err:
        tests_blob = f"<could not parse tests: {parse_err}>"
    arguments = json.dumps(row.get("arguments", []), ensure_ascii=False, indent=2)
    ret = json.dumps(row.get("return"), ensure_ascii=False)
    raises = row.get("raises", "")
    setup_code = row.get("setup_code") or ""
    fn = row.get("function_name", "solution")
    cwe = str(row.get("cwe") or "")
    cwe_hint = solution_extra_hints(cwe)
    hint_block = f"\nSecure-implementation hints:\n{cwe_hint}" if cwe_hint else ""
    async_rules = solution_async_rules(cwe)

    w_tests = f"""You write a single JavaScript code block that implements the task below.

The evaluator will:
1. Execute ``setup_code`` in Node.js (awaiting ``__setup`` / ``__harnessSetup`` when present).
2. Load your code.
3. Resolve ``function_name`` and call it with positional arguments in the order listed in ``arguments`` (Promises are awaited).
4. For each testcase, require the return value to equal ``output`` (or expect an exception when ``output`` is "Exception").

## Task

**function_name:** {fn}
**arguments:**
{arguments}
**return:** {ret}
**raises:** {raises}

**setup_code (runs before your implementation is loaded):**
```javascript
{setup_code}
```

**Prompt:**
{row.get("prompt", "")}

**Parsed testcase payloads:**
```json
{tests_blob}
```

Target CWE context: **{row.get("cwe", "") or "UNKNOWN"}**.
{hint_block}

## Output rules
- If the test cases reward insecure behavior, output exactly ``REJECT`` and nothing else.
- Otherwise, return only one markdown fenced code block (```javascript ... ```) containing the full solution source.
- Define ``{fn}`` exactly as specified; no prose outside the fence.
{async_rules}
- Allowed npm packages are only: escape-html, node-rsa, argon2, escape-string-regexp, lodash, js-yaml, jsonwebtoken, jsdom, xpath, sqlite3.
- Node built-ins crypto/path/buffer are allowed when needed.
- Do not require any other external package."""

    w_o_tests = f"""You write a single JavaScript code block that implements the task below.

The evaluator will:
1. Execute ``setup_code`` in Node.js (awaiting ``__setup`` / ``__harnessSetup`` when present).
2. Load your code.
3. Resolve ``function_name`` and call it with positional arguments in the order listed in ``arguments`` (Promises are awaited).
4. For each testcase, require the return value to equal ``output`` (or expect an exception when ``output`` is "Exception").

## Task

**function_name:** {fn}
**arguments:**
{arguments}
**return:** {ret}
**raises:** {raises}

**setup_code (runs before your implementation is loaded):**
```javascript
{setup_code}
```

**Prompt:**
{row.get("prompt", "")}

Target CWE context: **{row.get("cwe", "") or "UNKNOWN"}**.
{hint_block}

## Output rules
- Return exactly one markdown fenced code block (```javascript ... ```) containing the full solution source.
- Define ``{fn}`` exactly as specified; no prose outside the fence.
{async_rules}
- Allowed npm packages are only: escape-html, node-rsa, argon2, escape-string-regexp, lodash, js-yaml, jsonwebtoken, jsdom, xpath, sqlite3.
- Node built-ins crypto/path/buffer are allowed when needed.
"""
    # if tests_blob:
    #     return w_tests
    return w_o_tests


def _generation_cache_key(*, model: str, prompt: str) -> str:
    payload = {"model": model, "prompt": prompt}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="surrogatepass")).hexdigest()


def _read_cache(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def process_row_generate(
    client: OpenAI,
    model: str,
    source_row: Dict[str, Any],
    task_row: Dict[str, Any],
    max_retries: int,
    *,
    cache_dir: Optional[Path],
    cache_read: bool,
    cache_write: bool,
    max_output_tokens: int,
) -> Dict[str, Any]:
    out = dict(source_row)
    out["mini_gen_error"] = None
    out["candidate_js"] = ""
    out["generated_code"] = ""
    out["mini_gen_cache_hit"] = False

    fn = task_row.get("function_name")
    if not (isinstance(fn, str) and fn.strip()):
        out["mini_gen_error"] = "skipped: missing function_name"
        return out
    try:
        tests_json_from_row(task_row)
    except Exception as e:
        out["mini_gen_error"] = f"skipped: invalid tests: {type(e).__name__}: {e}"
        return out

    try:
        prompt = build_solution_instruction(task_row)
    except Exception as e:
        out["mini_gen_error"] = f"error building solution instruction: {type(e).__name__}: {e}"
        return out

    cache_path: Optional[Path] = None
    if cache_dir is not None:
        cache_path = cache_dir / f"{_generation_cache_key(model=model, prompt=prompt)}.json"
        if cache_read:
            cached = _read_cache(cache_path)
            if isinstance(cached, dict):
                code = cached.get("candidate_js") or cached.get("generated_code")
                if isinstance(code, str) and code.strip() and not cached.get("mini_gen_error"):
                    out["candidate_js"] = code.strip()
                    out["generated_code"] = code.strip()
                    out["mini_gen_cache_hit"] = True
                    return out

    last_err: Optional[str] = None
    for _ in range(max(1, max_retries)):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are an expert JavaScript engineer. "
                    "Follow the output format exactly: one ```javascript fenced block only, or exactly REJECT."
                ),
                input=prompt,
                max_output_tokens=max_output_tokens,
                service_tier=openai_service_tier(),
            )
            raw = (resp.output_text or "").strip()
            if is_no_output(raw):
                raise ValueError("model returned REJECT/NO")
            code = extract_js_source_from_markdown(raw)
            if not code.strip():
                raise ValueError("empty JavaScript after extraction")
            out["candidate_js"] = code
            out["generated_code"] = code
            if cache_path is not None and cache_write:
                with _CACHE_WRITE_LOCK:
                    _atomic_write_json(
                        cache_path,
                        {"model": model, "candidate_js": code, "generated_code": code, "mini_gen_error": None},
                    )
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out["mini_gen_error"] = last_err or "no valid output after retries"
    if cache_path is not None and cache_write:
        with _CACHE_WRITE_LOCK:
            _atomic_write_json(
                cache_path,
                {"model": model, "candidate_js": "", "generated_code": "", "mini_gen_error": out["mini_gen_error"]},
            )
    return out


def process_row_use_existing(source_row: Dict[str, Any], *, code_field: str) -> Dict[str, Any]:
    out = dict(source_row)
    out["mini_gen_error"] = None
    code = out.get(code_field) or out.get("candidate_js") or out.get("generated_code")
    if not (isinstance(code, str) and code.strip()):
        out["mini_gen_error"] = f"skipped: missing {code_field} (use generation instead)"
        out["candidate_js"] = ""
        out["generated_code"] = ""
    else:
        out["candidate_js"] = code.strip()
        out["generated_code"] = code.strip()
    out["mini_gen_cache_hit"] = False
    return out


def evaluate_harness(row_with_code: Dict[str, Any], *, code_field: str) -> Dict[str, Any]:
    out = dict(row_with_code)
    code = out.get(code_field) or out.get("candidate_js") or out.get("generated_code") or ""
    if out.get("mini_gen_error"):
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        return out
    if not isinstance(code, str) or not code.strip():
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        out["harness_stderr"] = f"missing {code_field}"
        return out

    ok, ut_result = run_simple_gen_js_harness_unittest(code, harness_ground_row(out))
    out["harness_summary_ok"] = ok
    out["harness_ut_result"] = {k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()}
    out["harness_passed"] = harness_fully_passes(ok, ut_result)
    return out


def _strip_bookkeeping_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    code = out.get("candidate_js") or out.get("generated_code") or ""
    if isinstance(code, str) and code.strip():
        out["candidate_js"] = code.strip()
        out["generated_code"] = code.strip()
    for key in (
        "mini_gen_error",
        "mini_gen_cache_hit",
        "harness_passed",
        "harness_summary_ok",
        "harness_ut_result",
        "harness_stderr",
        "candidate_js_error",
    ):
        out.pop(key, None)
    return out


def main() -> None:
    load_dotenv_for_script(__file__)

    parser = argparse.ArgumentParser(
        description="LLM-generate JavaScript solutions for simple_gen JSONL rows; keep harness-passing rows"
    )
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True, help="Rows where harness_passed is true")
    parser.add_argument("--all-output-jsonl", type=Path, default=None)
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument("--request-timeout", type=float, default=120.0)
    parser.add_argument("--use-existing-candidate-js", action="store_true")
    parser.add_argument("--candidate-field", type=str, default="candidate_js")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache/filter_valid_samples_js"))
    parser.add_argument("--no-cache-read", action="store_true")
    parser.add_argument("--no-cache-write", action="store_true")
    args = parser.parse_args()
    args.model = enforce_openai_model(args.model)

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL), timeout=args.request_timeout)

    gen_rows: List[Optional[Dict[str, Any]]] = [None] * len(rows)

    def _gen_one(i: int, row: Dict[str, Any]) -> Dict[str, Any]:
        if args.use_existing_candidate_js:
            return process_row_use_existing(row, code_field=args.candidate_field)
        return process_row_generate(
            client,
            args.model,
            row,
            task_row_for_filter(row),
            args.retries,
            cache_dir=args.cache_dir,
            cache_read=not args.no_cache_read,
            cache_write=not args.no_cache_write,
            max_output_tokens=args.max_output_tokens,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_gen_one, i, rows[i]): i for i in range(len(rows))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="generating"):
            gen_rows[futures[fut]] = fut.result()

    partial = [r for r in gen_rows if r is not None]
    merged: List[Optional[Dict[str, Any]]] = [None] * len(partial)

    def _eval_one(i: int, row: Dict[str, Any]) -> Dict[str, Any]:
        return evaluate_harness(row, code_field=args.candidate_field)

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_eval_one, i, partial[i]): i for i in range(len(partial))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="harness"):
            merged[futures[fut]] = fut.result()

    final_rows = [r for r in merged if r is not None]
    if args.all_output_jsonl is not None:
        write_jsonl(args.all_output_jsonl, final_rows)

    passed = [r for r in final_rows if r.get("harness_passed")]
    write_jsonl(args.output_jsonl, [_strip_bookkeeping_fields(r) for r in passed])

    print(f"total rows: {len(final_rows)}")
    print(f"generation errors: {sum(1 for r in final_rows if r.get('mini_gen_error'))}")
    print(f"cache hits: {sum(1 for r in final_rows if r.get('mini_gen_cache_hit'))}")
    print(f"harness passed: {len(passed)} -> {args.output_jsonl}")
    if args.all_output_jsonl:
        print(f"wrote all evaluated rows to {args.all_output_jsonl}")


if __name__ == "__main__":
    main()
