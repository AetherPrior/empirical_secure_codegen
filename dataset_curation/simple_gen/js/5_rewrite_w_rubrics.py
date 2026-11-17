#!/usr/bin/env python3
"""Audit-rewrite ``4_valid.jsonl`` rows and re-run the Node harness.

For each pipeline row (passing oracle + authoring guidelines), this script:

1. Builds an audit task from ``prompt``, ``test_code`` / ``tests_json``, ``candidate_js``.
2. Calls an LLM audit using CWE rubrics from ``data_annotation_files/js/rubrics_js/``.
3. Applies rewritten JSON tests / oracle onto the row when the harness passes.
4. Runs ``run_simple_gen_js_harness_unittest`` via ``4_filter_valid_samples.evaluate_harness``.
5. Writes ``5_rewritten.jsonl`` — harness-passing rows only.

**Input:** ``<run-dir>/4_valid.jsonl``
**Output:** ``<run-dir>/5_rewritten.jsonl``
"""

from __future__ import annotations

import argparse
import importlib.util
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
ANNOT_JS_DIR = Path(__file__).resolve().parents[2] / "data_annotation_files" / "js"
for _p in (SIMPLE_GEN_DIR, JS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import CWE_ID_DESC, DEFAULT_OPENAI_BASE_URL, enforce_openai_model, openai_service_tier  # noqa: E402
from js_utils import (  # noqa: E402
    extract_js_source_from_markdown,
    extract_param_names,
    parse_and_validate_tests_json,
    read_jsonl,
    tests_json_from_row,
    write_jsonl,
)

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc


def _load_filter_module():
    path = JS_DIR / "4_filter_valid_samples.py"
    spec = importlib.util.spec_from_file_location("_js_filter_for_rewrite", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_js_filter_for_rewrite"] = mod
    spec.loader.exec_module(mod)
    return mod


_FILTER = _load_filter_module()
load_dotenv_for_script = _FILTER.load_dotenv_for_script
evaluate_harness = _FILTER.evaluate_harness

ISSUE_ANTI_SECURITY = "anti_security_tests"
ISSUE_CWE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INVALID = "prompt_requests_invalid_behavior"
ISSUE_BROKEN_SETUP = "broken_setup_code"

DEFAULT_CWE_REWRITE_RUBRIC = """- **reject:** prompt requires vulnerable behavior or lacks the CWE mitigation boundary.
- **UNCHANGED:** security cases already defeat naive insecure implementations; setup_code is harness-runnable.
- **rewrite:** tests reward the exploit, wrong category, security does not test this CWE, or setup_code is broken (e.g. invalid jsdom DOMParser import)."""

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

REWRITE_METADATA_KEYS = frozenset(
    {
        "original_test_code",
        "original_tests_json",
        "original_setup_code",
        "original_generated_code",
        "original_candidate_js",
        "rewrite_change",
        "rewrite_issues",
        "rewrite_analysis",
        "rewrite_error",
        "rewrite_test_parse_error",
        "rewrite_rejected",
        "rewrite_harness_error",
        "harness_passed",
        "harness_summary_ok",
        "harness_ut_result",
        "harness_stderr",
    }
)

JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
RUBRICS_DIR = ANNOT_JS_DIR / "rubrics_js"


def normalize_cwe(cwe: Any) -> str:
    text = str(cwe or "").strip().upper()
    if not text:
        return ""
    if not text.startswith("CWE-"):
        m = re.search(r"(\d+)", text)
        if m:
            text = f"CWE-{m.group(1)}"
    return text


def parse_cwe_list(values: List[str]) -> List[str]:
    out: List[str] = []
    for value in values:
        for part in value.split(","):
            cwe = normalize_cwe(part)
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def cwe_description(cwe: str) -> str:
    c = normalize_cwe(cwe)
    desc = CWE_ID_DESC.get(c) or CWE_ID_DESC.get(c.replace("CWE-", ""))
    if desc:
        return f"**{c}**: {desc}"
    return f"**{c}**"


def load_rubric(cwe: str) -> str:
    m = re.search(r"(\d+)", normalize_cwe(cwe))
    if not m:
        return DEFAULT_CWE_REWRITE_RUBRIC
    path = RUBRICS_DIR / f"{m.group(1)}.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return DEFAULT_CWE_REWRITE_RUBRIC


def extract_json_object(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    m = JSON_FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    i = text.find("{")
    j = text.rfind("}")
    if i < 0 or j <= i:
        raise ValueError("no JSON object in model output")
    obj = json.loads(text[i : j + 1])
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be an object")
    return obj


def _parse_change(value: Any) -> tuple[str, Optional[str]]:
    if isinstance(value, bool):
        return ("rewrite" if value else "UNCHANGED"), None
    if isinstance(value, str):
        key = value.strip()
        lower = key.lower()
        if lower == "reject":
            return "reject", None
        if key.upper() == "UNCHANGED" or lower in {"false", "no", "unchanged"}:
            return "UNCHANGED", None
        if lower in {"rewrite", "true", "yes"}:
            return "rewrite", None
    return "", "change must be reject, rewrite, or UNCHANGED"


def parse_model_result(raw: str) -> tuple[Dict[str, Any], Optional[str]]:
    try:
        obj = extract_json_object(raw)
    except (json.JSONDecodeError, ValueError) as e:
        return {}, f"{type(e).__name__}: {e}"

    issues = obj.get("issues")
    if issues is None:
        issues = []
    if not isinstance(issues, list):
        return {}, "issues must be a list"
    issues = [str(x) for x in issues]

    raw_change = obj.get("change")
    if raw_change is None:
        raw_change = obj.get("needs_rewrite")
    change, change_err = _parse_change(raw_change)
    if change_err:
        return {}, change_err

    analysis = obj.get("analysis")
    if not isinstance(analysis, str):
        analysis = ""

    for field in ("setup_code", "test_code", "ground_truth_solution"):
        val = obj.get(field)
        if not isinstance(val, str) or not val.strip():
            return {}, f"missing or empty {field}"

    allowed = {
        ISSUE_ANTI_SECURITY,
        ISSUE_CWE_IRRELEVANT,
        ISSUE_PROMPT_INVALID,
        ISSUE_BROKEN_SETUP,
    }
    issue_aliases = {
        "1": ISSUE_ANTI_SECURITY,
        "2": ISSUE_CWE_IRRELEVANT,
        "3": ISSUE_PROMPT_INVALID,
        "4": ISSUE_BROKEN_SETUP,
        "anti_security": ISSUE_ANTI_SECURITY,
        "cwe_irrelevant": ISSUE_CWE_IRRELEVANT,
        "prompt_invalid": ISSUE_PROMPT_INVALID,
        "broken_setup": ISSUE_BROKEN_SETUP,
        "setup": ISSUE_BROKEN_SETUP,
    }
    normalized: List[str] = []
    for x in issues:
        key = issue_aliases.get(x.strip().lower(), x.strip())
        if key not in allowed:
            return {}, f"unknown issue label: {x}"
        if key not in normalized:
            normalized.append(key)

    if change == "reject" and normalized != [ISSUE_PROMPT_INVALID]:
        return {}, "reject requires issues exactly [prompt_requests_invalid_behavior]"
    if change == "UNCHANGED" and normalized:
        return {}, "UNCHANGED requires empty issues"

    return {
        "issues": normalized,
        "change": change,
        "analysis": analysis,
        "setup_code": obj["setup_code"].strip(),
        "test_code": obj["test_code"].strip(),
        "ground_truth_solution": obj["ground_truth_solution"].strip(),
    }, None


def _resolved_revision(parsed_val: str, original: str) -> tuple[str, bool]:
    if parsed_val.strip().upper() == "UNCHANGED":
        return original, False
    return parsed_val, True


def _tests_blob_for_prompt(row: Dict[str, Any]) -> str:
    try:
        return json.dumps(tests_json_from_row(row), ensure_ascii=False, indent=2)
    except Exception:
        raw = row.get("test_code") or ""
        return raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False, default=str)


def validate_and_normalize_test_code(
    test_code: str,
    *,
    arguments: Any = None,
) -> tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    code = (test_code or "").strip()
    if not code:
        return code, None, "empty test_code"
    try:
        param_names = extract_param_names({"arguments": arguments}) if arguments is not None else None
        parsed = parse_and_validate_tests_json(code, param_names=param_names or None)
    except Exception as e:
        return code, None, f"invalid tests JSON: {type(e).__name__}: {e}"
    return json.dumps(parsed, ensure_ascii=False), parsed, None


def build_fix_instruction(task: Dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    cwe_rubric = load_rubric(cwe)
    setup_code = task.get("setup_code") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI_SECURITY,
        irrelevant=ISSUE_CWE_IRRELEVANT,
        setup=ISSUE_BROKEN_SETUP,
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
```javascript
{setup_code}
```

## test_code (JSON)
```json
{task.get("test_code", "")}
```

## oracle JavaScript (may share test bugs)
```javascript
{task.get("ground_truth_solution", "")}
```
"""


def audit_process_row(
    client: OpenAI,
    model: str,
    task: Dict[str, Any],
    *,
    max_retries: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "model_parsed": None,
        "fix_error": None,
        "test_parse_error": "",
        "final_setup_code": "",
        "final_test_code": "",
        "final_tests_json": None,
        "final_ground_truth_solution": "",
        "kept": False,
        "rejected": False,
        "harness_passed": False,
        "harness_ut_result": {},
        "harness_error": "",
    }

    instruction = build_fix_instruction(task)
    parsed: Optional[Dict[str, Any]] = None
    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are a security auditor for JavaScript GRPO harnesses. "
                    "Return only one JSON object. "
                    "Rewrite on anti-security expectations, wrong-category security tests, missing CWE coverage, "
                    "or broken setup_code (e.g. invalid jsdom DOMParser import). "
                    "When change is rewrite, fix every field you criticized: setup_code and/or test_code and/or "
                    "ground_truth_solution (use literal UNCHANGED for fields that are already fine)."
                ),
                input=instruction,
                max_output_tokens=max_output_tokens,
                service_tier=openai_service_tier(),
            )
            parsed_obj, err = parse_model_result((resp.output_text or "").strip())
            out["model_parsed"] = parsed_obj or None
            out["fix_error"] = err
            if err is None:
                parsed = parsed_obj
                break
            last_err = err
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    if parsed is None:
        out["fix_error"] = last_err or out.get("fix_error") or "no valid output after retries"
        return out

    if parsed.get("change") == "reject":
        out["rejected"] = True
        return out

    final_setup, _ = _resolved_revision(parsed.get("setup_code") or "UNCHANGED", task.get("setup_code") or "")
    final_tests, _ = _resolved_revision(parsed["test_code"], task["test_code"])
    final_gt, _ = _resolved_revision(parsed["ground_truth_solution"], task["ground_truth_solution"])
    final_tests, parsed_tests, parse_err = validate_and_normalize_test_code(
        final_tests,
        arguments=task.get("arguments"),
    )
    out["final_setup_code"] = final_setup
    out["final_test_code"] = final_tests
    out["final_tests_json"] = parsed_tests
    out["final_ground_truth_solution"] = extract_js_source_from_markdown(final_gt) or final_gt.strip()
    if parse_err:
        out["test_parse_error"] = parse_err
        return out

    probe = {
        "function_name": task["function_name"],
        "cwe": task["cwe"],
        "arguments": task.get("arguments") or [],
        "setup_code": final_setup,
        "test_code": final_tests,
        "tests_json": parsed_tests,
        "candidate_js": out["final_ground_truth_solution"],
        "generated_code": out["final_ground_truth_solution"],
    }
    harness_row = evaluate_harness(probe, code_field="candidate_js")
    out["harness_passed"] = bool(harness_row.get("harness_passed"))
    out["harness_ut_result"] = harness_row.get("harness_ut_result") or {}
    out["harness_error"] = harness_row.get("harness_stderr") or ""
    if out["harness_passed"]:
        out["kept"] = True
    return out


def _oracle_from_row(row: Dict[str, Any]) -> str:
    for key in ("candidate_js", "generated_code"):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def row_to_audit_task(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    fn = str(row.get("function_name") or "").strip()
    prompt = str(row.get("prompt") or "").strip()
    ground_truth = _oracle_from_row(row)
    cwe = str(row.get("cwe") or "").strip()
    try:
        tests_blob = _tests_blob_for_prompt(row)
    except Exception:
        tests_blob = str(row.get("test_code") or "").strip()
    if not (fn and prompt and tests_blob and ground_truth and cwe):
        return None
    return {
        "language": "javascript",
        "cwe": normalize_cwe(cwe),
        "function_name": fn,
        "user_prompt": prompt,
        "setup_code": str(row.get("setup_code") or ""),
        "arguments": row.get("arguments") or [],
        "test_code": tests_blob,
        "ground_truth_solution": ground_truth,
    }


def apply_rewrite(row: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    parsed = result.get("model_parsed") or {}
    change = parsed.get("change") or ""
    if result.get("rejected"):
        change = "reject"

    harness_passed = bool(result.get("harness_passed"))
    original_test_code = row.get("test_code") or ""
    original_tests_json = row.get("tests_json")
    original_setup = row.get("setup_code") or ""
    original_oracle = _oracle_from_row(row)

    out["original_test_code"] = original_test_code
    out["original_tests_json"] = original_tests_json
    out["original_setup_code"] = original_setup
    out["original_generated_code"] = original_oracle
    out["original_candidate_js"] = original_oracle
    out["rewrite_change"] = change
    out["rewrite_issues"] = parsed.get("issues")
    out["rewrite_analysis"] = parsed.get("analysis") or ""
    out["rewrite_error"] = result.get("fix_error")
    out["rewrite_test_parse_error"] = result.get("test_parse_error") or ""
    out["rewrite_rejected"] = bool(result.get("rejected"))
    out["rewrite_harness_error"] = result.get("harness_error") or ""
    out["harness_passed"] = harness_passed
    out["harness_summary_ok"] = harness_passed
    out["harness_ut_result"] = result.get("harness_ut_result") or {}

    if harness_passed:
        final_tests = result.get("final_test_code") or original_test_code
        final_json = result.get("final_tests_json")
        out["test_code"] = final_tests
        if isinstance(final_json, dict):
            out["tests_json"] = final_json
        out["setup_code"] = result.get("final_setup_code") if result.get("final_setup_code") is not None else original_setup
        code = result.get("final_ground_truth_solution") or original_oracle
        out["candidate_js"] = code
        out["generated_code"] = code

    return out


def row_for_output(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if k not in REWRITE_METADATA_KEYS}


def process_row(
    client: OpenAI,
    model: str,
    row: Dict[str, Any],
    *,
    max_retries: int,
    max_output_tokens: int,
) -> Dict[str, Any]:
    task = row_to_audit_task(row)
    if task is None:
        out = dict(row)
        out["rewrite_error"] = "skipped: missing prompt/test_code/oracle/function_name/cwe"
        out["rewrite_change"] = "skip"
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        return out

    audit_result = audit_process_row(
        client,
        model,
        task,
        max_retries=max_retries,
        max_output_tokens=max_output_tokens,
    )
    return apply_rewrite(row, audit_result)


def discover_guidelines_paths(
    run_root: Path,
    *,
    language: str,
    cwes: Optional[List[str]],
) -> List[Tuple[Path, Path]]:
    lang_dir = run_root / language
    if not lang_dir.is_dir():
        raise FileNotFoundError(f"language directory not found: {lang_dir}")

    wanted = {normalize_cwe(c) for c in cwes} if cwes else None
    pairs: List[Tuple[Path, Path]] = []
    for cwe_dir in sorted(lang_dir.glob("cwe-*")):
        if not cwe_dir.is_dir():
            continue
        m = re.search(r"cwe[-_]?(\d+)", cwe_dir.name, re.I)
        cwe_id = f"CWE-{m.group(1)}" if m else normalize_cwe(cwe_dir.name)
        if wanted is not None and cwe_id not in wanted:
            continue
        inp = cwe_dir / "4_valid.jsonl"
        if not inp.is_file():
            continue
        pairs.append((inp, cwe_dir / "5_rewritten.jsonl"))
    return pairs


def run_file(
    client: OpenAI,
    model: str,
    input_jsonl: Path,
    output_jsonl: Path,
    *,
    max_rows: int,
    max_workers: int,
    retries: int,
    max_output_tokens: int,
    all_output_jsonl: Optional[Path],
) -> None:
    rows = read_jsonl(input_jsonl)
    if max_rows > 0:
        rows = rows[:max_rows]

    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        output_jsonl.write_text("", encoding="utf-8")
        if all_output_jsonl is not None:
            all_output_jsonl.parent.mkdir(parents=True, exist_ok=True)
            all_output_jsonl.write_text("", encoding="utf-8")
        print(f"{input_jsonl}: no rows, wrote empty {output_jsonl}")
        return

    results: List[Optional[Dict[str, Any]]] = [None] * len(rows)

    def _one(i: int, r: Dict[str, Any]) -> Dict[str, Any]:
        return process_row(
            client,
            model,
            r,
            max_retries=retries,
            max_output_tokens=max_output_tokens,
        )

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = {ex.submit(_one, i, rows[i]): i for i in range(len(rows))}
        desc = input_jsonl.parent.name
        for fut in tqdm(as_completed(futures), total=len(futures), desc=desc):
            results[futures[fut]] = fut.result()

    evaluated = [r for r in results if r is not None]
    passing = [r for r in evaluated if r.get("harness_passed")]

    write_jsonl(output_jsonl, [row_for_output(r) for r in passing])

    if all_output_jsonl is not None:
        write_jsonl(all_output_jsonl, evaluated)

    n_pass = len(passing)
    n_reject = sum(1 for r in evaluated if r.get("rewrite_rejected"))
    msg = (
        f"{input_jsonl.name}: wrote {n_pass} passing rows -> {output_jsonl} "
        f"(input {len(rows)}, harness_passed {n_pass}, rewrite_rejected {n_reject})"
    )
    if all_output_jsonl is not None:
        msg += f"; all eval -> {all_output_jsonl}"
    print(msg)


def main() -> None:
    load_dotenv_for_script(__file__)
    parser = argparse.ArgumentParser(
        description="Rewrite 4_valid.jsonl rows via rubrics_js audit and re-run Node harness"
    )
    parser.add_argument("--input-jsonl", type=Path, default=None)
    parser.add_argument("--output-jsonl", type=Path, default=None)
    parser.add_argument("--run-root", type=Path, default=None)
    parser.add_argument("--language", type=str, default="js")
    parser.add_argument("--cwes", nargs="+", default=None)
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=8)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--request-timeout", type=float, default=180.0)
    parser.add_argument("--all-output-jsonl", type=Path, default=None)
    args = parser.parse_args()
    args.model = enforce_openai_model(args.model)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL),
        timeout=args.request_timeout,
    )
    cwes = parse_cwe_list(args.cwes) if args.cwes else None

    if args.run_root is not None:
        pairs = discover_guidelines_paths(args.run_root.resolve(), language=args.language, cwes=cwes)
        if not pairs:
            raise SystemExit(f"no 4_valid.jsonl under {args.run_root}/{args.language}")
        for inp, out in pairs:
            debug = None
            if args.all_output_jsonl is not None:
                debug = out.with_name("5_all_eval.debug.jsonl")
            run_file(
                client,
                args.model,
                inp,
                out,
                max_rows=args.max_rows,
                max_workers=args.max_workers,
                retries=args.retries,
                max_output_tokens=args.max_output_tokens,
                all_output_jsonl=debug,
            )
        return

    if args.input_jsonl is None:
        raise SystemExit("provide --input-jsonl or --run-root")
    input_jsonl = args.input_jsonl.resolve()
    output_jsonl = (args.output_jsonl or input_jsonl.with_name("5_rewritten.jsonl")).resolve()
    run_file(
        client,
        args.model,
        input_jsonl,
        output_jsonl,
        max_rows=args.max_rows,
        max_workers=args.max_workers,
        retries=args.retries,
        max_output_tokens=args.max_output_tokens,
        all_output_jsonl=args.all_output_jsonl.resolve() if args.all_output_jsonl else None,
    )


if __name__ == "__main__":
    main()
