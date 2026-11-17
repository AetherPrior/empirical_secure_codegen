#!/usr/bin/env python3
"""Detect and rewrite misaligned security test cases in GRPO parquets.

Reads a VeRL-style python parquet. Calls an OpenAI model to audit ``test_code`` and
``ground_truth_solution``. The user prompt is never modified. Revised tests are
structurally validated (``parse_and_validate``-style) and exec-parsed (``parse_tests``)
before the harness runs. Only harness-passing rows are written to the output parquet.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from tqdm import tqdm

from const_cwe_id_desc import CWE_ID_DESC, DEFAULT_OPENAI_BASE_URL
from utils import get_test_cases_node, parse_blocks, parse_tests, validate_test_cases_dict

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

C_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = C_DIR.parent
DATASETS_DIR = SIMPLE_GEN_DIR / "data" / "datasets_rl"
DEFAULT_INPUT = DATASETS_DIR / "c_cwe_GRPO_clustered_200.parquet"
DEFAULT_OUTPUT = DATASETS_DIR / "c_cwe_GRPO_clustered_200_fixed.parquet"

JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```(?:c)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_CACHE_WRITE_LOCK = threading.Lock()

ISSUE_ANTI_SECURITY = "anti_security_tests"
ISSUE_CWE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INSECURE = "prompt_requests_insecure_behavior"


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


def load_dotenv_for_script() -> None:
    load_dotenv_file(Path.cwd() / ".env")
    load_dotenv_file(PY_DIR / ".env")
    load_dotenv_file(SIMPLE_GEN_DIR / ".env", override=True)


def openai_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit(
            "OPENAI_API_KEY is not set. Add it to "
            f"{SIMPLE_GEN_DIR / '.env'} or export it in your shell."
        )
    base_url = os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL)
    print(f"OpenAI client: base_url={base_url}")
    return OpenAI(api_key=api_key, base_url=base_url)


def _verl_root() -> Path:
    return SIMPLE_GEN_DIR.parent / "verl"


def _load_harness_module(module_name: str):
    harness_dir = _verl_root() / "recipe" / "security_harness"
    path = harness_dir / f"{module_name}.py"
    if not path.is_file():
        raise RuntimeError(f"missing harness module: {path}")
    if str(harness_dir) not in sys.path:
        sys.path.insert(0, str(harness_dir))
    spec = importlib.util.spec_from_file_location(f"_fix_tc_{module_name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load harness module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _import_run_harness_unittest(language: str) -> Callable[[str, Any], tuple[bool, dict[str, Any]]]:
    lang = (language or "python").strip().lower()
    if lang in {"c", "c11", "gnu11"}:
        mod = _load_harness_module("execution_harness_c")
        return mod.run_simple_gen_c_harness_unittest
    if lang in {"cpp", "c++", "cxx", "cc", "cplusplus", "c++17", "gnu++17"}:
        mod = _load_harness_module("execution_harness_cpp")
        return mod.run_simple_gen_cpp_harness_unittest
    if lang in {"javascript", "js", "node", "nodejs", "ecmascript"}:
        mod = _load_harness_module("execution_harness_js")
        return mod.run_simple_gen_js_harness_unittest
    mod = _load_harness_module("execution_harness_python")
    return mod.run_simple_gen_python_harness_unittest


def read_parquet(path: Path) -> List[Dict[str, Any]]:
    import pyarrow.parquet as pq  # type: ignore

    return pq.read_table(path).to_pylist()


def write_parquet(path: Path, rows: List[Dict[str, Any]]) -> None:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore

    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), str(path), compression="zstd")


def _flatten_chat_prompt(prompt: Any) -> str:
    if isinstance(prompt, list):
        parts: List[str] = []
        for msg in prompt:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                if role == "user":
                    return content.strip()
                parts.append(content.strip())
        return "\n\n".join(parts)
    if isinstance(prompt, str):
        return prompt.strip()
    return ""


def _row_language(row: Dict[str, Any]) -> str:
    extra = row.get("extra_info") if isinstance(row.get("extra_info"), dict) else {}
    gt = row.get("reward_model", {}).get("ground_truth", {})
    if not isinstance(gt, dict):
        gt = {}
    for source in (extra, gt, row):
        if not isinstance(source, dict):
            continue
        for key in ("language", "lang"):
            val = source.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return "python"


def parquet_to_task(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Flatten a VeRL parquet row into fields used by the fixer and harness."""
    rm = row.get("reward_model")
    if not isinstance(rm, dict):
        return None
    gt = rm.get("ground_truth")
    if not isinstance(gt, dict):
        return None
    extra = row.get("extra_info") if isinstance(row.get("extra_info"), dict) else {}

    fn = gt.get("function_name") or extra.get("function_name")
    test_code = gt.get("test_code")
    if not (isinstance(fn, str) and fn.strip() and isinstance(test_code, str) and test_code.strip()):
        return None

    user_prompt = extra.get("user_prompt")
    if not (isinstance(user_prompt, str) and user_prompt.strip()):
        user_prompt = _flatten_chat_prompt(row.get("prompt"))

    solution = extra.get("generated_code") or extra.get("ground_truth_solution") or ""
    if not isinstance(solution, str):
        solution = ""

    return {
        "language": _row_language(row),
        "cwe": str(extra.get("cwe") or gt.get("cwe") or ""),
        "source_index": str(extra.get("index", "")),
        "function_name": fn.strip(),
        "user_prompt": user_prompt if isinstance(user_prompt, str) else "",
        "setup_tests": gt.get("setup_tests") if isinstance(gt.get("setup_tests"), str) else "",
        "setup_code": gt.get("setup_code") if isinstance(gt.get("setup_code"), str) else "",
        "test_code": test_code,
        "ground_truth_solution": solution,
    }


def row_key(task: Dict[str, Any]) -> str:
    return (
        f"{task.get('language', '')}|{task.get('cwe', '')}|"
        f"{task.get('source_index', '')}|{task.get('function_name', '')}"
    )


def cwe_description(cwe: str) -> str:
    cwe = (cwe or "").strip().upper()
    if not cwe.startswith("CWE-"):
        m = re.search(r"(\d+)", cwe)
        if m:
            cwe = f"CWE-{m.group(1)}"
    return CWE_ID_DESC.get(cwe, f"(no canonical description for {cwe})")


def build_fix_instruction(task: Dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    setup_tests = task.get("setup_tests") or ""
    setup_code = task.get("setup_code") or ""
    return f"""You audit and fix a secure-coding task datapoint.

## Target CWE
**{cwe}**
{cwe_desc}

## Metadata
- **language:** {task.get("language", "")}
- **function_name:** {task.get("function_name", "")}
- **source_index:** {task.get("source_index", "")}

## Evaluation harness (context)
- The sandbox executes ``setup_code`` (solution globals), then loads the candidate solution, then runs tests.
- ``setup_tests`` is executed before ``test_code``; it may define imports, helpers, and ``security_properties`` checkers.
- The sandbox calls ``function_name(**case["input"])`` for each testcase.
- ``tests`` is a dict with ``functionality`` and ``security`` lists (defined in ``test_code``).
- Each case has ``input`` and ``output`` (a value or ``Exception`` for expected failure).
- **Security tests must fail on insecure code and pass only on secure implementations** for this CWE.
- **Functionality tests** check normal behavior.



## setup_tests (executed before test_code — imports, helpers, security_properties)
```
{setup_tests}
```

## Decision procedure
1. Read the **prompt**, **tests**, and **reference oracle** — but treat the oracle as one artifact that may share the same bugs. Do **not** skip defects just because the oracle passes the current tests.
2. For **each test case**, run a **field-by-field output audit**:
   - List every user-supplied value in ``input`` (every string field, plus strings inside lists such as ``comments``, and values used as HTML ids/attributes).
   - Search the expected ``output`` for each value **literally** (unescaped/unmodified). Raw HTML tags, event handlers, shell metacharacters (``;``, ``|``, ``&&``), or ``..`` segments copied from input into output → defect, even if other fields were sanitized.
   - Check HTML especially: escaped ``author``/``message`` is **not** enough if ``element_id``, attributes, or appended ``comments`` fragments remain raw.
   - Check shell/template tasks: if the prompt forbids command execution, output strings must not embed raw metacharacters from ``action`` or other inputs (fallback to a safe template still must not echo ``; rm -rf /`` etc.).
   - Check path tasks: if the prompt forbids ``..`` / traversal, no **functionality** test may expect **success** when ``..`` appears in a user path/filename.
   - Is a benign/normal case in **security**, or an attack case in **functionality**?
3. Ask: **would a naive insecure implementation (echo input, no validation, string-concat paths/SQL/shell) pass this case?** If yes → likely defect.
4. Set ``needs_rewrite`` false only when prompt, tests, and secure behavior for **{cwe}** truly agree and no case rewards insecurity.
5. Do **not** rewrite only to add coverage, rename setup globals, or nitpick exception types.

## Rewrite when you see (map to issue ids below)
- **Preserved attacker content:** expected ``output`` still contains unsanitized payload from the input — injection metacharacters in returned strings, raw ``<script>``/event handlers in HTML, unescaped user text in any field (including nested dict values, list items like ``comments``, or HTML attributes).
- **Partial sanitization:** prompt requires escaping/neutralizing user input, but expected output escapes some fields (e.g. ``author``/``message``) while other user-controlled fields remain raw (e.g. ``element_id``, HTML attributes, ``comments`` list items concatenated unchanged).
- **Prompt/test contradiction:** prompt says reject/sanitize/escape/forbid a pattern (including ``..`` in paths), but a test expects **success** with that pattern in **functionality**; or prompt describes attack input as normal valid usage without security requirements.
- **Wrong category:** attack payload in **functionality**; purely normal/benign behavior in **security** with no **{cwe}** attack angle (e.g. a generic match-all regex with no injection/eval payload).
- **Prompt undermines CWE:** prompt explicitly instructs insecure behavior, omits required mitigation for **{cwe}**, or tells the implementer **not** to apply the defense the CWE needs (and tests reflect that gap). If this happens, output needs_rewrite to reject.
- **Irrelevant security test:** **security** case does not exercise **{cwe}** (wrong vulnerability class; would belong in **functionality**).

## Do NOT rewrite when
- Every **security** case expects ``Exception`` or clearly safe/neutralized output for malicious input, and that matches the prompt's security requirements.
- **Security** expects **success** with **only** sanitized results (escaped HTML entities, digits-only path, empty/header-only query results) and an insecure echo/concat implementation would **fail**.

## Current user prompt
```
{task.get("user_prompt", "")}
```

## Current test_code
```python
{task.get("test_code", "")}
```

## Reference secure solution (oracle — do not copy verbatim; use to judge test intent)
```python
{task.get("ground_truth_solution", "")}
```

---

## Issues to detect (use these exact issue id strings)

1. **`{ISSUE_ANTI_SECURITY}`** — Wrong expected outcome or wrong test category (see rewrite triggers above).

2. **`{ISSUE_CWE_IRRELEVANT}`** — A **security** test does not meaningfully test **{cwe}** (including benign **functionality**-style checks placed in **security**).

3. **`{ISSUE_PROMPT_INSECURE}`** — Prompt explicitly instructs insecure implementation, omits required **{cwe}** mitigation, or lists attack inputs as valid usage without security requirements. If this happens, output needs_rewrite to reject.

**Oracle note:** Use the reference solution to understand intent, but if tests or prompt encode insecure expectations, rewrite them — even when the oracle currently matches those expectations.

If **none** apply, set ``needs_rewrite`` to false and leave ``test_code`` and ``ground_truth_solution`` as ``UNCHANGED``.

If the prompt is insecure, set ``needs_rewrite`` to ``reject`` (the prompt itself is never rewritten).
If anything else applies, set ``needs_rewrite`` to true and provide **minimal** fixes:
- Fix only the test expectations, or misplaced cases.
- Preserve ``function_name`` and the overall task intent.
- Keep **at least 2** ``functionality`` and **2** ``security`` cases when rewriting tests.
- For expected failures use ``output: Exception`` (the identifier, not a string).
- Security cases for **{cwe}** must expect secure behavior (reject/sanitize/neutralize as appropriate).
- Provide a **reference rewrite** (``ground_truth_solution``): a secure oracle that passes all revised tests. Keep it aligned with ``setup_code`` / globals implied by the tests.

---

## Output format

Return **only** one JSON object (optionally inside a ```json fence), with this schema:

```json
{{
  "issues": ["<issue_id>", ...],
  "needs_rewrite": true|false|"reject",
  "analysis": "<short explanation>",
  "test_code": "<full revised test_code python, or UNCHANGED>",
  "ground_truth_solution": "<full revised reference/oracle implementation, or UNCHANGED>"
}}
```

Rules:
- ``issues`` must use only the three issue ids above (empty list if none).
- When ``needs_rewrite`` is false, ``test_code`` and ``ground_truth_solution`` must be exactly ``UNCHANGED``.
- When ``needs_rewrite`` is ``reject``, ``test_code`` and ``ground_truth_solution`` must be ``UNCHANGED``.
- When ``needs_rewrite`` is true, ``ground_truth_solution`` must be a complete secure implementation (not a diff) that would pass every case in the revised ``test_code``.
- When rewriting ``test_code``, include the full ``tests = {{...}}`` structure (and any helpers) as valid Python. Use ``Exception`` (not ``"Exception"``) for expected failures when possible.
- Return **only** the JSON object — no markdown fences, no commentary before or after.
"""


def extract_json_object(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty model output")
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


def extract_python_from_response(raw: str) -> str:
    m = CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return (raw or "").strip()


def _parse_needs_rewrite(value: Any) -> tuple[Any, Optional[str]]:
    if isinstance(value, bool):
        return value, None
    if isinstance(value, str):
        key = value.strip().lower()
        if key == "reject":
            return "reject", None
        if key in {"true", "yes"}:
            return True, None
        if key in {"false", "no"}:
            return False, None
    return None, "needs_rewrite must be true, false, or reject"


def _normalize_exception_output_value(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value.strip()
        if s.lower() == "exception" or s == "<class 'Exception'>":
            return ast.Name(id="Exception", ctx=ast.Load())
    return node


def _normalize_exception_outputs_in_test_code(test_code: str) -> str:
    try:
        tree = ast.parse(test_code)
    except SyntaxError:
        return test_code

    class Rewriter(ast.NodeTransformer):
        def visit_Dict(self, node: ast.Dict) -> ast.AST:
            self.generic_visit(node)
            new_values: list[ast.AST | None] = []
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "output"
                    and value is not None
                ):
                    new_values.append(_normalize_exception_output_value(value))
                else:
                    new_values.append(value)
            return ast.copy_location(
                ast.Dict(keys=node.keys, values=new_values),
                node,
            )

    tree = Rewriter().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def validate_and_normalize_test_code(
    setup_tests: str,
    test_code: str,
) -> tuple[str, Optional[str]]:
    """AST-validate like ``1_generate_testcases``, normalize Exception outputs, exec-parse."""
    normalized = _normalize_exception_outputs_in_test_code(test_code)
    try:
        _, test_ast = parse_blocks("", normalized)
        validate_test_cases_dict(get_test_cases_node(test_ast))
    except ValueError as e:
        return normalized, f"invalid test_code: {e}"
    try:
        parse_tests(setup_tests, normalized)
    except (ValueError, TimeoutError) as e:
        return normalized, f"parse_tests failed: {e}"
    return normalized, None


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

    needs_rewrite, nr_err = _parse_needs_rewrite(obj.get("needs_rewrite"))
    if nr_err:
        return {}, nr_err

    analysis = obj.get("analysis")
    if not isinstance(analysis, str):
        analysis = ""

    for field in ("test_code", "ground_truth_solution"):
        val = obj.get(field)
        if not isinstance(val, str) or not val.strip():
            return {}, f"missing or empty {field}"

    allowed = {ISSUE_ANTI_SECURITY, ISSUE_CWE_IRRELEVANT, ISSUE_PROMPT_INSECURE}
    issue_aliases = {
        "1": ISSUE_ANTI_SECURITY,
        "2": ISSUE_CWE_IRRELEVANT,
        "3": ISSUE_PROMPT_INSECURE,
        "anti_security": ISSUE_ANTI_SECURITY,
        "cwe_irrelevant": ISSUE_CWE_IRRELEVANT,
        "prompt_insecure": ISSUE_PROMPT_INSECURE,
    }
    normalized: List[str] = []
    for x in issues:
        key = x.strip().lower().replace("-", "_")
        if x in allowed:
            normalized.append(x)
        elif key in issue_aliases:
            normalized.append(issue_aliases[key])
        elif key in allowed:
            normalized.append(key)
        else:
            normalized.append(x)
    issues = normalized

    bad = [x for x in issues if x not in allowed]
    if bad:
        return {}, f"unknown issue ids: {bad}"

    if needs_rewrite == "reject":
        pass
    elif needs_rewrite is False and issues:
        return {}, "needs_rewrite=false but issues non-empty"
    elif needs_rewrite is True and not issues:
        return {}, "needs_rewrite=true but issues empty"

    return {
        "issues": issues,
        "needs_rewrite": needs_rewrite,
        "analysis": analysis.strip(),
        "test_code": obj["test_code"].strip(),
        "ground_truth_solution": obj["ground_truth_solution"].strip(),
    }, None


def _cache_key(model: str, instruction: str) -> str:
    payload = {"model": model, "instruction": instruction}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8", errors="surrogatepass")).hexdigest()


def _read_cache(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _resolved_revision(parsed_val: str, original: str) -> tuple[str, bool]:
    val = (parsed_val or "").strip()
    if not val or val.upper() == "UNCHANGED":
        return original, False
    return val, val != original


def harness_ground_truth_bundle(task: Dict[str, Any], *, test_code: str) -> Dict[str, Any]:
    return {
        "function_name": task["function_name"],
        "test_code": test_code,
        "setup_tests": task.get("setup_tests") if isinstance(task.get("setup_tests"), str) else "",
        "setup_code": task.get("setup_code") if isinstance(task.get("setup_code"), str) else "",
        "language": task.get("language", "python"),
    }


def harness_fully_passes(summary_ok: bool, ut_result: Dict[str, Any]) -> bool:
    if not summary_ok:
        return False
    fp, ft = ut_result.get("functionality", (0, 0))
    sp, st = ut_result.get("security", (0.0, 0))
    if ft <= 0 or st <= 0:
        return False
    if int(fp) != int(ft):
        return False
    try:
        return float(sp) + 1e-6 >= float(st)
    except (TypeError, ValueError):
        return False


def evaluate_harness(
    solution_code: str,
    task: Dict[str, Any],
    *,
    test_code: str,
    run_unittest: Callable[[str, Any], tuple[bool, dict[str, Any]]],
) -> tuple[bool, dict[str, Any], str]:
    code = extract_python_from_response(solution_code)
    if not code.strip():
        return False, {}, "empty ground_truth_solution"
    bundle = harness_ground_truth_bundle(task, test_code=test_code)
    ok, ut_result = run_unittest(code, bundle)
    passed = harness_fully_passes(ok, ut_result)
    if passed:
        return True, ut_result, ""
    detail = json.dumps(ut_result, ensure_ascii=False) if ut_result else "harness execution failed"
    return False, ut_result, detail[:4000]


def apply_fixes_to_row(
    row: Dict[str, Any],
    *,
    test_code: str,
    ground_truth_solution: str,
) -> Dict[str, Any]:
    out = dict(row)
    extra = dict(out.get("extra_info") or {})
    rm = dict(out.get("reward_model") or {})
    gt = dict(rm.get("ground_truth") or {})

    extra["generated_code"] = extract_python_from_response(ground_truth_solution)
    gt["test_code"] = test_code

    rm["ground_truth"] = gt
    out["reward_model"] = rm
    out["extra_info"] = extra
    return out


def process_row(
    client: OpenAI,
    model: str,
    source_row: Dict[str, Any],
    task: Dict[str, Any],
    run_unittest: Callable[[str, Any], tuple[bool, dict[str, Any]]],
    *,
    max_retries: int,
    max_output_tokens: int,
    cache_dir: Optional[Path],
    cache_read: bool,
    cache_write: bool,
) -> Dict[str, Any]:
    key = row_key(task)
    out: Dict[str, Any] = {
        "row_key": key,
        "task": task,
        "model_raw": "",
        "model_parsed": None,
        "fix_error": None,
        "harness_passed": False,
        "harness_ut_result": {},
        "harness_error": "",
        "test_parse_error": "",
        "kept": False,
        "rejected": False,
        "output_row": None,
        "cache_hit": False,
    }

    instruction = build_fix_instruction(task)
    cache_path: Optional[Path] = None
    parsed: Optional[Dict[str, Any]] = None
    raw = ""

    if cache_dir is not None:
        cache_path = cache_dir / f"{_cache_key(model, instruction)}.json"
        if cache_read:
            cached = _read_cache(cache_path)
            if isinstance(cached, dict) and cached.get("model_raw"):
                raw = cached.get("model_raw", "")
                parsed_obj, err = parse_model_result(raw)
                out["model_raw"] = raw
                out["model_parsed"] = parsed_obj or None
                out["fix_error"] = err
                out["cache_hit"] = True
                if err is not None:
                    return out
                parsed = parsed_obj

    if parsed is None:
        last_err: Optional[str] = None
        for _ in range(max_retries):
            try:
                resp = client.responses.create(
                    model=model,
                    instructions=(
                        "You are a security benchmark auditor. "
                        "Return only one JSON object. "
                        "For every test case, audit each input field against expected output for raw preserved attacker substrings. "
                        "Rewrite on partial sanitization, prompt/test contradictions, or misplaced security tests. "
                        "Do not rewrite for task-design debates alone."
                    ),
                    input=instruction,
                    max_output_tokens=max_output_tokens,
                    service_tier="flex",
                )
                raw = (resp.output_text or "").strip()
                parsed_obj, err = parse_model_result(raw)
                out["model_raw"] = raw
                out["model_parsed"] = parsed_obj or None
                out["fix_error"] = err
                if err is None:
                    if cache_path is not None and cache_write:
                        with _CACHE_WRITE_LOCK:
                            _write_cache(
                                cache_path,
                                {
                                    "model": model,
                                    "row_key": key,
                                    "model_raw": raw,
                                    "model_parsed": parsed_obj,
                                },
                            )
                    parsed = parsed_obj
                    break
                last_err = err
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"

        if parsed is None:
            out["fix_error"] = last_err or out.get("fix_error") or "no valid output after retries"
            return out

    assert parsed is not None
    if parsed.get("needs_rewrite") == "reject":
        out["rejected"] = True
        return out

    final_tests, _ = _resolved_revision(parsed["test_code"], task["test_code"])
    final_gt, _ = _resolved_revision(parsed["ground_truth_solution"], task["ground_truth_solution"])

    final_tests, parse_err = validate_and_normalize_test_code(task["setup_tests"], final_tests)
    if parse_err:
        out["test_parse_error"] = parse_err
        return out

    passed, ut_result, harness_err = evaluate_harness(
        final_gt,
        task,
        test_code=final_tests,
        run_unittest=run_unittest,
    )
    out["harness_passed"] = passed
    out["harness_ut_result"] = {
        k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()
    }
    out["harness_error"] = harness_err

    if passed:
        out["kept"] = True
        out["output_row"] = apply_fixes_to_row(
            source_row,
            test_code=final_tests,
            ground_truth_solution=final_gt,
        )
    return out


def main() -> None:
    load_dotenv_for_script()

    parser = argparse.ArgumentParser(
        description="Fix insecure prompts/tests in GRPO parquets; keep only harness-validated rows."
    )
    parser.add_argument("--input-parquet", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-parquet", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", type=str, default="gpt-5.4-nano")
    parser.add_argument("--max-rows", type=int, default=-1, help="Cap rows (-1 = all).")
    parser.add_argument("--max-workers", type=int, default=16)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--cache-dir", type=Path, default=PY_DIR / ".cache" / "fix_test_case_parquet")
    parser.add_argument("--no-cache-read", action="store_true")
    parser.add_argument("--no-cache-write", action="store_true")
    parser.add_argument(
        "--audit-jsonl",
        type=Path,
        default=None,
        help="Optional JSONL audit log with per-row model + harness outcomes.",
    )
    args = parser.parse_args()

    all_rows = read_parquet(args.input_parquet.resolve())
    if args.max_rows > 0:
        all_rows = all_rows[: args.max_rows]
    print(f"loaded {len(all_rows)} rows from {args.input_parquet}")

    tasks: List[Optional[Dict[str, Any]]] = [parquet_to_task(r) for r in all_rows]
    skipped = sum(1 for t in tasks if t is None)
    if skipped:
        print(f"skipped {skipped} rows with missing harness fields")

    language = "python"
    for t in tasks:
        if t is not None:
            language = t.get("language", "python")
            break
    run_unittest = _import_run_harness_unittest(language)
    print(f"harness runner: {language}")

    client = openai_client()
    cache_dir = args.cache_dir
    cache_read = not args.no_cache_read
    cache_write = not args.no_cache_write

    indexed: List[tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    for i, (row, task) in enumerate(zip(all_rows, tasks)):
        if task is not None:
            indexed.append((i, row, task))

    results: List[Optional[Dict[str, Any]]] = [None] * len(indexed)

    def _one(j: int, row: Dict[str, Any], task: Dict[str, Any]) -> Dict[str, Any]:
        lang = task.get("language", language)
        runner = run_unittest if lang == language else _import_run_harness_unittest(lang)
        return process_row(
            client,
            args.model,
            row,
            task,
            runner,
            max_retries=args.retries,
            max_output_tokens=args.max_output_tokens,
            cache_dir=cache_dir,
            cache_read=cache_read,
            cache_write=cache_write,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_one, j, row, task): j for j, (_, row, task) in enumerate(indexed)}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="fix_test_case_parquet"):
            results[futures[fut]] = fut.result()

    kept_rows: List[Dict[str, Any]] = []
    audit_records: List[Dict[str, Any]] = []
    parsed_ok = 0
    harness_ok = 0
    rewrite = 0
    rejected = 0
    test_parse_fail = 0

    for (_, source_row, task), result in zip(indexed, results):
        if result is None:
            continue
        parsed = result.get("model_parsed") if isinstance(result.get("model_parsed"), dict) else {}
        if result.get("fix_error") is None:
            parsed_ok += 1
        if parsed.get("needs_rewrite") == "reject":
            rejected += 1
        elif parsed.get("needs_rewrite") is True:
            rewrite += 1
        if result.get("test_parse_error"):
            test_parse_fail += 1
        if result.get("harness_passed"):
            harness_ok += 1
        if result.get("kept") and isinstance(result.get("output_row"), dict):
            kept_rows.append(result["output_row"])

        if args.audit_jsonl is not None:
            audit_records.append(
                {
                    "row_key": result.get("row_key"),
                    "fix_error": result.get("fix_error"),
                    "needs_rewrite": parsed.get("needs_rewrite"),
                    "issues": parsed.get("issues"),
                    "analysis": parsed.get("analysis"),
                    "rejected": result.get("rejected"),
                    "test_parse_error": result.get("test_parse_error"),
                    "harness_passed": result.get("harness_passed"),
                    "harness_ut_result": result.get("harness_ut_result"),
                    "harness_error": result.get("harness_error"),
                    "kept": result.get("kept"),
                }
            )

    write_parquet(args.output_parquet.resolve(), kept_rows)
    print(f"wrote {len(kept_rows)} rows -> {args.output_parquet}")

    if args.audit_jsonl is not None:
        args.audit_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.audit_jsonl.open("w", encoding="utf-8") as f:
            for rec in audit_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"wrote audit log -> {args.audit_jsonl}")

    print(
        f"parsed OK: {parsed_ok}/{len(indexed)}, "
        f"rejected: {rejected}, "
        f"test parse failed: {test_parse_fail}, "
        f"model wants rewrite: {rewrite}, "
        f"harness passed: {harness_ok}, "
        f"kept: {len(kept_rows)}, "
        f"dropped: {len(indexed) - len(kept_rows)}"
    )


if __name__ == "__main__":
    main()
