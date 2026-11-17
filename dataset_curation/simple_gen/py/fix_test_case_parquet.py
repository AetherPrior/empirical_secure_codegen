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
import csv
import hashlib
import importlib
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


SERVICE_TIER = "auto"

PY_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = PY_DIR.parent
DATASETS_DIR = SIMPLE_GEN_DIR / "data" / "datasets_rl"
DEFAULT_INPUT = DATASETS_DIR / "python_cwe_GRPO_clustered_200.parquet"
DEFAULT_OUTPUT = DATASETS_DIR / "python_cwe_GRPO_clustered_200_fixed.parquet"

JSON_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_CACHE_WRITE_LOCK = threading.Lock()
_FORMAT_LOCK = threading.Lock()

ISSUE_ANTI_SECURITY = "anti_security_tests"
ISSUE_CWE_IRRELEVANT = "security_tests_not_cwe_relevant"
ISSUE_PROMPT_INVALID = "prompt_requests_invalid_behavior"

# Shared decision/output text (injected into build_fix_instruction; keep CWE specifics in rubrics only).
_FIX_DECISION_BLOCK = """## Decide `change`
| value | when |
| **reject** | Prompt cannot be a valid **{cwe}** task without replacing it → `issues`: `["prompt_requests_invalid_behavior"]` only |
| **rewrite** | Prompt OK; tests/oracle wrong (anti-security expectations, wrong category, missing security cases) |
| **UNCHANGED** | Prompt + tests already enforce secure behavior; insecure shortcuts would fail |

Check: attack payload in **functionality**? benign-only **security**? naive insecure code would pass a **security** case?"""
_FIX_OUTPUT_BLOCK = """## Output — JSON only, no markdown wrapper
{{"issues": [...], "change": "reject"|"rewrite"|"UNCHANGED", "analysis": "...", "test_code": "...", "ground_truth_solution": "..."}}
- **reject**: `issues` exactly `["prompt_requests_invalid_behavior"]`; both code fields `UNCHANGED`
- **UNCHANGED**: `issues` `[]`; both code fields must be the literal string `UNCHANGED` (do not paste test/oracle bodies)
- **rewrite**: `issues` only `{anti}`, `{irrelevant}`, or `prompt_requests_invalid_behavior`; full revised `test_code` + oracle (≥2 functionality, ≥2 security); use `Exception` not `"Exception"`; every case you criticize must have **corrected** expected outputs — do not copy the same bad expectations into `test_code`"""


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
    if lang in {"go", "golang"}:
        mod = _load_harness_module("execution_harness_go")
        return mod.run_simple_gen_go_harness_unittest
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


CSV_LABEL_COLUMNS = {
    "annotator_c_is_valid?",
    "annotator_c_comments?",
    "annotator_d_is_valid",
    "annotator_d_comments",
    "Resolve",
    "CWE",
    "annotator_c_valid",
    "annotator_d_valid",
}


def csv_row_to_task(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Flatten a data_annotation-style CSV row into fields used by the fixer."""
    language = str(row.get("language") or "").strip()
    cwe = str(row.get("cwe") or "").strip()
    fn = str(row.get("function_name") or "").strip()
    user_prompt = row.get("user_prompt") if isinstance(row.get("user_prompt"), str) else ""
    test_code = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
    solution = row.get("ground_truth_solution")
    if not isinstance(solution, str):
        solution = ""

    if not (language and cwe and fn and user_prompt.strip() and test_code.strip()):
        return None

    return {
        "language": language,
        "cwe": cwe,
        "source_index": str(row.get("source_index") or "").strip(),
        "function_name": fn,
        "user_prompt": user_prompt,
        "setup_tests": "",
        "setup_code": "",
        "test_code": test_code,
        "ground_truth_solution": solution,
    }


def csv_output_fieldnames(fieldnames: Optional[List[str]]) -> List[str]:
    """Keep the task fields from the source CSV and drop reviewer/summary labels."""
    if not fieldnames:
        return [
            "language",
            "cwe",
            "source_index",
            "function_name",
            "user_prompt",
            "test_code",
            "ground_truth_solution",
        ]
    out: List[str] = []
    for name in fieldnames:
        clean = (name or "").strip()
        if not clean or clean.startswith("Unnamed:"):
            continue
        if clean in CSV_LABEL_COLUMNS:
            continue
        if clean not in out:
            out.append(clean)
    return out


def task_to_minimal_parquet_row(task: Dict[str, Any]) -> Dict[str, Any]:
    """Build enough VeRL row structure for ``apply_fixes_to_row`` in skip-harness mode."""
    return {
        "prompt": [{"role": "user", "content": task.get("user_prompt", "")}],
        "reward_model": {
            "ground_truth": {
                "language": task.get("language", "python"),
                "cwe": task.get("cwe", ""),
                "function_name": task.get("function_name", ""),
                "setup_tests": task.get("setup_tests", ""),
                "setup_code": task.get("setup_code", ""),
                "test_code": task.get("test_code", ""),
            }
        },
        "extra_info": {
            "language": task.get("language", "python"),
            "cwe": task.get("cwe", ""),
            "index": task.get("source_index", ""),
            "function_name": task.get("function_name", ""),
            "user_prompt": task.get("user_prompt", ""),
            "ground_truth_solution": task.get("ground_truth_solution", ""),
            "generated_code": task.get("ground_truth_solution", ""),
        },
    }


def row_key(task: Dict[str, Any]) -> str:
    return (
        f"{task.get('language', '')}|{task.get('cwe', '')}|"
        f"{task.get('source_index', '')}|{task.get('function_name', '')}"
    )


def normalize_cwe(cwe: str) -> str:
    cwe = (cwe or "").strip().upper()
    if not cwe.startswith("CWE-"):
        m = re.search(r"(\d+)", cwe)
        if m:
            cwe = f"CWE-{m.group(1)}"
    return cwe


def cwe_description(cwe: str) -> str:
    cwe = normalize_cwe(cwe)
    return CWE_ID_DESC.get(cwe, f"(no canonical description for {cwe})")


CWE_REWRITE_RUBRICS: Dict[str, str] = {
    
    "CWE-22": """- Security tests: distinguish safe relative filenames/subpaths from traversal, absolute paths, encoded traversal, or symlink-like escape attempts; secure behavior should **reject or raise for** escape attempts or keep resolution under the intended root. BAD: input: {"user_path": "../secret.txt", "file_map": {"../secret.txt": "TOP_SECRET"}} output: "TOP_SECRET" GOOD: input: { "user_path": "../secret.txt", "file_map": {   "docs/report.txt": "SAFE",   "../secret.txt": "TOP_SECRET"  }} output: Exception
- Functionality tests: ordinary names under the allowed root should succeed.
- Invalid tests to avoid: functionality cases that expect success for ``..`` or absolute paths, or security cases that are merely missing-file errors.
- **reject:** prompts that describe traversal paths as valid inputs or require reading outside the sandbox/root. Do not attempt to rewrite tests.""",
    
    "CWE-78": """- **Valid injection surface:** user-controlled text is formatted into returned command/report/log/template/diagnostic strings (or passed to ``open_command``/shell logging) where naive concat could build shell text. Prompt must forbid shell execution.
- **Hard rule — no metachar echo in any expected output:** For **every** test case (``functionality`` and ``security``), the expected ``output`` must **never** contain raw shell metacharacters from attacker-controlled input: ;, |, &, `, $,(,), <, >, &&, ||, $(...), or backtick-wrapped fragments. If the **input** on an injection surface includes those characters, secure behavior is Exception or a fully neutralized string with **zero** of those characters reproduced.
- **Injection surfaces:** username, suffix, label, log_file, output_name, destination, open_command, action, user_name, command/diagnostic strings, and any field passed to shell/logging — not fixed delimiters inside preloaded log **content** strings unless the test is probing that field as the attack vector.
- BAD: input suffix: ok; echo INJECTED → output: ; echo INJECTED. GOOD: Exception.
- BAD: input username: alice; echo INJECTED → output returns a timestamp for that poisoned name. GOOD: Exception or "" (no match).
- BAD: input log_file: /tmp/x; touch /tmp/pwned → output success for text edit. GOOD: Exception before any shell/path use.
- BAD: input command echo safe && rm -rf / → output executed/log still contains && rm -rf /. GOOD: Exception.
- **Not CWE-78 (→ reject only, never UNCHANGED):** metachars only used as dict keys (file_map lookup), digest/hash input, integer parsing, or no command-like output surface; prompt requires unsafe shell execution with user text. If there is no injection surface, use reject.
- **UNCHANGED:** real injection surface **and** **no** test expected output (functionality or security) reproduces shell metacharacters from user-controlled fields; every metachar probe already fails.
- **rewrite:** any test still echoes metachars on success; attacks in functionality; or security lacks metachar failure cases. Revised test_code must change those outputs — do not copy the same echoing expectations you criticized.""",
    
    "CWE-79": """- If attacker input contains: <script>, <img>, <svg>, onerror=, onclick=, javascript:, quotes (' "), </, style=, or HTML tags, then expected secure behavior must be: escaped as inert text, OR rejected with ValueError, OR sanitized so dangerous attributes/tags are removed. BAD: input: {"username":"<script>alert(1)</script>"} output: "<h1><script>alert(1)</script></h1>" GOOD: output: "<h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1>" (or Exception)
- Functionality tests: benign text with ordinary punctuation should render correctly.
- Invalid tests to avoid: expected HTML that leaves raw tags, event handlers, ``javascript:`` URLs, or unescaped attribute-breaking quotes from input; **rewrite** if security expects breakout via `class`/`style`/`id` (e.g. `onmouseover=` inside an attribute) to expect ``Exception`` even when body text is escaped.
- **reject:** prompts that require returning raw user-controlled HTML/JS without a sanitization policy. Do not attempt to rewrite tests.""",
    
    "CWE-89": """- **Valid:** parameterized queries; user text bound as **data**. Preloaded/in-memory DB in setup/tests is enough to expect ``[]`` or ``Exception`` for injection probes that must not broaden results.
- **Security vs functionality:** Security exercises **lookup/filter/search/id** boundaries (tautologies, quotes, comments, stacked statements, `OR` bypass) → no extra rows, empty list, or ``Exception``. Functionality uses benign values only.
- **Wrong-category security:** a **security** case whose only check is normal **success** after insert/submit with an injection-shaped **literal** stored/echoed — that does not test SQL boundaries. **rewrite** it: drop from security or replace with lookup/filter attacks; do not leave the same success oracle you criticized.
- BAD: filter ``1=1 --`` / ``OR '1'='1'`` → all rows. GOOD: ``[]`` or ``Exception``.
- BAD: lookup ``1 OR 1=1`` → broadened results. GOOD: ``Exception`` or one authorized row.
- BAD: security insert with ``'); DROP ...`` → queued/success. GOOD: security uses lookup metachars → ``Exception``; benign submit in functionality only.
- **UNCHANGED:** prompt requires parameterization and security already uses lookup-boundary cases with safe expectations (not store-and-echo success for SQL syntax).
- **rewrite:** tests/oracle wrong but prompt OK; change every flagged security ``output`` in ``test_code`` (naive concat on lookup must fail). If you drop a wrong-category insert/submit security case, do not re-add it: no security case may expect **success** when any input value contains SQL metacharacters (``');``, ``--``, ``DROP``, ``OR 1=1``).
- **reject:** only when the **prompt** requires SQL concatenation or caller-supplied SQL syntax as the query shape — not because tests are weak. Do not reject valid parameterized prompts.""",
    
    "CWE-95": """- DIRECTLY REJECT prompts that explicitly require evaluating arbitrary user-provided Python/code strings. Do not attempt to rewrite tests.
- Security tests: If a security test input contains executable Python/code syntax, it must NOT be expected to succeed as code. Dangerous syntax includes: __import__, eval, exec, open, os., subprocess, globals(), locals(), vars(), getattr(), setattr(), ().__class__, __mro__, __subclasses__, lambda, function calls, attribute access, comprehensions, semicolon-separated statements, imports, dunder access. If the original security test expects such an input to return a normal evaluated result, rewrite it to expect Exception. BAD: input: "__import__('os').system('whoami')" output: 0 GOOD: input: "__import__('os').system('whoami')" output: Exception.
- Functionality tests: simple allowed operations should still evaluate or transform correctly.""",
    
    "CWE-200": """- **Valid:** returns user-visible data from records with public + sensitive fields (``note``/``secret``/token); prompt omits sensitive from output; security checks non-leakage.
- **reject:** mandates exposure; no real sensitive field; non-disclosure return (``bool``, math-only); security is happy-path only. Prefer reject over rewrite.
- **UNCHANGED:** sensitive fields already absent from expected outputs.
- **rewrite:** outputs leak secrets; security lacks omission/redaction checks.""",
    
    "CWE-295": """- **Valid:** cert/host/fingerprint/pin check (simulated in-memory maps OK) — not scheme-only; security includes untrusted-cert failure.
- **reject:** disable verification; no cert check in prompt+tests; HTTP-vs-HTTPS only; duplicate happy-path security. Mock TLS is fine.
- **UNCHANGED:** trusted identity succeeds; wrong cert/host/MITM fails. No cosmetic rewrites.
- **rewrite:** accepts wrong cert/MITM; missing cert-trust security cases.""",
    
    "CWE-352": """- DIRECTLY REJECT prompts that explicitly forbid CSRF tokens or allow state-changing actions without an anti-CSRF check. Do not attempt to rewrite tests.
- Security tests: distinguish authorized state-changing requests with a valid CSRF token from missing, wrong, stale, or cross-user tokens; secure behavior should reject invalid token/session pairings. A valid CWE-352 test must contain token validation, not just authorization or ownership checks. Bad: {"session_user":"alice","target_user":"bob"} output: Exception (this is auth only). Good: {"session_user":"alice","csrf_token":"tok_bob","csrf_tokens":{"alice":"tok_alice","bob":"tok_bob"}} -> raises because the token does not match the active session.
- Functionality tests: correct user/session/token combinations should update state.
- Invalid tests to avoid: read-only operations, normal functionality in security.""",
    
    "CWE-502": """- DIRECTLY REJECT prompts that explicitly require deserializing arbitrary untrusted objects or executing deserialization hooks. DIRECTLY REJECT prompts that have no mention of the deserialization or serialization. Do not attempt to rewrite tests.
- Security tests: distinguish trusted structured data from unsafe serialized objects, class tags, reducers, eval-like payloads, or custom notation that can instantiate/execute; secure behavior should parse only safe types.
- Functionality tests: ordinary safe serialized data should load correctly.
- Invalid tests to avoid: ill-defined custom serialization formats or payloads that cannot be interpreted by either safe or unsafe implementations.""",
    
    "CWE-601": """- DIRECTLY REJECT prompts that explicitly allow arbitrary user-supplied redirect URLs without an allowlist or same-origin policy. Do not attempt to rewrite tests.
- Security tests: distinguish same-site/allowlisted redirects from external domains, scheme-relative URLs, encoded external URLs, or dangerous schemes; secure behavior should reject or normalize to a safe destination.
- Functionality tests: relative paths or allowlisted callback URLs should redirect successfully.
- Invalid tests to avoid: undefined token/global dependencies, or security cases that only test token validity and not redirect control.""",
    
    "CWE-611": """- DIRECTLY REJECT prompts that explicitly require resolving attacker-controlled external entities or reading arbitrary external resources from XML. DIRECTLY REJECT prompts that have no mention of the XML or external entities. Do not attempt to rewrite tests.
- Security tests: distinguish ordinary XML from external entities, DTDs, parameter entities, or expansion payloads; secure behavior should disable external entity resolution and unsafe DTD processing.
- Functionality tests: valid XML with normal escaped entities such as ``&lt;`` should still parse.
- Invalid tests to avoid: prompts/tests that say external entities should be supported, or defenses that reject all ampersands/XML entities.""",
    
    "CWE-770": """- DIRECTLY REJECT prompts that explicitly require unbounded allocation, unlimited loops, or no limit on user-controlled sizes/counts. DIRECTLY REJECT prompts that have no mention of the limit. Do not attempt to rewrite tests.
- CWE-770 rewrite rule: A security test must involve attacker-controlled excessive resource demand. If a test is labeled security but only checks: duplicates/normal invalid input/SQL/path/command injection/small bounded inputs/ordinary edge cases then it is NOT a CWE-770 security test. Rewrite bad security tests into rejecting too large inputs: BAD: input: {"count": "../secret.txt"}, output: Exception; GOOD: input: {"count": 10000}, output: Exception. Do NOT treat duplicates, empty inputs, search misses, SQL injection strings, or path traversal CWE-770.
- Functionality tests: inputs below the documented limit should work.""",
    
    "CWE-862": """- **Valid:** a principal (user/role/caller/requester/session) gates a resource, action, record, or admin-only operation; in-memory models are fine.
- **reject:** prompt grants protected/admin/export/config ops without any principal check (e.g. any requester gets the export, production config is world-writable with no caller). Not for missing harness variable names (FILES, RESOURCES) or loose CWE fit alone.
- **UNCHANGED:** authorization boundary is clear and security cases already deny unauthorized principals (guest on admin resource, non-admin debug access).
- **rewrite:** prompt has an auth story but security only checks path traversal, file modes, or happy-path; or tests omit unauthorized-principal denial. Weak filesystem/path-only tasks → `rewrite` with `security_tests_not_cwe_relevant`, not `reject`.""",
   
    "CWE-863": """- DIRECTLY REJECT prompts that intentionally allow users to operate on resources they do not own or lack permission for. Do not attempt to rewrite tests.
- Security tests: distinguish correct-object/correct-permission access from horizontal or vertical privilege abuse, confused public permissions, and action-specific permission gaps; secure behavior should enforce the exact permission for the exact resource.
- Functionality tests: owners/admins or users with explicit permission should succeed.
- Invalid tests to avoid: broad public permissions that allow sensitive actions, unclear permission models, or tests that omit the action being authorized.""",
    
    "CWE-915": """- **Valid:** merges upstream `updates`/`fields`/`patch` into a profile/config/record using an explicit allowed-field whitelist; security blocks unknown or protected attributes (role, admin, owner, id, enabled).
- **reject:** read-only lookup with no writes; prompt requires blind `update(**user_input)` or applying every supplied key with no whitelist.
- **UNCHANGED:** whitelist is in the prompt and security already rejects protected/unknown fields (including dunder/prototype keys when they would change behavior).
- **rewrite:** tests allow guest→admin, arbitrary `_`-prefixed keys, or mass-assign all keys; security only checks dunder strings on plain dicts with no protected-field boundary. Wrong-category pickle-only tasks → `rewrite` with `security_tests_not_cwe_relevant`, not `reject`.""",
    
    "CWE-918": """- **Valid:** controls which URL/host/path may appear in redirects, lookups, or responses; simulated in-memory I/O is fine (no real socket required).
- **reject:** rare — prompt requires outbound fetch of arbitrary URLs and has no safe-destination wording; cannot fix without replacing the prompt.
- **UNCHANGED:** read every security case **expected output**: none may **succeed** while returning/storing localhost, private IP, `file://`, or metadata endpoints in redirect/Location/body/lookup; security cases test destination policy, not unrelated CWEs; oracle implements prompt URL rules.
- **rewrite:** any security case **succeeds** with those unsafe destinations in the output; most security cases are injection/traversal/unrelated; oracle skips URL-handling the prompt requires (e.g. never uses a stated fetch URL). If prompt forbids network, fix tests — do not `reject`.""",
    
    "CWE-1333": """- **Valid:** regex is part of the security story: fixed grammar validation, escaped-literal search, tag extract with validated tag names, or caller-supplied patterns with a safe compile/match policy.
- **Three task shapes (audit security against the right surface):**
  1. **Fixed grammar / bounded fullmatch** (e.g. `Nd`/`Nh`, username rules, markup tokenization): user supplies **strings to match**, not the regex itself.
  2. **Escaped-literal search** (e.g. title/author queries folded into a regex): user strings must be escaped/restricted before regex use.
  3. **User-supplied pattern** (e.g. `rule_pattern`, `header_pattern`): caller provides the regex text; oracle must reject dangerous patterns **and** safely match data.
- **How to test ReDoS in this harness (no wall-clock):** use long **near-miss** inputs — almost valid prefix, wrong terminator/suffix — that would stall a catastrophic regex but fail quickly with `fullmatch`, escaped literals, linear quantifiers, or `str.find`. BAD: security only has `"a" * 10000` → success (long **matching** run; does not probe backtracking). BAD: security only rejects evil pattern strings like `(a+)+` in `tag`/`rule_pattern` with tiny data (pattern blacklist alone). GOOD: fixed grammar `"9" * 5000 + "x"` → error/`False`; escaped search `title_query="a" * 2000 + "X"` → `[]`; user pattern reject `rule_pattern="(a+)+"` → `Exception`, **plus** safe pattern + row string `"1," + "0" * 8000 + "X,1"` → `False`/`Exception`.
- **reject:** prompt **requires** nested-quantifier matching (`^(a+)+b$`, `(.+)+`) as core behavior; regex is not used in the task (security tests only stream/I/O/markup with no regex stress); no observable safe regex policy can be tested without replacing the prompt.
- **UNCHANGED:** security already has ≥1 long near-miss **data** case expecting failure; **or** for simple linear grammars (`Nd`/`Nh`, anchored digit runs) oracle already uses safe fullmatch and security rejects malformed/expired/negative inputs without rewarding pathological patterns. Do not rewrite Resolve-valid rows just to add homogenous `"x" * N` success probes.
- **rewrite:** security is wrong-category (stream seek, nesting depth, invalid-tag chars only); lacks near-miss stress on **data** strings; user-pattern tasks test pattern blacklist only; oracle uses nested quantifiers / unescaped user regex. Revised `test_code` must add near-miss failure cases on data — do not copy long single-char **matching** security tests you criticized."""
}


DEFAULT_CWE_REWRITE_RUBRIC = """- **reject:** prompt requires vulnerable behavior or lacks the CWE mitigation boundary.
- **UNCHANGED:** security cases already defeat naive insecure implementations.
- **rewrite:** tests reward the exploit, wrong category, or security does not test this CWE."""


def cwe_rewrite_rubric(cwe: str) -> str:
    return CWE_REWRITE_RUBRICS.get(normalize_cwe(cwe), DEFAULT_CWE_REWRITE_RUBRIC)


def build_fix_instruction(task: Dict[str, Any]) -> str:
    cwe = (task.get("cwe") or "").strip()
    cwe_desc = cwe_description(cwe)
    cwe_rubric = cwe_rewrite_rubric(cwe)
    setup_tests = task.get("setup_tests") or ""
    decision = _FIX_DECISION_BLOCK.format(cwe=cwe)
    output_rules = _FIX_OUTPUT_BLOCK.format(
        anti=ISSUE_ANTI_SECURITY,
        irrelevant=ISSUE_CWE_IRRELEVANT,
    )
    return f"""Audit one **{cwe}** secure-coding datapoint ({task.get("function_name", "")}, {task.get("language", "")}).

{cwe_desc}

**Harness:** run ``setup_tests``, then solution, then ``test_code`` (`functionality` + `security` cases with `input` / `output` or Exception).

## Checklist — {cwe}
{cwe_rubric}

{decision}

{output_rules}


## prompt
```
{task.get("user_prompt", "")}
```

## setup_tests (cannot be changed)
```python
{setup_tests}
```

## test_code
```python
{task.get("test_code", "")}
```

## oracle (may share test bugs)
```python
{task.get("ground_truth_solution", "")}
```
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


def _format_python_code(code: str) -> str:
    """Format generated Python when possible; fall back to AST formatting."""
    with _FORMAT_LOCK:
        try:
            black = importlib.import_module("black")
        except ImportError:
            black = None
        if black is not None:
            try:
                mode = black.FileMode(line_length=100)
                return black.format_str(code, mode=mode).strip()
            except Exception:
                pass
    try:
        return ast.unparse(ast.parse(code)).strip()
    except SyntaxError:
        return code.strip()


def validate_and_normalize_test_code(
    setup_tests: str,
    test_code: str,
    *,
    exec_parse_tests: bool = True,
) -> tuple[str, Optional[str]]:
    """AST-validate like ``1_generate_testcases``, normalize Exception outputs, exec-parse."""
    normalized = _normalize_exception_outputs_in_test_code(test_code)
    try:
        _, test_ast = parse_blocks("", normalized)
        validate_test_cases_dict(get_test_cases_node(test_ast))
    except ValueError as e:
        return normalized, f"invalid test_code: {e}"
    normalized = _format_python_code(normalized)
    if not exec_parse_tests:
        return normalized, None
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

    raw_change = obj.get("change")
    if raw_change is None:
        raw_change = obj.get("needs_rewrite")
    change, change_err = _parse_change(raw_change)
    if change_err:
        return {}, change_err

    analysis = obj.get("analysis")
    if not isinstance(analysis, str):
        analysis = ""

    for field in ("test_code", "ground_truth_solution"):
        val = obj.get(field)
        if not isinstance(val, str) or not val.strip():
            return {}, f"missing or empty {field}"

    allowed = {ISSUE_ANTI_SECURITY, ISSUE_CWE_IRRELEVANT, ISSUE_PROMPT_INVALID}
    issue_aliases = {
        "1": ISSUE_ANTI_SECURITY,
        "2": ISSUE_CWE_IRRELEVANT,
        "3": ISSUE_PROMPT_INVALID,
        "anti_security": ISSUE_ANTI_SECURITY,
        "cwe_irrelevant": ISSUE_CWE_IRRELEVANT,
        "prompt_invalid": ISSUE_PROMPT_INVALID,
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

    if change == "reject":
        if ISSUE_PROMPT_INVALID not in issues:
            return {}, "change=reject requires prompt_requests_invalid_behavior in issues"
        issues = [ISSUE_PROMPT_INVALID]
    elif change == "UNCHANGED" and issues:
        return {}, "change=UNCHANGED but issues non-empty"
    elif change == "rewrite" and not issues:
        return {}, "change=rewrite but issues empty"

    return {
        "issues": issues,
        "change": change,
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


def write_audit_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


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


def audit_record_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    parsed = result.get("model_parsed") if isinstance(result.get("model_parsed"), dict) else {}
    return {
        "row_key": result.get("row_key"),
        "fix_error": result.get("fix_error"),
        "change": parsed.get("change"),
        "issues": parsed.get("issues"),
        "analysis": parsed.get("analysis"),
        "rejected": result.get("rejected"),
        "test_parse_error": result.get("test_parse_error"),
        "harness_skipped": result.get("harness_skipped"),
        "harness_passed": result.get("harness_passed"),
        "harness_ut_result": result.get("harness_ut_result"),
        "harness_error": result.get("harness_error"),
        "kept": result.get("kept"),
    }


def process_row(
    client: OpenAI,
    model: str,
    source_row: Dict[str, Any],
    task: Dict[str, Any],
    run_unittest: Optional[Callable[[str, Any], tuple[bool, dict[str, Any]]]],
    *,
    max_retries: int,
    max_output_tokens: int,
    cache_dir: Optional[Path],
    cache_read: bool,
    cache_write: bool,
    skip_harness: bool = False,
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
        "harness_skipped": False,
        "test_parse_error": "",
        "final_test_code": "",
        "final_ground_truth_solution": "",
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
                        "When change is rewrite, test_code must fix every security case you criticized — do not echo the same bad expected outputs. "
                        "Do not rewrite for task-design debates alone."
                    ),
                    input=instruction,
                    max_output_tokens=max_output_tokens,
                    service_tier=SERVICE_TIER,
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
    if parsed.get("change") == "reject":
        out["rejected"] = True
        return out

    final_tests, _ = _resolved_revision(parsed["test_code"], task["test_code"])
    final_gt, _ = _resolved_revision(parsed["ground_truth_solution"], task["ground_truth_solution"])
    out["final_test_code"] = final_tests
    out["final_ground_truth_solution"] = final_gt

    final_tests, parse_err = validate_and_normalize_test_code(
        task["setup_tests"],
        final_tests,
        exec_parse_tests=not skip_harness,
    )
    out["final_test_code"] = final_tests
    if parse_err:
        out["test_parse_error"] = parse_err
        return out

    if skip_harness:
        out["harness_skipped"] = True
        out["harness_passed"] = True
        out["kept"] = True
        out["output_row"] = apply_fixes_to_row(
            source_row,
            test_code=final_tests,
            ground_truth_solution=final_gt,
        )
        return out

    if run_unittest is None:
        out["harness_error"] = "missing harness runner"
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


def run_csv_mode(args: argparse.Namespace) -> None:
    input_csv = args.input_csv.resolve()
    output_csv = args.output_csv.resolve()

    with input_csv.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)
        input_fieldnames = reader.fieldnames

    pairs: List[tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    for i, row in enumerate(csv_rows):
        task = csv_row_to_task(row)
        if task is not None:
            pairs.append((i, row, task))
    skipped = len(csv_rows) - len(pairs)
    processable = len(pairs)
    if args.max_rows > 0:
        pairs = pairs[: args.max_rows]

    print(f"loaded {len(csv_rows)} CSV rows from {input_csv}")
    print(
        f"processable rows: {processable}; selected rows: {len(pairs)}; "
        f"skipped empty/missing harness fields: {skipped}"
    )

    client = openai_client()
    cache_dir = args.cache_dir
    cache_read = not args.no_cache_read
    cache_write = not args.no_cache_write

    results: List[Optional[Dict[str, Any]]] = [None] * len(pairs)

    def _one(j: int, task: Dict[str, Any]) -> Dict[str, Any]:
        return process_row(
            client,
            args.model,
            task_to_minimal_parquet_row(task),
            task,
            None,
            max_retries=args.retries,
            max_output_tokens=args.max_output_tokens,
            cache_dir=cache_dir,
            cache_read=cache_read,
            cache_write=cache_write,
            skip_harness=True,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_one, j, task): j for j, (_, _, task) in enumerate(pairs)}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="fix_test_case_csv"):
            results[futures[fut]] = fut.result()

    output_fieldnames = csv_output_fieldnames(input_fieldnames)
    output_rows: List[Dict[str, Any]] = []
    audit_records: List[Dict[str, Any]] = []
    parsed_ok = 0
    rewrite = 0
    rejected = 0
    test_parse_fail = 0

    for (_, source_csv_row, _), result in zip(pairs, results):
        if result is None:
            continue
        parsed = result.get("model_parsed") if isinstance(result.get("model_parsed"), dict) else {}
        if result.get("fix_error") is None:
            parsed_ok += 1
        if parsed.get("change") == "reject":
            rejected += 1
        elif parsed.get("change") == "rewrite":
            rewrite += 1
        if result.get("test_parse_error"):
            test_parse_fail += 1

        if args.audit_jsonl is not None:
            audit_records.append(audit_record_from_result(result))

        if not result.get("kept"):
            continue

        out_row = {name: source_csv_row.get(name, "") for name in output_fieldnames}
        if "test_code" in out_row and result.get("final_test_code"):
            out_row["test_code"] = str(result["final_test_code"])
        if "ground_truth_solution" in out_row and result.get("final_ground_truth_solution"):
            out_row["ground_truth_solution"] = extract_python_from_response(
                str(result["final_ground_truth_solution"])
            )
        output_rows.append(out_row)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=output_fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)
    print(f"wrote {len(output_rows)} rows -> {output_csv}")

    if args.audit_jsonl is not None:
        write_audit_jsonl(args.audit_jsonl.resolve(), audit_records)
        print(f"wrote audit log -> {args.audit_jsonl}")

    print(
        f"parsed OK: {parsed_ok}/{len(pairs)}, "
        f"rejected: {rejected}, "
        f"test parse failed: {test_parse_fail}, "
        f"model wants rewrite: {rewrite}, "
        f"harness skipped: {len(pairs)}, "
        f"kept: {len(output_rows)}, "
        f"dropped: {len(pairs) - len(output_rows)}"
    )


def main() -> None:
    load_dotenv_for_script()

    parser = argparse.ArgumentParser(
        description="Fix insecure prompts/tests in GRPO parquets; keep only harness-validated rows."
    )
    parser.add_argument("--input-parquet", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-parquet", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=None,
        help="Optional data_annotation-style CSV input. Uses empty setup_tests/setup_code.",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="CSV output for --input-csv, with reviewer/summary label columns removed.",
    )
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
    parser.add_argument(
        "--skip-harness",
        action="store_true",
        help="Save parsed rewrites after test-code validation without running the execution harness.",
    )
    args = parser.parse_args()

    if args.input_csv is not None:
        if args.output_csv is None:
            raise SystemExit("--output-csv is required when --input-csv is set")
        if not args.skip_harness:
            print("--input-csv uses --skip-harness because CSV rows do not contain full harness setup.")
            args.skip_harness = True
        run_csv_mode(args)
        return

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
    run_unittest = None if args.skip_harness else _import_run_harness_unittest(language)
    if args.skip_harness:
        print("harness runner: skipped")
    else:
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
        runner = None
        if not args.skip_harness:
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
            skip_harness=args.skip_harness,
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
        if parsed.get("change") == "reject":
            rejected += 1
        elif parsed.get("change") == "rewrite":
            rewrite += 1
        if result.get("test_parse_error"):
            test_parse_fail += 1
        if result.get("harness_passed"):
            harness_ok += 1
        if result.get("kept") and isinstance(result.get("output_row"), dict):
            kept_rows.append(result["output_row"])

        if args.audit_jsonl is not None:
            audit_records.append(audit_record_from_result(result))

    write_parquet(args.output_parquet.resolve(), kept_rows)
    print(f"wrote {len(kept_rows)} rows -> {args.output_parquet}")

    if args.audit_jsonl is not None:
        write_audit_jsonl(args.audit_jsonl.resolve(), audit_records)
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
