#!/usr/bin/env python3
"""Generate C solutions with an LLM, then keep rows whose code passes the pytest harness.

Reads flat simple_gen C JSONL rows (e.g. ``3_filtered.jsonl``). It asks an LLM to emit C source,
then evaluates with ``verl/recipe/security_harness/execution_harness_c.py`` (prepends ``setup_code``,
compiles ``{function_name}_task``, runs pytest functionality/security markers).

Output rows keep the input schema plus ``candidate_c`` (and ``generated_code`` as a mirror for py tooling).
Only harness-passing rows are written to ``--output-jsonl``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from tqdm import tqdm

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, openai_service_tier
from c_utils import extract_c_source_from_markdown, read_jsonl
from cwe_rules import default_cflags_for_cwe, default_ldflags_for_cwe, solution_generation_cwe_rules
from native_deps import native_compile_env

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

_CACHE_WRITE_LOCK = threading.Lock()
_C_CODE_BLOCK_RE = re.compile(r"```(?:c|C)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

_SYSTEM_INSTRUCTION = (
    "You are an expert C programmer. "
    "Follow the output format exactly: one ```c fenced block only, or exactly NO."
)

_BOOKKEEPING_FIELDS = (
    "mini_gen_error",
    "mini_gen_cache_hit",
    "harness_passed",
    "harness_summary_ok",
    "harness_ut_result",
    "harness_exit_code",
    "harness_stdout",
    "harness_stderr",
    "candidate_c_error",
)

_C_SOLUTION_INSTRUCTION = """You write a single C11 translation unit that implements the task below.

The evaluator will:
1. Prepend ``setup_code`` to your source and compile the result as ``{fn}_task`` under ``compiled/``.
2. Run pytest cases that invoke that binary via ``subprocess``.

## Task

**Compiled binary filename:** ``{fn}_task``
**arguments (hint):**
{args_json}
**return:** {ret}
**raises:** {raises}
**setup_code (prepended before your translation unit is compiled):**
```c
{setup_code}
```

**Prompt (what to implement):**
{prompt}

Target CWE context: **{cwe}**.

---

## Output rules
- Return **only** one markdown fenced code block (```c ... ```).
- No prose outside the fence.
{CWE_SOLUTION_RULES}
"""


# ---------------------------------------------------------------------------
# Environment & imports
# ---------------------------------------------------------------------------


def _verl_root() -> Path:
    return Path(__file__).resolve().parents[2] / "verl"


def _import_run_harness_unittest():
    harness_dir = _verl_root() / "recipe" / "security_harness"
    if str(harness_dir) not in sys.path:
        sys.path.insert(0, str(harness_dir))
    from execution_harness_c import run_simple_gen_c_harness_unittest

    return run_simple_gen_c_harness_unittest


def _pytest_available() -> bool:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            capture_output=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@contextlib.contextmanager
def _temporary_env(updates: Dict[str, Optional[str]]) -> Iterator[None]:
    old: Dict[str, Optional[str]] = {}
    try:
        for key, value in updates.items():
            old[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, previous in old.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous


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


# ---------------------------------------------------------------------------
# Row helpers & LLM prompts
# ---------------------------------------------------------------------------


def extract_c_from_response(raw: str) -> str:
    m = _C_CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return extract_c_source_from_markdown(raw or "")


def is_no_output(raw_text: str) -> bool:
    return bool(re.match(r"^\s*NO\s*$", (raw_text or ""), flags=re.IGNORECASE))


def _flatten_chat_prompt(prompt: Any) -> str:
    if isinstance(prompt, list):
        parts: List[str] = []
        for message in prompt:
            if isinstance(message, dict):
                content = message.get("content", "")
                if isinstance(content, str) and content.strip():
                    parts.append(content.strip())
        return "\n\n".join(parts)
    if isinstance(prompt, str):
        return prompt
    return str(prompt or "")


def task_row_for_filter(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a pipeline row for instruction building."""
    out = dict(row)
    out["prompt"] = _flatten_chat_prompt(out.get("prompt"))
    return out


def _format_raises(raises: Any) -> str:
    if isinstance(raises, str):
        return raises
    if raises is None:
        return ""
    return json.dumps(raises, ensure_ascii=False)


def build_solution_instruction(row: Dict[str, Any]) -> str:
    """Task + harness instruction for C solution generation."""
    row = task_row_for_filter(row)
    fn = str(row.get("function_name", "") or "").strip()
    setup_code = row.get("setup_code") if isinstance(row.get("setup_code"), str) else ""
    cwe = str(row.get("cwe", "") or "") or "UNKNOWN"
    cwe_rules = solution_generation_cwe_rules(cwe)
    cwe_block = f"\n{cwe_rules}" if cwe_rules else ""
    return _C_SOLUTION_INSTRUCTION.format(
        fn=fn,
        args_json=json.dumps(row.get("arguments", []), ensure_ascii=False, indent=2),
        ret=json.dumps(row.get("return"), ensure_ascii=False),
        raises=_format_raises(row.get("raises")) or "(see task description)",
        setup_code=setup_code,
        prompt=row.get("prompt", ""),
        cwe=cwe,
        CWE_SOLUTION_RULES=cwe_block,
    )


# ---------------------------------------------------------------------------
# Generation cache
# ---------------------------------------------------------------------------


def _prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8", errors="surrogatepass")).hexdigest()


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


def _write_generation_cache(
    cache_path: Path,
    *,
    model: str,
    prompt: str,
    code: str,
    error: Optional[str],
) -> None:
    with _CACHE_WRITE_LOCK:
        _atomic_write_json(
            cache_path,
            {
                "model": model,
                "prompt_sha256": _prompt_sha256(prompt),
                "candidate_c": code,
                "generated_code": code,
                "mini_gen_error": error,
            },
        )


def _fresh_gen_row(source_row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(source_row)
    out["mini_gen_error"] = None
    out["candidate_c"] = ""
    out["generated_code"] = ""
    out["mini_gen_cache_hit"] = False
    return out


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
    out = _fresh_gen_row(source_row)

    fn = task_row.get("function_name")
    if not (isinstance(fn, str) and fn.strip()):
        out["mini_gen_error"] = "skipped: missing function_name"
        return out
    if not (task_row.get("test_code") or "").strip():
        out["mini_gen_error"] = "skipped: empty test_code"
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
                cached_code = cached.get("candidate_c") or cached.get("generated_code")
                cached_err = cached.get("mini_gen_error")
                if isinstance(cached_code, str) and cached_code.strip() and not cached_err:
                    out["candidate_c"] = cached_code
                    out["generated_code"] = cached_code
                    out["mini_gen_cache_hit"] = True
                    return out

    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=_SYSTEM_INSTRUCTION,
                input=prompt,
                max_output_tokens=max_output_tokens,
                service_tier=openai_service_tier(),
            )
            raw = (resp.output_text or "").strip()
            if is_no_output(raw):
                raise ValueError("model returned NO")
            code = extract_c_from_response(raw)
            if not code.strip():
                raise ValueError("empty C after extraction")
            out["candidate_c"] = code
            out["generated_code"] = code
            if cache_path is not None and cache_write:
                _write_generation_cache(cache_path, model=model, prompt=prompt, code=code, error=None)
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out["mini_gen_error"] = last_err or "no valid output after retries"
    if cache_path is not None and cache_write:
        _write_generation_cache(cache_path, model=model, prompt=prompt, code="", error=out["mini_gen_error"])
    return out


def process_row_use_existing(source_row: Dict[str, Any], *, code_field: str) -> Dict[str, Any]:
    out = _fresh_gen_row(source_row)
    code = out.get(code_field) or out.get("generated_code") or out.get("candidate_c")
    if not (isinstance(code, str) and code.strip()):
        out["mini_gen_error"] = f"skipped: missing {code_field} (use generation instead)"
        return out
    out["candidate_c"] = code.strip()
    out["generated_code"] = code.strip()
    return out


# ---------------------------------------------------------------------------
# Harness evaluation
# ---------------------------------------------------------------------------


def harness_ground_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal row for ``run_simple_gen_c_harness_unittest``."""
    return {
        "function_name": row.get("function_name"),
        "test_code": row.get("test_code"),
        "setup_tests": row["setup_tests"] if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
        "cwe": row.get("cwe") if isinstance(row.get("cwe"), str) else "",
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


def _set_harness_failure(row: Dict[str, Any], *, exit_code: int, stderr: str) -> Dict[str, Any]:
    out = dict(row)
    out["harness_passed"] = False
    out["harness_summary_ok"] = False
    out["harness_ut_result"] = {}
    out["harness_exit_code"] = exit_code
    out["harness_stderr"] = stderr
    out["harness_stdout"] = ""
    return out


def evaluate_harness(
    row_with_code: Dict[str, Any],
    run_unittest: Any,
    *,
    cc: str,
    cflags: str,
    ldflags: str,
    compile_timeout_s: float,
    code_field: str,
) -> Dict[str, Any]:
    if row_with_code.get("mini_gen_error"):
        return _set_harness_failure(row_with_code, exit_code=-1, stderr=str(row_with_code["mini_gen_error"]))

    raw = row_with_code.get(code_field) or row_with_code.get("candidate_c") or row_with_code.get("generated_code") or ""
    if not isinstance(raw, str) or not raw.strip():
        return _set_harness_failure(row_with_code, exit_code=2, stderr=f"missing {code_field}")

    cwe = str(row_with_code.get("cwe") or "")
    effective_cflags = default_cflags_for_cwe(cwe, cflags)
    effective_ldflags = default_ldflags_for_cwe(cwe, ldflags)

    env_updates: Dict[str, Optional[str]] = {
        "SAFE_K_NATIVE_COMPILE_TIMEOUT_SECONDS": str(compile_timeout_s),
        "SAFE_K_CFLAGS": effective_cflags.strip() or None,
        "SAFE_K_LDFLAGS": effective_ldflags.strip() or None,
    }
    if cc.strip():
        env_updates["CC"] = cc.strip()

    with _temporary_env(env_updates):
        ok, ut_result = run_unittest(raw, harness_ground_row(row_with_code))

    out = dict(row_with_code)
    out["harness_summary_ok"] = ok
    out["harness_ut_result"] = {k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()}
    out["harness_passed"] = harness_fully_passes(ok, ut_result)
    out["harness_exit_code"] = 0 if out["harness_passed"] else 2
    out["harness_stdout"] = ""
    out["harness_stderr"] = (
        ""
        if out["harness_passed"]
        else json.dumps(out["harness_ut_result"], ensure_ascii=False)[:4000]
    )
    return out


def _strip_bookkeeping_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    code = out.get("candidate_c") or out.get("generated_code") or ""
    if isinstance(code, str) and code.strip():
        out["candidate_c"] = code.strip()
        out["generated_code"] = code.strip()
    for key in _BOOKKEEPING_FIELDS:
        out.pop(key, None)
    return out


# ---------------------------------------------------------------------------
# CLI & orchestration
# ---------------------------------------------------------------------------


def _parallel_map(
    items: List[Any],
    worker: Callable[[int, Any], Any],
    *,
    max_workers: int,
    desc: str,
) -> List[Any]:
    results: List[Optional[Any]] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futures = {ex.submit(worker, i, items[i]): i for i in range(len(items))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc=desc):
            results[futures[fut]] = fut.result()
    return results  # type: ignore[return-value]


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _resolve_cc(explicit: str) -> str:
    cc = (explicit or "").strip() or (os.environ.get("CC") or "").strip() or (shutil.which("gcc") or "")
    if not cc:
        raise RuntimeError("no C compiler found (set --cc or install gcc)")
    return cc


def _build_arg_parser(default_cache_dir: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LLM-generate C solutions for simple_gen JSONL rows; keep pytest-passing rows"
    )
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-jsonl", type=Path, required=True, help="Rows where harness_passed is true")
    parser.add_argument(
        "--all-output-jsonl",
        type=Path,
        default=None,
        help="Write every row after generation + harness eval (default: no file)",
    )
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=120.0,
        help="Timeout (seconds) for each OpenAI API call.",
    )
    parser.add_argument(
        "--use-existing-candidate-c",
        action="store_true",
        help="Skip LLM generation; evaluate existing candidate_c / generated_code on each row.",
    )
    parser.add_argument(
        "--candidate-field",
        type=str,
        default="candidate_c",
        help="JSONL field with C source for harness evaluation (default: candidate_c).",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default_cache_dir,
        help="Directory for on-disk generation cache (keyed by model+prompt).",
    )
    parser.add_argument("--no-cache-read", action="store_true")
    parser.add_argument("--no-cache-write", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--compile-timeout-seconds", type=float, default=20.0)
    # Accepted for shell-script compatibility (run_validate_c.sh); harness applies limits internally.
    parser.add_argument("--rlimit-cpu-seconds", type=int, default=0)
    parser.add_argument("--rlimit-address-space-mib", type=int, default=0)
    parser.add_argument("--rlimit-stack-mib", type=int, default=0)
    parser.add_argument("--cc", type=str, default="")
    parser.add_argument(
        "--cflags",
        type=str,
        default="-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter",
    )
    parser.add_argument("--ldflags", type=str, default="")
    return parser


def main() -> None:
    load_dotenv_for_script(__file__)

    default_cache_dir = Path(__file__).resolve().parents[1] / ".cache" / "filter_valid_samples_c"
    args = _build_arg_parser(default_cache_dir).parse_args()
    args.cache_dir = args.cache_dir.expanduser().resolve()

    print(f"[cache] dir={args.cache_dir} read={not args.no_cache_read} write={not args.no_cache_write}")

    if not _pytest_available():
        raise RuntimeError(
            f"pytest is not available in the current Python environment ({sys.executable})."
        )

    os.environ["UNITTEST_TIMEOUT_SECONDS"] = str(args.timeout_seconds)
    os.environ["SAFE_K_NATIVE_COMPILE_TIMEOUT_SECONDS"] = str(args.compile_timeout_seconds)
    # Optional overrides for verl native harness (SAFE_K_RLIMIT_*); 0 means unset.
    if int(args.rlimit_cpu_seconds) > 0:
        os.environ["SAFE_K_RLIMIT_CPU_SECONDS"] = str(int(args.rlimit_cpu_seconds))
    if int(args.rlimit_address_space_mib) > 0:
        os.environ["SAFE_K_RLIMIT_AS_MIB"] = str(int(args.rlimit_address_space_mib))
    if int(args.rlimit_stack_mib) > 0:
        os.environ["SAFE_K_RLIMIT_STACK_MIB"] = str(int(args.rlimit_stack_mib))
    run_unittest = _import_run_harness_unittest()

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    # Apply once for the process (not per-row): ASAN_OPTIONS=allocator_may_return_null
    # for CWE-476, plus native include/lib paths. Per-row os.environ mutations race
    # under ThreadPoolExecutor and can clear ASAN_OPTIONS mid-flight.
    if rows:
        for key, value in native_compile_env(str(rows[0].get("cwe") or "")).items():
            if value:
                os.environ[key] = value
        asan = os.environ.get("ASAN_OPTIONS", "")
        if asan:
            print(f"[env] ASAN_OPTIONS={asan}", flush=True)

    cc = _resolve_cc(args.cc)
    client = OpenAI(
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL),
        timeout=args.request_timeout,
    )

    def generate_one(i: int, row: Dict[str, Any]) -> Dict[str, Any]:
        del i
        if args.use_existing_candidate_c:
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

    generated = _parallel_map(rows, generate_one, max_workers=args.max_workers, desc="generating")

    def evaluate_one(i: int, row: Dict[str, Any]) -> Dict[str, Any]:
        del i
        return evaluate_harness(
            row,
            run_unittest,
            cc=cc,
            cflags=str(args.cflags),
            ldflags=str(args.ldflags),
            compile_timeout_s=float(args.compile_timeout_seconds),
            code_field=args.candidate_field,
        )

    evaluated = _parallel_map(
        generated, evaluate_one, max_workers=args.max_workers, desc="harness"
    )

    if args.all_output_jsonl is not None:
        write_jsonl(args.all_output_jsonl, evaluated)

    passed = [row for row in evaluated if row.get("harness_passed")]
    write_jsonl(args.output_jsonl, [_strip_bookkeeping_fields(row) for row in passed])

    n_gen_err = sum(1 for row in evaluated if row.get("mini_gen_error"))
    n_cache_hit = sum(1 for row in evaluated if row.get("mini_gen_cache_hit"))
    print(f"total rows: {len(evaluated)}")
    print(f"generation errors: {n_gen_err}")
    print(f"cache hits: {n_cache_hit}")
    print(f"harness passed: {len(passed)} -> {args.output_jsonl}")
    if args.all_output_jsonl:
        print(f"wrote all evaluated rows to {args.all_output_jsonl}")


if __name__ == "__main__":
    main()
