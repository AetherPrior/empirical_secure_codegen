#!/usr/bin/env python3
"""Generate C++ solutions with an LLM, then keep rows whose code passes the CWEval pytest harness.

Reads flat simple_gen C++ JSONL rows (e.g. ``3_filtered.jsonl``). It asks an LLM to emit C++ source,
then evaluates with ``verl/recipe/security_harness/execution_harness_cpp.py`` (prepends ``setup_code``,
compiles ``{function_name}_task``, runs pytest functionality/security markers).

Output rows keep the input schema plus ``candidate_cpp`` (and ``generated_code`` as a mirror for py tooling).
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
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from tqdm import tqdm

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL, openai_service_tier
from cpp_utils import extract_cpp_source_from_markdown, read_jsonl
from cwe_rules import default_cxxflags_for_cwe, default_ldflags_for_cwe, solution_generation_cwe_rules

try:
    from openai import OpenAI
except Exception as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

_CACHE_WRITE_LOCK = threading.Lock()
_CPP_CODE_BLOCK_RE = re.compile(r"```(?:cpp|c\+\+|C\+\+)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _verl_root() -> Path:
    return Path(__file__).resolve().parents[2] / "verl"


def _import_run_harness_unittest():
    # Import as package so relative imports in execution_harness_cpp work
    # (``from .pytest_harness_utils import ...``).
    verl_root = _verl_root()
    if str(verl_root) not in sys.path:
        sys.path.insert(0, str(verl_root))
    try:
        from recipe.security_harness.execution_harness_cpp import (  # type: ignore
            run_simple_gen_cpp_harness_unittest,
        )
    except ImportError:
        harness_dir = verl_root / "recipe" / "security_harness"
        if str(harness_dir) not in sys.path:
            sys.path.insert(0, str(harness_dir))
        from execution_harness_cpp import run_simple_gen_cpp_harness_unittest  # type: ignore

    return run_simple_gen_cpp_harness_unittest


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


def extract_cpp_from_response(raw: str) -> str:
    m = _CPP_CODE_BLOCK_RE.search(raw or "")
    if m:
        return m.group(1).strip()
    return extract_cpp_source_from_markdown(raw or "")


def is_no_output(raw_text: str) -> bool:
    return bool(re.match(r"^\s*NO\s*$", (raw_text or ""), flags=re.IGNORECASE))


def task_row_for_filter(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a pipeline row for instruction building."""
    out = dict(row)
    prompt = out.get("prompt")
    if isinstance(prompt, list):
        parts: List[str] = []
        for m in prompt:
            if isinstance(m, dict):
                c = m.get("content", "")
                if isinstance(c, str) and c.strip():
                    parts.append(c.strip())
        out["prompt"] = "\n\n".join(parts)
    elif not isinstance(prompt, str):
        out["prompt"] = str(prompt or "")
    return out


def build_solution_instruction(row: Dict[str, Any]) -> str:
    """Task + harness instruction for C++ solution generation (mirrors py ``build_solution_instruction``)."""
    row = task_row_for_filter(row)
    args_json = json.dumps(row.get("arguments", []), ensure_ascii=False, indent=2)
    ret = json.dumps(row.get("return"), ensure_ascii=False)
    raises = row.get("raises", "")
    if not isinstance(raises, str):
        raises = json.dumps(raises, ensure_ascii=False) if raises is not None else ""
    setup_code = row.get("setup_code") if isinstance(row.get("setup_code"), str) else ""
    fn = str(row.get("function_name", "") or "").strip()
    cwe = str(row.get("cwe", "") or "")
    cwe_rules = solution_generation_cwe_rules(cwe)
    cwe_block = f"\n{cwe_rules}" if cwe_rules else ""

    w_tests = f"""You write a single C++17 translation unit that implements the task below.

The evaluator will:
1. Compile your source to an executable named ``{fn}_task`` under ``compiled/``.
2. Run pytest cases that invoke that binary via ``subprocess`` (CWEval-style harness).

## Task

**Compiled binary filename:** ``{fn}_task``
**arguments (hint):**
{args_json}
**return:** {ret}
**raises:** {raises or '(see task description)'}

**setup_code (prepended before your translation unit is compiled):**
```cpp
{setup_code}
```

**Prompt (what to implement):**
{row.get("prompt", "")}

**Test harness — setup_tests (pytest prelude):**
```python
{row.get("setup_tests") or ""}
```

**Test harness — test_code (pytest module body):**
```python
{row.get("test_code") or ""}
```

Target CWE context: **{cwe or 'UNKNOWN'}**.
{cwe_block}
---

## Output rules
- Include ``int main(int argc, char **argv)`` that parses ``argv`` per the task; tests invoke ``compiled/{fn}_task``.
- Return **only** one markdown fenced code block (```cpp ... ```) with the complete `.cpp` source.
- If the test cases would reward insecure behavior, output exactly ``NO`` and nothing else.
- No prose outside the fence.
"""

    w_no_tests = f"""You write a single C++17 translation unit that implements the task below.

The evaluator will:
1. Prepend ``setup_code`` to your source and compile the result as ``{fn}_task`` under ``compiled/``.
2. Run pytest cases that invoke that binary via ``subprocess`` (CWEval-style harness).

## Task

**Compiled binary filename:** ``{fn}_task``
**arguments (hint):**
{args_json}
**return:** {ret}
**raises:** {raises or '(see task description)'}

**setup_code (prepended before your translation unit is compiled):**
```cpp
{setup_code}
```

**Prompt (what to implement):**
{row.get("prompt", "")}

Target CWE context: **{cwe or 'UNKNOWN'}**.
{cwe_block}
---

## Output rules
- Return **only** one markdown fenced code block (```cpp ... ```).
- No prose outside the fence.
"""

    return w_no_tests


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
    out["candidate_cpp"] = ""
    out["generated_code"] = ""
    out["mini_gen_cache_hit"] = False

    fn = task_row.get("function_name")
    if not (isinstance(fn, str) and fn.strip()):
        out["mini_gen_error"] = "skipped: missing function_name"
        print(f"skipped: missing function_name: {fn}")
        return out
    if not (task_row.get("test_code") or "").strip():
        out["mini_gen_error"] = "skipped: empty test_code"
        print(f"skipped: empty test_code: {task_row.get('test_code')}")
        return out

    try:
        prompt = build_solution_instruction(task_row)
    except Exception as e:
        out["mini_gen_error"] = f"error building solution instruction: {type(e).__name__}: {e}"
        print(f"error building solution instruction: {type(e).__name__}: {e}")
        return out

    cache_path: Optional[Path] = None
    if cache_dir is not None:
        key = _generation_cache_key(model=model, prompt=prompt)
        cache_path = cache_dir / f"{key}.json"
        if cache_read:
            cached = _read_cache(cache_path)
            if isinstance(cached, dict):
                cached_code = cached.get("candidate_cpp") or cached.get("generated_code")
                cached_err = cached.get("mini_gen_error")
                if isinstance(cached_code, str) and cached_code.strip() and not cached_err:
                    out["candidate_cpp"] = cached_code
                    out["generated_code"] = cached_code
                    out["mini_gen_error"] = None
                    out["mini_gen_cache_hit"] = True
                    return out

    last_err: Optional[str] = None
    for _ in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                instructions=(
                    "You are an expert C++ programmer. "
                    "Follow the output format exactly: one ```cpp fenced block only, or exactly NO."
                ),
                input=prompt,
                max_output_tokens=max_output_tokens,
                service_tier=openai_service_tier(),
            )
            raw = (resp.output_text or "").strip()
            if is_no_output(raw):
                raise ValueError("model returned NO")
            code = extract_cpp_from_response(raw)
            if not code.strip():
                raise ValueError("empty C++ after extraction")
            out["candidate_cpp"] = code
            out["generated_code"] = code
            out["mini_gen_error"] = None
            if cache_path is not None and cache_write:
                with _CACHE_WRITE_LOCK:
                    _atomic_write_json(
                        cache_path,
                        {
                            "model": model,
                            "prompt_sha256": hashlib.sha256(
                                prompt.encode("utf-8", errors="surrogatepass")
                            ).hexdigest(),
                            "candidate_cpp": code,
                            "generated_code": code,
                            "mini_gen_error": None,
                        },
                    )
            return out
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

    out["mini_gen_error"] = last_err or "no valid output after retries"
    if cache_path is not None and cache_write:
        with _CACHE_WRITE_LOCK:
            _atomic_write_json(
                cache_path,
                {
                    "model": model,
                    "prompt_sha256": hashlib.sha256(
                        prompt.encode("utf-8", errors="surrogatepass")
                    ).hexdigest(),
                    "candidate_cpp": "",
                    "generated_code": "",
                    "mini_gen_error": out["mini_gen_error"],
                },
            )
    return out


def process_row_use_existing(source_row: Dict[str, Any], *, code_field: str) -> Dict[str, Any]:
    out = dict(source_row)
    out["mini_gen_error"] = None
    code = out.get(code_field) or out.get("generated_code") or out.get("candidate_cpp")
    if not (isinstance(code, str) and code.strip()):
        out["mini_gen_error"] = f"skipped: missing {code_field} (use generation instead)"
        out["candidate_cpp"] = ""
        out["generated_code"] = ""
    else:
        out["candidate_cpp"] = code.strip()
        out["generated_code"] = code.strip()
    out["mini_gen_cache_hit"] = False
    return out


def harness_ground_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal row for ``run_simple_gen_cpp_harness_unittest``."""
    return {
        "function_name": row.get("function_name"),
        "cwe": row.get("cwe"),
        "test_code": row.get("test_code"),
        "setup_tests": row["setup_tests"] if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
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
    row_with_code: Dict[str, Any],
    run_unittest: Any,
    *,
    cc: str,
    cflags: str,
    ldflags: str,
    compile_timeout_s: float,
    code_field: str,
) -> Dict[str, Any]:
    out = dict(row_with_code)
    if out.get("mini_gen_error"):
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        out["harness_exit_code"] = -1
        out["harness_stderr"] = str(out.get("mini_gen_error"))
        return out

    raw = out.get(code_field) or out.get("candidate_cpp") or out.get("generated_code") or ""
    if not isinstance(raw, str) or not raw.strip():
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        out["harness_exit_code"] = 2
        out["harness_stderr"] = f"missing {code_field}"
        return out

    cwe = str(out.get("cwe") or "")
    effective_cflags = default_cxxflags_for_cwe(cwe, cflags)
    effective_ldflags = default_ldflags_for_cwe(cwe, ldflags)

    env_updates: Dict[str, Optional[str]] = {
        "SAFE_K_NATIVE_COMPILE_TIMEOUT_SECONDS": str(compile_timeout_s),
        "SAFE_K_CXXFLAGS": effective_cflags.strip() or None,
        "SAFE_K_LDFLAGS": effective_ldflags.strip() or None,
    }
    if cc.strip():
        env_updates["CXX"] = cc.strip()

    with _temporary_env(env_updates):
        ok, ut_result = run_unittest(raw, harness_ground_row(out))

    out["harness_summary_ok"] = ok
    out["harness_ut_result"] = {k: list(v) if isinstance(v, tuple) else v for k, v in ut_result.items()}
    out["harness_passed"] = harness_fully_passes(ok, ut_result)
    out["harness_exit_code"] = 0 if out["harness_passed"] else 2
    if not out["harness_passed"]:
        out["harness_stderr"] = json.dumps(out["harness_ut_result"], ensure_ascii=False)[:4000]
    else:
        out["harness_stderr"] = ""
    out["harness_stdout"] = ""
    return out


def _strip_bookkeeping_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    code = out.get("candidate_cpp") or out.get("generated_code") or ""
    if isinstance(code, str) and code.strip():
        out["candidate_cpp"] = code.strip()
        out["generated_code"] = code.strip()
    for k in (
        "mini_gen_error",
        "mini_gen_cache_hit",
        "harness_passed",
        "harness_summary_ok",
        "harness_ut_result",
        "harness_exit_code",
        "harness_stdout",
        "harness_stderr",
        "candidate_cpp_error",
    ):
        out.pop(k, None)
    return out


def _resolve_cxx(explicit: str) -> str:
    cxx = (explicit or "").strip() or (os.environ.get("CXX") or "").strip() or (shutil.which("g++") or "")
    if not cxx:
        raise RuntimeError("no C++ compiler found (set --cxx or install g++)")
    return cxx


def main() -> None:
    load_dotenv_for_script(__file__)

    parser = argparse.ArgumentParser(
        description="LLM-generate C++ solutions for simple_gen JSONL rows; keep pytest-passing rows"
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
        "--use-existing-candidate-cpp",
        action="store_true",
        help="Skip LLM generation; evaluate existing candidate_cpp / generated_code on each row.",
    )
    parser.add_argument(
        "--candidate-field",
        type=str,
        default="candidate_cpp",
        help="JSONL field with C++ source for harness evaluation (default: candidate_cpp).",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/filter_valid_samples_cpp"),
        help="Directory for on-disk generation cache (keyed by model+prompt).",
    )
    parser.add_argument("--no-cache-read", action="store_true")
    parser.add_argument("--no-cache-write", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--compile-timeout-seconds", type=float, default=60.0)
    parser.add_argument(
        "--harness-row-timeout",
        type=float,
        default=0.0,
        help=(
            "Wall-clock abort per harness row (seconds). "
            "0 = auto (compile + 2*pytest timeouts + 60s slack). "
            "If all in-flight workers exceed this, remaining rows are marked failed "
            "and the executor shuts down without waiting (avoids infinite wedge)."
        ),
    )
    parser.add_argument("--rlimit-cpu-seconds", type=int, default=0)
    parser.add_argument("--rlimit-address-space-mib", type=int, default=0)
    parser.add_argument("--rlimit-stack-mib", type=int, default=0)
    parser.add_argument("--cxx", type=str, default="")
    parser.add_argument(
        "--cxxflags",
        type=str,
        default="-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter",
    )
    parser.add_argument("--ldflags", type=str, default="")
    args = parser.parse_args()

    if not _pytest_available():
        raise RuntimeError(
            "pytest is not available in the current Python environment. "
            "Install pytest into this interpreter "
            f"({sys.executable})."
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

    cxx = _resolve_cxx(args.cxx)

    client = OpenAI(
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL),
        timeout=args.request_timeout,
    )

    gen_rows: List[Optional[Dict[str, Any]]] = [None] * len(rows)

    def _gen_one(i: int, r: Dict[str, Any]) -> Dict[str, Any]:
        if args.use_existing_candidate_cpp:
            return process_row_use_existing(r, code_field=args.candidate_field)
        task = task_row_for_filter(r)
        return process_row_generate(
            client,
            args.model,
            r,
            task,
            args.retries,
            cache_dir=args.cache_dir,
            cache_read=not args.no_cache_read,
            cache_write=not args.no_cache_write,
            max_output_tokens=args.max_output_tokens,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
        futures = {ex.submit(_gen_one, i, rows[i]): i for i in range(len(rows))}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="generating"):
            i = futures[fut]
            gen_rows[i] = fut.result()

    partial: List[Dict[str, Any]] = [r for r in gen_rows if r is not None]
    merged: List[Optional[Dict[str, Any]]] = [None] * len(partial)

    def _eval_one(i: int, r: Dict[str, Any]) -> Dict[str, Any]:
        return evaluate_harness(
            r,
            run_unittest,
            cc=cxx,
            cflags=str(args.cxxflags),
            ldflags=str(args.ldflags),
            compile_timeout_s=float(args.compile_timeout_seconds),
            code_field=args.candidate_field,
        )

    def _stall_fail_row(r: Dict[str, Any], reason: str) -> Dict[str, Any]:
        out = dict(r)
        out["harness_passed"] = False
        out["harness_summary_ok"] = False
        out["harness_ut_result"] = {}
        out["harness_exit_code"] = -2
        out["harness_stderr"] = reason
        out["harness_stdout"] = ""
        return out

    row_wall = float(args.harness_row_timeout)
    if row_wall <= 0:
        row_wall = (
            float(args.compile_timeout_seconds)
            + 2.0 * float(args.timeout_seconds)
            + 60.0
        )

    max_workers = max(1, args.max_workers)
    ex = ThreadPoolExecutor(max_workers=max_workers)
    try:
        next_i = 0
        inflight: Dict[Any, tuple[int, float]] = {}
        with tqdm(total=len(partial), desc="harness") as pbar:
            while next_i < len(partial) or inflight:
                while next_i < len(partial) and len(inflight) < max_workers:
                    fut = ex.submit(_eval_one, next_i, partial[next_i])
                    inflight[fut] = (next_i, time.monotonic())
                    next_i += 1

                done, _ = wait(list(inflight.keys()), timeout=5.0, return_when=FIRST_COMPLETED)
                now = time.monotonic()
                if not done:
                    overdue = {
                        fut: meta
                        for fut, meta in inflight.items()
                        if now - meta[1] > row_wall
                    }
                    if overdue and len(overdue) == len(inflight):
                        print(
                            f"[harness] abort: all {len(overdue)} in-flight worker(s) exceeded "
                            f"{row_wall:.0f}s; failing them and skipping "
                            f"{len(partial) - next_i} not-yet-started rows",
                            flush=True,
                        )
                        for fut, (i, _) in list(overdue.items()):
                            inflight.pop(fut, None)
                            merged[i] = _stall_fail_row(
                                partial[i],
                                f"harness stall abort after {row_wall:.0f}s",
                            )
                            pbar.update(1)
                        for i in range(next_i, len(partial)):
                            merged[i] = _stall_fail_row(
                                partial[i],
                                f"harness skipped after stall abort ({row_wall:.0f}s)",
                            )
                            pbar.update(1)
                        next_i = len(partial)
                        break
                    continue

                for fut in done:
                    i, _ = inflight.pop(fut)
                    try:
                        merged[i] = fut.result()
                    except Exception as exc:  # noqa: BLE001 — keep pipeline moving
                        merged[i] = _stall_fail_row(partial[i], f"harness exception: {exc}")
                    pbar.update(1)
    finally:
        # Do not wait on wedged worker threads (old communicate()-after-kill hang).
        ex.shutdown(wait=False, cancel_futures=True)

    final_rows: List[Dict[str, Any]] = [r for r in merged if r is not None]

    if args.all_output_jsonl is not None:
        args.all_output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.all_output_jsonl.open("w", encoding="utf-8") as f:
            for r in final_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    passed = [r for r in final_rows if r.get("harness_passed")]
    slim = [_strip_bookkeeping_fields(r) for r in passed]
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for r in slim:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_gen_err = sum(1 for r in final_rows if r.get("mini_gen_error"))
    n_cache_hit = sum(1 for r in final_rows if r.get("mini_gen_cache_hit"))
    n_h = len(passed)
    print(f"total rows: {len(final_rows)}")
    print(f"generation errors: {n_gen_err}")
    print(f"cache hits: {n_cache_hit}")
    print(f"harness passed: {n_h} -> {args.output_jsonl}")
    if args.all_output_jsonl:
        print(f"wrote all evaluated rows to {args.all_output_jsonl}")


if __name__ == "__main__":
    main()
