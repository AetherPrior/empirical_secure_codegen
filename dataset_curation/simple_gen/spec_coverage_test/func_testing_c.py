#!/usr/bin/env python3
"""C pipeline variant of ``func_testing.py``: CWE markers + gcov coverage via pytest harness.

Expects rows with ``setup_tests``, ``test_code`` (pytest), and ``function_name`` — e.g.
``data/pipeline_runs/c/**/3_filtered.jsonl`` or ``4_valid.jsonl``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Tuple

from tqdm import tqdm

_SPEC = Path(__file__).resolve().parent
_SIMPLE_GEN = _SPEC.parent
for _p in (_SIMPLE_GEN, _SIMPLE_GEN / "c"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL
from utils import extract_c_source_from_markdown, merge_cw_eval_pytest_single_file, read_jsonl

from spec_coverage_test.func_testing import (
    _atomic_write_json,
    _has_required_test_categories,
    _read_completion_cache,
    security_spec_presence_fraction,
)
from spec_coverage_test.func_testing_lib import (
    completion_cache_key,
    load_rows,
    parse_gcov_summary,
    print_summary,
)

try:
    from openai import OpenAI
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

_C_BLOCK_RE = re.compile(r"```(?:c)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_CACHE_LOCK = threading.Lock()
_GCOV_LOCK = threading.Lock()

_JSONL_NAMES = ("3_filtered.jsonl", "4_valid.jsonl")


def extract_c_code(text: str) -> str:
    m = _C_BLOCK_RE.search(text or "")
    if m:
        return m.group(1).strip()
    return extract_c_source_from_markdown(text or "")


def build_generation_prompt(row: Dict[str, Any]) -> str:
    return textwrap.dedent(
        f"""
        Write C11 code in exactly one triple-backticked c block.

        Task:
        {row.get("prompt", "")}

        Required function name (implement logic called from main / tests):
        {row.get("function_name", "")}

        Test setup (pytest prelude):
        ```python
        {row.get("setup_tests", "")}
        ```

        Test cases (pytest):
        ```python
        {row.get("test_code", "")}
        ```

        Constraints:
        - Include a ``main`` if tests invoke ``{row.get("function_name", "")}_task`` via subprocess.
        - Return only code, no explanation.
        """
    ).strip()


def _run_c_coverage(
    *,
    row: Dict[str, Any],
    generated_c: str,
    categories: Sequence[str],
    cc: str,
    cflags: str,
    compile_timeout_s: float,
    pytest_timeout_s: float,
) -> Tuple[Optional[float], Optional[float], str]:
    fn = row.get("function_name")
    if not isinstance(fn, str) or not fn.strip():
        return None, None, "missing function_name"
    fn = fn.strip()

    setup = row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else ""
    test_code = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
    if not test_code.strip():
        return None, None, "empty test_code"

    try:
        merged = merge_cw_eval_pytest_single_file(setup, test_code)
    except ValueError as e:
        return None, None, str(e)

    marker = "functionality" if categories == ("functionality",) else "security"
    if marker not in categories:
        marker = categories[0] if categories else "functionality"

    with tempfile.TemporaryDirectory(prefix="func_cov_c_") as td_s:
        td = Path(td_s)
        src = td / "solution.c"
        src.write_text(generated_c.strip() + "\n", encoding="utf-8")
        compiled = td / "compiled"
        compiled.mkdir()
        exe = compiled / f"{fn}_task"

        cov_flags = ["-fprofile-arcs", "-ftest-coverage", "-O0"]
        extra = cflags.split() if cflags.strip() else []
        cmd = [cc, "-std=c11", *cov_flags, *extra, str(src), "-o", str(exe)]
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, cwd=str(td), timeout=compile_timeout_s)
        except subprocess.TimeoutExpired:
            return None, None, f"compile timeout {compile_timeout_s}s"
        if cp.returncode != 0:
            err = (cp.stderr or cp.stdout or "").strip()
            return None, None, f"compile failed: {err[:2000]}"

        test_path = td / "test_row.py"
        test_path.write_text(merged, encoding="utf-8")

        py = sys.executable
        try:
            pr = subprocess.run(
                [py, "-m", "pytest", "-q", str(test_path), "-m", marker],
                capture_output=True,
                text=True,
                cwd=str(td),
                timeout=pytest_timeout_s,
            )
        except subprocess.TimeoutExpired:
            return None, None, f"pytest timeout {pytest_timeout_s}s"
        if pr.returncode != 0:
            err = (pr.stderr or pr.stdout or "").strip()
            return None, None, f"pytest failed: {err[:2000]}"

        with _GCOV_LOCK:
            try:
                gp = subprocess.run(
                    [shutil.which("gcov") or "gcov", "-b", "-c", "solution.c"],
                    capture_output=True,
                    text=True,
                    cwd=str(td),
                    timeout=30.0,
                )
            except subprocess.TimeoutExpired:
                return None, None, "gcov timeout"
        if gp.returncode != 0 and not (gp.stdout or gp.stderr):
            return None, None, "gcov failed"
        return parse_gcov_summary((gp.stdout or "") + "\n" + (gp.stderr or ""))


def sample_completion(
    client: OpenAI,
    model: str,
    row: Dict[str, Any],
    max_output_tokens: int,
    temperature: float,
    *,
    sample_index: int,
    cache_dir: Optional[Path],
    use_cache: bool,
    openai_timeout_seconds: float,
) -> Tuple[Optional[str], str, bool]:
    prompt = build_generation_prompt(row)
    cache_path: Optional[Path] = None
    if use_cache and cache_dir is not None:
        key = completion_cache_key(
            model=model,
            prompt=prompt,
            max_output_tokens=max_output_tokens,
            temperature=temperature,
            sample_index=sample_index,
        )
        cache_path = cache_dir / f"{key}.json"
        cached = _read_completion_cache(cache_path)
        if isinstance(cached, dict):
            code = cached.get("code")
            if isinstance(code, str) and code.strip():
                return code.strip(), "", True

    try:
        resp = client.responses.create(
            model=model,
            instructions="You are a secure C coding assistant.",
            input=prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout=openai_timeout_seconds,
        )
        text = (getattr(resp, "output_text", None) or "").strip()
        code = extract_c_code(text)
        if not code:
            return None, "empty generation", False
        if cache_path is not None:
            with _CACHE_LOCK:
                _atomic_write_json(
                    cache_path,
                    {"code": code, "raw_text": text, "model": model, "sample_index": sample_index},
                )
        return code, "", False
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", False


def _process_one_sample(
    *,
    row_index: int,
    sample_index: int,
    row: Dict[str, Any],
    function_name: str,
    n_fun: int,
    n_sec: int,
    client: OpenAI,
    model: str,
    max_output_tokens: int,
    temperature: float,
    openai_timeout_seconds: float,
    functional_timeout: float,
    security_timeout: float,
    cache_dir: Optional[Path],
    use_cache: bool,
    cc: str,
    cflags: str,
    compile_timeout: float,
    pytest_timeout: float,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "row_index": row_index,
        "sample_index": sample_index,
        "n_functionality_cases": n_fun,
        "n_security_cases": n_sec,
        "functional_statement_coverage": None,
        "functional_branch_coverage": None,
        "security_statement_coverage": None,
        "security_branch_coverage": None,
        "errors": [],
    }
    code, gen_err, from_cache = sample_completion(
        client,
        model,
        row,
        max_output_tokens,
        temperature,
        sample_index=sample_index,
        cache_dir=cache_dir,
        use_cache=use_cache,
        openai_timeout_seconds=openai_timeout_seconds,
    )
    out["completion_from_cache"] = from_cache
    if code is None:
        out["errors"].append(f"generation: {gen_err}")
        return out

    if n_fun > 0:
        stmt, branch, err = _run_c_coverage(
            row=row,
            generated_c=code,
            categories=("functionality",),
            cc=cc,
            cflags=cflags,
            compile_timeout_s=compile_timeout,
            pytest_timeout_s=pytest_timeout,
        )
        if stmt is None:
            out["errors"].append(f"functional coverage: {err}")
        else:
            out["functional_statement_coverage"] = stmt
            out["functional_branch_coverage"] = branch

    if n_sec > 0:
        stmt, branch, err = _run_c_coverage(
            row=row,
            generated_c=code,
            categories=("security",),
            cc=cc,
            cflags=cflags,
            compile_timeout_s=compile_timeout,
            pytest_timeout_s=pytest_timeout,
        )
        if stmt is None:
            out["errors"].append(f"security coverage: {err}")
        else:
            out["security_statement_coverage"] = stmt
            out["security_branch_coverage"] = branch

    return out


def main() -> None:
    default_root = _SIMPLE_GEN / "data" / "pipeline_runs" / "c"
    default_cache = _SIMPLE_GEN / ".cache" / "func_testing_completions_c"

    parser = argparse.ArgumentParser(description="C: CWE markers + gcov coverage (pytest harness).")
    parser.add_argument("--jsonl", type=Path, default=None)
    parser.add_argument("--root-dir", type=Path, default=default_root)
    parser.add_argument("-n", type=int, default=1, dest="n_samples")
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-output-tokens", type=int, default=16384)
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--openai-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--functional-exec-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--security-exec-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--compile-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-rows", type=int, default=-1)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--cwes", nargs="*", default=None)
    parser.add_argument("--cache-dir", type=Path, default=default_cache)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cc", type=str, default="")
    parser.add_argument(
        "--cflags",
        type=str,
        default="-Wall -Wextra -Wno-error=unused-parameter",
    )
    args = parser.parse_args()

    use_cache = not args.no_cache
    cache_dir = args.cache_dir.expanduser().resolve() if use_cache else None

    rows, source_desc = load_rows(jsonl=args.jsonl, root_dir=args.root_dir, jsonl_names=_JSONL_NAMES)
    if not rows:
        raise SystemExit(f"No rows in {source_desc}")
    if args.max_rows > 0:
        rows = rows[: args.max_rows]
    if args.cwes:
        allow = {c.strip() for c in args.cwes if c}
        rows = [r for r in rows if str(r.get("cwe") or "").strip() in allow]
    if not rows:
        raise SystemExit("No rows after filters")

    cc = (args.cc or "").strip() or (os.environ.get("CC") or "").strip() or (shutil.which("gcc") or "")
    if not cc:
        raise SystemExit("no C compiler (set --cc or install gcc)")

    spec_values: DefaultDict[str, List[float]] = defaultdict(list)
    spec_skipped: DefaultDict[str, int] = defaultdict(int)
    missing_tests: DefaultDict[str, int] = defaultdict(int)

    for ri, row in enumerate(rows):
        cwe_id = str(row.get("cwe") or "").strip()
        ok, reason, _, _ = _has_required_test_categories(row)
        if not ok:
            missing_tests[cwe_id or "<missing>"] += 1
            spec_skipped[cwe_id or "<missing>"] += 1
            continue
        sf, serr = security_spec_presence_fraction(row, cwe_id)
        if sf is None:
            spec_skipped[cwe_id or "<missing>"] += 1
        else:
            spec_values[cwe_id or "<missing>"].append(sf)

    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))
    jobs: List[Tuple[int, int, Dict[str, Any], str, int, int, str]] = []
    for ri, row in enumerate(rows):
        fn = str(row.get("function_name") or "").strip()
        if not fn:
            continue
        ok, _, n_fun, n_sec = _has_required_test_categories(row)
        if not ok:
            continue
        cwe_id = str(row.get("cwe") or "").strip() or "<missing>"
        for si in range(max(0, args.n_samples)):
            jobs.append((ri, si, row, fn, n_fun, n_sec, cwe_id))

    gen_failed = func_failed = sec_failed = 0
    cache_hits = cache_misses = 0
    by_row_fun_stmt: Dict[int, List[float]] = {}
    by_row_fun_branch: Dict[int, List[float]] = {}
    by_row_sec_stmt: Dict[int, List[float]] = {}
    by_row_sec_branch: Dict[int, List[float]] = {}
    row_cwe: Dict[int, str] = {}

    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as ex:
            futs = {
                ex.submit(
                    _process_one_sample,
                    row_index=ri,
                    sample_index=si,
                    row=row,
                    function_name=fn,
                    n_fun=n_fun,
                    n_sec=n_sec,
                    client=client,
                    model=args.model,
                    max_output_tokens=args.max_output_tokens,
                    temperature=args.temperature,
                    openai_timeout_seconds=args.openai_timeout_seconds,
                    functional_timeout=args.functional_exec_timeout_seconds,
                    security_timeout=args.security_exec_timeout_seconds,
                    cache_dir=cache_dir,
                    use_cache=use_cache,
                    cc=cc,
                    cflags=str(args.cflags),
                    compile_timeout=float(args.compile_timeout_seconds),
                    pytest_timeout=float(args.functional_exec_timeout_seconds),
                ): (ri, si, cwe_id)
                for ri, si, row, fn, n_fun, n_sec, cwe_id in jobs
            }
            for fut in tqdm(as_completed(futs), total=len(futs), desc="c coverage"):
                r = fut.result()
                ri = r["row_index"]
                _, _, cwe_id = futs[fut]
                row_cwe[ri] = cwe_id
                if use_cache:
                    if r.get("completion_from_cache"):
                        cache_hits += 1
                    else:
                        cache_misses += 1
                if any(e.startswith("generation:") for e in r["errors"]):
                    gen_failed += 1
                else:
                    if r["functional_statement_coverage"] is None and r["n_functionality_cases"] > 0:
                        func_failed += 1
                    if r["security_statement_coverage"] is None and r["n_security_cases"] > 0:
                        sec_failed += 1
                if r["functional_statement_coverage"] is not None:
                    by_row_fun_stmt.setdefault(ri, []).append(r["functional_statement_coverage"])
                if r["functional_branch_coverage"] is not None:
                    by_row_fun_branch.setdefault(ri, []).append(r["functional_branch_coverage"])
                if r["security_statement_coverage"] is not None:
                    by_row_sec_stmt.setdefault(ri, []).append(r["security_statement_coverage"])
                if r["security_branch_coverage"] is not None:
                    by_row_sec_branch.setdefault(ri, []).append(r["security_branch_coverage"])

    func_stmt_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    func_branch_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    sec_stmt_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    sec_branch_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    for ri, vals in by_row_fun_stmt.items():
        if vals:
            func_stmt_cwe[row_cwe.get(ri, "<missing>")].append(sum(vals) / len(vals))
    for ri, vals in by_row_fun_branch.items():
        if vals:
            func_branch_cwe[row_cwe.get(ri, "<missing>")].append(sum(vals) / len(vals))
    for ri, vals in by_row_sec_stmt.items():
        if vals:
            sec_stmt_cwe[row_cwe.get(ri, "<missing>")].append(sum(vals) / len(vals))
    for ri, vals in by_row_sec_branch.items():
        if vals:
            sec_branch_cwe[row_cwe.get(ri, "<missing>")].append(sum(vals) / len(vals))

    print_summary(
        source_desc=source_desc,
        n_rows=len(rows),
        n_jobs=len(jobs),
        spec_values_by_cwe=spec_values,
        spec_skipped_by_cwe=spec_skipped,
        missing_required_by_cwe=missing_tests,
        func_stmt_by_cwe=func_stmt_cwe,
        func_branch_by_cwe=func_branch_cwe,
        sec_stmt_by_cwe=sec_stmt_cwe,
        sec_branch_by_cwe=sec_branch_cwe,
        gen_failed=gen_failed,
        func_cov_failed=func_failed,
        sec_cov_failed=sec_failed,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        use_cache=use_cache,
        cache_dir=cache_dir,
        lang_label="C",
    )


if __name__ == "__main__":
    main()
