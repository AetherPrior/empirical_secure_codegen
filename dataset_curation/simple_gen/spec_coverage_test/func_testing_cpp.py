#!/usr/bin/env python3
"""C++ pipeline variant of ``func_testing.py``: CWE markers on ``tests_json`` + gcov coverage.

Expects rows with ``tests_json``, ``function_name``, ``arguments`` — e.g.
``data/pipeline_runs/cpp/**/3_filtered.jsonl`` or ``4_valid.jsonl``.
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
from typing import Any, DefaultDict, Dict, List, Optional, Tuple

from tqdm import tqdm

_SPEC = Path(__file__).resolve().parent
_SIMPLE_GEN = _SPEC.parent
for _p in (_SIMPLE_GEN, _SIMPLE_GEN / "cpp", _SIMPLE_GEN / "c"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL
from cpp_utils import extract_cpp_source_from_markdown

from cpp_harness_codegen import build_harness_runner_cpp
from spec_coverage_test.func_testing import _atomic_write_json, _read_completion_cache
from spec_coverage_test.func_testing_lib import (
    completion_cache_key,
    load_rows,
    parse_gcov_summary,
    print_summary,
    security_spec_presence_fraction_tests_json,
    test_category_counts_tests_json,
)

try:
    from openai import OpenAI
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

_CPP_BLOCK_RE = re.compile(r"```(?:cpp|c\+\+)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_CACHE_LOCK = threading.Lock()
_GCOV_LOCK = threading.Lock()

_JSONL_NAMES = ("3_filtered.jsonl", "4_valid.jsonl")


def extract_cpp_code(text: str) -> str:
    m = _CPP_BLOCK_RE.search(text or "")
    if m:
        return m.group(1).strip()
    return extract_cpp_source_from_markdown(text or "")


def build_generation_prompt(row: Dict[str, Any]) -> str:
    tests_blob = json.dumps(row.get("tests_json", {}), ensure_ascii=False, indent=2)
    return textwrap.dedent(
        f"""
        Write C++17 code in exactly one triple-backticked cpp block.

        Task:
        {row.get("prompt", "")}

        Required function name (no main):
        {row.get("function_name", "")}

        tests_json:
        ```json
        {tests_blob}
        ```

        Constraints:
        - Implement only the named function plus includes.
        - Return only code, no explanation.
        """
    ).strip()


def _run_cpp_coverage(
    *,
    row: Dict[str, Any],
    generated_cpp: str,
    categories: Tuple[str, ...],
    cxx: str,
    cxxflags: str,
    compile_timeout_s: float,
    run_timeout_s: float,
) -> Tuple[Optional[float], Optional[float], str]:
    try:
        runner = build_harness_runner_cpp(row, categories=categories)
    except Exception as e:
        return None, None, f"harness codegen: {type(e).__name__}: {e}"

    with tempfile.TemporaryDirectory(prefix="func_cov_cpp_") as td_s:
        td = Path(td_s)
        src = td / "solution.cpp"
        src.write_text(generated_cpp.strip() + "\n", encoding="utf-8")
        runner_path = td / "runner.cpp"
        runner_path.write_text(runner, encoding="utf-8")
        out_exe = td / "harness.out"

        cov_flags = ["-fprofile-arcs", "-ftest-coverage", "-O0", "-std=c++17"]
        extra = cxxflags.split() if cxxflags.strip() else []
        cmd = [cxx, *cov_flags, *extra, str(src), str(runner_path), "-o", str(out_exe)]
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, cwd=str(td), timeout=compile_timeout_s)
        except subprocess.TimeoutExpired:
            return None, None, f"compile timeout {compile_timeout_s}s"
        if cp.returncode != 0:
            err = (cp.stderr or cp.stdout or "").strip()
            return None, None, f"compile failed: {err[:2000]}"

        try:
            rp = subprocess.run([str(out_exe)], capture_output=True, text=True, cwd=str(td), timeout=run_timeout_s)
        except subprocess.TimeoutExpired:
            return None, None, f"run timeout {run_timeout_s}s"
        if rp.returncode != 0:
            err = (rp.stderr or rp.stdout or "").strip()
            return None, None, f"harness failed: {err[:2000]}"

        with _GCOV_LOCK:
            try:
                gp = subprocess.run(
                    [shutil.which("gcov") or "gcov", "-b", "-c", "solution.cpp"],
                    capture_output=True,
                    text=True,
                    cwd=str(td),
                    timeout=30.0,
                )
            except subprocess.TimeoutExpired:
                return None, None, "gcov timeout"
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
        if isinstance(cached, dict) and isinstance(cached.get("code"), str) and cached["code"].strip():
            return cached["code"].strip(), "", True

    try:
        resp = client.responses.create(
            model=model,
            instructions="You are a secure C++ coding assistant.",
            input=prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout=openai_timeout_seconds,
        )
        text = (getattr(resp, "output_text", None) or "").strip()
        code = extract_cpp_code(text)
        if not code:
            return None, "empty generation", False
        if cache_path is not None:
            with _CACHE_LOCK:
                _atomic_write_json(cache_path, {"code": code, "raw_text": text, "model": model})
        return code, "", False
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", False


def _process_one_sample(
    *,
    row_index: int,
    sample_index: int,
    row: Dict[str, Any],
    n_fun: int,
    n_sec: int,
    client: OpenAI,
    model: str,
    max_output_tokens: int,
    temperature: float,
    openai_timeout_seconds: float,
    cache_dir: Optional[Path],
    use_cache: bool,
    cxx: str,
    cxxflags: str,
    compile_timeout: float,
    run_timeout: float,
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
        stmt, branch, err = _run_cpp_coverage(
            row=row,
            generated_cpp=code,
            categories=("functionality",),
            cxx=cxx,
            cxxflags=cxxflags,
            compile_timeout_s=compile_timeout,
            run_timeout_s=run_timeout,
        )
        if stmt is None:
            out["errors"].append(f"functional coverage: {err}")
        else:
            out["functional_statement_coverage"] = stmt
            out["functional_branch_coverage"] = branch

    if n_sec > 0:
        stmt, branch, err = _run_cpp_coverage(
            row=row,
            generated_cpp=code,
            categories=("security",),
            cxx=cxx,
            cxxflags=cxxflags,
            compile_timeout_s=compile_timeout,
            run_timeout_s=run_timeout,
        )
        if stmt is None:
            out["errors"].append(f"security coverage: {err}")
        else:
            out["security_statement_coverage"] = stmt
            out["security_branch_coverage"] = branch

    return out


def main() -> None:
    default_root = _SIMPLE_GEN / "data" / "pipeline_runs" / "cpp"
    default_cache = _SIMPLE_GEN / ".cache" / "func_testing_completions_cpp"

    parser = argparse.ArgumentParser(description="C++: CWE markers on tests_json + gcov coverage.")
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
    parser.add_argument("--cxx", type=str, default="")
    parser.add_argument(
        "--cxxflags",
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

    cxx = (args.cxx or "").strip() or (os.environ.get("CXX") or "").strip() or (shutil.which("g++") or "")
    if not cxx:
        raise SystemExit("no C++ compiler (set --cxx or install g++)")

    spec_values: DefaultDict[str, List[float]] = defaultdict(list)
    spec_skipped: DefaultDict[str, int] = defaultdict(int)
    missing_tests: DefaultDict[str, int] = defaultdict(int)

    for ri, row in enumerate(rows):
        cwe_id = str(row.get("cwe") or "").strip()
        n_fun, n_sec, reason = test_category_counts_tests_json(row)
        if reason:
            missing_tests[cwe_id or "<missing>"] += 1
            spec_skipped[cwe_id or "<missing>"] += 1
            continue
        sf, serr = security_spec_presence_fraction_tests_json(row, cwe_id)
        if sf is None:
            spec_skipped[cwe_id or "<missing>"] += 1
        else:
            spec_values[cwe_id or "<missing>"].append(sf)

    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))
    jobs: List[Tuple[int, int, Dict[str, Any], int, int, str]] = []
    for ri, row in enumerate(rows):
        fn = str(row.get("function_name") or "").strip()
        if not fn:
            continue
        n_fun, n_sec, reason = test_category_counts_tests_json(row)
        if reason:
            continue
        cwe_id = str(row.get("cwe") or "").strip() or "<missing>"
        for si in range(max(0, args.n_samples)):
            jobs.append((ri, si, row, n_fun, n_sec, cwe_id))

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
                    n_fun=n_fun,
                    n_sec=n_sec,
                    client=client,
                    model=args.model,
                    max_output_tokens=args.max_output_tokens,
                    temperature=args.temperature,
                    openai_timeout_seconds=args.openai_timeout_seconds,
                    cache_dir=cache_dir,
                    use_cache=use_cache,
                    cxx=cxx,
                    cxxflags=str(args.cxxflags),
                    compile_timeout=float(args.compile_timeout_seconds),
                    run_timeout=float(args.functional_exec_timeout_seconds),
                ): (ri, si, cwe_id)
                for ri, si, row, n_fun, n_sec, cwe_id in jobs
            }
            for fut in tqdm(as_completed(futs), total=len(futs), desc="cpp coverage"):
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
        lang_label="C++",
    )


if __name__ == "__main__":
    main()
