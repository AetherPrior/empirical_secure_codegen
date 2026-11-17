#!/usr/bin/env python3
"""Run HumanEval-style pytest harness rows (``setup_tests`` + ``test_code``).

This is meant to mirror the spirit of HumanEval's ``*_c_test.py`` files:
- pytest lives in Python
- native code is executed via ``subprocess`` against binaries in ``compiled/``

Each JSONL row should include:
- ``setup_tests`` (optional) and ``test_code`` (required), same as ``1_generate_testcases.py``.

This runner writes a temporary ``test_<idx>.py`` per row and executes:
``python -m pytest -q <tmp>/test_<idx>.py``

Optionally applies Linux rlimits in a pre-exec Python wrapper (same approach as
``3_contract_smoke_test.py``'s pytest-smoke mode).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tqdm import tqdm

from cpp_utils import (
    extract_cpp_source_from_markdown,
    merge_cw_eval_pytest_single_file,
    read_jsonl,
    stub_candidate_cpp_source,
)


def _pytest_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("pytest") is not None
    except Exception:
        return False


def _child_prelimit_py() -> str:
    return textwrap.dedent(
        """
        import os
        import sys

        resource = None
        try:
            import resource as _resource
            resource = _resource
        except Exception as e:
            print("NO_RESOURCE_MODULE", repr(e), file=sys.stderr)

        def _setrlimit_safe(which, soft, hard):
            if resource is None:
                return
            try:
                resource.setrlimit(which, (soft, hard))
            except Exception as e:
                print("SETRLIMIT_FAILED", which, repr(e), file=sys.stderr)

        cpu = int(os.environ.get("HARNESS_RLIMIT_CPU", "0"))
        mem = int(os.environ.get("HARNESS_RLIMIT_AS", "0"))
        stk = int(os.environ.get("HARNESS_RLIMIT_STACK", "0"))

        if resource is not None:
            if cpu > 0:
                _setrlimit_safe(resource.RLIMIT_CPU, cpu, cpu)
            if mem > 0:
                _setrlimit_safe(resource.RLIMIT_AS, mem, mem)
            if stk > 0:
                _setrlimit_safe(resource.RLIMIT_STACK, stk, stk)

        os.execvp(sys.argv[1], sys.argv[1:])
        """
    ).strip() + "\n"


def _extract_cpp_source(raw: str) -> str:
    return extract_cpp_source_from_markdown(raw)


def _run_cmd_with_rlimits(
    cmd: List[str],
    *,
    cwd: Path,
    env: Dict[str, str],
    timeout_s: float,
    rlimit_cpu: int,
    rlimit_as_mib: int,
    rlimit_stack_mib: int,
) -> subprocess.CompletedProcess[str]:
    env2 = dict(env)
    env2["HARNESS_RLIMIT_CPU"] = str(int(rlimit_cpu))
    env2["HARNESS_RLIMIT_AS"] = str(int(rlimit_as_mib) * 1024 * 1024) if rlimit_as_mib > 0 else "0"
    env2["HARNESS_RLIMIT_STACK"] = str(int(rlimit_stack_mib) * 1024 * 1024) if rlimit_stack_mib > 0 else "0"

    py = sys.executable
    pre = _child_prelimit_py()
    wrapped = [py, "-c", pre, *cmd]
    return subprocess.run(wrapped, capture_output=True, text=True, cwd=str(cwd), env=env2, timeout=timeout_s)


def _compile_cpp_to_exe(
    *,
    src: str,
    out_exe: Path,
    cc: str,
    cflags: str,
    ldflags: str,
    cwd: Path,
    env: Dict[str, str],
    timeout_s: float,
    rlimit_cpu: int,
    rlimit_as_mib: int,
    rlimit_stack_mib: int,
) -> Tuple[bool, str]:
    src_path = cwd / "_candidate.cpp"
    src_path.write_text(src, encoding="utf-8")

    flags = cflags.split() if cflags.strip() else []
    ld = ldflags.split() if ldflags.strip() else []
    cmd = [cc, "-std=c++17", *flags, str(src_path), "-o", str(out_exe), *ld]
    try:
        proc = _run_cmd_with_rlimits(
            cmd,
            cwd=cwd,
            env=env,
            timeout_s=timeout_s,
            rlimit_cpu=rlimit_cpu,
            rlimit_as_mib=rlimit_as_mib,
            rlimit_stack_mib=rlimit_stack_mib,
        )
    except subprocess.TimeoutExpired:
        return False, f"compile timeout after {timeout_s}s"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, f"compile failed (exit {proc.returncode}): {err[:8000]}"
    return True, ""


def _run_pytest_on_file(
    *,
    test_path: Path,
    cwd: Path,
    timeout_s: float,
    rlimit_cpu: int,
    rlimit_as_mib: int,
    rlimit_stack_mib: int,
) -> Tuple[int, str, str]:
    env = dict(os.environ)
    py = sys.executable
    cmd = [py, "-m", "pytest", "-q", str(test_path)]
    proc = _run_cmd_with_rlimits(
        cmd,
        cwd=cwd,
        env=env,
        timeout_s=timeout_s,
        rlimit_cpu=rlimit_cpu,
        rlimit_as_mib=rlimit_as_mib,
        rlimit_stack_mib=rlimit_stack_mib,
    )
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def main() -> None:
    p = argparse.ArgumentParser(description="Run pytest harness rows from JSONL")
    p.add_argument("--input-jsonl", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=-1)
    p.add_argument("--report-jsonl", type=Path, default=None, help="Optional JSONL with per-row results")

    p.add_argument("--timeout-seconds", type=float, default=30.0)
    p.add_argument("--compile-timeout-seconds", type=float, default=30.0)
    p.add_argument("--rlimit-cpu-seconds", type=int, default=0)
    p.add_argument("--rlimit-address-space-mib", type=int, default=0)
    p.add_argument("--rlimit-stack-mib", type=int, default=0)

    p.add_argument(
        "--compile",
        action="store_true",
        help="Compile candidate C++ from JSONL into ``compiled/<task_name>_task`` before pytest (task name comes from metadata).",
    )
    p.add_argument(
        "--candidate-field",
        type=str,
        default="candidate_cpp",
        help="JSONL field containing candidate C/C++ source (may include markdown fences).",
    )
    p.add_argument(
        "--unsafe-candidate-field",
        type=str,
        default="",
        help="Optional second JSONL field for an ``_unsafe`` binary (compiled to ``compiled/<fn>_unsafe``).",
    )
    p.add_argument("--cxx", type=str, default="", help="Compiler (default: $CXX else g++)")
    p.add_argument(
        "--cxxflags",
        type=str,
        default="-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter",
        help="Extra C++ compiler flags (split on whitespace).",
    )
    p.add_argument("--ldflags", type=str, default="", help="Extra linker flags (split on whitespace).")

    p.add_argument(
        "--seed-compiled-dir",
        type=Path,
        default=None,
        help="Optional directory copied into each temp workspace as ``compiled/`` (for local smoke).",
    )
    p.add_argument(
        "--skip-pytest",
        action="store_true",
        help="Only compile (if requested) and skip executing pytest. Useful for smoke-checking builds.",
    )
    p.add_argument(
        "--stub-missing-candidate",
        action="store_true",
        help="If the candidate field is empty, compile ``utils.stub_candidate_cpp_source`` instead of failing.",
    )
    args = p.parse_args()

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    if not args.skip_pytest and not _pytest_available():
        raise SystemExit(
            "pytest is not installed for this Python interpreter "
            f"({sys.executable}). Install pytest in the environment, or pass --skip-pytest "
            "to only compile."
        )

    cxx = (args.cxx or "").strip() or (os.environ.get("CXX") or "").strip() or (shutil.which("g++") or "")
    if args.compile and not cxx:
        raise SystemExit("compile requested but no compiler found (set --cxx or install g++)")

    report: List[Dict[str, Any]] = []

    for i, row in enumerate(tqdm(rows, desc="pytest rows")):
        setup = row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else ""
        code = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
        if not code.strip():
            report.append({"row_index": i, "skipped": True, "error": "empty test_code"})
            continue

        with tempfile.TemporaryDirectory(prefix=f"cpp_pytest_run_{i}_") as td_s:
            td = Path(td_s)
            test_path = td / f"test_row_{i}.py"
            try:
                merged = merge_cw_eval_pytest_single_file(setup, code)
            except ValueError as e:
                report.append({"row_index": i, "skipped": True, "error": str(e)})
                continue
            test_path.write_text(merged, encoding="utf-8")

            compiled = td / "compiled"
            compiled.mkdir(parents=True, exist_ok=True)
            if args.seed_compiled_dir is not None and args.seed_compiled_dir.is_dir():
                # shallow copy to avoid symlink issues across filesystems
                for child in args.seed_compiled_dir.iterdir():
                    if child.is_file():
                        shutil.copy2(child, compiled / child.name)

            row_report: Dict[str, Any] = {"row_index": i, "skipped": False}

            env = dict(os.environ)

            if args.compile:
                fn = row.get("function_name")
                if not isinstance(fn, str) or not fn.strip():
                    row_report.update({"exit_code": 2, "stdout": "", "stderr": "compile skipped: invalid function_name"})
                    report.append(row_report)
                    continue
                fn = fn.strip()
                raw = row.get(args.candidate_field, "")
                if not isinstance(raw, str) or not raw.strip():
                    if args.stub_missing_candidate:
                        raw = stub_candidate_cpp_source(fn)
                    else:
                        row_report.update(
                            {
                                "exit_code": 2,
                                "stdout": "",
                                "stderr": f"missing candidate field {args.candidate_field!r}",
                            }
                        )
                        report.append(row_report)
                        continue

                src = _extract_cpp_source(raw)
                ok, cerr = _compile_cpp_to_exe(
                    src=src,
                    out_exe=compiled / f"{fn}_task",
                    cc=cxx,
                    cflags=str(args.cxxflags),
                    ldflags=str(args.ldflags),
                    cwd=td,
                    env=env,
                    timeout_s=float(args.compile_timeout_seconds),
                    rlimit_cpu=int(args.rlimit_cpu_seconds),
                    rlimit_as_mib=int(args.rlimit_address_space_mib),
                    rlimit_stack_mib=int(args.rlimit_stack_mib),
                )
                if not ok:
                    row_report.update({"exit_code": 2, "stdout": "", "stderr": cerr[:8000]})
                    report.append(row_report)
                    continue


            if args.skip_pytest:
                rc, out, err = 0, "", "skipped pytest (--skip-pytest)"
            else:
                try:
                    rc, out, err = _run_pytest_on_file(
                        test_path=test_path,
                        cwd=td,
                        timeout_s=float(args.timeout_seconds),
                        rlimit_cpu=int(args.rlimit_cpu_seconds),
                        rlimit_as_mib=int(args.rlimit_address_space_mib),
                        rlimit_stack_mib=int(args.rlimit_stack_mib),
                    )
                except subprocess.TimeoutExpired:
                    rc = 124
                    out = ""
                    err = f"timeout after {args.timeout_seconds}s"

            row_report.update({"exit_code": rc, "stdout": out[:8000], "stderr": err[:8000]})
            report.append(row_report)

    if args.report_jsonl is not None:
        args.report_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.report_jsonl.open("w", encoding="utf-8") as f:
            for r in report:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    ok = sum(1 for r in report if not r.get("skipped") and int(r.get("exit_code", 1)) == 0)
    print(f"rows={len(rows)} pytest_ok={ok} report={args.report_jsonl}")

    any_failed = any(
        (not r.get("skipped")) and int(r.get("exit_code", 1)) != 0 for r in report
    )
    raise SystemExit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
