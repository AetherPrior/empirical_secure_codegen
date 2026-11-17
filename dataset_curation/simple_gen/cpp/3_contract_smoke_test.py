#!/usr/bin/env python3
"""Contract smoke test for CWEval-style **pytest** harness rows (C++ tasks).

Each row is expected to contain:
- ``setup_tests`` (optional): python prelude
- ``test_code`` (required): pytest module body

This script validates static harness shape using ``utils.parse_and_validate_pytest``.

Optionally, it can run a **very small** ``python -m pytest`` smoke in a subprocess with a
hard wall timeout. With ``--pytest-via-cxx-compile``, smoke uses ``run_pytest.py --compile``
and the same ``--cc`` / ``--cxxflags`` / ``--ldflags`` contract as the standalone runner.

This is intentionally optional because executing generated tests can hang if the model
emits slow loops or tries to run missing binaries without guards.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tqdm import tqdm

from cpp_utils import merge_cw_eval_pytest_single_file, parse_and_validate_pytest, read_jsonl


def _synthetic_md(setup_tests: Any, test_code: Any) -> str:
    setup = setup_tests if isinstance(setup_tests, str) else ""
    tests = test_code if isinstance(test_code, str) else ""
    return (
        "## test setup\n```python\n"
        f"{setup.strip()}\n"
        "```\n\n"
        "## pytest tests\n```python\n"
        f"{tests.strip()}\n"
        "```\n"
    )


def _validate_row(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    mismatches: List[Dict[str, Any]] = []
    test_code = row.get("test_code")
    if not isinstance(test_code, str) or not test_code.strip():
        mismatches.append({"kind": "missing_test_code", "error": "row.test_code must be a non-empty string"})
        return mismatches

    try:
        md = _synthetic_md(row.get("setup_tests"), test_code)
        parse_and_validate_pytest(md)
    except Exception as e:
        mismatches.append({"kind": "pytest_harness_invalid", "error": f"{type(e).__name__}: {e}"})
    return mismatches


def _child_prelimit_py() -> str:
    """Multiline ``python -c`` program applied before exec'ing pytest."""
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


def _pytest_smoke_subprocess(
    *,
    setup_tests: str,
    test_code: str,
    timeout_s: float,
    rlimit_cpu: int,
    rlimit_as_mib: int,
    rlimit_stack_mib: int,
) -> Tuple[bool, str]:
    py = sys.executable
    with tempfile.TemporaryDirectory(prefix="c_pytest_smoke_") as td:
        p = Path(td)
        smoke_path = p / "test_smoke.py"
        try:
            merged = merge_cw_eval_pytest_single_file(setup_tests or "", test_code or "")
        except ValueError as e:
            return False, str(e)
        smoke_path.write_text(merged, encoding="utf-8")
        # Minimal compiled/ tree so imports/constants resolve if tests touch paths.
        (p / "compiled").mkdir(parents=True, exist_ok=True)

        env = dict(os.environ)
        env["PYTHONPATH"] = str(p) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["HARNESS_RLIMIT_CPU"] = str(int(rlimit_cpu))
        env["HARNESS_RLIMIT_AS"] = str(int(rlimit_as_mib) * 1024 * 1024) if rlimit_as_mib > 0 else "0"
        env["HARNESS_RLIMIT_STACK"] = str(int(rlimit_stack_mib) * 1024 * 1024) if rlimit_stack_mib > 0 else "0"

        pytest_exe = shutil.which("pytest") or ""
        if not pytest_exe:
            return False, "pytest executable not found on PATH"

        pre = _child_prelimit_py()
        cmd = [py, "-c", pre, pytest_exe, "-q", str(smoke_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, env=env, cwd=str(p))
        except subprocess.TimeoutExpired:
            return False, f"pytest smoke timed out after {timeout_s}s"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()[:4000]
            return False, f"pytest smoke failed: exit {proc.returncode}: {err}"
        return True, (proc.stdout or "").strip()[:4000]


def _pytest_smoke_via_cpp_runner(
    *,
    row: Dict[str, Any],
    runner: Path,
    pytest_timeout_s: float,
    compile_timeout_s: float,
    rlimit_cpu: int,
    rlimit_as_mib: int,
    rlimit_stack_mib: int,
    cc: str,
    cflags: str,
    ldflags: str,
    candidate_field: str,
) -> Tuple[bool, str]:
    """Run ``cpp/run_pytest.py --compile`` on a one-row JSONL.

    If ``candidate_field`` is empty, passes ``--stub-missing-candidate --skip-pytest`` so smoke
    only checks that the harness compiles; use a real candidate elsewhere for full pytest.
    """
    if not runner.is_file():
        return False, f"C++ pytest runner not found: {runner}"

    fd, tmp_path = tempfile.mkstemp(suffix=".jsonl", prefix="cpp_contract_row_")
    os.close(fd)
    fd_rep, rep_path = tempfile.mkstemp(suffix=".jsonl", prefix="cpp_contract_rep_")
    os.close(fd_rep)
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

        cmd: List[str] = [
            sys.executable,
            str(runner),
            "--input-jsonl",
            tmp_path,
            "--compile",
            "--max-rows",
            "1",
            "--report-jsonl",
            rep_path,
            "--timeout-seconds",
            str(float(pytest_timeout_s)),
            "--compile-timeout-seconds",
            str(float(compile_timeout_s)),
            "--cxxflags",
            str(cflags),
            "--candidate-field",
            str(candidate_field),
        ]
        if (cc or "").strip():
            cmd.extend(["--cxx", cc.strip()])
        if (ldflags or "").strip():
            cmd.extend(["--ldflags", ldflags.strip()])

        if int(rlimit_cpu) > 0:
            cmd.extend(["--rlimit-cpu-seconds", str(int(rlimit_cpu))])
        if int(rlimit_as_mib) > 0:
            cmd.extend(["--rlimit-address-space-mib", str(int(rlimit_as_mib))])
        if int(rlimit_stack_mib) > 0:
            cmd.extend(["--rlimit-stack-mib", str(int(rlimit_stack_mib))])

        raw_c = row.get(candidate_field, "")
        has_real_candidate = isinstance(raw_c, str) and raw_c.strip()
        if not has_real_candidate:
            # Compile-only smoke: a trivial main() so gcc succeeds; real evaluation uses candidate_cpp.
            cmd.extend(["--stub-missing-candidate", "--skip-pytest"])

        wall = float(pytest_timeout_s) + float(compile_timeout_s) + 15.0
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=wall)
        except subprocess.TimeoutExpired:
            return False, f"cpp/run_pytest compile+pytest timed out after {wall}s"
        out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[:8000]
        if proc.returncode != 0:
            rep_detail = ""
            try:
                rp = Path(rep_path)
                if rp.is_file() and rp.stat().st_size > 0:
                    last = rp.read_text(encoding="utf-8").strip().splitlines()[-1]
                    rep = json.loads(last)
                    ec = rep.get("exit_code")
                    se = (rep.get("stderr") or "").strip()
                    so = (rep.get("stdout") or "").strip()
                    if se or so:
                        rep_detail = f" (pytest/compile detail exit_code={ec}): stderr={se[:4000]!s}"
                        if so:
                            rep_detail += f" stdout={so[:2000]!s}"
            except Exception:
                pass
            return False, f"cpp/run_pytest failed (exit {proc.returncode}){rep_detail or ': ' + out}"
        return True, out
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            os.unlink(rep_path)
        except OSError:
            pass


def main() -> None:
    p = argparse.ArgumentParser(description="Static (+ optional pytest smoke) contract checks for CWEval-style rows")
    p.add_argument("--input-jsonl", type=Path, required=True)
    p.add_argument("--max-rows", type=int, default=-1)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--filtered-jsonl", type=Path, default=None)
    p.add_argument("--max-mismatches-per-row", type=int, default=20)

    p.add_argument("--pytest-smoke", action="store_true", help="Run a subprocess pytest smoke on each row (can be slow)")
    p.add_argument(
        "--pytest-via-cxx-compile",
        action="store_true",
        help="With --pytest-smoke, run ``cpp/run_pytest.py --compile``. If ``candidate_cpp`` is "
        "missing, uses a trivial C++ stub and ``--skip-pytest`` (compile-only smoke).",
    )
    p.add_argument(
        "--cxx-pytest-runner",
        type=Path,
        default=None,
        help="Path to run_pytest.py (default: sibling of this script).",
    )
    p.add_argument("--pytest-timeout-seconds", type=float, default=10.0)
    p.add_argument("--compile-timeout-seconds", type=float, default=30.0, help="g++ step timeout when using --pytest-via-cxx-compile")
    p.add_argument("--cxx", type=str, default="", help="Compiler for --pytest-via-cxx-compile (default: $CXX or g++)")
    p.add_argument(
        "--cxxflags",
        type=str,
        default="-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter",
        help="Extra C++ flags for --pytest-via-cxx-compile",
    )
    p.add_argument("--ldflags", type=str, default="", help="Extra linker flags for --pytest-via-cxx-compile")
    p.add_argument("--candidate-field", type=str, default="candidate_cpp", help="JSONL field with C++ source for --pytest-via-cxx-compile")
    p.add_argument(
        "--unsafe-candidate-field",
        type=str,
        default="",
        help="Optional second C++ field compiled to *_unsafe (same as run_pytest.py).",
    )
    p.add_argument("--rlimit-cpu-seconds", type=int, default=0, help="Apply RLIMIT_CPU in pytest-smoke child (0 disables)")
    p.add_argument("--rlimit-address-space-mib", type=int, default=0, help="Apply RLIMIT_AS in pytest-smoke child (0 disables)")
    p.add_argument("--rlimit-stack-mib", type=int, default=0, help="Apply RLIMIT_STACK in pytest-smoke child (0 disables)")
    args = p.parse_args()

    script_dir = Path(__file__).resolve().parent
    cpp_runner = args.cxx_pytest_runner if args.cxx_pytest_runner is not None else script_dir / "run_pytest.py"

    if args.pytest_via_cxx_compile and not args.pytest_smoke:
        raise SystemExit("--pytest-via-cxx-compile requires --pytest-smoke")

    rows = read_jsonl(args.input_jsonl)
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    report_rows: List[Dict[str, Any]] = []
    kept_rows: List[Dict[str, Any]] = []

    total_mismatches = 0
    for row_index, row in tqdm(enumerate(rows), total=len(rows), desc="Checking rows"):
        mismatches = _validate_row(row)

        if args.pytest_smoke and not mismatches:
            if args.pytest_via_cxx_compile:
                ok, msg = _pytest_smoke_via_cpp_runner(
                    row=row,
                    runner=cpp_runner,
                    pytest_timeout_s=float(args.pytest_timeout_seconds),
                    compile_timeout_s=float(args.compile_timeout_seconds),
                    rlimit_cpu=int(args.rlimit_cpu_seconds),
                    rlimit_as_mib=int(args.rlimit_address_space_mib),
                    rlimit_stack_mib=int(args.rlimit_stack_mib),
                    cc=str(args.cxx or ""),
                    cflags=str(args.cxxflags),
                    ldflags=str(args.ldflags),
                    candidate_field=str(args.candidate_field),
                )
            else:
                setup = row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else ""
                code = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
                ok, msg = _pytest_smoke_subprocess(
                    setup_tests=setup,
                    test_code=code,
                    timeout_s=float(args.pytest_timeout_seconds),
                    rlimit_cpu=int(args.rlimit_cpu_seconds),
                    rlimit_as_mib=int(args.rlimit_address_space_mib),
                    rlimit_stack_mib=int(args.rlimit_stack_mib),
                )
            if not ok:
                mismatches.append({"kind": "pytest_smoke_failed", "error": msg})

        capped = mismatches[: int(args.max_mismatches_per_row)]
        kinds = [m.get("kind") for m in mismatches if isinstance(m, dict)]

        row_entry = {
            "row_index": row_index,
            "function_name": row.get("function_name"),
            "contract_mismatches_count": len(mismatches),
            "total_pytest_harness_invalid": sum(1 for k in kinds if k == "pytest_harness_invalid"),
            "total_pytest_smoke_failed": sum(1 for k in kinds if k == "pytest_smoke_failed"),
            "contract_mismatches": capped,
        }
        report_rows.append(row_entry)

        if len(mismatches) == 0:
            kept_rows.append(row)

        total_mismatches += len(mismatches)
        tqdm.write(f"Row {row_index}: mismatches={len(mismatches)}")

    summary = {
        "rows_checked": len(rows),
        "rows_kept": len(kept_rows),
        "rows_dropped": len(rows) - len(kept_rows),
        "total_contract_mismatches": total_mismatches,
        "rows_with_mismatches": sum(1 for r in report_rows if r["contract_mismatches_count"] > 0),
        "details": report_rows,
    }

    if args.filtered_jsonl is not None:
        args.filtered_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with args.filtered_jsonl.open("w", encoding="utf-8") as f:
            for r in kept_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Kept {len(kept_rows)}/{len(rows)} rows with zero mismatches in {args.filtered_jsonl}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
    else:
        print(
            f"rows_checked={summary['rows_checked']} "
            f"total_contract_mismatches={summary['total_contract_mismatches']} "
            f"rows_with_mismatches={summary['rows_with_mismatches']}"
        )


if __name__ == "__main__":
    main()
