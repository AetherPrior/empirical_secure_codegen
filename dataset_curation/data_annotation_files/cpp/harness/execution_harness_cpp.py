"""C++ execution harness for simple_gen rows using CWEval-style pytest harness.

Contract:
- Candidate is C++ source for a CLI program (``main`` parses argv).
- Row may provide ``setup_code`` prepended before the candidate is compiled.
- Row provides ``setup_tests`` (optional) and ``test_code`` (required): Python pytest snippets.
- Harness compiles the combined translation unit into ``compiled/<function_name>_task``
  and runs pytest with functionality/security markers.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple

from .pytest_harness_utils import extract_c_source_from_markdown, merge_cw_eval_pytest_single_file


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _pytest_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("pytest") is not None
    except Exception:
        return False


def _task_bin_name(function_name: str) -> str:
    fn = (function_name or "task").strip() or "task"
    return f"{fn}_task"


def _default_cxxflags(cwe: str = "") -> str:
    base = os.getenv(
        "SAFE_K_CXXFLAGS",
        "-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter -std=c++17",
    )
    if not cwe:
        return base
    try:
        cpp_dir = _repo_root() / "simple_gen" / "cpp"
        if str(cpp_dir) not in sys.path:
            sys.path.insert(0, str(cpp_dir))
        from cwe_rules import default_cxxflags_for_cwe  # type: ignore

        return default_cxxflags_for_cwe(cwe, base)
    except Exception:
        return base


def _default_ldflags(cwe: str = "") -> str:
    base = os.getenv("SAFE_K_LDFLAGS", "")
    if not cwe:
        return base
    try:
        cpp_dir = _repo_root() / "simple_gen" / "cpp"
        if str(cpp_dir) not in sys.path:
            sys.path.insert(0, str(cpp_dir))
        from cwe_rules import default_ldflags_for_cwe  # type: ignore

        return default_ldflags_for_cwe(cwe, base)
    except Exception:
        return base


def _compile_timeout_s() -> float:
    return float(os.getenv("SAFE_K_NATIVE_COMPILE_TIMEOUT_SECONDS", "60"))


def _pytest_timeout_s() -> float:
    for key in ("UNITTEST_TIMEOUT_SECONDS", "SAFE_K_PYTEST_TIMEOUT_SECONDS"):
        raw = os.getenv(key)
        if raw:
            try:
                return float(raw)
            except ValueError:
                pass
    return 60.0


def _resolve_cxx() -> str:
    cxx = (os.getenv("CXX") or "").strip() or (shutil.which("g++") or "")
    return cxx


def _combine_setup_and_candidate(setup_code: Any, candidate_cpp: str) -> str:
    setup = setup_code if isinstance(setup_code, str) else ""
    setup = setup.strip()
    body = candidate_cpp.strip()
    if setup and body:
        return setup.rstrip() + "\n\n" + body + "\n"
    if setup:
        return setup.rstrip() + "\n"
    return body + "\n"


def _compile_cpp_source(
    *,
    src: str,
    out_exe: Path,
    cxx: str,
    cxxflags: str,
    ldflags: str,
    cwd: Path,
    env: Dict[str, str],
    timeout_s: float,
) -> Tuple[bool, str]:
    src_path = cwd / "_candidate.cpp"
    src_path.write_text(src, encoding="utf-8")

    flags = cxxflags.split() if cxxflags.strip() else []
    ld = ldflags.split() if ldflags.strip() else []
    cmd = [cxx, *flags, str(src_path), "-o", str(out_exe), *ld]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"g++ timeout after {timeout_s}s"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, f"g++ failed: {err[:4000]}"
    return True, ""


def run_simple_gen_cpp_harness_unittest(candidate_cpp: str, row: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Compile candidate C++ CLI program + run pytest harness.

    Returns (summary_ok, {"functionality": (passed, total), "security": (passed, total), ...}).
    """
    if not isinstance(candidate_cpp, str) or not candidate_cpp.strip():
        return False, {"error": "empty candidate_cpp"}
    if not _pytest_available():
        return False, {"error": "pytest not available"}

    fn = str(row.get("function_name") or "task")
    setup_code = row.get("setup_code") if isinstance(row.get("setup_code"), str) else ""
    setup_tests = row.get("setup_tests") if isinstance(row.get("setup_tests"), str) else ""
    test_code = row.get("test_code") if isinstance(row.get("test_code"), str) else ""
    if not test_code.strip():
        return False, {"error": "missing test_code"}

    cxx = _resolve_cxx()
    if not cxx:
        return False, {"error": "no C++ compiler found (set CXX or install g++)"}

    compile_timeout = _compile_timeout_s()
    pytest_timeout = _pytest_timeout_s()
    cwe = str(row.get("cwe") or "")
    cxxflags = _default_cxxflags(cwe)
    ldflags = _default_ldflags(cwe)

    src = _combine_setup_and_candidate(setup_code, extract_c_source_from_markdown(candidate_cpp))

    try:
        c_dir = _repo_root() / "simple_gen" / "c"
        if str(c_dir) not in sys.path:
            sys.path.insert(0, str(c_dir))
        from native_deps import native_compile_env  # type: ignore

        env = native_compile_env(cwe)
    except Exception:
        env = os.environ.copy()

    with tempfile.TemporaryDirectory(prefix="simple_gen_cpp_pytest_") as td_s:
        td = Path(td_s)
        compiled = td / "compiled"
        compiled.mkdir(parents=True, exist_ok=True)
        task_bin = compiled / _task_bin_name(fn)

        ok, cerr = _compile_cpp_source(
            src=src,
            out_exe=task_bin,
            cxx=cxx,
            cxxflags=cxxflags,
            ldflags=ldflags,
            cwd=td,
            env=env,
            timeout_s=compile_timeout,
        )
        if not ok:
            return False, {"error": cerr}

        try:
            merged = merge_cw_eval_pytest_single_file(setup_tests, test_code)
        except ValueError as exc:
            return False, {"error": f"invalid pytest harness: {exc}"}

        test_path = td / "test_task.py"
        test_path.write_text(merged, encoding="utf-8")

        def _count_marker_tests(marker: str) -> int:
            cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", str(test_path), "-m", marker]
            try:
                proc = subprocess.run(cmd, cwd=str(td), capture_output=True, text=True, timeout=30, env=env)
            except Exception:
                return 0
            if proc.returncode not in (0, 5):
                return 0
            return sum(1 for line in (proc.stdout or "").splitlines() if "::" in line)

        def _run_marker(marker: str) -> tuple[int, int, str]:
            cmd = [sys.executable, "-m", "pytest", "-q", str(test_path), "-m", marker]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(td),
                    capture_output=True,
                    text=True,
                    timeout=pytest_timeout,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                return 0, 1, f"pytest timeout ({marker})"
            if proc.returncode == 5:
                return 0, 0, "no tests collected"
            total = _count_marker_tests(marker)
            if proc.returncode == 0:
                return total, total, ""
            return 0, total, (proc.stdout + "\n" + proc.stderr).strip()[:4000]

        fp, ft, ferr = _run_marker("functionality")
        sp, st, serr = _run_marker("security")
        summary_ok = ft > 0 and st > 0
        out: Dict[str, Any] = {
            "functionality": (fp, ft),
            "security": (sp, st),
        }
        if ferr:
            out["functionality_error"] = ferr
        if serr:
            out["security_error"] = serr
        return summary_ok, out
