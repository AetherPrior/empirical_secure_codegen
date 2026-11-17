"""Validation helpers for C++ simple_gen pytest harnesses (structure + execution).

C++ GRPO rows use Python ``setup_tests`` + ``test_code`` that compile and run a C++
CLI via ``exec_cmd([TASK_BIN, ...])``. This module provides:

1. Static pytest structure checks (mark counts, ``exec_cmd``, ``TASK_BIN``).
2. Optional compile + pytest execution via local ``harness/execution_harness_cpp``.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable

_ANNOTATION_CPP_DIR = Path(__file__).resolve().parent
_SECURITY_TEST_CASE_ROOT = _ANNOTATION_CPP_DIR.parents[1]
_SIMPLE_GEN_CPP_DIR = _SECURITY_TEST_CASE_ROOT / "simple_gen" / "cpp"


def parse_blocks(setup_code: str, test_code: str) -> tuple[ast.Module, ast.Module]:
    try:
        setup_ast = ast.parse(setup_code or "")
        test_ast = ast.parse(test_code or "")
    except SyntaxError as e:
        raise ValueError(f"invalid python syntax: {e}") from e
    return setup_ast, test_ast


def _attr_chain(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_chain(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def _is_pytest_mark(node: ast.AST, mark: str) -> bool:
    chain = _attr_chain(node)
    return chain in {f"pytest.mark.{mark}", f"mark.{mark}"}


def _marks_from_pytest_param(call: ast.Call) -> list[str]:
    found: list[str] = []
    for kw in call.keywords:
        if kw.arg != "marks":
            continue
        nodes: Iterable[ast.AST]
        if isinstance(kw.value, (ast.Tuple, ast.List)):
            nodes = kw.value.elts
        else:
            nodes = [kw.value]
        for item in nodes:
            if _is_pytest_mark(item, "functionality"):
                found.append("functionality")
            elif _is_pytest_mark(item, "security"):
                found.append("security")
    return found


def count_pytest_mark_cases(module: ast.Module, mark: str) -> int:
    """Count parametrized cases (``pytest.param(..., marks=...)``) for a mark."""
    total = 0
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "param":
            base = _attr_chain(fn.value)
            if base in {"pytest", "pytest.param"}:
                if mark in _marks_from_pytest_param(node):
                    total += 1
        elif isinstance(fn, ast.Name) and fn.id == "param":
            if mark in _marks_from_pytest_param(node):
                total += 1
    return total


def _function_has_mark(decorators: list[ast.expr], mark: str) -> bool:
    for dec in decorators:
        if _is_pytest_mark(dec, mark):
            return True
        if isinstance(dec, ast.Call) and _is_pytest_mark(dec.func, mark):
            return True
    return False


def count_pytest_mark_functions(module: ast.Module, mark: str) -> int:
    """Count test functions decorated with ``@pytest.mark.<mark>``."""
    total = 0
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _function_has_mark(node.decorator_list, mark):
                total += 1
    return total


def count_marked_cases(module: ast.Module, mark: str) -> int:
    """Total functionality or security cases (param cases + decorated functions)."""
    return count_pytest_mark_cases(module, mark) + count_pytest_mark_functions(module, mark)


def _defines_name(module: ast.Module, name: str) -> bool:
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return True
    return False


def _uses_task_bin(module: ast.Module) -> bool:
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and node.id == "TASK_BIN":
            return True
    return False


def validate_cpp_harness_structure(setup_tests: str, test_code: str, *, min_per_mark: int = 2) -> None:
    """Validate pytest harness shape for C++ GRPO rows (AST only)."""
    setup_ast, test_ast = parse_blocks(setup_tests, test_code)

    for mark in ("functionality", "security"):
        n = count_marked_cases(test_ast, mark)
        if n < min_per_mark:
            raise ValueError(f"test_code must have >= {min_per_mark} {mark} cases (found {n})")

    if setup_tests.strip():
        if not _defines_name(setup_ast, "exec_cmd"):
            raise ValueError("setup_tests must define exec_cmd(cmd) -> (rc, stdout, stderr)")

    if not _uses_task_bin(test_ast):
        raise ValueError("test_code must invoke TASK_BIN via exec_cmd([TASK_BIN, ...])")


def validate_cpp_harness(setup_tests: str, test_code: str, *, min_per_mark: int = 2) -> None:
    """Backward-compatible alias for structure-only validation."""
    validate_cpp_harness_structure(setup_tests, test_code, min_per_mark=min_per_mark)


def _normalize_cwe(cwe: str) -> str:
    import re

    raw = (cwe or "").strip().upper()
    if raw.startswith("CWE-"):
        return raw
    m = re.search(r"(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else raw


def import_run_cpp_harness() -> Callable[[str, dict[str, Any]], tuple[bool, dict[str, Any]]]:
    """Load ``run_simple_gen_cpp_harness_unittest`` from the local harness package."""
    from harness.execution_harness_cpp import run_simple_gen_cpp_harness_unittest

    return run_simple_gen_cpp_harness_unittest


@contextmanager
def _temporary_env(updates: dict[str, str | None]):
    old: dict[str, str | None] = {}
    for key, val in updates.items():
        old[key] = os.environ.get(key)
        if val is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = val
    try:
        yield
    finally:
        for key, val in old.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val


@contextmanager
def cwe_compile_env(cwe: str, *, base_cxxflags: str = "", base_ldflags: str = ""):
    """Apply CWE-aware compiler flags and native dep paths (libjwt, openssl, …)."""
    cwe_norm = _normalize_cwe(cwe)
    updates: dict[str, str | None] = {}
    if str(_SIMPLE_GEN_CPP_DIR) not in sys.path:
        sys.path.insert(0, str(_SIMPLE_GEN_CPP_DIR))
    try:
        from cwe_rules import default_cxxflags_for_cwe, default_ldflags_for_cwe

        c_dir = _SECURITY_TEST_CASE_ROOT / "simple_gen" / "c"
        if str(c_dir) not in sys.path:
            sys.path.insert(0, str(c_dir))
        from native_deps import native_compile_env

        default_base = "-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter -std=c++17"
        updates["SAFE_K_CXXFLAGS"] = default_cxxflags_for_cwe(cwe_norm, base_cxxflags or default_base)
        updates["SAFE_K_LDFLAGS"] = default_ldflags_for_cwe(cwe_norm, base_ldflags)
        for key, val in native_compile_env(cwe_norm).items():
            updates[key] = val
    except Exception:
        pass
    with _temporary_env(updates):
        yield


def harness_ground_row(task: dict[str, Any], *, test_code: str | None = None) -> dict[str, Any]:
    """Minimal row for ``run_simple_gen_cpp_harness_unittest``."""
    tc = test_code if test_code is not None else str(task.get("test_code") or "")
    return {
        "function_name": task.get("function_name"),
        "test_code": tc,
        "setup_tests": task.get("setup_tests") if isinstance(task.get("setup_tests"), str) else "",
        "setup_code": task.get("setup_code") if isinstance(task.get("setup_code"), str) else "",
        "cwe": task.get("cwe") if isinstance(task.get("cwe"), str) else "",
    }


def harness_fully_passes(summary_ok: bool, ut_result: dict[str, Any]) -> bool:
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


def evaluate_cpp_harness(
    candidate_cpp: str,
    task: dict[str, Any],
    *,
    test_code: str,
    run_unittest: Callable[[str, dict[str, Any]], tuple[bool, dict[str, Any]]] | None = None,
) -> tuple[bool, dict[str, Any], str]:
    """Compile ``candidate_cpp`` and run pytest harness; returns (passed, ut_result, error_msg)."""
    code = (candidate_cpp or "").strip()
    if not code:
        return False, {}, "empty candidate_cpp"

    validate_cpp_harness_structure(str(task.get("setup_tests") or ""), test_code)

    if os.getenv("CPP_ANNOTATION_SKIP_HARNESS", "").strip().lower() in {"1", "true", "yes"}:
        return True, {}, ""

    runner = run_unittest or import_run_cpp_harness()
    cwe = str(task.get("cwe") or "")
    with cwe_compile_env(cwe):
        ok, ut_result = runner(code, harness_ground_row(task, test_code=test_code))

    passed = harness_fully_passes(ok, ut_result)
    if passed:
        return True, ut_result, ""
    detail = json.dumps(ut_result, ensure_ascii=False) if ut_result else "harness execution failed"
    return False, ut_result, detail[:4000]
