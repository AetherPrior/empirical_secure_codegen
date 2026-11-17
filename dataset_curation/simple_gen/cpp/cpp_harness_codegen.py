"""Shared C++ type mapping and tests_json harness code generation."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

_CPP_TYPE_MAP: dict[str, str] = {
    "int": "int",
    "long": "long",
    "long long": "long long",
    "double": "double",
    "float": "float",
    "bool": "bool",
    "size_t": "size_t",
    "char*": "const char*",
    "const char*": "const char*",
    "string": "const char*",
    "std::string": "const char*",
}


def extract_param_names(row: Dict[str, Any]) -> List[str]:
    args = row.get("arguments") or []
    out: List[str] = []
    for a in args:
        if isinstance(a, dict):
            name = a.get("name")
            if isinstance(name, str) and name.strip():
                out.append(name.strip())
    return out


def normalize_cpp_type(t: Any) -> str:
    s = str(t or "").strip()
    return " ".join(s.split())


def cpp_type_for(arg_type: Any) -> str:
    t = normalize_cpp_type(arg_type).lower()
    if t in _CPP_TYPE_MAP:
        return _CPP_TYPE_MAP[t]
    if t in {"uint32_t", "uint64_t", "int32_t", "int64_t"}:
        return t
    return ""


def ret_type_for_row(row: Dict[str, Any]) -> str:
    ret_raw = row.get("return")
    ret_type = "int"
    if isinstance(ret_raw, str):
        low = ret_raw.lower()
        for k, v in _CPP_TYPE_MAP.items():
            if k in low:
                ret_type = v
                break
    elif isinstance(ret_raw, dict):
        t = cpp_type_for(ret_raw.get("type"))
        if t:
            ret_type = t
    return ret_type


def cpp_literal_for_value(value: Any, *, cpp_type: str) -> str:
    if cpp_type in {"int", "long", "long long", "size_t", "uint32_t", "uint64_t", "int32_t", "int64_t"}:
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, (int, float)):
            return str(int(value))
        return "0"
    if cpp_type in {"double", "float"}:
        if isinstance(value, bool):
            return "1.0" if value else "0.0"
        if isinstance(value, (int, float)):
            return f"{float(value)}"
        return "0.0"
    if cpp_type == "bool":
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return "true" if bool(value) else "false"
        if isinstance(value, str):
            return "true" if value.strip().lower() in {"1", "true", "yes", "y"} else "false"
        return "false"
    if cpp_type == "const char*":
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f"\"{escaped}\""
        return "\"\""
    return "0"


def function_signature_parts(row: Dict[str, Any]) -> Tuple[str, List[str], List[str], List[str]]:
    """Return (ret_type, param_decls, param_names, cpp_types)."""
    fn = row.get("function_name")
    if not isinstance(fn, str) or not fn.strip():
        raise ValueError("missing function_name")
    fn = fn.strip()

    args = row.get("arguments") or []
    if not isinstance(args, list):
        raise ValueError("row.arguments must be a list")

    param_decls: List[str] = []
    param_names: List[str] = []
    cpp_types: List[str] = []
    for a in args:
        if not isinstance(a, dict):
            continue
        name = a.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        cpp_t = cpp_type_for(a.get("type"))
        if not cpp_t:
            raise ValueError(f"unsupported C++ type for argument {name!r}: {a.get('type')!r}")
        param_names.append(name.strip())
        cpp_types.append(cpp_t)
        param_decls.append(f"{cpp_t} {name.strip()}")

    ret_type = ret_type_for_row(row)
    return ret_type, param_decls, param_names, cpp_types


def _compare_stmt(*, ret_type: str, actual_expr: str, expected_literal: str) -> str:
    if ret_type == "const char*":
        return (
            f"if (std::strcmp({actual_expr}, {expected_literal}) != 0) "
            f'{{ std::fprintf(stderr, "string mismatch\\n"); return 1; }}'
        )
    if ret_type in {"double", "float"}:
        return (
            f"if (std::fabs(static_cast<double>({actual_expr}) - static_cast<double>({expected_literal})) > 1e-9) "
            f'{{ std::fprintf(stderr, "float mismatch\\n"); return 1; }}'
        )
    return (
        f"if (!({actual_expr} == {expected_literal})) "
        f'{{ std::fprintf(stderr, "value mismatch\\n"); return 1; }}'
    )


def build_harness_runner_cpp(
    row: Dict[str, Any],
    *,
    categories: Tuple[str, ...] = ("functionality", "security"),
) -> str:
    """Generate a ``main()`` that runs ``tests_json`` cases against ``function_name``."""
    fn = row.get("function_name")
    if not isinstance(fn, str) or not fn.strip():
        raise ValueError("missing function_name")
    fn = fn.strip()

    tests_obj = row.get("tests_json")
    if not isinstance(tests_obj, dict):
        raise ValueError("missing tests_json")

    ret_type, param_decls, param_names, cpp_types = function_signature_parts(row)
    sig = f"{ret_type} {fn}({', '.join(param_decls)})"

    tests = tests_obj.get("tests")
    if not isinstance(tests, dict):
        raise ValueError("tests_json.tests missing")

    blocks: List[str] = []
    for section in categories:
        cases = tests.get(section)
        if not isinstance(cases, list):
            continue
        for idx, case in enumerate(cases):
            if not isinstance(case, dict):
                continue
            inp = case.get("input")
            if not isinstance(inp, dict):
                continue
            call_args: List[str] = []
            for name, cpp_t in zip(param_names, cpp_types):
                call_args.append(cpp_literal_for_value(inp.get(name), cpp_type=cpp_t))
            expected = cpp_literal_for_value(case.get("output"), cpp_type=ret_type)
            actual = f"{fn}({', '.join(call_args)})"
            blocks.append(
                f"  // {section}[{idx}]\n"
                f"  {{\n"
                f"    auto _actual = {actual};\n"
                f"    { _compare_stmt(ret_type=ret_type, actual_expr='_actual', expected_literal=expected) }\n"
                f"  }}"
            )

    if not blocks:
        raise ValueError("no runnable test cases in tests_json")

    body = "\n".join(blocks)
    return (
        "#include <cmath>\n"
        "#include <cstdio>\n"
        "#include <cstring>\n"
        "#include <cstddef>\n"
        "#include <cstdint>\n"
        "#include <string>\n"
        "\n"
        f"extern {sig};\n"
        "\n"
        "int main() {\n"
        f"{body}\n"
        "  return 0;\n"
        "}\n"
    )


def run_tests_json_harness(
    row: Dict[str, Any],
    candidate_cpp: str,
    *,
    cxx: str,
    compile_timeout_s: float,
    run_timeout_s: float,
    cxxflags: str,
    categories: Tuple[str, ...] = ("functionality", "security"),
) -> Tuple[bool, str]:
    """Compile candidate + generated runner; return (passed, error_message)."""
    if not candidate_cpp.strip():
        return False, "empty candidate_cpp"

    try:
        runner = build_harness_runner_cpp(row, categories=categories)
    except Exception as e:
        return False, f"harness codegen: {type(e).__name__}: {e}"

    flags = cxxflags.split() if cxxflags.strip() else []
    with tempfile.TemporaryDirectory(prefix="cpp_tests_json_") as td_s:
        td = Path(td_s)
        solution = td / "solution.cpp"
        runner_path = td / "runner.cpp"
        solution.write_text(candidate_cpp.strip() + "\n", encoding="utf-8")
        runner_path.write_text(runner, encoding="utf-8")
        out_exe = td / "harness.out"
        cmd = [cxx, "-std=c++17", *flags, str(solution), str(runner_path), "-o", str(out_exe)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=compile_timeout_s)
        except subprocess.TimeoutExpired:
            return False, f"compile timeout after {compile_timeout_s}s"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return False, f"compile failed: {err[:4000]}"

        try:
            run = subprocess.run([str(out_exe)], capture_output=True, text=True, timeout=run_timeout_s, cwd=str(td))
        except subprocess.TimeoutExpired:
            return False, f"run timeout after {run_timeout_s}s"
        if run.returncode != 0:
            err = (run.stderr or run.stdout or "").strip()
            return False, f"harness failed: exit {run.returncode}: {err[:4000]}"
    return True, ""
