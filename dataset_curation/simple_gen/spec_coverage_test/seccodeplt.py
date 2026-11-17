#!/usr/bin/env python3
"""
Compute statement and branch coverage for SecCodePLT dataset code variants.

This script uses the SeCode-Eval harness conventions:
- Per example, we combine `unittest.setup` + a selected `ground_truth.*` code variant.
- We execute the example's `unittest.testcases` to drive calls into the target function.

Coverage is collected with `coverage.py` in a subprocess to avoid global tracer issues.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
import re

from datasets import load_dataset
from tqdm import tqdm

try:
    import coverage
except Exception as exc:  # pragma: no cover
    raise RuntimeError("coverage package is required") from exc

from cwe_markers import CWE_python


def _pick_code(row: Dict[str, Any], variant: str) -> str:
    gt = row.get("ground_truth") or {}
    if not isinstance(gt, dict):
        gt = {}
    if variant not in {"vulnerable_code", "patched_code", "code_before", "code_after"}:
        raise ValueError(f"Unknown variant: {variant}")
    before = gt.get("code_before") or ""
    after = gt.get("code_after") or ""
    if not isinstance(before, str):
        before = str(before)
    if not isinstance(after, str):
        after = str(after)

    code = gt.get(variant) or ""
    if not isinstance(code, str):
        code = str(code)

    # Many rows store `patched_code` / `vulnerable_code` as *function body fragments*.
    # Reconstruct a complete definition if possible.
    if variant in {"patched_code", "vulnerable_code"}:
        return (before.rstrip() + "\n" + code.lstrip("\n") + "\n" + after.lstrip("\n")).rstrip() + "\n"

    # If the user asks for the prefix/suffix directly, return as-is.
    return code


def _build_runner_source(
    *, setup: str, testcases_src: str, func_name: str, category: str
) -> str:
    """
    A non-asserting driver that executes the dataset testcases.

    It tries kwargs first, then falls back to positional arg calling if the function
    rejects keyword arguments (mirrors SeCode-Eval behavior).
    """
    setup = setup or ""
    testcases_src = testcases_src or ""
    func_name = func_name or ""
    category = (category or "all").strip().lower()
    if category == "security":
        category = "safety"
    if category not in {"all", "capability", "safety"}:
        raise ValueError(f"unknown category={category!r}")

    # Build without leading indentation to avoid accidental IndentationError.
    src = "\n".join(
        [
            "import traceback",
            setup.rstrip(),
            "",
            "# testcases is defined by dataset snippet below",
            testcases_src.rstrip(),
            "",
            f"from impl import {func_name} as _target",
            f"_CATEGORY = {category!r}",
            "",
            "def _call(inputs):",
            "    try:",
            "        return _target(**inputs)",
            "    except TypeError as e:",
            "        if \"got an unexpected keyword argument\" in str(e):",
            "            return _target(*inputs.values())",
            "        raise",
            "",
            "def main():",
            "    tc = globals().get(\"testcases\")",
            "    if not isinstance(tc, dict):",
            "        raise ValueError(\"testcases not defined as a dict\")",
            "    items = tc.items()",
            "    if _CATEGORY != \"all\":",
            "        items = [(k, v) for k, v in tc.items() if k == _CATEGORY]",
            "    for _category, cases in items:",
            "        if not isinstance(cases, list):",
            "            continue",
            "        for pair in cases:",
            "            if not isinstance(pair, tuple) or len(pair) != 2:",
            "                continue",
            "            inputs, expected = pair",
            "            if not isinstance(inputs, dict):",
            "                continue",
            "            try:",
            "                if isinstance(expected, type) and issubclass(expected, Exception):",
            "                    try:",
            "                        _call(inputs)",
            "                    except expected:",
            "                        pass",
            "                    except Exception:",
            "                        pass",
            "                elif isinstance(expected, Exception):",
            "                    try:",
            "                        _call(inputs)",
            "                    except type(expected):",
            "                        pass",
            "                    except Exception:",
            "                        pass",
            "                else:",
            "                    try:",
            "                        _call(inputs)",
            "                    except Exception:",
            "                        pass",
            "            except Exception:",
            "                pass",
            "",
            "if __name__ == \"__main__\":",
            "    main()",
            "",
        ]
    )
    return src


def _coverage_for_row(
    *,
    row_index: int,
    row: Dict[str, Any],
    variant: str,
    python_exe: str,
    category: str,
) -> Dict[str, Any]:
    func_name = (row.get("task_description") or {}).get("function_name") or ""
    if not isinstance(func_name, str) or not func_name.strip():
        return {
            "index": row_index,
            "ok": False,
            "error": "missing function_name",
            "statement_coverage_pct": None,
            "branch_coverage_pct": None,
            "category": category,
        }

    setup = (row.get("unittest") or {}).get("setup") or ""
    testcases_src = (row.get("unittest") or {}).get("testcases") or ""
    if not isinstance(setup, str):
        setup = str(setup)
    if not isinstance(testcases_src, str):
        testcases_src = str(testcases_src)

    code = _pick_code(row, variant)
    if not code.strip():
        return {
            "index": row_index,
            "ok": False,
            "error": f"empty code for variant={variant}",
            "statement_coverage_pct": None,
            "branch_coverage_pct": None,
            "category": category,
        }

    with tempfile.TemporaryDirectory(prefix="seccodeplt_cov_") as td_s:
        td = Path(td_s)
        impl_path = td / "impl.py"
        runner_path = td / "runner.py"
        data_file = td / ".coverage_data"

        impl_path.write_text(code, encoding="utf-8")
        runner_path.write_text(
            _build_runner_source(
                setup=setup,
                testcases_src=testcases_src,
                func_name=func_name,
                category=category,
            ),
            encoding="utf-8",
        )

        env = os.environ.copy()
        # Ensure runner imports impl from the temp directory.
        env["PYTHONPATH"] = str(td) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

        cmd = [
            python_exe,
            "-m",
            "coverage",
            "run",
            "--branch",
            f"--data-file={data_file}",
            str(runner_path),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)
        except subprocess.TimeoutExpired:
            return {
                "index": row_index,
                "ok": False,
                "error": "timeout",
                "statement_coverage_pct": None,
                "branch_coverage_pct": None,
                "category": category,
            }

        if proc.returncode != 0:
            return {
                "index": row_index,
                "ok": False,
                "error": f"coverage-run failed (rc={proc.returncode})",
                "stderr": (proc.stderr or "")[:4000],
                "stdout": (proc.stdout or "")[:4000],
                "statement_coverage_pct": None,
                "branch_coverage_pct": None,
                "category": category,
            }

        cov = coverage.Coverage(data_file=str(data_file), branch=True)
        try:
            cov.load()
        except Exception as e:
            return {
                "index": row_index,
                "ok": False,
                "error": f"coverage load failed: {type(e).__name__}: {e}",
                "statement_coverage_pct": None,
                "branch_coverage_pct": None,
                "category": category,
            }

        try:
            _, statements, excluded, missing, _ = cov.analysis2(str(impl_path))
        except coverage.exceptions.NoDataError:
            return {
                "index": row_index,
                "ok": False,
                "error": "no coverage data collected",
                "statement_coverage_pct": None,
                "branch_coverage_pct": None,
                "category": category,
            }
        except Exception as e:
            return {
                "index": row_index,
                "ok": False,
                "error": f"coverage report failed: {type(e).__name__}: {e}",
                "statement_coverage_pct": None,
                "branch_coverage_pct": None,
                "category": category,
            }

        executable_statements = max(0, len(statements) - len(excluded))
        statement_pct: Optional[float]
        if executable_statements == 0:
            statement_pct = None
        else:
            statement_pct = 100.0 * (executable_statements - len(missing)) / executable_statements

        branch_stats = cov.branch_stats(str(impl_path))
        total_branches = 0
        taken_branches = 0
        for total_exits, taken_exits in branch_stats.values():
            if total_exits > 0:
                total_branches += total_exits
                taken_branches += taken_exits
        branch_pct = (100.0 * taken_branches / total_branches) if total_branches > 0 else None

        return {
            "index": row_index,
            "ok": True,
            "error": None,
            "statement_coverage_pct": statement_pct,
            "branch_coverage_pct": branch_pct,
            "category": category,
        }


def _normalize_cwe_token(x: Any) -> str:
    raw = str(x).strip().upper()
    if not raw:
        return ""
    match = re.search(r"(\d+)", raw)
    if match:
        return f"CWE-{match.group(1)}"
    return raw


def _extract_cwe_tokens(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for v in value:
            tok = _normalize_cwe_token(v)
            if tok:
                out.append(tok)
        return out
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
        return [_normalize_cwe_token(p) for p in parts if p.strip()]
    tok = _normalize_cwe_token(value)
    return [tok] if tok else []


def _choose_cwe_column(columns: List[str], preferred: str) -> Optional[str]:
    if preferred in columns:
        return preferred
    for c in ["CWE_ID", "cwe_id", "cwe", "CWE"]:
        if c in columns:
            return c
    return None


def _normalize_category(category: str) -> str:
    c = (category or "all").strip().lower()
    if c == "security":
        return "safety"
    return c


def _compile_marker_regexes(patterns: List[str]) -> List[re.Pattern[str]]:
    compiled: List[re.Pattern[str]] = []
    for p in patterns:
        compiled.append(re.compile(str(p)))
    return compiled


def _has_exception_signal(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if re.search(r"(Error|Exception)$", child.id):
                return True
        elif isinstance(child, ast.Attribute):
            if re.search(r"(Error|Exception)$", child.attr):
                return True
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            if re.search(r"\b(error|exception)\b", child.value, flags=re.IGNORECASE):
                return True
    return False


def _collect_spec_patterns_for_cwes(cwes: Sequence[str]) -> Tuple[List[str], bool, List[str]]:
    patterns: List[str] = []
    expect_reject = False
    missing_cfg: List[str] = []
    for cwe_id in sorted(set(cwes)):
        cfg = CWE_python.get(cwe_id)
        if not cfg:
            missing_cfg.append(cwe_id)
            continue
        for marker in (cfg.get("attack_markers") or []):
            patterns.append(str(marker))
        for behavior in (cfg.get("expected_behavior") or []):
            b = str(behavior).strip()
            b_upper = b.upper()
            if not b:
                continue
            if b_upper == "SANITIZE":
                continue
            if b_upper == "REJECT":
                expect_reject = True
                continue
            patterns.append(b)
    return patterns, expect_reject, missing_cfg


def _find_testcases_expr(mod: ast.Module) -> Optional[ast.AST]:
    for node in mod.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "testcases":
                    return node.value
    return None


def _resolve_expr(expr: ast.AST, env: Dict[str, ast.AST], depth: int = 0) -> Optional[ast.AST]:
    if depth > 12:
        return None
    if isinstance(expr, ast.Name) and expr.id in env:
        return _resolve_expr(env[expr.id], env, depth + 1)
    return expr


def _resolve_list_expr(expr: ast.AST, env: Dict[str, ast.AST], depth: int = 0) -> Optional[List[ast.AST]]:
    if depth > 12:
        return None
    expr = _resolve_expr(expr, env, depth) or expr
    if isinstance(expr, ast.List):
        return list(expr.elts)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _resolve_list_expr(expr.left, env, depth + 1)
        right = _resolve_list_expr(expr.right, env, depth + 1)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "list" and len(expr.args) == 1:
        return _resolve_list_expr(expr.args[0], env, depth + 1)
    return None


def _security_spec_presence_fraction_for_row(testcases_src: str, cwe_ids: Sequence[str]) -> Tuple[Optional[float], str]:
    cwes = [c for c in cwe_ids if isinstance(c, str) and c.strip()]
    if not cwes:
        return None, "missing cwe list"

    patterns, expect_reject, missing_cfg = _collect_spec_patterns_for_cwes(cwes)

    if not patterns:
        if missing_cfg:
            return None, f"no marker config for cwes: {', '.join(missing_cfg)}"
        if expect_reject:
            # REJECT-only specs are valid; we'll use exception/error signals only.
            pass
        else:
            return None, "no spec patterns available"

    regexes: List[re.Pattern[str]] = []
    if patterns:
        try:
            regexes = _compile_marker_regexes(patterns)
        except re.error as e:
            return None, f"invalid spec regex: {e}"

    try:
        mod = ast.parse(testcases_src or "")
    except SyntaxError as e:
        return None, f"invalid testcase syntax: {e}"

    env: Dict[str, ast.AST] = {}
    for node in mod.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            env[node.targets[0].id] = node.value

    tc_expr = _find_testcases_expr(mod)
    if tc_expr is None:
        return None, "testcases assignment not found"
    tc_expr = _resolve_expr(tc_expr, env) or tc_expr
    if not isinstance(tc_expr, ast.Dict):
        return None, "testcases is not a dict literal"

    safety_expr: Optional[ast.AST] = None
    for k, v in zip(tc_expr.keys, tc_expr.values):
        if isinstance(k, ast.Constant) and k.value in {"safety", "security"}:
            safety_expr = v
            break
    if safety_expr is None:
        return None, "no safety/security testcases"

    cases = _resolve_list_expr(safety_expr, env)
    if cases is None:
        return None, "safety/security cases are not a resolvable list"
    if not cases:
        return None, "no safety/security cases"

    total = 0
    hits = 0
    for node in cases:
        total += 1
        svals: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                svals.append(child.value)
        has_pattern_hit = any(rx.search(s) for s in svals for rx in regexes) if regexes else False
        has_reject_signal = expect_reject and _has_exception_signal(node)
        if has_pattern_hit or has_reject_signal:
            hits += 1
    if total == 0:
        return None, "no safety/security cases"
    return hits / total, ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Statement + branch coverage on anonymous/SecCodePLT")
    parser.add_argument("--dataset", default="anonymous/SecCodePLT")
    parser.add_argument("--split", default="insecure_coding")
    parser.add_argument(
        "--variant",
        default="patched_code",
        choices=["vulnerable_code", "patched_code", "code_before", "code_after"],
        help="Which ground_truth code field to measure.",
    )
    parser.add_argument("--min-index", type=int, default=0)
    parser.add_argument("--max-index", type=int, default=10_000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--category",
        default="capability",
        choices=["capability", "safety", "security", "all", "split"],
        help="Which testcase category to drive coverage with: capability, safety/security, all, or split (default: capability).",
    )
    parser.add_argument(
        "--cwe-column",
        default="CWE_ID",
        help="Dataset column name for CWE filtering (default: CWE_ID).",
    )
    parser.add_argument(
        "--cwes",
        nargs="*",
        default=None,
        help="Optional CWE filter values (e.g. 79, CWE-79, 22). Uses --cwe-column if present.",
    )
    parser.add_argument(
        "--output-jsonl",
        default="seccodeplt_branch_coverage.jsonl",
        help="Write per-example results JSONL (path).",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable to run coverage in (default: current).",
    )
    args = parser.parse_args()

    ds = load_dataset(args.dataset, split=args.split)
    # Match SeCode-Eval filtering.
    if "use_rule" in ds.column_names:
        ds = ds.filter(lambda x: x["use_rule"] is False)

    base_indices = [i for i in range(len(ds)) if args.min_index <= i < args.max_index]
    cwe_column = _choose_cwe_column(list(ds.column_names), args.cwe_column)

    cwe_allow: Optional[set[str]] = None
    if args.cwes:
        cwe_allow = {_normalize_cwe_token(c) for c in args.cwes if str(c).strip()}

    if cwe_allow and cwe_column is None:
        print(
            f"warning: no CWE column found (requested={args.cwe_column!r}); "
            "skipping CWE filter"
        )

    if cwe_allow and cwe_column is not None:
        indices: List[int] = []
        for i in base_indices:
            row = dict(ds[i])
            row_cwes = _extract_cwe_tokens(row.get(cwe_column))
            if any(c in cwe_allow for c in row_cwes):
                indices.append(i)
    else:
        indices = base_indices

    out_path = Path(args.output_jsonl)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []

    run_mode = _normalize_category(args.category)
    if run_mode not in {"capability", "safety", "all", "split"}:
        raise ValueError(f"Unknown category mode: {args.category}")

    def _job(i: int) -> Dict[str, Any]:
        row = dict(ds[i])
        cwe_val = None
        cwe_tokens: List[str] = []
        if cwe_column is not None:
            cwe_tokens = _extract_cwe_tokens(row.get(cwe_column))
            if cwe_tokens:
                cwe_val = ",".join(cwe_tokens)

        marker_cwes: List[str] = cwe_tokens if cwe_tokens else (sorted(cwe_allow) if cwe_allow else [])

        if run_mode != "split":
            rec = _coverage_for_row(
                row_index=i,
                row=row,
                variant=args.variant,
                python_exe=args.python,
                category=run_mode,
            )
            rec["cwe_id"] = cwe_val
            spec_frac, spec_err = _security_spec_presence_fraction_for_row(
                (row.get("unittest") or {}).get("testcases") or "",
                marker_cwes,
            )
            rec["security_spec_presence_fraction"] = spec_frac
            rec["security_spec_presence_error"] = spec_err if spec_frac is None else None
            if run_mode == "safety":
                rec["security_statement_coverage_pct"] = rec.get("statement_coverage_pct")
                rec["security_branch_coverage_pct"] = rec.get("branch_coverage_pct")
            return rec

        cap = _coverage_for_row(
            row_index=i,
            row=row,
            variant=args.variant,
            python_exe=args.python,
            category="capability",
        )
        sec = _coverage_for_row(
            row_index=i,
            row=row,
            variant=args.variant,
            python_exe=args.python,
            category="safety",
        )
        spec_frac, spec_err = _security_spec_presence_fraction_for_row(
            (row.get("unittest") or {}).get("testcases") or "",
            marker_cwes,
        )
        return {
            "index": i,
            "ok": bool(cap.get("ok")) and bool(sec.get("ok")),
            "capability_ok": bool(cap.get("ok")),
            "security_ok": bool(sec.get("ok")),
            "capability_error": cap.get("error"),
            "security_error": sec.get("error"),
            "capability_statement_coverage_pct": cap.get("statement_coverage_pct"),
            "capability_branch_coverage_pct": cap.get("branch_coverage_pct"),
            "security_statement_coverage_pct": sec.get("statement_coverage_pct"),
            "security_branch_coverage_pct": sec.get("branch_coverage_pct"),
            "security_spec_presence_fraction": spec_frac,
            "security_spec_presence_error": spec_err if spec_frac is None else None,
            "cwe_id": cwe_val,
            "category": "split",
        }

    if args.workers <= 1:
        for i in tqdm(indices, desc="coverage"):
            rec = _job(i)
            results.append(rec)
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = {ex.submit(_job, i): i for i in indices}
            for fut in tqdm(as_completed(futs), total=len(futs), desc="coverage"):
                results.append(fut.result())
        results.sort(key=lambda r: r["index"])

    if run_mode == "split":
        cap_stmt_ok = [r for r in results if r.get("capability_ok") and r.get("capability_statement_coverage_pct") is not None]
        cap_ok = [r for r in results if r.get("capability_ok") and r.get("capability_branch_coverage_pct") is not None]
        cap_none = [r for r in results if r.get("capability_ok") and r.get("capability_branch_coverage_pct") is None]
        sec_stmt_ok = [r for r in results if r.get("security_ok") and r.get("security_statement_coverage_pct") is not None]
        sec_ok = [r for r in results if r.get("security_ok") and r.get("security_branch_coverage_pct") is not None]
        sec_none = [r for r in results if r.get("security_ok") and r.get("security_branch_coverage_pct") is None]
        spec_ok = [r for r in results if r.get("security_spec_presence_fraction") is not None]
        avg_cap_stmt = (
            sum(float(r["capability_statement_coverage_pct"]) for r in cap_stmt_ok) / len(cap_stmt_ok)
            if cap_stmt_ok
            else float("nan")
        )
        avg_cap = (
            sum(float(r["capability_branch_coverage_pct"]) for r in cap_ok) / len(cap_ok)
            if cap_ok
            else float("nan")
        )
        avg_sec_stmt = (
            sum(float(r["security_statement_coverage_pct"]) for r in sec_stmt_ok) / len(sec_stmt_ok)
            if sec_stmt_ok
            else float("nan")
        )
        avg_sec = (
            sum(float(r["security_branch_coverage_pct"]) for r in sec_ok) / len(sec_ok)
            if sec_ok
            else float("nan")
        )
        cap_alt_den = len(cap_ok) + len(cap_none)
        avg_cap_alt_none_as_100 = (
            (sum(float(r["capability_branch_coverage_pct"]) for r in cap_ok) + 100.0 * len(cap_none))
            / cap_alt_den
            if cap_alt_den > 0
            else float("nan")
        )
        sec_alt_den = len(sec_ok) + len(sec_none)
        avg_sec_alt_none_as_100 = (
            (sum(float(r["security_branch_coverage_pct"]) for r in sec_ok) + 100.0 * len(sec_none))
            / sec_alt_den
            if sec_alt_den > 0
            else float("nan")
        )
        avg_spec = (
            sum(float(r["security_spec_presence_fraction"]) for r in spec_ok) / len(spec_ok)
            if spec_ok
            else float("nan")
        )
    else:
        ok_stmt = [r for r in results if r.get("ok") and r.get("statement_coverage_pct") is not None]
        ok = [r for r in results if r.get("ok") and r.get("branch_coverage_pct") is not None]
        ok_none = [r for r in results if r.get("ok") and r.get("branch_coverage_pct") is None]
        spec_ok = [r for r in results if r.get("security_spec_presence_fraction") is not None]
        avg_stmt = sum(float(r["statement_coverage_pct"]) for r in ok_stmt) / len(ok_stmt) if ok_stmt else float("nan")
        avg = sum(float(r["branch_coverage_pct"]) for r in ok) / len(ok) if ok else float("nan")
        alt_den = len(ok) + len(ok_none)
        avg_alt_none_as_100 = (
            (sum(float(r["branch_coverage_pct"]) for r in ok) + 100.0 * len(ok_none)) / alt_den
            if alt_den > 0
            else float("nan")
        )
        avg_spec = (
            sum(float(r["security_spec_presence_fraction"]) for r in spec_ok) / len(spec_ok)
            if spec_ok
            else float("nan")
        )

    with out_path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if run_mode == "split":
        print(
            f"variant={args.variant} mode=split examples={len(results)} "
            f"capability_ok={len(cap_ok)} avg_capability_statement_coverage={avg_cap_stmt:.4f} "
            f"avg_capability_branch_coverage={avg_cap:.4f} "
            f"avg_capability_branch_coverage_none_as_100={avg_cap_alt_none_as_100:.4f} "
            f"security_ok={len(sec_ok)} avg_security_statement_coverage={avg_sec_stmt:.4f} "
            f"avg_security_branch_coverage={avg_sec:.4f} "
            f"avg_security_branch_coverage_none_as_100={avg_sec_alt_none_as_100:.4f} "
            f"avg_security_spec_presence={avg_spec:.4f}"
        )
    else:
        stmt_label = "avg_security_statement_coverage" if run_mode == "safety" else "avg_statement_coverage"
        branch_label = "avg_security_branch_coverage" if run_mode == "safety" else "avg_branch_coverage"
        branch_alt_label = (
            "avg_security_branch_coverage_none_as_100"
            if run_mode == "safety"
            else "avg_branch_coverage_none_as_100"
        )
        print(
            f"variant={args.variant} mode={run_mode} examples={len(results)} "
            f"ok_statement={len(ok_stmt)} {stmt_label}={avg_stmt:.4f} "
            f"ok_branch={len(ok)} {branch_label}={avg:.4f} "
            f"{branch_alt_label}={avg_alt_none_as_100:.4f} "
            f"avg_security_spec_presence={avg_spec:.4f}"
        )
    if cwe_allow:
        print(f"cwe_filter_column={cwe_column} cwes={','.join(sorted(cwe_allow))}")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()

