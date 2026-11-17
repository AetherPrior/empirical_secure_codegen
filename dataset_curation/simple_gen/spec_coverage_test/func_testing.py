#!/usr/bin/env python3
"""Evaluate filtered JSONL tasks: CWE markers on security tests; branch coverage split by test category."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import multiprocessing as mp
import os
import re
import shutil
import sys
import tempfile
import textwrap
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Tuple

# simple_gen/ (parent of spec_coverage_test/)
_SIMPLE_GEN = Path(__file__).resolve().parent.parent
if str(_SIMPLE_GEN) not in sys.path:
    sys.path.insert(0, str(_SIMPLE_GEN))

from utils import read_jsonl

from spec_coverage_test.cwe_markers import CWE_python

try:
    import coverage
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "The coverage package is required (e.g. conda env vulnscan)."
    ) from exc

try:
    from openai import OpenAI
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("openai package required") from exc

from const_cwe_id_desc import DEFAULT_OPENAI_BASE_URL

from tqdm import tqdm

CODE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

# coverage.py uses global tracing machinery and isn't safe to start/stop concurrently
# across threads. We keep LLM sampling parallel but serialize coverage measurement.
_COVERAGE_LOCK = threading.Lock()
_CACHE_WRITE_LOCK = threading.Lock()


class _Chdir:
    def __init__(self, path: Path):
        self._path = path
        self._old: Optional[str] = None

    def __enter__(self) -> None:
        self._old = os.getcwd()
        os.chdir(self._path)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._old is not None:
            os.chdir(self._old)


def _completion_cache_key(
    *,
    model: str,
    row: Dict[str, Any],
    max_output_tokens: int,
    temperature: float,
    sample_index: int,
) -> str:
    """Stable SHA-256 hex digest for cache filename."""
    prompt = build_generation_prompt(row)
    payload = {
        "model": model,
        "max_output_tokens": max_output_tokens,
        "temperature": temperature,
        "sample_index": sample_index,
        "prompt": prompt,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _read_completion_cache(path: Path) -> Optional[Dict[str, Any]]:
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


def _expects_exception_value(expected: Any) -> bool:
    """Match ``validate_testcases.expects_exception_value`` for harness ``output`` fields."""
    return expected is Exception or str(expected).lower() == "exception"


def _functionality_case_passes(
    func: Any, inp: Dict[str, Any], expected: Any
) -> Tuple[bool, str]:
    """Allow expected-exception cases; otherwise require no runtime error.

    For functionality coverage, we do **not** require correct return values; we only
    require that the implementation loads and that calling the function doesn't raise
    unexpectedly. If a case expects an exception, then either raising or returning is OK.
    """
    try:
        func(**inp)
    except BaseException as e:
        if _expects_exception_value(expected):
            return True, ""
        return False, f"unexpected exception: {type(e).__name__}: {e}"

    return True, ""


def _exec_fragment(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    if isinstance(x, str):
        return x
    return str(x)


def extract_code_block(text: str) -> str:
    m = CODE_BLOCK_RE.search(text or "")
    if m:
        return m.group(1).strip()
    return (text or "").strip()


def build_generation_prompt(row: Dict[str, Any]) -> str:
    return textwrap.dedent(
        f"""
        Write Python code in exactly one triple-backticked python block.

        Task:
        {row.get("prompt", "")}

        Required function name:
        {row.get("function_name", "")}

        Test setup code:
        ```python
        {row.get("setup_tests", "")}
        ```

        Test cases:
        ```python
        {row.get("test_code", "")}
        ```

        Constraints:
        - Return only code, no explanation.
        - Implement only what is needed for correctness and safety.
        """
    ).strip()


def security_spec_presence_fraction(
    row: Dict[str, Any], cwe_id: str
) -> Tuple[Optional[float], str]:
    """Fraction of security cases with at least one matched security spec signal.

    Spec signals are:
    - any CWE attack marker regex,
    - any expected_behavior regex except SANITIZE,
    - REJECT semantics mapped to exception/error indicators.
    """
    cfg = CWE_python.get(cwe_id)
    if not cfg:
        return None, f"no marker config for {cwe_id!r}"
    patterns: List[str] = [str(x) for x in (cfg.get("attack_markers") or [])]
    expect_reject = False
    for b in (cfg.get("expected_behavior") or []):
        bs = str(b).strip()
        bu = bs.upper()
        if not bs:
            continue
        if bu == "SANITIZE":
            continue
        if bu == "REJECT":
            expect_reject = True
            continue
        patterns.append(bs)

    frac, err = _security_spec_presence_fraction_from_ast(
        row.get("test_code"), patterns, expect_reject
    )
    if frac is not None:
        return frac, ""
    return None, err


def _parse_test_code_ast(test_code: Any) -> Tuple[Optional[ast.Module], str]:
    src = _exec_fragment(test_code).strip()
    if not src:
        return None, "empty test_code"
    try:
        return ast.parse(src), ""
    except SyntaxError as e:
        return None, f"invalid python syntax in test_code: {e}"


def _collect_simple_bindings(mod: ast.Module) -> Dict[str, ast.AST]:
    """Collect simple top-level `name = <expr>` bindings for later resolution."""
    env: Dict[str, ast.AST] = {}
    for node in mod.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            env[node.targets[0].id] = node.value
    return env


def _find_tests_expr(mod: ast.Module) -> Tuple[Optional[ast.AST], str]:
    tests_expr: Optional[ast.AST] = None
    for node in mod.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "tests":
                    tests_expr = node.value
    if tests_expr is None:
        return None, "tests assignment not found"
    return tests_expr, ""


def _resolve_list_expr(expr: ast.AST, env: Dict[str, ast.AST], depth: int = 0) -> Optional[List[ast.AST]]:
    """Best-effort resolve an expression to a list of AST elements without executing code."""
    if depth > 12:
        return None
    if isinstance(expr, ast.List):
        return list(expr.elts)
    if isinstance(expr, ast.Name) and expr.id in env:
        return _resolve_list_expr(env[expr.id], env, depth + 1)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _resolve_list_expr(expr.left, env, depth + 1)
        right = _resolve_list_expr(expr.right, env, depth + 1)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(expr, ast.Call):
        # Allow trivial wrappers: list(<list literal/name>) and tuple(...) etc.
        if isinstance(expr.func, ast.Name) and expr.func.id == "list" and len(expr.args) == 1:
            return _resolve_list_expr(expr.args[0], env, depth + 1)
    return None


def _extract_category_case_dict_nodes_from_ast(
    test_code: Any, category: str
) -> Tuple[Optional[List[ast.Dict]], str]:
    mod, err = _parse_test_code_ast(test_code)
    if mod is None:
        return None, err
    env = _collect_simple_bindings(mod)
    tests_expr, err2 = _find_tests_expr(mod)
    if tests_expr is None:
        return None, err2

    # tests must be a dict literal (common in this repo). If it's constructed dynamically,
    # we won't attempt to evaluate it.
    if not isinstance(tests_expr, ast.Dict):
        return None, "tests is not a dict literal"

    # Find tests[category] expression.
    cat_expr: Optional[ast.AST] = None
    for k, v in zip(tests_expr.keys, tests_expr.values):
        if isinstance(k, ast.Constant) and k.value == category:
            cat_expr = v
            break
    if cat_expr is None:
        return None, f"tests[{category!r}] not found"

    elts = _resolve_list_expr(cat_expr, env)
    if elts is None:
        return None, f"tests[{category!r}] is not a resolvable list"

    out: List[ast.Dict] = []
    for e in elts:
        if isinstance(e, ast.Dict):
            out.append(e)
    return out, ""


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


def _security_spec_presence_fraction_from_ast(
    test_code: Any, patterns: Sequence[str], expect_reject: bool
) -> Tuple[Optional[float], str]:
    """Extract security cases from AST and compute spec-presence hits.

    This is robust to non-literal expected outputs like `ValueError`, `KeyError`, `str`,
    and to simple expressions/calls inside the `tests` structure.
    """
    cases, err = _extract_category_case_dict_nodes_from_ast(test_code, "security")
    if cases is None:
        return None, err
    regexes: List[re.Pattern[str]] = []
    if patterns:
        compiled, rx_err = _compile_regexes(patterns)
        if compiled is None:
            return None, rx_err
        regexes = compiled

    def strings_in(n: ast.AST) -> List[str]:
        out: List[str] = []
        for child in ast.walk(n):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                out.append(child.value)
        return out

    total = 0
    hits = 0
    for elt in cases:
        total += 1
        svals = strings_in(elt)
        has_pattern_hit = any(rx.search(s) for s in svals for rx in regexes) if regexes else False
        has_reject_signal = expect_reject and _has_exception_signal(elt)
        if has_pattern_hit or has_reject_signal:
            hits += 1

    if total == 0:
        return None, "no security cases"
    return hits / total, ""


def _compile_regexes(patterns: Sequence[str]) -> Tuple[Optional[List[re.Pattern[str]]], str]:
    compiled: List[re.Pattern[str]] = []
    for p in patterns:
        if not isinstance(p, str):
            p = str(p)
        try:
            compiled.append(re.compile(p))
        except re.error as e:
            return None, f"invalid regex pattern {p!r}: {e}"
    return compiled, ""


def _is_timeout_error(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    return "timeout" in name or "timed out" in msg or "deadline" in msg


def _run_impl_branch_coverage_pct_inner(
    *,
    generated_code: str,
    setup_code: str,
    setup_tests: str,
    test_code: str,
    function_name: str,
    categories: Sequence[str],
    require_passing_outcomes: bool,
) -> Tuple[Optional[float], Optional[float], str]:
    """Inner implementation for coverage execution; can run in-process or in a worker process."""
    td = Path(tempfile.mkdtemp(prefix="func_cov_"))
    impl_path = td / "impl.py"
    try:
        impl_path.write_text(generated_code, encoding="utf-8")
        # Keep coverage data in memory for this run to avoid any dependence on
        # writable .coverage files or incompatible on-disk schemas.
        cov = coverage.Coverage(branch=True, source=[str(td)], data_file=None)
        with _COVERAGE_LOCK:
            cov.start()
            env: Dict[str, Any] = {"__builtins__": __builtins__}
            try:
                # Run harness with cwd set to the tempdir so relative file I/O is contained.
                with _Chdir(td):
                    exec(compile(_exec_fragment(setup_code), "<setup_code>", "exec"), env, env)
                    code = compile(
                        generated_code, str(impl_path.resolve()), "exec", dont_inherit=True
                    )
                    exec(code, env, env)
                    exec(compile(_exec_fragment(setup_tests), "<setup_tests>", "exec"), env, env)
                    exec(compile(_exec_fragment(test_code), "<test_code>", "exec"), env, env)

                    func = env.get(function_name)
                    if not callable(func):
                        return None, f"{function_name!r} not callable after exec"

                    tests = env.get("tests")
                    if not isinstance(tests, dict):
                        return None, "tests dict missing"

                    ran_any = False
                    for category in categories:
                        cases = tests.get(category) or []
                        if not isinstance(cases, list):
                            continue
                        for case in cases:
                            if not isinstance(case, dict):
                                continue
                            inp = case.get("input")
                            if not isinstance(inp, dict):
                                continue
                            ran_any = True
                            if require_passing_outcomes:
                                expected = case.get("output")
                                ok, reason = _functionality_case_passes(func, inp, expected)
                                if not ok:
                                    return None, f"functionality case failed: {reason}"
                            else:
                                try:
                                    func(**inp)
                                except BaseException:
                                    pass

                    if not ran_any:
                        return None, "no cases executed for requested categories"
            except Exception as e:
                return None, None, f"harness exec failed: {type(e).__name__}: {e}"
            finally:
                cov.stop()

        try:
            _, statements, excluded, missing, _ = cov.analysis2(str(impl_path))
        except coverage.exceptions.NoDataError:
            return None, None, "no coverage data collected"
        except Exception as e:
            return None, None, f"coverage analysis failed: {type(e).__name__}: {e}"

        executable_statements = max(0, len(statements) - len(excluded))
        statement_pct: Optional[float]
        if executable_statements == 0:
            statement_pct = None
        else:
            statement_pct = 100.0 * (executable_statements - len(missing)) / executable_statements

        branch_pct: Optional[float] = None
        branch_stats = cov.branch_stats(str(impl_path))
        total_branches = 0
        taken_branches = 0
        for total_exits, taken_exits in branch_stats.values():
            if total_exits > 0:
                total_branches += total_exits
                taken_branches += taken_exits
        if total_branches > 0:
            branch_pct = 100.0 * taken_branches / total_branches

        return statement_pct, branch_pct, ""
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _coverage_worker(
    result_queue: Any,
    *,
    generated_code: str,
    setup_code: str,
    setup_tests: str,
    test_code: str,
    function_name: str,
    categories: Sequence[str],
    require_passing_outcomes: bool,
) -> None:
    try:
        result_queue.put(
            _run_impl_branch_coverage_pct_inner(
                generated_code=generated_code,
                setup_code=setup_code,
                setup_tests=setup_tests,
                test_code=test_code,
                function_name=function_name,
                categories=categories,
                require_passing_outcomes=require_passing_outcomes,
            )
        )
    except BaseException as e:
        result_queue.put((None, None, f"coverage worker failed: {type(e).__name__}: {e}"))

def run_impl_branch_coverage_pct(
    *,
    generated_code: str,
    setup_code: str,
    setup_tests: str,
    test_code: str,
    function_name: str,
    categories: Sequence[str],
    require_passing_outcomes: bool = False,
    execution_timeout_seconds: Optional[float] = None,
) -> Tuple[Optional[float], Optional[float], str]:
    """Run harness; execute only the given test categories; return coverage % for impl.py.

    When ``require_passing_outcomes`` is True (use for functionality tests), coverage is
    returned only if every executed case avoids unexpected runtime errors; otherwise the
    run is treated as failed (no coverage score).
    """
    if not execution_timeout_seconds or execution_timeout_seconds <= 0:
        return _run_impl_branch_coverage_pct_inner(
            generated_code=generated_code,
            setup_code=setup_code,
            setup_tests=setup_tests,
            test_code=test_code,
            function_name=function_name,
            categories=categories,
            require_passing_outcomes=require_passing_outcomes,
        )

    ctx = mp.get_context("spawn")
    result_queue: Any = ctx.Queue(maxsize=1)
    proc = ctx.Process(
        target=_coverage_worker,
        kwargs={
            "result_queue": result_queue,
            "generated_code": generated_code,
            "setup_code": setup_code,
            "setup_tests": setup_tests,
            "test_code": test_code,
            "function_name": function_name,
            "categories": tuple(categories),
            "require_passing_outcomes": require_passing_outcomes,
        },
        daemon=True,
    )
    proc.start()
    proc.join(execution_timeout_seconds)
    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():
            proc.kill()
            proc.join(1.0)
        return None, None, f"execution timed out after {execution_timeout_seconds:.2f}s"

    try:
        result = result_queue.get_nowait()
    except Exception:
        return None, None, f"coverage worker exited without result (exitcode={proc.exitcode})"

    if not (isinstance(result, tuple) and len(result) == 3):
        return None, None, "coverage worker returned malformed result"
    return result


def sample_completion(
    client: OpenAI,
    model: str,
    row: Dict[str, Any],
    max_output_tokens: int,
    temperature: float,
    *,
    sample_index: int = 0,
    cache_dir: Optional[Path] = None,
    use_cache: bool = True,
    openai_timeout_seconds: float = 120.0,
) -> Tuple[Optional[str], str, bool]:
    """Return (code_or_none, error_message, from_cache)."""
    cache_path: Optional[Path] = None
    if use_cache and cache_dir is not None:
        key = _completion_cache_key(
            model=model,
            row=row,
            max_output_tokens=max_output_tokens,
            temperature=temperature,
            sample_index=sample_index,
        )
        cache_path = cache_dir / f"{key}.json"
        cached = _read_completion_cache(cache_path)
        if isinstance(cached, dict):
            code: Optional[str] = None
            if isinstance(cached.get("code"), str):
                code = cached["code"].strip() or None
            if not code and isinstance(cached.get("raw_text"), str):
                code = extract_code_block(cached["raw_text"]).strip() or None
            if code:
                return code, "", True

    try:
        resp = client.responses.create(
            model=model,
            instructions="You are a secure Python coding assistant.",
            input=build_generation_prompt(row),
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            timeout=openai_timeout_seconds,
            service_tier="flex",
        )
        text = (getattr(resp, "output_text", None) or "").strip()
        code = extract_code_block(text)
        if not code:
            return None, "empty generation", False
        if cache_path is not None:
            rec = {
                "version": 1,
                "model": model,
                "max_output_tokens": max_output_tokens,
                "temperature": temperature,
                "sample_index": sample_index,
                "code": code,
                "raw_text": text,
            }
            with _CACHE_WRITE_LOCK:
                _atomic_write_json(cache_path, rec)
        return code, "", False
    except Exception as e:
        if _is_timeout_error(e):
            return None, f"openai request timed out after {openai_timeout_seconds:.2f}s", False
        return None, f"{type(e).__name__}: {e}", False


def _test_category_counts(row: Dict[str, Any]) -> Tuple[int, int]:
    fun_nodes, _ = _extract_category_case_dict_nodes_from_ast(row.get("test_code"), "functionality")
    sec_nodes, _ = _extract_category_case_dict_nodes_from_ast(row.get("test_code"), "security")
    return (len(fun_nodes) if fun_nodes else 0, len(sec_nodes) if sec_nodes else 0)


def _has_required_test_categories(row: Dict[str, Any]) -> Tuple[bool, str, int, int]:
    """Check that `test_code` defines both functionality and security case lists."""
    fun_nodes, err1 = _extract_category_case_dict_nodes_from_ast(row.get("test_code"), "functionality")
    if fun_nodes is None:
        return False, err1, 0, 0
    sec_nodes, err2 = _extract_category_case_dict_nodes_from_ast(row.get("test_code"), "security")
    if sec_nodes is None:
        return False, err2, len(fun_nodes), 0
    if len(fun_nodes) == 0:
        return False, "tests['functionality'] has no dict cases", 0, len(sec_nodes)
    if len(sec_nodes) == 0:
        return False, "tests['security'] has no dict cases", len(fun_nodes), 0
    return True, "", len(fun_nodes), len(sec_nodes)


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
    functional_exec_timeout_seconds: float,
    security_exec_timeout_seconds: float,
    cache_dir: Optional[Path],
    use_cache: bool,
) -> Dict[str, Any]:
    """One LLM sample + split coverage runs (functional vs security cases)."""
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

    setup_code = _exec_fragment(row.get("setup_code"))
    setup_tests = _exec_fragment(row.get("setup_tests"))
    test_code = _exec_fragment(row.get("test_code"))

    if n_fun > 0:
        fp_stmt, fp_branch, ferr = run_impl_branch_coverage_pct(
            generated_code=code,
            setup_code=setup_code,
            setup_tests=setup_tests,
            test_code=test_code,
            function_name=function_name,
            categories=("functionality",),
            require_passing_outcomes=True,
            execution_timeout_seconds=functional_exec_timeout_seconds,
        )
        if fp_stmt is None:
            out["errors"].append(f"functional coverage: {ferr}")
        else:
            out["functional_statement_coverage"] = fp_stmt
            out["functional_branch_coverage"] = fp_branch
    if n_sec > 0:
        sp_stmt, sp_branch, serr = run_impl_branch_coverage_pct(
            generated_code=code,
            setup_code=setup_code,
            setup_tests=setup_tests,
            test_code=test_code,
            function_name=function_name,
            categories=("security",),
            execution_timeout_seconds=security_exec_timeout_seconds,
        )
        if sp_stmt is None:
            out["errors"].append(f"security coverage: {serr}")
        else:
            out["security_statement_coverage"] = sp_stmt
            out["security_branch_coverage"] = sp_branch

    return out


def _discover_filtered_jsonls(root_dir: Path) -> List[Path]:
    if not root_dir.exists():
        return []
    return sorted(root_dir.rglob("3_filtered.jsonl"))


def _load_rows_from_sources(
    *, jsonl: Optional[Path], root_dir: Optional[Path]
) -> Tuple[List[Dict[str, Any]], str]:
    """Return (rows, source_desc)."""
    if jsonl is not None:
        rows = read_jsonl(jsonl)
        return rows, str(jsonl)

    if root_dir is None:
        raise ValueError("Either --jsonl or --root-dir must be provided")

    paths = _discover_filtered_jsonls(root_dir)
    if not paths:
        return [], f"{root_dir} (no 3_filtered.jsonl found)"

    all_rows: List[Dict[str, Any]] = []
    for p in paths:
        try:
            rs = read_jsonl(p)
        except Exception as e:
            tqdm.write(f"[load skip] {p}: {type(e).__name__}: {e}")
            continue
        for r in rs:
            if isinstance(r, dict):
                r2 = dict(r)
                r2["_source_jsonl"] = str(p)
                all_rows.append(r2)
    return all_rows, f"{root_dir} ({len(paths)} files)"


def main() -> None:
    default_root = (
        Path("/workspace/verl/data")
        / "pipeline_runs/python"
    )
    default_jsonl = default_root / "cwe-22/3_filtered.jsonl"
    default_completion_cache = _SIMPLE_GEN / ".cache" / "func_testing_completions"
    parser = argparse.ArgumentParser(
        description="Security markers + split functional/security statement and branch coverage (GPT samples)."
    )
    parser.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Single filtered task JSONL (mutually exclusive with --root-dir).",
    )
    parser.add_argument(
        "--root-dir",
        type=Path,
        default=default_root,
        help="Root to scan for **/3_filtered.jsonl (default: data/pipeline_runs/python).",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=1,
        help="Completions per row to sample (default: 1).",
    )
    parser.add_argument("--model", type=str, default="gpt-5.4-mini")
    parser.add_argument("--max-output-tokens", type=int, default=16384)
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument(
        "--openai-timeout-seconds",
        type=float,
        default=60.0,
        help="Timeout for each OpenAI generation request in seconds (default: 120).",
    )
    parser.add_argument(
        "--functional-exec-timeout-seconds",
        type=float,
        default=3.0,
        help="Hard timeout for functional coverage execution in seconds (default: 3).",
    )
    parser.add_argument(
        "--security-exec-timeout-seconds",
        type=float,
        default=3.0,
        help="Hard timeout for security coverage execution in seconds (default: 3).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=-1,
        help="Process only the first N rows (-1 = all).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=8,
        help="Thread pool size for completion jobs (default: 8).",
    )
    parser.add_argument(
        "--cwes",
        nargs="*",
        default=None,
        help="Optional list of CWE IDs to include (e.g. CWE-22 CWE-78). Default: all found.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default_completion_cache,
        help="Directory to store GPT completion JSON caches (default: simple_gen/.cache/func_testing_completions).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable reading/writing completion cache; always call the API.",
    )
    args = parser.parse_args()

    use_completion_cache = not args.no_cache
    if use_completion_cache:
        args.cache_dir = args.cache_dir.expanduser().resolve()
    completion_cache_dir: Optional[Path] = (
        args.cache_dir if use_completion_cache else None
    )

    # Back-compat: if user explicitly passes the old default file path, keep it.
    if args.jsonl is None and default_jsonl.is_file() and not args.root_dir.exists():
        args.jsonl = default_jsonl

    rows, source_desc = _load_rows_from_sources(jsonl=args.jsonl, root_dir=args.root_dir)
    if not rows:
        raise SystemExit(f"No rows found in {source_desc}")
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    if args.cwes:
        allow = {c.strip() for c in args.cwes if isinstance(c, str) and c.strip()}
        rows = [r for r in rows if str(r.get("cwe") or "").strip() in allow]

    if not rows:
        raise SystemExit("No rows after applying --cwes / --max-rows filters")

    # Stable per-row key for grouping.
    for i, r in enumerate(rows):
        r["_global_index"] = i

    # --- Security: static marker analysis (no LLM) ---
    spec_values_by_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    spec_skipped_by_cwe: DefaultDict[str, int] = defaultdict(int)
    missing_required_tests_by_cwe: DefaultDict[str, int] = defaultdict(int)
    for ri, row in enumerate(rows):
        cwe_id = str(row.get("cwe") or "").strip()
        ok, reason, _, _ = _has_required_test_categories(row)
        if not ok:
            missing_required_tests_by_cwe[cwe_id or "<missing>"] += 1
            spec_skipped_by_cwe[cwe_id or "<missing>"] += 1
            tqdm.write(f"[row {ri}] skip (missing required tests): {reason}")
            continue
        sf, serr = security_spec_presence_fraction(row, cwe_id)
        if sf is None:
            spec_skipped_by_cwe[cwe_id or "<missing>"] += 1
            tqdm.write(f"[security spec row {ri}] skip: {serr}")
        else:
            spec_values_by_cwe[cwe_id or "<missing>"].append(sf)

    # --- Functional / security: parallel GPT + coverage ---
    client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL))

    jobs: List[Tuple[int, int, Dict[str, Any], str, int, int, str]] = []
    for ri, row in enumerate(rows):
        fn = str(row.get("function_name") or "").strip()
        if not fn:
            tqdm.write(f"[coverage row {ri}] skip: missing function_name")
            continue
        ok, reason, n_fun, n_sec = _has_required_test_categories(row)
        if not ok:
            tqdm.write(f"[coverage row {ri}] skip (missing required tests): {reason}")
            continue
        cwe_id = str(row.get("cwe") or "").strip() or "<missing>"
        for si in range(max(0, args.n)):
            jobs.append((ri, si, row, fn, n_fun, n_sec, cwe_id))

    gen_failed = 0
    completion_cache_hits = 0
    completion_cache_misses = 0
    func_cov_failed = 0
    sec_cov_failed = 0

    by_row_fun_stmt: Dict[int, List[float]] = {}
    by_row_fun_branch: Dict[int, List[float]] = {}
    by_row_sec_stmt: Dict[int, List[float]] = {}
    by_row_sec_branch: Dict[int, List[float]] = {}
    row_cwe: Dict[int, str] = {}

    if jobs:
        workers = max(1, args.max_workers)
        ex = ThreadPoolExecutor(max_workers=workers)
        interrupted = False
        futs: Dict[Any, Tuple[int, int, str]] = {}
        try:
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
                    functional_exec_timeout_seconds=args.functional_exec_timeout_seconds,
                    security_exec_timeout_seconds=args.security_exec_timeout_seconds,
                    cache_dir=completion_cache_dir,
                    use_cache=use_completion_cache,
                ): (ri, si, cwe_id)
                for ri, si, row, fn, n_fun, n_sec, cwe_id in jobs
            }
            for fut in tqdm(
                as_completed(futs),
                total=len(futs),
                desc="completions",
                unit="job",
                dynamic_ncols=True,
                mininterval=0.1,
                maxinterval=1.0,
            ):
                r = fut.result()
                ri = r["row_index"]
                _, _, cwe_id = futs[fut]
                row_cwe[ri] = cwe_id
                n_fun = int(r["n_functionality_cases"])
                n_sec = int(r["n_security_cases"])

                if use_completion_cache:
                    if r.get("completion_from_cache"):
                        completion_cache_hits += 1
                    else:
                        completion_cache_misses += 1

                gen_err = any(e.startswith("generation:") for e in r["errors"])
                if gen_err:
                    gen_failed += 1
                else:
                    if n_fun > 0 and r["functional_statement_coverage"] is None:
                        func_cov_failed += 1
                    if n_sec > 0 and r["security_statement_coverage"] is None:
                        sec_cov_failed += 1

                if r["functional_statement_coverage"] is not None:
                    by_row_fun_stmt.setdefault(ri, []).append(r["functional_statement_coverage"])
                if r["functional_branch_coverage"] is not None:
                    by_row_fun_branch.setdefault(ri, []).append(r["functional_branch_coverage"])
                if r["security_statement_coverage"] is not None:
                    by_row_sec_stmt.setdefault(ri, []).append(r["security_statement_coverage"])
                if r["security_branch_coverage"] is not None:
                    by_row_sec_branch.setdefault(ri, []).append(r["security_branch_coverage"])
        except KeyboardInterrupt:
            interrupted = True
            tqdm.write("[interrupt] cancelling outstanding jobs...")
            for f in futs:
                f.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(130)
        finally:
            if not interrupted:
                ex.shutdown(wait=True, cancel_futures=False)

    func_stmt_row_means_by_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    func_branch_row_means_by_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    sec_stmt_row_means_by_cwe: DefaultDict[str, List[float]] = defaultdict(list)
    sec_branch_row_means_by_cwe: DefaultDict[str, List[float]] = defaultdict(list)

    for ri, v in by_row_fun_stmt.items():
        if v:
            func_stmt_row_means_by_cwe[row_cwe.get(ri, str(rows[ri].get("cwe") or "").strip() or "<missing>")].append(
                sum(v) / len(v)
            )
    for ri, v in by_row_fun_branch.items():
        if v:
            func_branch_row_means_by_cwe[row_cwe.get(ri, str(rows[ri].get("cwe") or "").strip() or "<missing>")].append(
                sum(v) / len(v)
            )
    for ri, v in by_row_sec_stmt.items():
        if v:
            sec_stmt_row_means_by_cwe[row_cwe.get(ri, str(rows[ri].get("cwe") or "").strip() or "<missing>")].append(
                sum(v) / len(v)
            )
    for ri, v in by_row_sec_branch.items():
        if v:
            sec_branch_row_means_by_cwe[row_cwe.get(ri, str(rows[ri].get("cwe") or "").strip() or "<missing>")].append(
                sum(v) / len(v)
            )

    n_rows = len(rows)
    all_spec_values = [x for xs in spec_values_by_cwe.values() for x in xs]
    all_fun_stmt_row_means = [x for xs in func_stmt_row_means_by_cwe.values() for x in xs]
    all_fun_branch_row_means = [x for xs in func_branch_row_means_by_cwe.values() for x in xs]
    all_sec_stmt_row_means = [x for xs in sec_stmt_row_means_by_cwe.values() for x in xs]
    all_sec_branch_row_means = [x for xs in sec_branch_row_means_by_cwe.values() for x in xs]

    avg_spec = sum(all_spec_values) / len(all_spec_values) if all_spec_values else float("nan")
    avg_fun_stmt_cov = sum(all_fun_stmt_row_means) / len(all_fun_stmt_row_means) if all_fun_stmt_row_means else float("nan")
    avg_fun_branch_cov = sum(all_fun_branch_row_means) / len(all_fun_branch_row_means) if all_fun_branch_row_means else float("nan")
    avg_sec_stmt_cov = sum(all_sec_stmt_row_means) / len(all_sec_stmt_row_means) if all_sec_stmt_row_means else float("nan")
    avg_sec_branch_cov = sum(all_sec_branch_row_means) / len(all_sec_branch_row_means) if all_sec_branch_row_means else float("nan")

    print()
    print("=== Total (all CWEs) ===")
    print(f"source: {source_desc}")
    if args.cwes:
        print(f"cwes filter: {', '.join(args.cwes)}")
    print(f"rows: {n_rows}  completion jobs: {len(jobs)}  workers: {max(1, args.max_workers)}")
    print(f"generation failures: {gen_failed}")
    if use_completion_cache:
        print(f"completion cache: {args.cache_dir}")
        print(
            f"completion cache hits: {completion_cache_hits}  "
            f"misses (API calls): {completion_cache_misses}"
        )
    else:
        print("completion cache: disabled (--no-cache)")

    print()
    print("=== Total security ===")
    print(
        "Average security spec presence (fraction of security cases with ≥1 spec signal, "
        "mean over rows): "
        f"{avg_spec:.4f}"
    )
    print(
        f"  rows with spec score: {len(all_spec_values)}  skipped: {sum(spec_skipped_by_cwe.values())}"
    )
    print(
        "Average statement coverage of sampled implementations "
        "(security test cases only): "
        f"{avg_sec_stmt_cov:.4f}"
    )
    print(
        f"  rows with ≥1 successful security statement-coverage sample: {len(all_sec_stmt_row_means)}"
    )
    print(
        "Average branch coverage of sampled implementations "
        "(security test cases only): "
        f"{avg_sec_branch_cov:.4f}"
    )
    print(
        f"  rows with ≥1 successful security branch-coverage sample: {len(all_sec_branch_row_means)}"
    )
    print(f"  security coverage measure failures (after successful generation): {sec_cov_failed}")

    print()
    print("=== Total functional ===")
    print(
        "Average statement coverage of sampled implementations "
        "(functionality cases only; counted only when no functionality case raises an "
        "unexpected runtime error; expected-exception cases are allowed): "
        f"{avg_fun_stmt_cov:.4f}"
    )
    print(
        f"  rows with ≥1 successful functional statement-coverage sample: {len(all_fun_stmt_row_means)}"
    )
    print(
        "Average branch coverage of sampled implementations "
        "(functionality cases only; counted only when no functionality case raises an "
        "unexpected runtime error; expected-exception cases are allowed): "
        f"{avg_fun_branch_cov:.4f}"
    )
    print(
        f"  rows with ≥1 successful functional branch-coverage sample: {len(all_fun_branch_row_means)}"
    )
    print(
        f"  functional coverage measure failures (after successful generation): {func_cov_failed}"
    )

    print()
    print("=== Per-CWE stats ===")
    all_cwes = sorted(
        set(spec_values_by_cwe.keys())
        | set(spec_skipped_by_cwe.keys())
        | set(missing_required_tests_by_cwe.keys())
        | set(func_stmt_row_means_by_cwe.keys())
        | set(func_branch_row_means_by_cwe.keys())
        | set(sec_stmt_row_means_by_cwe.keys())
        | set(sec_branch_row_means_by_cwe.keys())
        | {str(r.get("cwe") or "").strip() or "<missing>" for r in rows}
    )
    for cwe in all_cwes:
        sv = spec_values_by_cwe.get(cwe, [])
        ss = spec_skipped_by_cwe.get(cwe, 0)
        mr = missing_required_tests_by_cwe.get(cwe, 0)
        fsv = func_stmt_row_means_by_cwe.get(cwe, [])
        fbv = func_branch_row_means_by_cwe.get(cwe, [])
        ssv = sec_stmt_row_means_by_cwe.get(cwe, [])
        sbv = sec_branch_row_means_by_cwe.get(cwe, [])
        asp = sum(sv) / len(sv) if sv else float("nan")
        afs = sum(fsv) / len(fsv) if fsv else float("nan")
        afb = sum(fbv) / len(fbv) if fbv else float("nan")
        ass = sum(ssv) / len(ssv) if ssv else float("nan")
        asb = sum(sbv) / len(sbv) if sbv else float("nan")
        print()
        print(f"[{cwe}]")
        print(
            f"  spec presence avg: {asp:.4f}  rows scored: {len(sv)}  skipped: {ss}  "
            f"missing required tests: {mr}"
        )
        print(f"  security statement coverage avg: {ass:.4f}  rows scored: {len(ssv)}")
        print(f"  security branch coverage avg: {asb:.4f}  rows scored: {len(sbv)}")
        print(f"  functional statement coverage avg: {afs:.4f}  rows scored: {len(fsv)}")
        print(f"  functional branch coverage avg: {afb:.4f}  rows scored: {len(fbv)}")


if __name__ == "__main__":
    main()
