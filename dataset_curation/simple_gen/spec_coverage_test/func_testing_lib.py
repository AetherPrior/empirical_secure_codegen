"""Shared helpers for ``func_testing*.py`` (Python, C, C++)."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Tuple

from spec_coverage_test.cwe_markers import CWE_python as CWE_MARKERS


def discover_jsonls(root_dir: Path, *, filenames: Sequence[str]) -> List[Path]:
    if not root_dir.exists():
        return []
    found: List[Path] = []
    for name in filenames:
        found.extend(sorted(root_dir.rglob(name)))
    return sorted(set(found))


def load_rows(*, jsonl: Optional[Path], root_dir: Optional[Path], jsonl_names: Sequence[str]) -> Tuple[List[Dict[str, Any]], str]:
    from utils import read_jsonl

    if jsonl is not None:
        return read_jsonl(jsonl), str(jsonl)
    if root_dir is None:
        raise ValueError("Either --jsonl or --root-dir must be provided")
    paths = discover_jsonls(root_dir, filenames=jsonl_names)
    if not paths:
        return [], f"{root_dir} (no {' or '.join(jsonl_names)} found)"
    all_rows: List[Dict[str, Any]] = []
    for p in paths:
        try:
            for r in read_jsonl(p):
                if isinstance(r, dict):
                    r2 = dict(r)
                    r2["_source_jsonl"] = str(p)
                    all_rows.append(r2)
        except Exception as e:
            print(f"[load skip] {p}: {type(e).__name__}: {e}")
    return all_rows, f"{root_dir} ({len(paths)} files)"


def cwe_marker_patterns(cwe_id: str) -> Tuple[List[str], bool]:
    cfg = CWE_MARKERS.get(cwe_id)
    if not cfg:
        return [], False
    patterns: List[str] = [str(x) for x in (cfg.get("attack_markers") or [])]
    expect_reject = False
    for b in cfg.get("expected_behavior") or []:
        bs = str(b).strip()
        bu = bs.upper()
        if not bs or bu == "SANITIZE":
            continue
        if bu == "REJECT":
            expect_reject = True
            continue
        patterns.append(bs)
    return patterns, expect_reject


def _compile_regexes(patterns: Sequence[str]) -> Tuple[Optional[List[re.Pattern[str]]], str]:
    compiled: List[re.Pattern[str]] = []
    for p in patterns:
        try:
            compiled.append(re.compile(str(p)))
        except re.error as e:
            return None, f"invalid regex {p!r}: {e}"
    return compiled, ""


def _strings_match_patterns(strings: Sequence[str], regexes: Sequence[re.Pattern[str]], expect_reject: bool, reject_signal: bool) -> bool:
    has_pattern = any(rx.search(s) for s in strings for rx in regexes) if regexes else False
    return has_pattern or (expect_reject and reject_signal)


def security_spec_presence_fraction_tests_json(row: Dict[str, Any], cwe_id: str) -> Tuple[Optional[float], str]:
    """Fraction of security cases whose JSON ``input``/``output`` strings match CWE markers."""
    patterns, expect_reject = cwe_marker_patterns(cwe_id)
    if not patterns and not expect_reject:
        return None, f"no marker config for {cwe_id!r}"

    tests_obj = row.get("tests_json")
    if not isinstance(tests_obj, dict):
        return None, "missing tests_json"
    tests = tests_obj.get("tests")
    if not isinstance(tests, dict):
        return None, "tests_json.tests missing"

    regexes, rx_err = _compile_regexes(patterns) if patterns else ([], "")
    if patterns and regexes is None:
        return None, rx_err

    cases = tests.get("security")
    if not isinstance(cases, list) or not cases:
        return None, "no security cases"

    hits = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        strings: List[str] = []
        for key in ("input", "output"):
            val = case.get(key)
            if isinstance(val, str):
                strings.append(val)
            elif val is not None:
                strings.append(json.dumps(val, ensure_ascii=False))
        reject_signal = any(
            re.search(r"\b(error|exception|reject)\b", s, flags=re.IGNORECASE) for s in strings
        )
        if _strings_match_patterns(strings, regexes or [], expect_reject, reject_signal):
            hits += 1

    return hits / len(cases), ""


def test_category_counts_tests_json(row: Dict[str, Any]) -> Tuple[int, int, str]:
    tests_obj = row.get("tests_json")
    if not isinstance(tests_obj, dict):
        return 0, 0, "missing tests_json"
    tests = tests_obj.get("tests")
    if not isinstance(tests, dict):
        return 0, 0, "tests_json.tests missing"
    fun = tests.get("functionality")
    sec = tests.get("security")
    n_fun = len(fun) if isinstance(fun, list) else 0
    n_sec = len(sec) if isinstance(sec, list) else 0
    if n_fun == 0:
        return 0, n_sec, "tests.functionality empty"
    if n_sec == 0:
        return n_fun, 0, "tests.security empty"
    return n_fun, n_sec, ""


def parse_gcov_summary(stdout: str) -> Tuple[Optional[float], Optional[float]]:
    """Parse ``gcov`` summary lines for line and branch percentages."""
    line_pct: Optional[float] = None
    branch_pct: Optional[float] = None
    for raw in stdout.splitlines():
        line = raw.strip()
        m = re.search(r"Lines executed:\s*([\d.]+)%", line)
        if m:
            line_pct = float(m.group(1))
        m = re.search(r"Branches executed:\s*([\d.]+)%", line)
        if m:
            branch_pct = float(m.group(1))
    return line_pct, branch_pct


def completion_cache_key(*, model: str, prompt: str, max_output_tokens: int, temperature: float, sample_index: int) -> str:
    payload = {
        "model": model,
        "max_output_tokens": max_output_tokens,
        "temperature": temperature,
        "sample_index": sample_index,
        "prompt": prompt,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def print_summary(
    *,
    source_desc: str,
    n_rows: int,
    n_jobs: int,
    spec_values_by_cwe: DefaultDict[str, List[float]],
    spec_skipped_by_cwe: DefaultDict[str, int],
    missing_required_by_cwe: DefaultDict[str, int],
    func_stmt_by_cwe: DefaultDict[str, List[float]],
    func_branch_by_cwe: DefaultDict[str, List[float]],
    sec_stmt_by_cwe: DefaultDict[str, List[float]],
    sec_branch_by_cwe: DefaultDict[str, List[float]],
    gen_failed: int,
    func_cov_failed: int,
    sec_cov_failed: int,
    cache_hits: int,
    cache_misses: int,
    use_cache: bool,
    cache_dir: Optional[Path],
    lang_label: str,
) -> None:
    all_spec = [x for xs in spec_values_by_cwe.values() for x in xs]
    all_fs = [x for xs in func_stmt_by_cwe.values() for x in xs]
    all_fb = [x for xs in func_branch_by_cwe.values() for x in xs]
    all_ss = [x for xs in sec_stmt_by_cwe.values() for x in xs]
    all_sb = [x for xs in sec_branch_by_cwe.values() for x in xs]

    print()
    print(f"=== {lang_label}: Total (all CWEs) ===")
    print(f"source: {source_desc}")
    print(f"rows: {n_rows}  jobs: {n_jobs}")
    print(f"generation failures: {gen_failed}")
    if use_cache:
        print(f"completion cache: {cache_dir}  hits: {cache_hits}  misses: {cache_misses}")

    avg_spec = sum(all_spec) / len(all_spec) if all_spec else float("nan")
    print()
    print("=== Security (static CWE markers in tests) ===")
    print(f"avg spec presence: {avg_spec:.4f}  rows scored: {len(all_spec)}  skipped: {sum(spec_skipped_by_cwe.values())}")

    print()
    print("=== Security (generated impl coverage) ===")
    ass = sum(all_ss) / len(all_ss) if all_ss else float("nan")
    asb = sum(all_sb) / len(all_sb) if all_sb else float("nan")
    print(f"avg statement coverage: {ass:.4f}  rows: {len(all_ss)}  failures: {sec_cov_failed}")
    print(f"avg branch coverage: {asb:.4f}  rows: {len(all_sb)}")

    print()
    print("=== Functional (generated impl coverage) ===")
    afs = sum(all_fs) / len(all_fs) if all_fs else float("nan")
    afb = sum(all_fb) / len(all_fb) if all_fb else float("nan")
    print(f"avg statement coverage: {afs:.4f}  rows: {len(all_fs)}  failures: {func_cov_failed}")
    print(f"avg branch coverage: {afb:.4f}  rows: {len(all_fb)}")

    print()
    print("=== Per-CWE ===")
    all_cwes = sorted(
        set(spec_values_by_cwe)
        | set(func_stmt_by_cwe)
        | set(sec_stmt_by_cwe)
        | set(spec_skipped_by_cwe)
        | set(missing_required_by_cwe)
    )
    for cwe in all_cwes:
        sv = spec_values_by_cwe.get(cwe, [])
        fsv = func_stmt_by_cwe.get(cwe, [])
        fbv = func_branch_by_cwe.get(cwe, [])
        ssv = sec_stmt_by_cwe.get(cwe, [])
        sbv = sec_branch_by_cwe.get(cwe, [])
        print(f"[{cwe}] spec={sum(sv)/len(sv):.4f} n={len(sv)}" if sv else f"[{cwe}] spec=n/a skipped={spec_skipped_by_cwe.get(cwe,0)}")
        if fsv:
            print(f"  functional stmt={sum(fsv)/len(fsv):.4f} branch={sum(fbv)/len(fbv):.4f} n={len(fsv)}" if fbv else f"  functional stmt={sum(fsv)/len(fsv):.4f} n={len(fsv)}")
        if ssv:
            print(f"  security stmt={sum(ssv)/len(ssv):.4f} branch={sum(sbv)/len(sbv):.4f} n={len(ssv)}" if sbv else f"  security stmt={sum(ssv)/len(ssv):.4f} n={len(ssv)}")
