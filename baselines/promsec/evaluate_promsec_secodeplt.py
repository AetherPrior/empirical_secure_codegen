"""
Evaluate PromSec-generated code on SecCodePLT using SeCode-Eval metrics.

Produces per-sample scores compatible with secure_reasoning/SeCode-Eval/get_results.py:
  - capability_score, safety_score, secpass (safety_score if capability_score==1 else 0)

Summary (SecCodePLT-Python, use_rule=False rows only):
  - secpass@1  = mean(secpass) * 100
  - pass@1     = mean(capability_score) * 100
  - sec_rate   = mean(safety_score) * 100

Usage:
    python evaluate_promsec_secodeplt.py \
        --results_csv results_promsec_secodeplt/promsec_insecure_coding_all.csv \
        --output_dir  results_promsec_secodeplt
"""

import argparse
import ast
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import datasets
import pandas as pd
from tqdm import tqdm

from paths import PROMSEC_ROOT

# Import SeCode-Eval unittest runner + official score aggregation
SECODE_EVAL_DIR = os.path.join(PROMSEC_ROOT, "secure_reasoning", "SeCode-Eval")
sys.path.insert(0, SECODE_EVAL_DIR)
from evaluate_dataset import execute_tests_w_traceback, process_test_results  # noqa: E402

DEFAULT_DATASET_SNAPSHOT = (
    "/workspace/dabstep/cache/hub/datasets--Virtue-AI-HUB--SecCodePLT/"
    "snapshots/62efb6f03741aa6ae10afa801a7905f734baa3c1"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_unittest(unittest_field) -> dict:
    """Safely parse the unittest field (may be dict or JSON string)."""
    if isinstance(unittest_field, dict):
        return unittest_field
    if isinstance(unittest_field, str):
        try:
            return json.loads(unittest_field)
        except Exception:
            return {}
    return {}


def _parse_task_description(td_field) -> dict:
    if isinstance(td_field, dict):
        return td_field
    if isinstance(td_field, str):
        try:
            return ast.literal_eval(td_field)
        except Exception:
            try:
                return json.loads(td_field)
            except Exception:
                return {}
    return {}


def strip_markdown(code: str) -> str:
    if not isinstance(code, str):
        return ""
    code = code.strip()
    m = re.search(r"```(?:python)?\s*\n(.*?)```", code, re.DOTALL)
    if m:
        return m.group(1).strip()
    return code


def _truncate_before_last(c: str, s: str) -> str:
    return c[: c.rfind(s)]


def safecoder_postprocess_py(code: str) -> str:
    """Truncate after the function body (SafeCoder ICML'24 / SVEN evaler.postprocess).

    Walks the completion looking for the first newline followed by a non-indented
    line — that's the end of the function. Falls back to the last indented comment.
    Anchored on the first def: lines before/up-to the def are preserved as-is.
    """
    # Find first def to anchor; everything before is preserved (imports, decorators).
    m = re.search(r"^(?:async\s+)?def\s+\w+", code, re.MULTILINE)
    if not m:
        return code
    # Find the end of the signature (matched parens, then ':' line)
    sig_start = m.start()
    i = m.end()
    paren_depth = 0
    while i < len(code):
        ch = code[i]
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif ch == "\n" and paren_depth == 0:
            i += 1
            break
        i += 1
    prefix = code[:i]
    completion = code[i:]

    for match in re.finditer("\n", completion):
        cur_idx, next_idx = match.start(), match.end()
        if next_idx < len(completion) and not completion[next_idx].isspace():
            completion = completion[:cur_idx]
            break
    else:
        if "\n    #" in completion:
            completion = _truncate_before_last(completion, "\n    #")
    return prefix + completion


def evaluate_single(row: dict, code_col: str, apply_truncate: bool = True) -> dict:
    """Run SeCode-Eval unit tests; return official capability/safety scores."""
    code = strip_markdown(row.get(code_col, ""))
    if apply_truncate:
        code = safecoder_postprocess_py(code)
    if not code.strip():
        return {
            "capability_score": 0.0,
            "safety_score": 0.0,
            "secpass": 0.0,
            "eval_error": "empty_code",
        }

    unittest_field = _parse_unittest(row.get("unittest", {}))
    td_field = _parse_task_description(row.get("task_description", {}))

    setup = unittest_field.get("setup", "")
    testcases = unittest_field.get("testcases", "")
    func_name = td_field.get("function_name", "")
    install_requires = row.get("install_requires", [])
    if isinstance(install_requires, str):
        try:
            install_requires = ast.literal_eval(install_requires)
        except Exception:
            try:
                install_requires = json.loads(install_requires)
            except Exception:
                install_requires = []
    if install_requires is None:
        install_requires = []

    if not testcases or not str(testcases).strip():
        return {
            "capability_score": 0.0,
            "safety_score": 0.0,
            "secpass": 0.0,
            "eval_error": "empty_testcases",
        }

    try:
        results = execute_tests_w_traceback(
            code=code,
            setup=setup,
            testcases=testcases,
            func_name=func_name,
            install_requires=install_requires,
        )
    except Exception as e:
        return {
            "capability_score": 0.0,
            "safety_score": 0.0,
            "secpass": 0.0,
            "eval_error": str(e),
        }

    processed = process_test_results(results)
    cap = float(processed["capability_score"])
    saf = float(processed["safety_score"])
    secpass = saf if cap >= 1.0 else 0.0
    return {
        "capability_score": cap,
        "safety_score": saf,
        "secpass": secpass,
        "eval_error": None,
    }


def summarize_secode_eval(df: pd.DataFrame) -> dict:
    """Aggregate metrics like SeCode-Eval/get_results.py."""
    if "secpass" not in df.columns:
        df = df.copy()
        df["secpass"] = df["safety_score"]
        df.loc[df["capability_score"] < 1.0, "secpass"] = 0.0
    return {
        "secpass@1": round(df["secpass"].mean() * 100, 2),
        "pass@1": round(df["capability_score"].mean() * 100, 2),
        "sec_rate": round(df["safety_score"].mean() * 100, 2),
        "n": len(df),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Evaluate PromSec results on SecCodePLT (SeCode-Eval metrics)")
    parser.add_argument("--results_csv", type=str, required=True,
                        help="Path to CSV from run_promsec_secodeplt.py")
    parser.add_argument("--dataset_path", type=str, default=DEFAULT_DATASET_SNAPSHOT,
                        help="HF dataset id or local snapshot path")
    parser.add_argument("--split", type=str, default="insecure_coding")
    parser.add_argument("--output_dir", type=str, default=None,
                        help="Directory to save eval results (default: same as results_csv dir)")
    parser.add_argument("--n_workers", type=int, default=8,
                        help="Parallel workers for test execution")
    parser.add_argument("--code_col", type=str, default="final_code",
                        help="CSV column containing generated code (default: final_code; use generated_code for SVEN)")
    parser.add_argument("--include_use_rule", action="store_true",
                        help="Include use_rule=True rows (default: exclude, SecCodePLT-Python subset)")
    parser.add_argument("--no_truncate", action="store_true",
                        help="Disable SafeCoder-style function-body truncation post-processing")
    args = parser.parse_args()

    print(f"Loading PromSec results from {args.results_csv} ...")
    results_df = pd.read_csv(args.results_csv)
    print(f"  {len(results_df)} rows loaded")

    print(f"Loading SecCodePLT ({args.split}) from {args.dataset_path} ...")
    ds = datasets.load_dataset(args.dataset_path, split=args.split)
    seccode_df = ds.to_pandas()

    merge_cols = [c for c in ["id", "unittest", "task_description", "install_requires", "use_rule"]
                  if c in seccode_df.columns]
    merged = results_df.merge(seccode_df[merge_cols], on="id", how="left", suffixes=("", "_sc"))
    for col in ["unittest", "task_description", "install_requires", "use_rule"]:
        if f"{col}_sc" in merged.columns:
            merged[col] = merged[f"{col}_sc"].fillna(merged.get(col, ""))
            merged.drop(columns=[f"{col}_sc"], inplace=True)

    if not args.include_use_rule and "use_rule" in merged.columns:
        before = len(merged)
        merged = merged[~merged["use_rule"].astype(bool)].reset_index(drop=True)
        print(f"  Filtered use_rule=False: {len(merged)} / {before} rows (SecCodePLT-Python)")

    print(f"Evaluating {args.code_col} (SeCode-Eval process_test_results) ...")
    rows = merged.to_dict("records")
    final_metrics = [None] * len(rows)
    with ThreadPoolExecutor(max_workers=args.n_workers) as executor:
        futures = {
            executor.submit(evaluate_single, row, args.code_col, not args.no_truncate): i
            for i, row in enumerate(rows)
        }
        for future in tqdm(as_completed(futures), total=len(futures)):
            i = futures[future]
            try:
                final_metrics[i] = future.result()
            except Exception as e:
                final_metrics[i] = {
                    "capability_score": 0.0, "safety_score": 0.0, "secpass": 0.0,
                    "eval_error": str(e),
                }

    for key in ("capability_score", "safety_score", "secpass", "eval_error"):
        merged[key] = [m[key] for m in final_metrics]

    out_dir = args.output_dir or os.path.join(PROMSEC_ROOT, "results_promsec_eval")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(args.results_csv))[0]

    results_csv = os.path.join(out_dir, "results.csv")
    merged.to_csv(results_csv, index=False)
    merged.to_csv(os.path.join(out_dir, f"{base}_secode_eval.csv"), index=False)

    summary = summarize_secode_eval(merged)
    summary_path = os.path.join(out_dir, f"{base}_secode_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSaved → {results_csv}")
    print("\n" + "=" * 50)
    print("SecCodePLT-Python (SeCode-Eval / get_results.py format)")
    print("=" * 50)
    print(f"{'':12} {'secpass@1':>10} {'pass@1':>10} {'sec_rate':>10}")
    print(f"{'PromSec':12} {summary['secpass@1']:10.2f} {summary['pass@1']:10.2f} {summary['sec_rate']:10.2f}")
    print(f"(n={summary['n']} samples, use_rule=False)")
    print("=" * 50)


if __name__ == "__main__":
    main()
