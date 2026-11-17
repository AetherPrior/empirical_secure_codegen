"""
Re-run PromSec vet_code loop on existing SecCodePLT results (no initial LLM generation).

Fixes markdown-stripped og_code, re-runs Bandit + vet_code, writes a new CSV.

Usage:
    python run_promsec_rerun_vet.py \
        --input_csv results_promsec_secodeplt/promsec_insecure_coding_all.csv \
        --output_dir results_promsec_secodeplt \
        --iter_num 20
"""

import argparse
import os

import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from transformers import AutoModelForCausalLM, AutoTokenizer

from run_promsec_secodeplt import (
    GENERATOR_PT,
    IN_FEATS,
    HIDDEN_FEATS,
    OUT_FEATS,
    MODEL_PATH,
    Generator,
    calculate_vcs,
    code_to_pyg,
    remove_markdown,
    vet_code,
)


def _save_checkpoint(df: pd.DataFrame, output_dir: str, tag: str):
    csv_path = os.path.join(output_dir, f"promsec_{tag}.csv")
    json_path = os.path.join(output_dir, f"promsec_{tag}.json")
    df.to_csv(csv_path, index=False)
    df.to_json(json_path, orient="records", lines=True)
    print(f"  [saved] {csv_path}")


def run_vet_loop(row, idx, df, llm_model, tokenizer, generator, ggan_device, label_encoder, iter_num):
    task_id = row.get("id", str(idx))
    cwe = row.get("CWE_ID", "?")
    print(f"\n[{idx+1}/{len(df)}] id={task_id} CWE={cwe}")

    raw_og = row.get("og_code") or row.get("final_code") or ""
    og_code = remove_markdown(str(raw_og))
    if not og_code.strip():
        print("  [SKIP] empty code after markdown strip")
        return

    df.at[idx, "og_code"] = og_code
    k_og, cwes_og = calculate_vcs(og_code)
    df.at[idx, "og_cwe_count"] = k_og
    df.at[idx, "og_cwes"] = str(cwes_og)
    print(f"  Stripped og_code | Initial CWEs: {k_og} {cwes_og}")

    pyg_data = code_to_pyg(og_code, label_encoder)
    if pyg_data is None:
        print("  [SKIP] CFG/PyG conversion failed")
        df.at[idx, "final_code"] = og_code
        df.at[idx, "final_cwe_count"] = k_og
        df.at[idx, "final_cwes"] = str(cwes_og)
        df.at[idx, "iterations_used"] = 0
        df.at[idx, "security_improved"] = False
        return

    ci = og_code
    k_cur = k_og
    iterations_used = 0

    for iteration in range(iter_num):
        print(f"  iter {iteration}: CWEs={k_cur}", end="")
        if k_cur == 0:
            print(" → already secure, stopping.")
            break
        try:
            ci, _, pyg_data = vet_code(
                llm_model, tokenizer, generator, ggan_device,
                ci, pyg_data, label_encoder,
            )
        except Exception as e:
            print(f"\n  [vet_code error] {e}")
            break
        k_cur, cwes_cur = calculate_vcs(ci)
        print(f" → {k_cur} {cwes_cur}")
        iterations_used = iteration + 1

    k_final, cwes_final = calculate_vcs(ci)
    df.at[idx, "final_code"] = ci
    df.at[idx, "final_cwe_count"] = k_final
    df.at[idx, "final_cwes"] = str(cwes_final)
    df.at[idx, "iterations_used"] = iterations_used
    df.at[idx, "security_improved"] = k_final < k_og
    print(f"  Final CWEs: {k_final} | improved={df.at[idx, 'security_improved']}")


def main():
    parser = argparse.ArgumentParser(description="Re-run PromSec vet_code on existing CSV")
    parser.add_argument(
        "--input_csv",
        type=str,
        default="results_promsec_secodeplt/promsec_insecure_coding_all.csv",
    )
    parser.add_argument("--output_dir", type=str, default="results_promsec_secodeplt")
    parser.add_argument("--output_tag", type=str, default="insecure_coding_all_vetfixed",
                        help="Output file tag (promsec_{tag}.csv)")
    parser.add_argument("--split", type=str, default="insecure_coding")
    parser.add_argument("--iter_num", type=int, default=20)
    parser.add_argument("--max_samples", type=int, default=None)
    parser.add_argument("--python_only", action="store_true",
                        help="Only rows with use_rule=False (819 SecCodePLT-Python)")
    parser.add_argument("--start_idx", type=int, default=0,
                        help="Resume from dataframe index")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Loading results from {args.input_csv} ...")
    df = pd.read_csv(args.input_csv)
    print(f"  {len(df)} rows")

    if args.python_only and "use_rule" in df.columns:
        before = len(df)
        df = df[~df["use_rule"].astype(bool)].reset_index(drop=True)
        print(f"  python_only (use_rule=False): {len(df)} / {before}")

    if args.max_samples:
        df = df.head(args.max_samples).reset_index(drop=True)

    for col in ("og_cwe_count", "final_cwe_count", "iterations_used", "security_improved"):
        if col not in df.columns:
            df[col] = None

    print(f"Loading Qwen3-8B from {MODEL_PATH} ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    llm_model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH, torch_dtype=torch.bfloat16, device_map="auto"
    )
    llm_model.eval()
    print(f"LLM loaded on: {next(llm_model.parameters()).device}")

    ggan_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    generator = Generator(IN_FEATS, HIDDEN_FEATS, OUT_FEATS).to(ggan_device)
    generator.load_state_dict(torch.load(GENERATOR_PT, map_location=ggan_device))
    generator.eval()
    print(f"gGAN loaded on: {ggan_device}")

    label_encoder = LabelEncoder()

    for idx in range(args.start_idx, len(df)):
        run_vet_loop(
            df.iloc[idx].to_dict(), idx, df,
            llm_model, tokenizer, generator, ggan_device, label_encoder, args.iter_num,
        )
        if (idx + 1) % 10 == 0:
            _save_checkpoint(df, args.output_dir, args.output_tag)

    _save_checkpoint(df, args.output_dir, args.output_tag)

    processed = df["og_cwe_count"].notna()
    n = int(processed.sum())
    if n > 0:
        improved = int(df.loc[processed, "security_improved"].sum())
        iters = df.loc[processed, "iterations_used"].fillna(0)
        print("\n" + "=" * 60)
        print(f"Processed: {n}")
        print(f"Avg initial CWE: {df.loc[processed, 'og_cwe_count'].mean():.2f}")
        print(f"Avg final CWE:   {df.loc[processed, 'final_cwe_count'].mean():.2f}")
        print(f"vet_code iters>0: {(iters > 0).sum()}")
        print(f"Security improved: {improved}/{n} ({improved/n:.1%})")
        print("=" * 60)


if __name__ == "__main__":
    main()
