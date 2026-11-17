"""
PromSec baseline evaluation on CyberSecEval Instruct (Python subset only).

For each Python test_case_prompt in instruct-v2.json:
  1. Generate initial code with Qwen3-8B (chat-instruct, single shot)
  2. Run PromSec vet_code() loop (gGAN + LLM iterative fix) up to iter_num steps
  3. Save the vetted final code as the CyberSecEval response

Output JSON shape matches run_cosec_cyberseceval.py / eval_cyberseceval_icd.py so
downstream ICD scoring just works:
  [
    {"prompt_id": int,
     "test_case_prompt": str,
     "response": "```python\\n<vetted code>\\n```",
     "model": str,
     "language": "python",
     "cwe_identifier": str,
     "variant": "instruct",
     ...},
    ...
  ]

Usage:
    python run_promsec_cyberseceval.py \\
        --prompt_path /workspace/PromSec/secure_reasoning/PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct-v2.json \\
        --output_path /workspace/PromSec/results_promsec_cyberseceval/responses.json \\
        --iter_num 5
"""

import argparse
import ast
import datetime
import json
import os
import sys

import torch
from sklearn.preprocessing import LabelEncoder
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
# Reuse PromSec's CFG / vet_code utilities from the SecCodePLT runner so we
# don't fork the gGAN code path.
from run_promsec_secodeplt import (
    MODEL_PATH,
    GENERATOR_PT,
    IN_FEATS,
    HIDDEN_FEATS,
    OUT_FEATS,
    Generator,
    code_to_pyg,
    get_completion,
    remove_markdown,
    vet_code,
)

from transformers import AutoModelForCausalLM, AutoTokenizer


PASS_THROUGH_FIELDS = [
    "prompt_id", "test_case_prompt", "language", "cwe_identifier",
    "origin_code", "file_path", "pattern_desc", "pattern_id", "rule",
    "analyzer", "line_number", "line_text", "variant", "repo",
]


def generate_initial_code(llm_model, tokenizer, user_prompt: str) -> str:
    """One-shot Qwen3-8B chat completion (matches PromSec's initial-gen behavior)."""
    code = get_completion(llm_model, tokenizer, user_prompt, max_new_tokens=2048)
    return remove_markdown(code)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target_model_path", type=str, default=MODEL_PATH,
                        help="Qwen3-8B chat model path (PromSec uses Qwen3-8B Instruct)")
    parser.add_argument("--prompt_path", type=str, required=True,
                        help="Path to instruct-v2.json")
    parser.add_argument("--output_path", type=str, default=None)
    parser.add_argument("--language", type=str, default="python",
                        help="Language filter (default: python only)")
    parser.add_argument("--max_samples", type=int, default=None)
    parser.add_argument("--iter_num", type=int, default=5,
                        help="Max PromSec vet_code iterations per sample (paper uses 20; "
                             "we default to 5 for runtime — each iter is several LLM calls)")
    parser.add_argument("--save_every", type=int, default=10)
    args = parser.parse_args()

    if args.output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_path = f"/workspace/PromSec/results_promsec_cyberseceval/responses_{ts}.json"
    os.makedirs(os.path.dirname(args.output_path), exist_ok=True)

    with open(args.prompt_path) as f:
        prompts = json.load(f)
    if args.language:
        prompts = [p for p in prompts if p.get("language") == args.language]
    if args.max_samples:
        prompts = prompts[: args.max_samples]
    print(f"Loaded {len(prompts)} {args.language} prompts")

    # ------------------------------------------------------------------
    # Load Qwen3-8B
    # ------------------------------------------------------------------
    print(f"Loading tokenizer from {args.target_model_path} ...")
    tokenizer = AutoTokenizer.from_pretrained(args.target_model_path)
    print(f"Loading model from {args.target_model_path} ...")
    llm_model = AutoModelForCausalLM.from_pretrained(
        args.target_model_path, device_map="auto", torch_dtype=torch.bfloat16
    )
    llm_model.eval()

    # ------------------------------------------------------------------
    # Load PromSec gGAN generator
    # ------------------------------------------------------------------
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    generator = Generator(IN_FEATS, HIDDEN_FEATS, OUT_FEATS).to(device)
    generator.load_state_dict(torch.load(GENERATOR_PT, map_location=device))
    generator.eval()
    print(f"Loaded gGAN generator from {GENERATOR_PT}")

    label_encoder = LabelEncoder()
    # Fit on a small vocabulary of common Python tokens to avoid LabelEncoder
    # crashing on unseen labels — same as the SecCodePLT runner.
    label_encoder.fit([
        "def", "return", "if", "else", "for", "while", "try", "except",
        "import", "class", "with", "as", "in", "and", "or", "not",
        "True", "False", "None", "pass", "break", "continue", "raise",
    ])

    # ------------------------------------------------------------------
    # Per-prompt: initial-gen → vet_code loop
    # ------------------------------------------------------------------
    model_label = f"PromSec({os.path.basename(args.target_model_path.rstrip('/'))})"
    responses = []

    for i, sample in enumerate(tqdm(prompts, desc="PromSec CyberSecEval")):
        user_prompt = sample.get("test_case_prompt") or sample.get("mutated_prompt", "")
        if not user_prompt:
            continue

        try:
            code = generate_initial_code(llm_model, tokenizer, user_prompt)
        except Exception as e:
            print(f"  [ERROR] init gen prompt_id={sample.get('prompt_id', i)}: {e}")
            code = "FAIL TO QUERY"

        # vet_code loop — only run if we have valid code to seed the gGAN.
        if code and code != "FAIL TO QUERY":
            try:
                pyg_data = code_to_pyg(code, label_encoder)
                for _ in range(args.iter_num):
                    if pyg_data is None:
                        break
                    new_code, k_bef, new_pyg = vet_code(
                        llm_model, tokenizer, generator, device,
                        code, pyg_data, label_encoder,
                    )
                    # Stop early if vet returns same code or fewer CWEs
                    if new_code == code:
                        break
                    code = new_code
                    pyg_data = new_pyg
                    if k_bef == 0:
                        break
            except Exception as e:
                print(f"  [WARN] vet_code failed prompt_id={sample.get('prompt_id', i)}: {e}")

        # Wrap as markdown fence so downstream ICD eval picks it up via code_pass.
        response_text = code if code.startswith("```") else f"```python\n{code}\n```"

        rec = {
            "model": model_label,
            "response": response_text,
            "variant": sample.get("variant", "instruct"),
        }
        for field in PASS_THROUGH_FIELDS:
            if field in sample and field not in rec:
                rec[field] = sample[field]
        responses.append(rec)

        if (i + 1) % args.save_every == 0:
            with open(args.output_path, "w") as f:
                json.dump(responses, f, indent=2)

    with open(args.output_path, "w") as f:
        json.dump(responses, f, indent=2)

    print(f"\nSaved {len(responses)} responses → {args.output_path}")
    print("Next: run eval_cyberseceval_icd.py to compute secpass.")


if __name__ == "__main__":
    main()
