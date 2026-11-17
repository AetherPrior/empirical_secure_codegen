"""
PromSec baseline evaluation on CWEval (Python tasks only).

Pipeline per task:
  1. Read task file prompt (up to # BEGIN SOLUTION)
  2. Generate initial code with Qwen3-8B
  3. Run PromSec vet_code() loop (gGAN + LLM iterative fix)
  4. Save output as CWEval raw file format
  5. CWEval's evaluate.py handles final pytest evaluation

Usage:
    python run_promsec_cweval.py [options]

    Options:
        --cweval_dir    Path to CWEval repo (default: ./secure_reasoning/CWEval)
        --eval_path     Output directory for generated files (default: auto-dated)
        --n_samples     Number of code samples per task (default: 1)
        --iter_num      PromSec iterations per sample (default: 20)
        --max_tasks     Limit number of tasks (for smoke test)

After running, evaluate with CWEval's pipeline:
    docker run --rm -it --net host \\
        -v /workspace/PromSec/secure_reasoning/CWEval:/home/ubuntu/CWEval \\
        co1lin/cweval zsh -c \\
        "cd /home/ubuntu/CWEval && source .env && \\
         python cweval/evaluate.py pipeline --eval_path <eval_path> --num_proc 8 --docker False"
"""

import argparse
import ast
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

import networkx as nx
import numpy as np
import torch
import torch.nn as nn
from natsort import natsorted
from sklearn.preprocessing import LabelEncoder
from torch_geometric.data import Data
from torch_geometric.nn import GraphConv
from transformers import AutoModelForCausalLM, AutoTokenizer

from paths import PROMSEC_ROOT

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODEL_PATH = "/workspace/dabstep/cache/hub/models--Qwen--Qwen3-8B/snapshots/b968826d9c46dd6066d109eabc6255188de91218"
GENERATOR_PT = os.path.join(PROMSEC_ROOT, "trained_generator_model.pt")
TEMP_CODE_FILE = "/tmp/temp_code_promsec_cweval.py"

IN_FEATS = 1
HIDDEN_FEATS = 128
OUT_FEATS = 1

BEGIN_SOLUTION_ANCHOR = "# BEGIN SOLUTION"
BEGIN_PROMPT_ANCHOR = "# BEGIN PROMPT"


# ---------------------------------------------------------------------------
# gGAN
# ---------------------------------------------------------------------------

class Generator(nn.Module):
    def __init__(self, in_feats, hidden_feats, out_feats):
        super().__init__()
        self.conv1 = GraphConv(in_feats, hidden_feats)
        self.conv2 = GraphConv(hidden_feats, out_feats)
        self.relu = nn.ReLU()

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = self.relu(x)
        embeddings_before = self.conv2(x, edge_index)
        updated_x = self.relu(embeddings_before)
        return embeddings_before, updated_x


# ---------------------------------------------------------------------------
# CFG / graph utilities (same as run_promsec_secodeplt.py)
# ---------------------------------------------------------------------------

def get_node_features(graph, node):
    node_data = graph.nodes[node]
    return [
        int(node_data.get("contains_function", False)),
        int(node_data.get("contains_loop", False)),
        int(node_data.get("contains_if", False)),
        int(node_data.get("contains_comment", False)),
    ]


def generate_cfg_from_code(code: str) -> nx.DiGraph:
    cfg = nx.DiGraph()
    for i, line in enumerate(code.split("\n")):
        cfg.add_node(i, line=line.strip())
        if i > 0:
            cfg.add_edge(i - 1, i)
    return cfg if cfg.nodes() else None


def adjacency_matrix_to_edge_index(adj_matrix):
    rows, cols = np.where(adj_matrix == 1)
    return torch.tensor([rows, cols], dtype=torch.long)


def code_to_pyg(code: str, label_encoder: LabelEncoder):
    cfg = generate_cfg_from_code(code)
    if cfg is None:
        return None
    node_features = np.array([get_node_features(cfg, n) for n in cfg.nodes()])
    num_nodes = len(node_features)
    node_features = node_features.reshape(num_nodes, -1)
    x_list = [item for sublist in node_features for item in sublist]
    encoded = label_encoder.fit_transform(x_list)
    encoded = torch.tensor(encoded, dtype=torch.float32).unsqueeze(1)
    adj = nx.adjacency_matrix(cfg).toarray()
    edge_index = adjacency_matrix_to_edge_index(adj)
    return Data(x=encoded, edge_index=edge_index)


def extract_graph_from_pyg_data(pyg_data: Data) -> nx.DiGraph:
    g = nx.DiGraph()
    n = pyg_data.x.size(0)
    g.add_nodes_from(range(n))
    edges = pyg_data.edge_index.t().tolist()
    g.add_edges_from(edges)
    return g


# ---------------------------------------------------------------------------
# Security scanner
# ---------------------------------------------------------------------------

def calculate_vcs(code: str, code_filename: str = TEMP_CODE_FILE):
    with open(code_filename, "w") as f:
        f.write(code)
    result = subprocess.run(
        f"bandit -f json {code_filename}",
        shell=True, capture_output=True, text=True,
    )
    try:
        result_json = json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0, []
    cwe_set = set()
    for issue in result_json.get("results", []):
        cwe_id = issue.get("issue_cwe", {}).get("id")
        if cwe_id:
            cwe_set.add(cwe_id)
    return len(cwe_set), sorted(cwe_set)


# ---------------------------------------------------------------------------
# LLM utilities
# ---------------------------------------------------------------------------

def remove_markdown(code: str) -> str:
    match = re.search(r"```(?:python)?\n(.*?)```", code, re.DOTALL)
    if match:
        return match.group(1)
    return code


def get_completion(llm_model, tokenizer, prompt: str, max_new_tokens: int = 1024) -> str:
    messages = [{"role": "user", "content": prompt}]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True,
        enable_thinking=False,
    )
    inputs = tokenizer([text], return_tensors="pt").to(llm_model.device)
    with torch.no_grad():
        outputs = llm_model.generate(
            **inputs, max_new_tokens=max_new_tokens,
            do_sample=False, temperature=None, top_p=None,
        )
    output_ids = outputs[0][len(inputs.input_ids[0]):]
    return tokenizer.decode(output_ids, skip_special_tokens=True)


def graph_to_code(llm_model, tokenizer, original_code, original_ast_obj,
                  g_before, g_after) -> str:
    prompt = (
        "You are a coding assistant. Given an original Python code, its AST, "
        "the original CFG, and an updated CFG, generate an updated version of "
        "the code that maintains functionality but aligns with the updated CFG "
        "structure. Adjust control structures like loops and conditionals as needed.\n\n"
        f"Original Code:\n{original_code}\n\n"
        f"Original AST:\n{ast.dump(original_ast_obj, annotate_fields=True, include_attributes=True)}\n\n"
        f"Original CFG:\n{str(g_before)}\n\n"
        f"Updated CFG:\n{str(g_after)}\n\n"
        "Provide the updated Python code."
    )
    try:
        return get_completion(llm_model, tokenizer, prompt).strip()
    except Exception as e:
        print(f"  [graph_to_code error] {e}")
        return original_code


# ---------------------------------------------------------------------------
# Task file parsing
# ---------------------------------------------------------------------------

def extract_prompt_from_task(task_path: str) -> str:
    """Extract the prompt portion (up to # BEGIN SOLUTION) from a CWEval task file."""
    with open(task_path, "r") as f:
        content = f.read()
    if BEGIN_SOLUTION_ANCHOR in content:
        return content[:content.index(BEGIN_SOLUTION_ANCHOR)].rstrip()
    return content.rstrip()


def get_py_task_files(benchmark_dir: str) -> list:
    py_dir = os.path.join(benchmark_dir, "benchmark", "core", "py")
    if not os.path.exists(py_dir):
        raise FileNotFoundError(f"Python benchmark dir not found: {py_dir}")
    files = natsorted([
        os.path.join(py_dir, f)
        for f in os.listdir(py_dir)
        if f.endswith("_task.py")
    ])
    return files


# ---------------------------------------------------------------------------
# PromSec vet_code (same logic as run_promsec_secodeplt.py)
# ---------------------------------------------------------------------------

def vet_code(llm_model, tokenizer, generator, device,
             ci: str, pyg_data, label_encoder: LabelEncoder):
    g_before = extract_graph_from_pyg_data(pyg_data)
    k_bef, _ = calculate_vcs(ci)

    x = pyg_data.x.to(device)
    edge_index = pyg_data.edge_index.to(device)
    embeddings_before, updated_x = generator(x, edge_index)

    num_nodes = updated_x.size(0)
    if edge_index.min() < 0 or edge_index.max() >= num_nodes:
        return ci, k_bef, pyg_data

    g_after = extract_graph_from_pyg_data(Data(x=updated_x, edge_index=edge_index))
    try:
        original_ast_obj = ast.parse(ci)
    except SyntaxError:
        return ci, k_bef, pyg_data

    ci_hat = graph_to_code(llm_model, tokenizer, ci, original_ast_obj, g_before, g_after)
    ci_hat = remove_markdown(ci_hat)

    prompt_inv1 = (
        "Estimate a detailed prompt that could be given to ChatGPT to generate the "
        "following Python code making sure that the code generated is secure and "
        "maintains the same functionality of the code:\n"
    )
    p0 = (
        prompt_inv1 + "[" + ci_hat + "]. "
        "Try to be as specific as possible. The prompt must assure that the code must "
        "be in Python, not any other language. "
        "Do not provide any explanatory text, marks, or comments. Only give the prompt requested."
    )
    p_inext = (
        get_completion(llm_model, tokenizer, p0)
        + ". Do not put any explanatory text, marks, or comments. Only give the source code as a response."
    )
    p_inext = (
        "In your code generation, ensure that sensitive information (secret keys, passwords) "
        "is stored in environment variables not hard-coded. "
        + p_inext
    )
    codei_vetted = get_completion(llm_model, tokenizer, p_inext)
    codei_vetted = remove_markdown(codei_vetted)

    new_pyg = code_to_pyg(codei_vetted, label_encoder)
    if new_pyg is None:
        new_pyg = pyg_data

    return codei_vetted, k_bef, new_pyg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PromSec baseline on CWEval (Python tasks)")
    parser.add_argument("--cweval_dir", type=str,
                        default=os.path.join(PROMSEC_ROOT, "secure_reasoning", "CWEval"),
                        help="Path to CWEval repo root")
    parser.add_argument("--eval_path", type=str, default=None,
                        help="Output directory (default: CWEval/evals/promsec_YYYYMMDD_HHMMSS)")
    parser.add_argument("--n_samples", type=int, default=1,
                        help="Code samples per task (default: 1)")
    parser.add_argument("--iter_num", type=int, default=20,
                        help="PromSec iterations per sample (default: 20)")
    parser.add_argument("--max_tasks", type=int, default=None,
                        help="Limit tasks for smoke test")
    args = parser.parse_args()

    # Output directory (CWEval eval_path format)
    if args.eval_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.eval_path = os.path.join(args.cweval_dir, "evals", f"promsec_qwen3_8b_{ts}")
    os.makedirs(args.eval_path, exist_ok=True)
    print(f"Eval path: {args.eval_path}")

    # Copy pytest.ini (required by CWEval evaluate.py)
    pytest_ini_src = os.path.join(args.cweval_dir, "benchmark", "pytest.ini")
    pytest_ini_dst = os.path.join(args.eval_path, "pytest.ini")
    if os.path.exists(pytest_ini_src) and not os.path.exists(pytest_ini_dst):
        shutil.copy(pytest_ini_src, pytest_ini_dst)

    # ------------------------------------------------------------------
    # Load LLM
    # ------------------------------------------------------------------
    print(f"Loading Qwen3-8B from {MODEL_PATH} ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    llm_model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH, torch_dtype=torch.bfloat16, device_map="auto"
    )
    llm_model.eval()
    device = next(llm_model.parameters()).device
    print(f"LLM loaded on: {device}")

    # ------------------------------------------------------------------
    # Load gGAN
    # ------------------------------------------------------------------
    ggan_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    generator = Generator(IN_FEATS, HIDDEN_FEATS, OUT_FEATS).to(ggan_device)
    generator.load_state_dict(torch.load(GENERATOR_PT, map_location=ggan_device))
    generator.eval()
    print(f"gGAN Generator loaded on: {ggan_device}")
    label_encoder = LabelEncoder()

    # ------------------------------------------------------------------
    # Get Python task files
    # ------------------------------------------------------------------
    task_files = get_py_task_files(args.cweval_dir)
    if args.max_tasks:
        task_files = task_files[:args.max_tasks]
    print(f"Found {len(task_files)} Python tasks")

    # Track results for summary
    results_summary = []

    # ------------------------------------------------------------------
    # Process each task × n_samples
    # ------------------------------------------------------------------
    for task_path in task_files:
        task_name = os.path.basename(task_path).replace("_task.py", "")
        test_path = task_path.replace("_task.py", "_test.py")
        print(f"\n[Task] {task_name}")

        prompt = extract_prompt_from_task(task_path)

        for sample_idx in range(args.n_samples):
            out_py_dir = os.path.join(
                args.eval_path, f"generated_{sample_idx}", "core", "py"
            )
            os.makedirs(out_py_dir, exist_ok=True)

            # Copy test file
            if os.path.exists(test_path):
                shutil.copy(test_path, os.path.join(out_py_dir, os.path.basename(test_path)))

            raw_out_path = os.path.join(out_py_dir, f"{task_name}_raw.py")

            # Step 1: Generate initial code from task prompt
            gen_prompt = (
                f"{prompt}\n\n"
                "Implement the function above in Python. "
                "Output the code in a markdown code block (```python ... ```)."
            )
            print(f"  [sample {sample_idx}] Generating initial code ...")
            try:
                og_response = get_completion(llm_model, tokenizer, gen_prompt, max_new_tokens=2048)
                og_code = remove_markdown(og_response)
                if not og_code.strip():
                    og_code = og_response
            except Exception as e:
                print(f"  [SKIP] Initial generation failed: {e}")
                continue

            k_og, cwes_og = calculate_vcs(og_code)
            print(f"  Initial CWEs: {k_og} {cwes_og}")

            # Step 2: PromSec vet_code loop
            pyg_data = code_to_pyg(og_code, label_encoder)
            ci = og_code
            k_cur = k_og

            if pyg_data is not None:
                for iteration in range(args.iter_num):
                    print(f"  iter {iteration}: CWEs={k_cur}", end="")
                    if k_cur == 0:
                        print(" → secure, stopping.")
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
            else:
                print("  [warn] CFG conversion failed, using initial code")

            # Step 3: Save as CWEval raw format
            # CWEval evaluate.py expects raw LLM response with code in markdown block
            raw_content = f"```python\n{ci}\n```"
            with open(raw_out_path, "w") as f:
                f.write(raw_content)

            results_summary.append({
                "task": task_name,
                "sample": sample_idx,
                "og_cwe_count": k_og,
                "final_cwe_count": k_cur,
                "security_improved": k_cur < k_og,
            })
            print(f"  Saved → {raw_out_path} (CWEs: {k_og} → {k_cur})")

    # ------------------------------------------------------------------
    # Save summary
    # ------------------------------------------------------------------
    summary_path = os.path.join(args.eval_path, "promsec_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results_summary, f, indent=2)

    n = len(results_summary)
    if n > 0:
        og_avg = sum(r["og_cwe_count"] for r in results_summary) / n
        fin_avg = sum(r["final_cwe_count"] for r in results_summary) / n
        improved = sum(1 for r in results_summary if r["security_improved"])
        print("\n" + "=" * 60)
        print(f"Tasks processed    : {n}")
        print(f"Avg initial CWEs   : {og_avg:.2f}")
        print(f"Avg final CWEs     : {fin_avg:.2f}")
        print(f"Security improved  : {improved}/{n} ({improved/n:.1%})")
        print("=" * 60)
        print(f"\nSummary saved → {summary_path}")
        print(f"\nNow run CWEval evaluation:")
        print(f"  docker run --rm -it --net host \\")
        print(f"    -v {args.cweval_dir}:/home/ubuntu/CWEval \\")
        print(f"    co1lin/cweval zsh -c \\")
        print(f'    "cd /home/ubuntu/CWEval && source .env && \\')
        print(f'     python cweval/evaluate.py pipeline --eval_path {os.path.relpath(args.eval_path, args.cweval_dir)} --num_proc 8 --docker False"')


if __name__ == "__main__":
    main()
