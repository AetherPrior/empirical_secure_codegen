# PromSec

`run_promsec_plain.py` and `launch_all.sh` run PromSec on the plain benchmarks. The other scripts are
the May snapshot, copied unchanged; the plain runner imports `vet_code` from `run_promsec_secodeplt.py`.

## Plain benchmarks

```bash
bash baselines/promsec/launch_all.sh <results_dir>   # GPUs 0 and 2 by default; see the script header
```

- **Tasks:** Python only: CWEval 25, SecCodePLT 819, BaxBench 112, each with seeds 42, 43, 44.
- **First generation:** the prompts from `benchmarks/run_plain_vllm.py`, Qwen3-8B, temperature 0.6,
  top-p 0.95, 4096 tokens, thinking off.
- **Vet loop:** runs when Bandit flags the first generation, up to 20 iterations of 3 LLM calls.
- **Django:** multi-file answers skip the vet loop (`vet_skipped`), because it regenerates one file.
- **Reuse:** identical prompts reuse generations between the original and repaired variants.

### Behavior to expect

- BaxBench requires binding to `0.0.0.0:5000`, and Bandit reports that as CWE-605. The loop removes
  the binding, so vetted servers usually do not start and BaxBench functionality comes out at 0.
- The loop regenerates code from an estimated prompt, so vetted code often stops implementing the task.
- A generated CWEval module that calls `exit()` on import would abort pytest for its whole seed.
  `contain_import_exit` turns that into an import failure for that task alone.
- When a `graph_to_code` prompt exceeds the context length, vLLM returns 400 and the May code keeps
  the previous code for that step.

### Scoring the first generation

To score the code before the vet loop, use a separate folder, because `--evaluate` writes `evaluation/`
and `summary.json` into `--out`. Copy `frozen/`, `cases.json`, `generations.jsonl` and the pin files
(`container_images.json`, `preflight.json`, `seccodeplt_requirements.json`) there, then run:

```bash
$PY312 baselines/promsec/run_promsec_plain.py --benchmark cweval --variant repaired \
    --out <new_folder> --evaluate --column initial_answer
```

## May snapshot

These scripts produced the May numbers and do not use the repaired benchmarks.

Pipeline: generate code with Qwen3-8B (greedy, one sample), then run the PromSec `vet_code` loop
(gGAN plus LLM fixes, guided by Bandit), up to 20 iterations by default. Because Bandit only scans
Python, the method does not carry over to the C, C++ or JavaScript tasks as written.

## Run location

The scripts do not run from this folder. They resolve paths from `PromSec/script/` and need the
upstream repo's `utils_new.py` and `trained_*_model.pt`, plus a `secure_reasoning/` benchmark checkout.
The working copy is `/workspace/PromSec` on our server, with `*.py` in `script/` and `*.sh` at its root.

| File | Purpose |
|---|---|
| `docker_run.sh` | Generation in the `verlai/verl:vllm018.dev1` container (`--benchmark seccodeplt` or `cweval`) |
| `docker_run_cweval_full.sh` | CWEval generation, then scoring in `co1lin/cweval` |
| `docker_evaluate.sh` | SecCodePLT scoring with the SeCode-Eval harness |
| `docker_setup.sh` | Installs dependencies in a long-running `verl_vllm18` container |
| `run_promsec_secodeplt.py` | SecCodePLT generation and vet loop |
| `run_promsec_rerun_vet.py` | Reruns the vet loop on an existing SecCodePLT CSV; produced the `vetfixed` results |
| `run_promsec_cweval.py` | CWEval generation and vet loop (Python tasks) |
| `run_promsec_cyberseceval.py` | CyberSecEval Instruct generation and vet loop (Python subset) |
| `evaluate_promsec_secodeplt.py` | SecCodePLT scoring |
| `eval_cyberseceval_icd.py` | CyberSecEval scoring with the Insecure Code Detector |
| `paths.py` | Resolves the PromSec root |

## Stored results on our server

| Benchmark | Path | Contents |
|---|---|---|
| SecCodePLT (819 tasks) | `/workspace/eval_results/secodeplt/promsec_qwen3_vetfixed/` | `results.csv` (`og_code`, `final_code`) and scored CSV |
| CWEval (Python, 25 tasks) | `/workspace/eval_results/cweval_python/promsec_qwen3_2048/` | `generated_0/`, `res_all.json` |
| CyberSecEval (Python) | `/workspace/PromSec/results_promsec_cyberseceval/` | `responses.json`, scores |

For CyberSecEval, use `scored_semgrep151*`. The `summary.json` numbers used semgrep 1.164.0, while
PurpleLlama pins 1.51.0, and the score changes a lot (Python secure rate 98.94 vs 88.65).
