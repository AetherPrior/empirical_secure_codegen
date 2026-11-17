# CoSec on the plain benchmarks

CoSec co-decodes a target model with a security expert (a LoRA on a small model), so it cannot run
on vLLM. `run_cosec_plain.py` replaces only the generation step of `benchmarks/run_plain_vllm.py`.
Prompts come from that runner's `build_cases`, and scoring runs through its unmodified
`--operation evaluate`, so scores are comparable with the other plain runs.

| File | Purpose |
|---|---|
| `launch_all.sh` | Runs prepare, generation shards, merge and scoring for each benchmark and variant |
| `run_cosec_plain.py` | Prepares `cases.json`, generates one shard, merges shards into `generations.jsonl` |
| `cosec_generate.py` | The co-decoding sampler (`cosec_sample`) |

## Run

From the repo root on our server:

```bash
# Repaired only (default)
bash baselines/cosec/launch_all.sh <results_dir>

# Original, copying rows for unchanged prompts from existing repaired runs
VARIANTS=original REUSE_ROOT=/workspace/cosec_results/full \
    bash baselines/cosec/launch_all.sh <results_dir>
```

Each run writes `<results_dir>/<benchmark>_<variant>/`, including `generations.jsonl`, `summary.json`
and the `evaluation/` output. Progress is printed to stdout, so use `nohup` for a long run.
Rerunning the same command resumes: finished generations are kept and scored stages are skipped.

| Variable | Default | Meaning |
|---|---|---|
| `GPUS` | `0 1 2` | GPUs to use |
| `PER_GPU` | `3` | Processes per GPU, at about 18 GB each |
| `BENCHMARKS` | `cweval seccodeplt baxbench` | Benchmarks to run |
| `VARIANTS` | `repaired` | `original`, `repaired`, or both |
| `REUSE_ROOT` | `<results_dir>` | Where to look for `<benchmark>_<other variant>/` to reuse rows from |
| `BAXBENCH_PORT_BASE` | `27000` | Start of the BaxBench port range; change it if another evaluation is running |
| `PY_COSEC` | `/workspace/PromSec/.venv/bin/python` | Generation environment |
| `PY312` | `/opt/conda/envs/vllm/bin/python` | Prepare and scoring environment |

The two environments are separate on purpose. The BaxBench sources need Python 3.12, but the `vllm`
environment failed to load the LoRA because of a peft/torchao conflict from the `~/.local` packages.
`cases.json` connects them.
The generation environment uses Python 3.10, torch 2.6.0+cu124, transformers 4.51.3 and peft 0.19.1.

## Settings

| Setting | Value | Flag on `run_cosec_plain.py` |
|---|---|---|
| Target model | `/workspace/models/Qwen3-8B` | `--target-model` |
| Expert base model | `/workspace/models/Qwen3-0.6B` | `--lora-base` |
| Expert LoRA | `/workspace/CoSec/trained/qwen3-0.6b/checkpoint-last-lora-only` | `--lora-path` |
| Seeds | 42, 43, 44 | `--seeds` |
| Temperature (target and expert) | 0.6 | `--temperature`, `--expert-temperature` |
| Top-p | 0.95 | `--top-p` |
| CoSec threshold | 0.3 | `--threshold` |
| Max new tokens | 4096 (the vLLM runner defaults to 16384) | `--max-tokens` |
| Thinking | off | `--enable-thinking` |

`launch_all.sh` does not pass these flags, so these defaults apply. To change one, run
`run_cosec_plain.py` directly; its docstring shows the commands for each step.

## Notes

- **Speed:** CoSec generates one sequence at a time, so parallelism comes only from shards. Nine
  processes on three GPUs generated about 0.3–0.4 sequences per second on CWEval and SecCodePLT, and
  about 0.1 on BaxBench, whose outputs are about three times longer.
- **Reuse:** rows are matched on the SHA-256 of the prompt messages and the seed, so only
  byte-identical prompts are copied. Copied rows have `reused: true`.
- **Seeding:** each generation is seeded separately, so its output does not depend on shard order.
- **Truncation:** rows that hit the token limit have `finish_reason: "length"` and are still scored.
  `merge.log` reports how many there were.
