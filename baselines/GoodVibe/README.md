# GoodVibe Qwen3-8B reproduction

Source: [official USENIX artifact](https://zenodo.org/records/20412229),
[paper](https://arxiv.org/abs/2602.10778). The artifact has source code but no
trained checkpoints. `upstream/` is an unmodified, checksum-verified archive;
`record.json` includes file checksums and provenance.

GPU entrypoints allow physical GPUs 2 and 3, with tensor parallelism 1 per worker.
The current allocation in `configs/scheduling.json` assigns Python to GPU 2 and
C++ followed by JavaScript to GPU 3. GPUs 0 and 1 are unused. Configs,
logs, trained models and benchmark results remain under `baselines/GoodVibe/`; implementation lives here as well. The
isolated `.venv` inherits the existing torch installation and pins transformers
4.57.1, TRL 0.24.0 and datasets 3.3.2 to match the artifact. It does not change
the shared vLLM environment.
Evaluation sets `VLLM_USE_FLASHINFER_SAMPLER=0` because FlashInfer sampling
requires an unavailable `nvcc` here; vLLM's PyTorch sampler is used instead.
It also sets `VLLM_USE_DEEP_GEMM=0` to bypass a broken optional FP8-kernel warmup
in the installed vLLM; these models use BF16 weights.

## Training

`configs/{cpp,py,js}.json` pin the base model and CyberNative dataset revisions.
Each language has 424 safe/unsafe pairs: selection uses 848 snippets, and SFT
uses the 424 safe responses, shuffled and split 90/10 with seed 42 as upstream.
The dataset has no C subset. Python and JavaScript use the same released
per-language method; the paper's main reported languages are C++ and Java.

The runner calls the authors' clustered tuning implementation directly:
top 50 activation-gradient-ranked rows per linear layer, KMeans/silhouette
clustering, frozen base weights and shared additive updates per cluster.
It tunes attention q/k/v/o and MLP gate/up projections, matching their code.
Two epochs, learning rate 1e-4, batch size 1, accumulation 4, cosine schedule,
10% warmup, weight decay .01, BF16, full-sequence SFT loss, max length 1024
(TRL 0.24 default), epoch validation and best-loss checkpoint selection.
The final clustered updates are folded into ordinary HF weights for vLLM.

Adaptations and corrections are explicit:

- Selector uses tokenizer IDs for `0` and `1`. The artifact incorrectly uses
  `ord('0')` and `ord('1')` as vocabulary IDs. Set `label_token_mode` to
  `upstream_ascii` in a **new output directory** for exact buggy behavior.
- Frozen weights plus input gradients preserve activation derivatives while
  avoiding unused weight-gradient allocations. Running gradient sums replace
  storing every sample's gradients. Identification is resumable every 25 rows.
- BF16, gradient checkpointing, last-position-only logits, and SDPA make
  identification practical on one H100. cuDNN SDPA is disabled because its
  planner fails on this host; PyTorch SDPA remains enabled.
- TRL `SFTConfig` makes the training defaults explicit. Validation batch size
  is 1 for GPU memory. Checkpoint resume is enabled. No LoRA is substituted.
- The authors' regex comment stripping is retained, including its limitations.
  Their training targets contain code, not reasoning traces. The dataset's
  safety labels are used as supplied, not independently verified.

## Evaluation

`configs/evaluation.json` uses original benchmark variants, seeds 42/43/44,
temperature .6, top-p .95, 16,384 output tokens, and **thinking enabled**.
The released inference helper disables thinking but the paper provides no
claim that thinking is inappropriate. This is an intentional inference change.

| Checkpoint | Evaluations |
| --- | --- |
| Python | SecCodePLT Python (819), CWEval Python (25), BaxBench Python (112) |
| JavaScript | CWEval JS (23), BaxBench JS (112) |
| C++ | CWEval C++ (21) and C (31) |

**C results are transfer from C++ training**, not a separately C-trained model.
No benchmark data is used for tuning. Benchmark generation and evaluation use
the baseline-local `evaluation/run_plain_vllm.py` with explicit language filtering.
The shared `benchmarks/` tree is treated as read-only. Its sources are copied into
`outputs/` before evaluation; configs, environment, checkpoints, logs, caches
created by this baseline, and results all belong under this baseline directory.
The earlier edit to `benchmarks/run_plain_vllm.py` has been restored.

Language-specific jobs are execution details. `aggregate.py` pools their task-level
scores into **one report per benchmark**, computing each seed's metrics over all
tasks before taking the mean and standard deviation across seeds. It never
equally averages language percentages. Combined reports appear under
`baselines/GoodVibe/outputs/combined/` only when all required language jobs are
complete. The launcher refreshes these reports after each evaluation job.

The Python/JavaScript artifact naming mismatch has been fixed: directory names
now follow upstream's `python` and `javascript` names, while campaign identifiers
remain `py` and `js`. Existing completed neuron-selection artifacts were renamed
and reused without recomputation.

## Repaired-set evaluation

`configs/evaluation_repaired.json` evaluates the existing trained checkpoints on
the repaired sources. It retains thinking, seeds 42/43/44, temperature .6,
top-p .95 and the 16,384-token generation limit. Generation concurrency is 128
per GPU, with 92% GPU memory utilization. Evaluation uses 64 workers per process
for all three benchmarks; BaxBench reserves two ports per worker.

GPU 2 handles SecCodePLT. GPU 3 handles CWEval and BaxBench across all requested
languages, including their Python tasks. Results and combined benchmark summaries
are isolated in `outputs/repaired/`, preserving original-set results. Repaired
BaxBench uses port base 42000, separate from the original campaign's ports.

```bash
python baselines/GoodVibe/run.py --gpu 2 --evaluation-only --eval-config baselines/GoodVibe/configs/evaluation_repaired.json --output-dir baselines/GoodVibe/outputs/repaired
python baselines/GoodVibe/run.py --gpu 3 --evaluation-only --eval-config baselines/GoodVibe/configs/evaluation_repaired.json --output-dir baselines/GoodVibe/outputs/repaired
```

## Commands

From the repository root:

```bash
# One-time environment setup (already performed on this host):
/opt/conda/envs/vllm/bin/python -m venv --system-site-packages baselines/GoodVibe/.venv
baselines/GoodVibe/.venv/bin/pip install -r baselines/GoodVibe/requirements.txt

baselines/GoodVibe/.venv/bin/python baselines/GoodVibe/test_method.py
python baselines/GoodVibe/run.py --dry-run
python -u baselines/GoodVibe/run.py
```

For the current two-GPU allocation, launch these workers separately:

```bash
python -u baselines/GoodVibe/run.py --gpu 3 --languages cpp js
python -u baselines/GoodVibe/run.py --gpu 2 --languages py
```

GPU and language locks prevent overlapping workers. Each worker has its own
`baselines/GoodVibe/outputs/status_gpu{2,3}.json`, process ID file, and campaign log. BaxBench uses
separate port ranges (36000 on GPU 3, 37000 on GPU 2). Direct `train.py` calls
default to GPU 3; set `GOODVIBE_GPU=2` to select GPU 2.

Each worker trains its assigned languages sequentially, then runs their
benchmark/language jobs (seven in total). Inspect `baselines/GoodVibe/outputs/status.json`,
the per-GPU status files, and `baselines/GoodVibe/outputs/logs/`.
Rerunning resumes identification and training; completed training is skipped.
Evaluation generations are reused by the existing runner.

For the real-model smoke test (separate output, not benchmark results):

```bash
baselines/GoodVibe/.venv/bin/python baselines/GoodVibe/train.py --config baselines/GoodVibe/configs/smoke.json --stage identify
baselines/GoodVibe/.venv/bin/python baselines/GoodVibe/train.py --config baselines/GoodVibe/configs/smoke.json --stage tune
```
