# PurpCode Plain-vLLM Baseline

This directory is a thin, reproducible adapter for the repository's canonical
`benchmarks/run_plain_vllm.py` runner. It does not reimplement PurpCode or any
benchmark evaluator.

## Scope requested by the authors

The canonical runner already selects exactly the requested languages:

- SecCodePLT: Python, 819 tasks.
- CWEval: C, C++, Python, and JavaScript, 100 tasks total.
- BaxBench: Python and JavaScript only.

All three benchmarks run against both `original` and `repaired`, producing six
separate trace sets.

## Frozen generation parameters

These match the defaults in `benchmarks/run_plain_vllm.py`:

- seeds: `42 43 44`
- temperature: `0.6`
- top-p: `0.95`
- max generation tokens: `16384`
- dtype: `bfloat16`
- tensor parallelism: `1`
- concurrency: `64`
- GPU memory utilization: `0.9`
- SecCodePLT evaluator workers: `64`
- thinking mode: model chat-template default

The wrapper intentionally spells these values out so a later change to runner
defaults cannot silently change this baseline.

## Server preflight

The wrapper first runs `preflight.py`. This is a read-only check that fails
before model loading unless all of the following are true:

- `CUDA_VISIBLE_DEVICES=0` and GPU 0 has no active compute process.
- the selected Python imports `vllm`, `transformers`, and the Docker SDK.
- the Docker daemon is available to the current user.
- the exact pinned Python, Node, and CWEval evaluator image IDs are present.

The preflight prints pull candidates for missing images. A pulled CWEval image
must still match the repository's pinned image ID; do not rewrite the pin to
accept a different image.

Run it independently with:

```bash
CUDA_VISIBLE_DEVICES=0 \
python baselines/purpcode/preflight.py
```

## Smoke test on GPU 0

```bash
cd /path/to/secure_reasoning

CUDA_VISIBLE_DEVICES=0 \
RUN_ID=purpcode_plain_smoke \
LIMIT=2 \
bash baselines/purpcode/run_plain_vllm.sh
```

## Full run on GPU 0

```bash
CUDA_VISIBLE_DEVICES=0 \
RUN_ID=purpcode_plain_full_YYYYMMDD \
bash baselines/purpcode/run_plain_vllm.sh
```

`PYTHON`, `RESULTS_BASE`, and `MODEL` may be overridden. Do not override the
frozen generation parameters without first agreeing on a new protocol.

## Outputs

```text
artifacts/baselines/purpcode/<RUN_ID>/
  baseline_config.json
  seccodeplt_original/
    generations.jsonl
    evaluation/scores.json
    summary.json
  seccodeplt_repaired/
  cweval_original/
  cweval_repaired/
  baxbench_original/
  baxbench_repaired/
  analysis/
    summary.csv
    summary.json
    manifest.json
```

`generations.jsonl` is the original trace file to give the authors for each arm.
Each output directory also freezes the exact benchmark source used by that run.

The canonical runner incrementally appends completed generations. Re-running
the wrapper with the same `RUN_ID` resumes missing generations and skips arms
that already have a completed `summary.json`.
