#!/usr/bin/env bash
# Step-600 PurpCode-32B outcome-only RL (LoRA, merged) on the repaired benchmarks.
# Phase 1: generation, two TP=2 vLLM instances in parallel (GPUs 0,1 and 2,3).
# Phase 2: CPU/container evaluation, kept small because the host is shared.
# Sampling matches the other plain-vLLM baselines: seeds 42-44, T=0.6, top_p=0.95, 16384 tokens.
# The model is non-thinking (Qwen2.5 template), so --enable-thinking is not passed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY=/opt/conda/envs/vllm/bin/python
MODEL="$HERE/checkpoints/global_step_600_merged"
LABEL=purpcode32b_outcome_rl_step600
EVAL_WORKERS="${EVAL_WORKERS:-32}"
cd "$ROOT"

run() {  # run <gpus> <benchmark> <operation>
  local gpus="$1" bench="$2" op="$3" out="$HERE/outputs/repaired/$2"
  mkdir -p "$out" "$HERE/outputs/cache/gpu${gpus//,/}"
  CUDA_VISIBLE_DEVICES="$gpus" CUDA_DEVICE_ORDER=PCI_BUS_ID HF_HOME=/workspace/hf_home \
  PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TOKENIZERS_PARALLELISM=false OMP_NUM_THREADS=4 \
  VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 \
  VLLM_CACHE_ROOT="$HERE/outputs/cache/gpu${gpus//,/}/vllm" \
  TORCHINDUCTOR_CACHE_DIR="$HERE/outputs/cache/gpu${gpus//,/}/inductor" \
  TRITON_CACHE_DIR="$HERE/outputs/cache/gpu${gpus//,/}/triton" \
  "$PY" -B "$HERE/evaluation/run_plain_vllm.py" --model "$MODEL" --model-label "$LABEL" \
    --benchmark "$bench" --variant repaired --out "$out" --operation "$op" \
    --benchmarks-root "$ROOT/benchmarks" --seeds 42 43 44 --tp 2 \
    --temperature 0.6 --top-p 0.95 --max-tokens 16384 --max-model-len 24576 \
    --concurrency 256 --gpu-memory-utilization 0.9 --eval-workers "$EVAL_WORKERS" \
    >> "$out/${op}.log" 2>&1
  echo "$(date -u +%FT%TZ) $bench $op rc=$?" >> "$HERE/outputs/campaign.log"
}

echo "$(date -u +%FT%TZ) start" >> "$HERE/outputs/campaign.log"
( run 0,1 cweval generate; run 0,1 baxbench generate ) &
( run 2,3 seccodeplt generate ) &
wait
for b in cweval baxbench seccodeplt; do run 0,1 "$b" evaluate; done
echo "$(date -u +%FT%TZ) done" >> "$HERE/outputs/campaign.log"
