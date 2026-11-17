#!/usr/bin/env bash
# purpcode-32b-rule-sft on the plain benchmarks, six arms spread over GPUs 1-3.
# Same frozen parameters and the same canonical runner as run_plain_vllm.sh (which is pinned to GPU 0).
# Usage: bash baselines/purpcode/run_sft_parallel.sh <run_id>
set -uo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
PY=${PYTHON:-/opt/conda/envs/vllm/bin/python}
MODEL=${MODEL:-$REPO/dataset_curation/verl/models/purpcode-32b-rule-sft}
RUN=$REPO/baselines/purpcode/outputs/${1:?run id}; mkdir -p "$RUN"
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0
arm() {  # gpu benchmark variant port
  CUDA_VISIBLE_DEVICES=$1 $PY benchmarks/run_plain_vllm.py --model "$MODEL" --model-label purpcode-32b-rule-sft \
    --seeds 42 43 44 --temperature 0.6 --top-p 0.95 --max-tokens 16384 --tp 1 --dtype bfloat16 \
    --concurrency 64 --gpu-memory-utilization 0.9 --max-model-len 24576 --eval-workers 32 --baxbench-port-base $4 \
    --benchmark $2 --variant $3 --out "$RUN/${2}_${3}" >> "$RUN/${2}_${3}.log" 2>&1
}
( arm 1 seccodeplt original 27000; arm 1 baxbench original 27000 ) &
( arm 2 seccodeplt repaired 28000; arm 2 baxbench repaired 28000 ) &
( arm 3 cweval original 29000; arm 3 cweval repaired 29000 ) &
wait; echo "$(date -u +%FT%TZ) ALL_FINISHED" >> "$RUN/launch.log"
