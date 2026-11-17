#!/usr/bin/env bash
# Qwen3-8B base without thinking on the extra-language tasks (Table 5 has a no-think base row). Waits for a free GPU.
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"; OUT=$REPO/baselines_extended/extra_runs/qwen3-8b-nothink
PY=/opt/conda/envs/vllm/bin/python
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
free() { for k in 1 2 3; do [ "$(nvidia-smi -i $1 --query-gpu=memory.used --format=csv,noheader,nounits | tr -d ' ')" -lt 2000 ] || return 1; sleep 20; done; }
until for g in 0 1 2 3; do free $g && { gpu=$g; break; }; done; [ -n "${gpu:-}" ]; do sleep 60; done
for b in cweval baxbench; do mkdir -p $OUT/extra_$b
  CUDA_VISIBLE_DEVICES=$gpu $PY benchmarks/run_plain_vllm.py --model Qwen/Qwen3-8B --model-label qwen3-8b-nothink --variant repaired --temperature 0.6 --top-p 0.95 \
    --max-tokens 16384 --tp 1 --dtype bfloat16 --concurrency 64 --gpu-memory-utilization 0.9 --max-model-len 24576 --no-enable-thinking \
    --benchmark $b --seeds 42 43 44 --extra --operation generate --out $OUT/extra_$b >> $OUT/extra_$b.log 2>&1
  echo "$(date -u +%FT%TZ) qwen3-8b-nothink $b rc=$?" >> baselines_extended/extra_runs/queue.log
done
