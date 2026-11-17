#!/usr/bin/env bash
# ProSec-DPO / SafeCoder Qwen3-8B evaluated WITHOUT thinking (the models were tuned without thinking), repaired benchmarks + extras, then repaired+fuzzed rescore.
# Usage: run_prosec_nothink.sh <run id> [merged model dir name] [label]
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
PY=/opt/conda/envs/vllm/bin/python
MODEL=$REPO/baselines_extended/dpo/outputs/prosec_merged_eval/${2:-qwen3_8b_prosec_merged}
LABEL=${3:-qwen3-8b-prosec-dpo}
RUN=$REPO/baselines_extended/dpo/outputs/prosec_merged_eval/${1:?run id}; mkdir -p "$RUN"
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
COMMON=(--slice main --model "$MODEL" --model-label $LABEL --variant repaired --temperature 0.6 --top-p 0.95 --max-tokens 16384 --tp 1 --dtype bfloat16
        --concurrency 64 --gpu-memory-utilization 0.9 --max-model-len 24576 --no-enable-thinking --eval-workers 32)
for s in 42 43 44; do
  g=$((s-42)); CUDA_VISIBLE_DEVICES=$g $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark seccodeplt --seeds $s --operation generate --out "$RUN/seccodeplt_s$s" >> "$RUN/seccodeplt_s$s.log" 2>&1 &
done
( for b in cweval baxbench; do CUDA_VISIBLE_DEVICES=3 $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark $b --seeds 42 43 44 --baxbench-port-base 31000 --out "$RUN/$b" >> "$RUN/$b.log" 2>&1; done
  # tasks outside Python/C/C++/JavaScript (CWEval Go, BaxBench Go/PHP/Ruby/Rust): generation only
  for b in cweval baxbench; do CUDA_VISIBLE_DEVICES=3 $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark $b --seeds 42 43 44 --extra --operation generate --out "$RUN/extra_$b" >> "$RUN/extra_$b.log" 2>&1; done ) &
wait
mkdir -p "$RUN/seccodeplt"; cat "$RUN"/seccodeplt_s4{2,3,4}/generations.jsonl > "$RUN/seccodeplt/generations.jsonl"
$PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark seccodeplt --seeds 42 43 44 --operation evaluate --out "$RUN/seccodeplt" > "$RUN/seccodeplt_eval.log" 2>&1
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
for b in seccodeplt cweval; do
  out=$RUN/fuzzed_rescore/$b; mkdir -p "$out"; cp "$RUN/$b/generations.jsonl" "$out/generations.jsonl"
  $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model $LABEL --model-label $LABEL --benchmark $b --variant repaired \
    --out "$out" --benchmarks-root "$ROOT" --seeds 42 43 44 --eval-workers 32 --operation evaluate > "$out/rescore.log" 2>&1; echo "$b fuzz rc=$?"
done
echo "$(date -u +%FT%TZ) ALL_FINISHED" >> "$RUN/launch.log"
