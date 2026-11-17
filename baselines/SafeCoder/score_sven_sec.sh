#!/usr/bin/env bash
REPO=/workspace/verisec; cd $REPO
PY=/opt/conda/envs/vllm/bin/python
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
for m in orig ours; do
  D=$REPO/baselines/SafeCoder/sven_eval/$m; L=sven-$m
  COMMON=(--slice main --model $L --model-label $L --variant repaired --temperature 0.6 --top-p 0.95 --max-tokens 16384 --enable-thinking --eval-workers 32 --seeds 42 --operation evaluate)
  $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark seccodeplt --out $D/seccodeplt > $D/seccodeplt_eval.log 2>&1; echo "$m seccodeplt rc=$?"
  mkdir -p $D/fuzzed_rescore/seccodeplt; cp $D/seccodeplt/generations.jsonl $D/fuzzed_rescore/seccodeplt/
  $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model $L --model-label $L --benchmark seccodeplt --variant repaired --out $D/fuzzed_rescore/seccodeplt \
    --benchmarks-root "$ROOT" --seeds 42 --eval-workers 32 --operation evaluate > $D/fuzzed_rescore/seccodeplt/rescore.log 2>&1; echo "$m seccodeplt fuzz rc=$?"
done
echo SCORED_SEC
