#!/usr/bin/env bash
# Score SVEN generations already on disk: CWEval + BaxBench (repaired) and the fuzzed CWEval rescore. SecCodePLT is scored once generation completes.
REPO=/workspace/verisec; cd $REPO
PY=/opt/conda/envs/vllm/bin/python
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
port=38000
for m in orig ours; do
  D=$REPO/baselines/SafeCoder/sven_eval/$m; L=sven-$m
  COMMON=(--slice main --model $L --model-label $L --variant repaired --temperature 0.6 --top-p 0.95 --max-tokens 16384 --enable-thinking --eval-workers 32 --seeds 42 --operation evaluate)
  $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark cweval --out $D/cweval > $D/cweval_eval.log 2>&1; echo "$m cweval rc=$?"
  mkdir -p $D/fuzzed_rescore/cweval; cp $D/cweval/generations.jsonl $D/fuzzed_rescore/cweval/
  $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model $L --model-label $L --benchmark cweval --variant repaired --out $D/fuzzed_rescore/cweval \
    --benchmarks-root "$ROOT" --seeds 42 --eval-workers 32 --operation evaluate > $D/fuzzed_rescore/cweval/rescore.log 2>&1; echo "$m cweval fuzz rc=$?"
  $PY benchmarks/run_plain_vllm.py "${COMMON[@]}" --benchmark baxbench --baxbench-port-base $port --out $D/baxbench > $D/baxbench_eval.log 2>&1; echo "$m baxbench rc=$?"
  port=$((port+4000))
done
echo SCORED_MAIN
