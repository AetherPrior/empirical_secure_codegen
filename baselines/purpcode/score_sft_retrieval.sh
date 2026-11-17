#!/usr/bin/env bash
# After run_sft_retrieval.sh: merge seed shards, score repaired (plain), then rescore repaired+fuzzed. Usage: score_sft_retrieval.sh <run id>
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
RUN=$REPO/baselines/purpcode/outputs/${1:?run id}
PY=/opt/conda/envs/vllm/bin/python
export PYTHONDONTWRITEBYTECODE=1 PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
mkdir -p "$RUN/seccodeplt"; cat "$RUN"/seccodeplt_s4{2,3,4}/generations.jsonl > "$RUN/seccodeplt/generations.jsonl"
for b in seccodeplt cweval baxbench; do
  $PY benchmarks/run_plain_vllm.py --model purpcode-32b-rule-sft+retrieval --model-label purpcode-32b-rule-sft --benchmark $b --variant repaired \
    --out "$RUN/$b" --operation evaluate --eval-workers 32 --baxbench-port-base 27000 > "$RUN/${b}_eval.log" 2>&1; echo "$b plain rc=$?"
done
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
for b in seccodeplt cweval; do
  out=$RUN/fuzzed_rescore/$b; mkdir -p "$out"; cp "$RUN/$b/generations.jsonl" "$out/generations.jsonl"
  $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model purpcode-32b-rule-sft+retrieval --model-label purpcode-32b-rule-sft --benchmark $b --variant repaired \
    --out "$out" --benchmarks-root "$ROOT" --seeds 42 43 44 --eval-workers 32 --operation evaluate > "$out/rescore.log" 2>&1; echo "$b fuzz rc=$?"
done
