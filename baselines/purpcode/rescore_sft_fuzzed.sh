#!/usr/bin/env bash
# Score the purpcode-32b-rule-sft repaired generations on the repaired + fuzzed benchmarks
# (same root and runner as benchmarks_fuzzed/rescore_generations.py). Usage: bash rescore_sft_fuzzed.sh <run_id>
set -u
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
RUN=$REPO/baselines/purpcode/outputs/${1:?run id}
PY=/opt/conda/envs/vllm/bin/python
RUNNER=$REPO/baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
export PYTHONDONTWRITEBYTECODE=1 PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
for b in seccodeplt cweval; do
  out=$RUN/fuzzed_rescore/$b; mkdir -p "$out"; cp "$RUN/${b}_repaired/generations.jsonl" "$out/generations.jsonl"
  $PY $RUNNER --model purpcode-32b-rule-sft --model-label purpcode-32b-rule-sft --benchmark $b --variant repaired --out "$out" \
     --benchmarks-root "$ROOT" --seeds 42 43 44 --eval-workers 32 --operation evaluate > "$out/rescore.log" 2>&1
  echo "$b rc=$?"; python3 - "$out/summary.json" <<'PYEOF'
import json,sys; s=json.load(open(sys.argv[1])); print({k:round(v,4) for k,v in s['mean'].items()}, {k:round(v,4) for k,v in s.get('sd',{}).items()})
PYEOF
done
