#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PYTHON="${PYTHON:-python}"
MODEL="${MODEL:-purpcode/purpcode-32b-rl}"
RUN_ID="${RUN_ID:-purpcode_plain_$(date -u +%Y%m%dT%H%M%SZ)}"
RESULTS_BASE="${RESULTS_BASE:-$REPO_ROOT/artifacts/baselines/purpcode}"
RUN_DIR="$RESULTS_BASE/$RUN_ID"
LIMIT="${LIMIT:-}"

if [[ "${CUDA_VISIBLE_DEVICES:-}" != "0" ]]; then
  echo "This baseline is configured for GPU 0; set CUDA_VISIBLE_DEVICES=0." >&2
  exit 1
fi

if [[ ! -f "$REPO_ROOT/benchmarks/run_plain_vllm.py" ]]; then
  echo "Missing canonical runner: $REPO_ROOT/benchmarks/run_plain_vllm.py" >&2
  exit 1
fi

"$PYTHON" "$SCRIPT_DIR/preflight.py"

mkdir -p "$RUN_DIR" "$RUN_DIR/analysis"

LIMIT_ARGS=()
if [[ -n "$LIMIT" ]]; then
  if ! [[ "$LIMIT" =~ ^[1-9][0-9]*$ ]]; then
    echo "LIMIT must be a positive integer." >&2
    exit 1
  fi
  LIMIT_ARGS=(--limit "$LIMIT")
fi

COMMON_ARGS=(
  --model "$MODEL"
  --model-label purpcode-32b-rl
  --seeds 42 43 44
  --temperature 0.6
  --top-p 0.95
  --max-tokens 16384
  --tp 1
  --dtype bfloat16
  --concurrency 64
  --gpu-memory-utilization 0.9
  --eval-workers 64
)

cd "$REPO_ROOT"

"$PYTHON" - "$RUN_DIR/baseline_config.json" "$MODEL" "$LIMIT" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

path, model, limit = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
repo = Path.cwd()
runner = repo / "benchmarks/run_plain_vllm.py"
try:
    repository_commit = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except subprocess.CalledProcessError:
    repository_commit = (repo / "baselines/purpcode/source_commit.txt").read_text().strip()
config = {
    "repository_commit": repository_commit,
    "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
    "model": model,
    "gpu": 0,
    "benchmarks": ["seccodeplt", "cweval", "baxbench"],
    "variants": ["original", "repaired"],
    "language_scope": {
        "seccodeplt": ["py"],
        "cweval": ["c", "cpp", "py", "js"],
        "baxbench": ["py", "js"],
    },
    "parameters": {
        "seeds": [42, 43, 44],
        "temperature": 0.6,
        "top_p": 0.95,
        "max_tokens": 16384,
        "tensor_parallel_size": 1,
        "dtype": "bfloat16",
        "concurrency": 64,
        "gpu_memory_utilization": 0.9,
        "eval_workers": 64,
        "enable_thinking": None,
        "limit": int(limit) if limit else None,
    },
}
if path.exists():
    previous = json.loads(path.read_text())
    if previous != config:
        raise SystemExit(f"Refusing changed configuration in existing run: {path}")
else:
    path.write_text(json.dumps(config, indent=2) + "\n")
PY

run_arm() {
  local benchmark="$1"
  local variant="$2"
  local output="$RUN_DIR/${benchmark}_${variant}"

  if [[ -f "$output/summary.json" ]]; then
    echo "Skipping completed arm: $benchmark/$variant"
    return
  fi

  echo "Running $benchmark/$variant -> $output"
  "$PYTHON" benchmarks/run_plain_vllm.py \
    "${COMMON_ARGS[@]}" \
    --benchmark "$benchmark" \
    --variant "$variant" \
    --out "$output" \
    "${LIMIT_ARGS[@]}" \
    2>&1 | tee "$RUN_DIR/${benchmark}_${variant}.log"
}

for benchmark in seccodeplt cweval baxbench; do
  for variant in original repaired; do
    run_arm "$benchmark" "$variant"
  done
done

"$PYTHON" "$SCRIPT_DIR/summarize.py" --run-dir "$RUN_DIR"

echo "Complete: $RUN_DIR"
find "$RUN_DIR" -mindepth 2 -maxdepth 2 -name generations.jsonl -print | sort
