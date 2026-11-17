#!/bin/bash
# Run CoSec generation and scoring on the plain benchmarks. Repaired only by default.
# Rerunning resumes: finished generations are kept and finished stages are skipped.
#
# Usage: bash baselines/cosec/launch_all.sh <results_dir>
# Env:   GPUS (default "0 1 2"), PER_GPU (default 3), BENCHMARKS, VARIANTS, PY_COSEC, PY312,
#        REUSE_ROOT (default results_dir), BAXBENCH_PORT_BASE (default 27000). See README.md.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -eq 1 ] || { echo "usage: bash baselines/cosec/launch_all.sh <results_dir>" >&2; exit 2; }
mkdir -p "$1" && RESULTS=$(cd "$1" && pwd) || exit 1
GPUS=${GPUS:-"0 1 2"}
PER_GPU=${PER_GPU:-3}
BENCHMARKS=${BENCHMARKS:-"cweval seccodeplt baxbench"}
VARIANTS=${VARIANTS:-repaired}
PY_COSEC=${PY_COSEC:-/workspace/PromSec/.venv/bin/python}
PY312=${PY312:-/opt/conda/envs/vllm/bin/python}
REUSE_ROOT=${REUSE_ROOT:-$RESULTS}
BAXBENCH_PORT_BASE=${BAXBENCH_PORT_BASE:-27000}
LABEL=CoSec-Qwen3-8B
RUNNER=baselines/cosec/run_cosec_plain.py
export PYTHONDONTWRITEBYTECODE=1
cd "$REPO" || exit 1

SLOTS=()
for gpu in $GPUS; do
    for _ in $(seq "$PER_GPU"); do SLOTS+=("$gpu"); done
done
NUM_SHARDS=${#SLOTS[@]}

run_stage() {
    local benchmark=$1 variant=$2 out="$RESULTS/${1}_${2}"
    # Prompts a repair left unchanged are copied from the other variant instead of regenerated.
    local other=original reuse=()
    [ "$variant" = original ] && other=repaired
    [ -d "$REUSE_ROOT/${benchmark}_$other" ] && reuse=(--reuse-from "$REUSE_ROOT/${benchmark}_$other")
    mkdir -p "$out"
    if [ -f "$out/summary.json" ]; then
        echo "$(date -u +%FT%TZ) SKIP $benchmark/$variant (already scored)"
        return 0
    fi
    echo "$(date -u +%FT%TZ) START $benchmark/$variant shards=$NUM_SHARDS"
    [ -f "$out/cases.json" ] || "$PY312" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" --prepare \
        > "$out/prepare.log" 2>&1 || { echo "prepare failed, see $out/prepare.log"; return 1; }

    local attempt
    for attempt in 1 2 3; do
        local pids=() i
        for i in "${!SLOTS[@]}"; do
            CUDA_VISIBLE_DEVICES=${SLOTS[$i]} "$PY_COSEC" "$RUNNER" --benchmark "$benchmark" --variant "$variant" \
                --out "$out" --shard-id "$i" --num-shards "$NUM_SHARDS" ${reuse[@]+"${reuse[@]}"} \
                >> "$out/shard$i.log" 2>&1 &
            pids+=($!)
        done
        wait "${pids[@]}"
        "$PY_COSEC" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" \
            --num-shards "$NUM_SHARDS" --merge > "$out/merge.log" 2>&1 && break
        echo "$(date -u +%FT%TZ) merge incomplete (attempt $attempt): $(tail -1 "$out/merge.log" | cut -c1-160)"
    done
    [ -f "$out/generations.jsonl" ] && tail -1 "$out/merge.log" | cut -c1-160
    [ -f "$out/generations.jsonl" ] || { echo "generation incomplete for $benchmark/$variant"; return 1; }

    echo "$(date -u +%FT%TZ) EVAL $benchmark/$variant"
    "$PY312" benchmarks/run_plain_vllm.py --model "$LABEL" --benchmark "$benchmark" --variant "$variant" \
        --out "$out" --operation evaluate --baxbench-port-base "$BAXBENCH_PORT_BASE" > "$out/eval.log" 2>&1 \
        || { echo "evaluation failed, see $out/eval.log"; return 1; }
    echo "$(date -u +%FT%TZ) DONE $benchmark/$variant"
}

for benchmark in $BENCHMARKS; do
    for variant in $VARIANTS; do run_stage "$benchmark" "$variant" || break; done
done
echo "$(date -u +%FT%TZ) ALL_FINISHED"
