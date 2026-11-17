#!/bin/bash
# Run PromSec generation and scoring on the Python tasks of the plain benchmarks.
# Rerunning resumes: finished generations are kept and finished stages are skipped.
#
# Usage: bash baselines/promsec/launch_all.sh <results_dir>
# Env:   GPUS (default "0 2"), BENCHMARKS, VARIANTS, PY_PROMSEC, PY312, VLLM, MODEL, SERVER_PORT_BASE,
#        BAXBENCH_PORT_BASE, GPU_MEMORY_UTILIZATION, LIMIT (first N Python tasks). See README.md.
set -u
[ $# -eq 1 ] || { echo "usage: bash baselines/promsec/launch_all.sh <results_dir>" >&2; exit 2; }
REPO=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$1" && RESULTS=$(cd "$1" && pwd) || exit 1
GPUS=${GPUS:-"0 2"}
BENCHMARKS=${BENCHMARKS:-"cweval seccodeplt baxbench"}
VARIANTS=${VARIANTS:-"repaired original"}
PY_PROMSEC=${PY_PROMSEC:-/workspace/PromSec/.venv/bin/python}
PY312=${PY312:-/opt/conda/envs/vllm/bin/python}
VLLM=${VLLM:-/opt/conda/envs/vllm/bin/vllm}
MODEL=${MODEL:-/workspace/models/Qwen3-8B}
SERVER_PORT_BASE=${SERVER_PORT_BASE:-8100}
BAXBENCH_PORT_BASE=${BAXBENCH_PORT_BASE:-27000}
GPU_MEMORY_UTILIZATION=${GPU_MEMORY_UTILIZATION:-0.85}
LIMIT_ARGS=()
[ -n "${LIMIT:-}" ] && LIMIT_ARGS=(--limit "$LIMIT")
RUNNER=baselines/promsec/run_promsec_plain.py
export PYTHONDONTWRITEBYTECODE=1
# FlashInfer's sampler and DeepGEMM need nvcc, which is not on every account's PATH. Neither affects a
# bfloat16 model's outputs beyond the sampler implementation, so vLLM's own code paths are used instead.
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0
# Bandit is called by name, so it has to come from the PromSec environment.
PROMSEC_PATH="$(dirname "$PY_PROMSEC"):$PATH"
cd "$REPO" || exit 1

SERVER_PIDS=()
API_BASES=()
stop_servers() { [ ${#SERVER_PIDS[@]} -eq 0 ] || kill "${SERVER_PIDS[@]}" 2>/dev/null; }
trap stop_servers EXIT

start_servers() {
    local port=$SERVER_PORT_BASE gpu
    for gpu in $GPUS; do
        # --generation-config vllm matches the runner's sampling: no top-k from the model's config.
        CUDA_VISIBLE_DEVICES=$gpu "$VLLM" serve "$MODEL" --port "$port" --dtype bfloat16 --max-num-seqs 64 \
            --gpu-memory-utilization "$GPU_MEMORY_UTILIZATION" --generation-config vllm \
            --enable-prefix-caching > "$RESULTS/vllm_gpu$gpu.log" 2>&1 &
        SERVER_PIDS+=($!)
        API_BASES+=("http://localhost:$port")
        port=$((port + 1))
    done
    local i _
    for i in "${!API_BASES[@]}"; do
        for _ in $(seq 120); do
            curl -sf "${API_BASES[$i]}/health" > /dev/null && continue 2
            kill -0 "${SERVER_PIDS[$i]}" 2>/dev/null || break
            sleep 5
        done
        echo "server ${API_BASES[$i]} did not start, see $RESULTS/vllm_gpu*.log"
        return 1
    done
    echo "$(date -u +%FT%TZ) servers ready: ${API_BASES[*]}"
}

run_stage() {
    local benchmark=$1 variant=$2 out="$RESULTS/${1}_${2}"
    local other=original reuse=() attempt
    [ "$variant" = original ] && other=repaired
    [ -d "$RESULTS/${benchmark}_$other" ] && reuse=(--reuse-from "$RESULTS/${benchmark}_$other")
    mkdir -p "$out"
    if [ -f "$out/summary.json" ]; then
        echo "$(date -u +%FT%TZ) SKIP $benchmark/$variant (already scored)"
        return 0
    fi
    echo "$(date -u +%FT%TZ) START $benchmark/$variant"
    [ -f "$out/cases.json" ] || "$PY312" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" --prepare \
        > "$out/prepare.log" 2>&1 || { echo "prepare failed, see $out/prepare.log"; return 1; }

    for attempt in 1 2 3; do
        PATH=$PROMSEC_PATH "$PY_PROMSEC" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" \
            --api-bases "${API_BASES[@]}" --concurrency $((64 * ${#API_BASES[@]})) --target-model "$MODEL" \
            ${reuse[@]+"${reuse[@]}"} ${LIMIT_ARGS[@]+"${LIMIT_ARGS[@]}"} >> "$out/generate.log" 2>&1
        "$PY_PROMSEC" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" --merge-only \
            ${LIMIT_ARGS[@]+"${LIMIT_ARGS[@]}"} > "$out/merge.log" 2>&1 && break
        echo "$(date -u +%FT%TZ) merge incomplete (attempt $attempt): $(tail -1 "$out/merge.log" | cut -c1-160)"
    done
    [ -f "$out/generations.jsonl" ] && tail -1 "$out/merge.log" | cut -c1-200
    [ -f "$out/generations.jsonl" ] || { echo "generation incomplete for $benchmark/$variant"; return 1; }

    echo "$(date -u +%FT%TZ) EVAL $benchmark/$variant"
    "$PY312" "$RUNNER" --benchmark "$benchmark" --variant "$variant" --out "$out" --evaluate \
        --baxbench-port-base "$BAXBENCH_PORT_BASE" ${LIMIT_ARGS[@]+"${LIMIT_ARGS[@]}"} > "$out/eval.log" 2>&1 \
        || { echo "evaluation failed, see $out/eval.log"; return 1; }
    echo "$(date -u +%FT%TZ) DONE $benchmark/$variant"
}

start_servers || exit 1
for benchmark in $BENCHMARKS; do
    for variant in $VARIANTS; do run_stage "$benchmark" "$variant" || break; done
done
echo "$(date -u +%FT%TZ) ALL_FINISHED"
