#!/usr/bin/env bash
# PurpCode-32B-SFT + our retrieval, repaired benchmarks. Usage: run_sft_retrieval.sh <run id>
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
PY=${PY:-/opt/conda/envs/vllm/bin/python}
MODEL=$REPO/dataset_curation/verl/models/purpcode-32b-rule-sft
RUN=$REPO/baselines/purpcode/outputs/${1:?run id}; mkdir -p "$RUN"
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0
gen() { CUDA_VISIBLE_DEVICES=$1 $PY baselines/purpcode/gen_sft_retrieval.py --model "$MODEL" --benchmark $2 --out "$RUN/$3" --seeds $4 >> "$RUN/$3.log" 2>&1; }
gen 0 seccodeplt seccodeplt_s42 42 &
gen 1 seccodeplt seccodeplt_s43 43 &
gen 2 seccodeplt seccodeplt_s44 44 &
( gen 3 cweval cweval "42 43 44"; gen 3 baxbench baxbench "42 43 44" ) &
wait; echo "$(date -u +%FT%TZ) ALL_FINISHED" >> "$RUN/launch.log"
