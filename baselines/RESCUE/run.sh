#!/usr/bin/env bash
# RESCUE on Qwen3-8B (thinking on, plain protocol). Waits for the SVEN generation to finish, then:
#   analyze (GPU) -> retrieve (GPU encoder) -> generate 3 seeds on every benchmark incl. extra-language tasks -> score -> fuzzed rescore.
REPO=/workspace/verisec; cd $REPO; R=$REPO/baselines/RESCUE; O=$R/outputs; mkdir -p $O
VPY=/opt/conda/envs/vllm/bin/python; RPY=$R/upstream/.venv/bin/python
RUNNER=$REPO/baselines_extended/Our-Retrieval/evaluation/run_plain_vllm.py
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1 HF_HOME=/workspace/hf_home PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
log() { echo "$(date -u +%FT%TZ) $*" >> $O/launch.log; }
Q=$REPO/baselines/SafeCoder/sven_eval/queue.log
until grep -q SVEN_FINISHED $Q 2>/dev/null && grep -q 'orig extra_baxbench done16' $Q && grep -q 'ours extra_baxbench done16' $Q \
   && grep -q 'qwen3-8b-nothink baxbench' $REPO/baselines_extended/extra_runs/queue.log\
   && grep -q NOTHINK_ALL_FINISHED $REPO/baselines_extended/dpo/outputs/prosec_merged_eval/nothink_all.log 2>/dev/null; do sleep 120; done
gpu_free() { [ "$(nvidia-smi -i $1 --query-gpu=memory.used --format=csv,noheader,nounits | tr -d ' ')" -lt 2000 ]; }
until gpu_free 0; do sleep 30; done
if ! ls $O/{seccodeplt,cweval,baxbench,extra_cweval,extra_baxbench}/analysis.json >/dev/null 2>&1; then
  log analyze; CUDA_VISIBLE_DEVICES=0 $VPY $R/prepare.py analyze >> $O/analyze.log 2>&1 || { log ANALYZE_FAILED; exit 1; }
fi
log retrieve_gpu; CUDA_VISIBLE_DEVICES=3 $RPY $R/prepare.py retrieve >> $O/retrieve.log 2>&1 || { log RETRIEVE_FAILED; exit 1; }
COMMON=(--slice main --model Qwen/Qwen3-8B --model-label qwen3_8b_rescue --variant repaired --temperature 0.6 --top-p 0.95 --max-tokens 16384 --max-model-len 40960
        --concurrency 256 --gpu-memory-utilization 0.92 --eval-workers 32 --enable-thinking --tp 1 --benchmarks-root $REPO/benchmarks)
gen() { # gpu set(seccodeplt|cweval|baxbench|extra_*) seeds...
  local g=$1 s=$2; shift 2; local extra=""; local b=$s; [[ $s == extra_* ]] && { extra="--extra"; b=${s#extra_}; }
  mkdir -p $O/run/$s; CUDA_VISIBLE_DEVICES=$g $VPY $RUNNER "${COMMON[@]}" --benchmark $b --out $O/run/$s --prepared-cases $O/$s/prepared_cases.json \
    --seeds "$@" --operation generate $extra >> $O/run/$s.log 2>&1; log gen $s "$@" rc=$?; }
for s in 42 43 44; do g=$((s-42)); ( mkdir -p $O/run/seccodeplt_s$s; CUDA_VISIBLE_DEVICES=$g $VPY $RUNNER "${COMMON[@]}" --benchmark seccodeplt --out $O/run/seccodeplt_s$s \
    --prepared-cases $O/seccodeplt/prepared_cases.json --seeds $s --operation generate >> $O/run/seccodeplt_s$s.log 2>&1; log gen seccodeplt s$s rc=$? ) & done
( gen 3 cweval 42 43 44; gen 3 baxbench 42 43 44; gen 3 extra_cweval 42 43 44; gen 3 extra_baxbench 42 43 44 ) &
wait
mkdir -p $O/run/seccodeplt; cat $O/run/seccodeplt_s4{2,3,4}/generations.jsonl > $O/run/seccodeplt/generations.jsonl
for s in seccodeplt cweval baxbench; do
  CUDA_VISIBLE_DEVICES=0 $VPY $RUNNER "${COMMON[@]}" --benchmark $s --out $O/run/$s --prepared-cases $O/$s/prepared_cases.json --seeds 42 43 44 --baxbench-port-base 52000 \
    --operation evaluate >> $O/run/${s}_eval.log 2>&1; log eval $s rc=$?
done
ROOT=$REPO/baselines/Qwen3-8B-base/outputs/fuzzed_rescore/root
for b in seccodeplt cweval; do out=$O/run/fuzzed_rescore/$b; mkdir -p $out; cp $O/run/$b/generations.jsonl $out/
  $VPY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model qwen3_8b_rescue --model-label qwen3_8b_rescue --benchmark $b --variant repaired --out $out \
    --benchmarks-root "$ROOT" --seeds 42 43 44 --eval-workers 32 --operation evaluate > $out/rescore.log 2>&1; log fuzz $b rc=$?; done
log ALL_FINISHED
