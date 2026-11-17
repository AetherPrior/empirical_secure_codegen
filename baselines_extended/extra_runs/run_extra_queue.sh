#!/usr/bin/env bash
# Generation for the tasks outside Python/C/C++/JavaScript (CWEval Go, BaxBench Go/PHP/Ruby/Rust) for the baselines, same protocol as the main
# runs (temperature 0.6, top-p 0.95, 16,384 tokens, seeds 42-44). Tuned models without data for these languages use their Python checkpoint;
# our retrieval retrieves from the Python records; CodeGuarder runs unchanged (its index has no language filter).
# Each GPU takes the next unclaimed job as soon as it is free. GPU 3 also waits for the SafeCoder-on-our-data run to finish.
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
PY=/opt/conda/envs/vllm/bin/python; CGP=/opt/conda/envs/cgp/bin/python
OUT=$REPO/baselines_extended/extra_runs
GV=$REPO/baselines/GoodVibe/outputs/py/fine_tuned_cluster_models/cluster/train_model/Qwen3-8B_python/final_checkpoint/Qwen3-8B_python
GVO=$REPO/baselines_extended/GoodVibe-OurData/outputs/py/fine_tuned_cluster_models/cluster/train_model/Qwen3-8B_python/final_checkpoint/Qwen3-8B_python
PM=$REPO/baselines_extended/dpo/outputs/prosec_merged_eval
SFT=$REPO/dataset_curation/verl/models/purpcode-32b-rule-sft
# kind | name | model | thinking flag | max model len   (claim order: retrieval pipelines first, since the SFT+retrieval job needs our retrieval's prompts)
JOBS=(
"ret|our-retrieval|||"
"cg|codeguarder|||"
"sftret|sft-retrieval|$SFT||24576"
"gen|purpcode-32b-rl|purpcode/purpcode-32b-rl||24576"
"gen|purpcode-32b-sft|$SFT||24576"
"gen|outcome-rl-purpcode32b|$REPO/baselines_extended/Outcome-Only-RL-PurpCode32B/checkpoints/global_step_600_merged||24576"
"gen|qwen3-8b|Qwen/Qwen3-8B|--enable-thinking|24576"
"gen|prosec-data|$PM/qwen3_8b_prosec_merged|--enable-thinking|24576"
"gen|prosec-ours|$PM/qwen3_8b_prosec_ours_merged|--enable-thinking|24576"
"gen|goodvibe-orig-python|$GV|--enable-thinking|24576"
"gen|goodvibe-ours-python|$GVO|--enable-thinking|24576"
"gen|outcome-rl-qwen3|$REPO/baselines_extended/Outcome-Only-RL/checkpoints/global_step_700|--enable-thinking|24576"
)
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_USE_DEEP_GEMM=0 PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false HF_HOME=/workspace/hf_home PATH=/opt/conda/envs/cweval/go/bin:$HOME/go/bin:$PATH
log() { echo "$(date -u +%FT%TZ) $*" >> "$OUT/queue.log"; }
gpu_free() { for k in 1 2 3; do [ "$(nvidia-smi -i $1 --query-gpu=memory.used --format=csv,noheader,nounits | tr -d ' ')" -lt 2000 ] || return 1; sleep 20; done
  [ "$1" != 3 ] || grep -q ALL_FINISHED $REPO/baselines_extended/dpo/outputs/prosec_merged_eval/safecoder_ours_think/launch.log 2>/dev/null; }
# sampling flags of a retrieval campaign config
cfgflags() { $PY - "$1" <<'PYEOF'
import json,sys; c=json.load(open(sys.argv[1]))
print(' '.join(f"--{k.replace('_','-')} {c[k]}" for k in ['temperature','top_p','max_tokens','max_model_len','concurrency','eval_workers','gpu_memory_utilization']), '--revision', c['model_revision'])
PYEOF
}
gen_prepared() {  # runner dir, label, prepared-cases root, out name
  local runner=$1 label=$2 root=$3 name=$4 flags; flags=$(cfgflags $runner/configs/campaign.json)
  for b in cweval baxbench; do
    mkdir -p "$OUT/$name/extra_$b"
    CUDA_VISIBLE_DEVICES=$gpu $PY $runner/evaluation/run_plain_vllm.py --model Qwen/Qwen3-8B --model-label $label --benchmark $b --variant repaired \
      --out "$OUT/$name/extra_$b" --prepared-cases $root/$b/prepared_cases.json --benchmarks-root $REPO/benchmarks --seeds 42 43 44 --tp 1 $flags \
      --enable-thinking --extra --operation generate >> "$OUT/$name/extra_$b.log" 2>&1; log $name $b rc=$?
  done
}
run_job() {
  IFS='|' read -r kind name model think mlen <<< "$1"; mkdir -p "$OUT/$name"
  case $kind in
  gen) for b in cweval baxbench; do mkdir -p "$OUT/$name/extra_$b"
         CUDA_VISIBLE_DEVICES=$gpu $PY benchmarks/run_plain_vllm.py --model "$model" --model-label $name --variant repaired --temperature 0.6 --top-p 0.95 \
           --max-tokens 16384 --tp 1 --dtype bfloat16 --concurrency 64 --gpu-memory-utilization 0.9 --max-model-len $mlen $think \
           --benchmark $b --seeds 42 43 44 --extra --operation generate --out "$OUT/$name/extra_$b" >> "$OUT/$name/extra_$b.log" 2>&1; log $name $b rc=$?
       done;;
  ret) CUDA_VISIBLE_DEVICES=$gpu $CGP baselines_extended/Our-Retrieval/prepare_extra.py >> "$OUT/$name/prepare.log" 2>&1; log $name prepare rc=$?
       gen_prepared baselines_extended/Our-Retrieval qwen3_8b_our_retrieval baselines_extended/Our-Retrieval/outputs_extra/repaired $name;;
  cg)  export CG_EXTRA=1 CG_VARIANTS=repaired CG_BENCHMARKS="cweval baxbench" CG_GPU=$gpu
       for st in plan decompose retrieve; do
         py=$PY; [ $st = retrieve ] && py=$CGP
         $py baselines/CodeGuarder/prepare.py $st --out baselines/CodeGuarder/outputs_extra >> "$OUT/$name/prepare.log" 2>&1; log $name $st rc=$?
       done; unset CG_EXTRA CG_VARIANTS CG_BENCHMARKS CG_GPU
       gen_prepared baselines/CodeGuarder codeguarder_qwen3_8b baselines/CodeGuarder/outputs_extra/repaired $name;;
  sftret) for b in cweval baxbench; do
         until [ -f baselines_extended/Our-Retrieval/outputs_extra/repaired/$b/prepared_cases.json ]; do sleep 30; done; mkdir -p "$OUT/$name/extra_$b"
         CUDA_VISIBLE_DEVICES=$gpu $PY baselines/purpcode/gen_sft_retrieval.py --model "$model" --benchmark $b --out "$OUT/$name/extra_$b" \
           --cases baselines_extended/Our-Retrieval/outputs_extra/repaired/$b/prepared_cases.json >> "$OUT/$name/extra_$b.log" 2>&1; log $name $b rc=$?
       done;;
  esac
}
worker() {
  gpu=$1
  while true; do
    until gpu_free $gpu; do sleep 40; done
    claimed=""
    for ((i=0; i<${#JOBS[@]}; i++)); do mkdir "$OUT/.claim_$i" 2>/dev/null && { claimed=$i; break; }; done
    [ -z "$claimed" ] && break
    log "gpu$gpu claimed ${JOBS[$claimed]%%|||*}"
    run_job "${JOBS[$claimed]}"
  done
}
rm -rf "$OUT"/.claim_*
for g in 0 1 2 3; do worker $g & done
wait
log QUEUE_FINISHED
