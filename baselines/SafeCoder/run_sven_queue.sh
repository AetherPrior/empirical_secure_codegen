#!/usr/bin/env bash
# SVEN (prefix tuning) on Qwen3-8B with thinking on, one seed (42): paper slice + the tasks outside Python/C/C++/JavaScript.
# Starts once the extras queue has claimed all of its jobs, then takes any free GPU. First a short smoke test on the first free GPU.
REPO=$(cd "$(dirname "$0")/../.." && pwd); cd "$REPO"
SV=$REPO/baselines/SafeCoder; D=$SV/sven_eval; Q=$REPO/baselines_extended/extra_runs
PY=/workspace/verisec/baselines_extended/dpo/.venv/bin/python
export PYTHONPATH=$SV HF_HOME=/workspace/hf_home PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false
until [ "$(ls -d $Q/.claim_* 2>/dev/null | wc -l)" -ge 12 ]; do sleep 120; done
gpu_free() { for k in 1 2 3; do [ "$(nvidia-smi -i $1 --query-gpu=memory.used --format=csv,noheader,nounits | tr -d ' ')" -lt 2000 ] || return 1; sleep 20; done; }
declare -A PREF=( [orig]=$SV/trained/qwen3-8b-sven-sven-orig/checkpoint-last [ours]=$SV/trained/qwen3-8b-sven-sven-verisec/checkpoint-last )
gen() { # model set out-name
  mkdir -p $D/$1/$3; CUDA_VISIBLE_DEVICES=$gpu $PY $SV/scripts/sven_generate.py --prefix-dir ${PREF[$1]} --cases $D/$2/cases.json --out $D/$1/$3 --seeds 42 --slots 16 >> $D/$1/$3.log 2>&1
  echo "$(date -u +%FT%TZ) sven-$1 $3 rc=$?" >> $D/queue.log; }
JOBS=("orig seccodeplt" "ours seccodeplt" "orig rest" "ours rest")
run_job() { read -r m w <<< "$1"
  if [ $w = rest ]; then for s in cweval baxbench extra_cweval extra_baxbench; do gen $m $s $s; done; else gen $m $w $w; fi; }
# smoke test on the first free GPU
for g in 0 1 2 3; do :; done
until for g in 0 1 2 3; do gpu_free $g && { gpu=$g; break; }; done; [ -n "${gpu:-}" ]; do sleep 60; done
mkdir -p $D/smoke; CUDA_VISIBLE_DEVICES=$gpu $PY $SV/scripts/sven_generate.py --prefix-dir ${PREF[orig]} --cases $D/cweval/cases.json --out $D/smoke --seeds 42 --slots 4 --limit 4 --max-new 512 > $D/smoke.log 2>&1 \
  || { echo "$(date -u +%FT%TZ) SMOKE_FAILED see $D/smoke.log" >> $D/queue.log; exit 1; }
echo "$(date -u +%FT%TZ) smoke ok on gpu$gpu: $(wc -l < $D/smoke/generations.jsonl) rows" >> $D/queue.log
worker() { gpu=$1
  while true; do until gpu_free $gpu; do sleep 40; done
    c=""; for ((i=0;i<${#JOBS[@]};i++)); do mkdir "$D/.claim_$i" 2>/dev/null && { c=$i; break; }; done
    [ -z "$c" ] && break; run_job "${JOBS[$c]}"; done; }
rm -rf $D/.claim_*; for g in 0 1 2 3; do worker $g & done; wait
echo "$(date -u +%FT%TZ) SVEN_FINISHED" >> $D/queue.log
