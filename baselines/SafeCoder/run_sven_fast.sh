#!/usr/bin/env bash
# Relaunch of the remaining SVEN generations with more slots per GPU (resumes from generations.jsonl).
SV=/workspace/verisec/baselines/SafeCoder; D=$SV/sven_eval; SLOTS=${SLOTS:-24}
PY=/workspace/verisec/baselines_extended/dpo/.venv/bin/python
export PYTHONPATH=$SV HF_HOME=/workspace/hf_home PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false
declare -A PREF=( [orig]=$SV/trained/qwen3-8b-sven-sven-orig/checkpoint-last [ours]=$SV/trained/qwen3-8b-sven-sven-verisec/checkpoint-last )
go() { gpu=$1; m=$2; s=$3
  CUDA_VISIBLE_DEVICES=$gpu $PY $SV/scripts/sven_generate.py --prefix-dir ${PREF[$m]} --cases $D/$s/cases.json --out $D/$m/$s --seeds 42 --slots $SLOTS >> $D/$m/$s.log 2>&1
  echo "$(date -u +%FT%TZ) sven-$m $s rc=$? (slots $SLOTS)" >> $D/queue.log; }
go 0 orig seccodeplt & go 1 ours seccodeplt & go 2 orig extra_baxbench & go 3 ours extra_baxbench & wait
echo "$(date -u +%FT%TZ) SVEN_FINISHED" >> $D/queue.log
