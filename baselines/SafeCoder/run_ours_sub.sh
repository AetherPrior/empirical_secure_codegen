#!/usr/bin/env bash
# SafeCoder on VeriSec, recipe-matched: 1,141 stratified pairs + evol utility data -> train (4 GPUs) -> merge -> no-think plain evaluation on all benchmarks (3 seeds).
REPO=/workspace/verisec; S=$REPO/baselines/SafeCoder; D=$REPO/baselines_extended/dpo; P=$D/outputs/prosec_merged_eval; LOG=$S/ours_sub.log
log() { echo "$(date -u +%FT%TZ) $*" >> $LOG; }
log train; bash $S/launch_train_qwen3.sh ours-sub 0,1,2,3; log "train done rc=$?"
AD=$S/trained/qwen3-8b-lora-safecoder-verisec-sub/checkpoint-last
[ -f $AD/adapter_model.safetensors ] || { log NO_ADAPTER; exit 1; }
BASE=$(ls -d /workspace/hf_home/hub/models--Qwen--Qwen3-8B/snapshots/* | head -1)
/opt/conda/envs/vllm/bin/python $D/merge_lora.py $BASE $AD $P/qwen3_8b_safecoder_ours_sub_merged >> $LOG 2>&1 || { log MERGE_FAILED; exit 1; }
cp $AD/tokenizer* $AD/vocab.json $AD/merges.txt $AD/added_tokens.json $AD/special_tokens_map.json $P/qwen3_8b_safecoder_ours_sub_merged/ 2>/dev/null
log eval; bash $D/run_prosec_nothink.sh safecoder_ours_sub_nothink qwen3_8b_safecoder_ours_sub_merged qwen3-8b-safecoder-ours-sub-nothink >> $LOG 2>&1; log ALL_FINISHED
