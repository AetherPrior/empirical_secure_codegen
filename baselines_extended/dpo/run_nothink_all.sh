#!/usr/bin/env bash
# Re-evaluate ProSec and SafeCoder (own data and our data) without thinking, full data (main slice + extra-language tasks), 3 seeds.
# Starts once SVEN generation and the no-think base extras job are done; RESCUE waits for this to finish.
REPO=/workspace/verisec; D=$REPO/baselines_extended/dpo; O=$D/outputs/prosec_merged_eval
Q=$REPO/baselines/SafeCoder/sven_eval/queue.log
until grep -q SVEN_FINISHED $Q 2>/dev/null && grep -q 'orig extra_baxbench done16' $Q && grep -q 'ours extra_baxbench done16' $Q \
   && grep -q 'qwen3-8b-nothink baxbench' $REPO/baselines_extended/extra_runs/queue.log; do sleep 120; done
for spec in "prosec_data_nothink qwen3_8b_prosec_merged qwen3-8b-prosec-dpo-nothink" "prosec_ours_nothink qwen3_8b_prosec_ours_merged qwen3-8b-prosec-ours-nothink" \
            "safecoder_data_nothink qwen3_8b_safecoder_orig_merged qwen3-8b-safecoder-orig-nothink" "safecoder_ours_nothink qwen3_8b_safecoder_ours_merged qwen3-8b-safecoder-ours-nothink"; do
  set -- $spec; echo "$(date -u +%FT%TZ) start $1" >> $O/nothink_all.log
  bash $D/run_prosec_nothink.sh $1 $2 $3 >> $O/nothink_all.log 2>&1; echo "$(date -u +%FT%TZ) done $1 rc=$?" >> $O/nothink_all.log
done
echo "$(date -u +%FT%TZ) NOTHINK_ALL_FINISHED" >> $O/nothink_all.log
