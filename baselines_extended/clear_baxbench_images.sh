#!/usr/bin/env bash
# After all BaxBench scoring has finished, remove only the BaxBench-built images (they carry the labels language= and framework=).
# Waits for RESCUE (generation + scoring) and for the extras pollers; never touches images without both labels (pinned bases, other projects).
REPO=/workspace/verisec; L=$REPO/baselines_extended/clear_baxbench_images.log
echo "$(date -u +%FT%TZ) waiting" >> $L
until grep -q ALL_FINISHED $REPO/baselines/RESCUE/outputs/launch.log 2>/dev/null && ! pgrep -f "score_extras" >/dev/null && ! pgrep -f "run_plain_vllm.py.*baxbench" >/dev/null; do sleep 120; done
echo "$(date -u +%FT%TZ) before: $(docker images -q --filter label=framework --filter label=language | wc -l) labelled images; disk: $(df -h /workspace | tail -n1)" >> $L
docker image prune -a -f --filter label=framework --filter label=language >> $L 2>&1
echo "$(date -u +%FT%TZ) after: $(docker images -q --filter label=framework --filter label=language | wc -l) labelled images; disk: $(df -h /workspace | tail -n1)" >> $L
echo "$(date -u +%FT%TZ) DONE" >> $L
