#!/bin/bash
# Evaluate SecCodePLT results (SeCode-Eval unit tests) in Docker.
#
# Usage:
#   bash docker_evaluate.sh --results_csv <path> [options]
#
# Options:
#   --results_csv <path>   Path to CSV from run script (required)
#   --output_dir <dir>     Directory to save evaluated results
#   --n_workers 8          Parallel workers for test execution
#   --code_col <name>      Column to evaluate (default: final_code; SVEN: generated_code)
#   --dataset_path <path>  HF dataset id or local snapshot (optional)
#
# Example (PromSec):
#   bash docker_evaluate.sh \
#     --results_csv results_promsec_secodeplt/promsec_insecure_coding_all_vetfixed.csv \
#     --output_dir results_promsec_eval
#
# Example (SVEN):
#   bash docker_evaluate.sh \
#     --results_csv results_sven_official_6b_secodeplt/sven_official_insecure_coding_all.csv \
#     --code_col generated_code \
#     --output_dir results_sven_official_6b_eval

set -e

IMAGE="verlai/verl:vllm018.dev1"
PROMSEC_DIR="/workspace/PromSec"
DATASET_SNAPSHOT="/workspace/dabstep/cache/hub/datasets--Virtue-AI-HUB--SecCodePLT/snapshots/62efb6f03741aa6ae10afa801a7905f734baa3c1"

ARGS=("$@")
HAS_DATASET_PATH=0
for a in "${ARGS[@]}"; do
    [[ "$a" == "--dataset_path" ]] && HAS_DATASET_PATH=1
done
if [[ "${HAS_DATASET_PATH}" -eq 0 ]]; then
    ARGS+=(--dataset_path "${DATASET_SNAPSHOT}")
fi

echo "=== SecCodePLT evaluation (Docker) ==="
echo "    Image: ${IMAGE}"
echo "    Args : ${ARGS[*]}"
echo ""

docker run --rm \
    -v /workspace:/workspace \
    -v /workspace:/workspace \
    --workdir "${PROMSEC_DIR}" \
    -e PYTHONPATH="${PROMSEC_DIR}:${PROMSEC_DIR}/script:${PROMSEC_DIR}/secure_reasoning/SeCode-Eval" \
    -e HF_HOME="/workspace/dabstep/cache" \
    "${IMAGE}" \
    bash -c "
        set -e
        pip install -q datasets pandas tqdm huggingface_hub 2>&1 | tail -2
        python script/evaluate_promsec_secodeplt.py ${ARGS[*]}
    "
