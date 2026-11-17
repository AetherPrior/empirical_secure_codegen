#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR=${PROJECT_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}
DATA_DIR=${OFFLINE_ALL_RETRIEVAL_DATA_DIR:-$PROJECT_DIR/datasets/seccode/offline_all_17cwe_retrieval}

export PROJECT_NAME=${PROJECT_NAME:-verl_grpo_codeguarder_offline_all}
export EXPERIMENT_NAME=${EXPERIMENT_NAME:-qwen3_8b_codeguarder_offline_all_17cwe}
export BASE_TRAIN_FILE=${BASE_TRAIN_FILE:-$PROJECT_DIR/datasets/seccode/python_cwe_GRPO_train.parquet}
export BASE_VAL_FILE=${BASE_VAL_FILE:-$PROJECT_DIR/datasets/seccode/python_cwe_GRPO_val.parquet}
export TRAIN_FILE=${TRAIN_FILE:-$DATA_DIR/python_cwe_GRPO_train.parquet}
export VAL_FILE=${VAL_FILE:-$DATA_DIR/python_cwe_GRPO_val.parquet}
export SECURITY_KB_FILE=${SECURITY_KB_FILE:-$PROJECT_DIR/datasets/all_python_17cwe.blind_v1.flex.extractions.assigned.jsonl}
export GUIDELINES_FILE=${GUIDELINES_FILE:-$PROJECT_DIR/datasets/seccode/guidelines_17cwe.json}

if [ ! -f "$TRAIN_FILE" ] || [ ! -f "$VAL_FILE" ]; then
    echo "Missing offline-all dataset under $DATA_DIR. Build it with recipe/codeguarder_outcome/build_offline_all_rollout_dataset.py."
    exit 1
fi

exec bash "$SCRIPT_DIR/run_qwen3_8b_grpo_security_harness.sh" \
    data.custom_cls.path="$PROJECT_DIR/recipe/codeguarder_outcome/offline_all_rollout.py" \
    data.custom_cls.name=OfflineAllRetrievalDataset \
    "$@"
