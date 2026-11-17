#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR=${PROJECT_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}
DATA_DIR=${OFFLINE_RETRIEVAL_DATA_DIR:-$PROJECT_DIR/datasets/seccode/offline_single_retrieval}

export PROJECT_NAME=${PROJECT_NAME:-verl_grpo_codeguarder_offline_single}
export EXPERIMENT_NAME=${EXPERIMENT_NAME:-qwen3_8b_codeguarder_offline_single_5cwe}
export TRAIN_FILE=${TRAIN_FILE:-$DATA_DIR/python_cwe_GRPO_5cwe_train.parquet}
export VAL_FILE=${VAL_FILE:-$DATA_DIR/python_cwe_GRPO_5cwe_val.parquet}

if [ ! -f "$TRAIN_FILE" ] || [ ! -f "$VAL_FILE" ]; then
    echo "Missing offline retrieval dataset. Build train and val files as documented in recipe/codeguarder_outcome/OFFLINE_SINGLE_ROLLOUT.md"
    exit 1
fi

exec bash "$SCRIPT_DIR/run_qwen3_8b_grpo_security_harness.sh" \
    data.custom_cls.path="$PROJECT_DIR/recipe/codeguarder_outcome/offline_single_rollout.py" \
    data.custom_cls.name=OfflineSingleRetrievalDataset \
    ++data.offline_single_retrieval.rollout_index="${RETRIEVAL_ROLLOUT_INDEX:-0}" \
    ++actor_rollout_ref.rollout.agent.agent_loop_manager_class=recipe.codeguarder_outcome.offline_single_rollout.OfflineSingleRetrievalAgentLoopManager \
    "$@"
