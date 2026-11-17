set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
echo "$PROJECT_DIR"
PROJECT_NAME=${PROJECT_NAME:-verl_grpo_security_harness}
EXPERIMENT_NAME=${EXPERIMENT_NAME:-qwen3_8b_safe_k_reward_cot_real_style_full_ft}

#PATH_ROOT_DIR=${PATH_ROOT_DIR:-/workspace/verisec/code_reason/prosec/security-test-case/SDPO}
PATH_ROOT_DIR=${PATH_ROOT_DIR:-/workspace/verl}
TRAIN_FILE=${TRAIN_FILE:-$PATH_ROOT_DIR/datasets/seccode/python_simple_gen_train.parquet}
VAL_FILE=${VAL_FILE:-$PATH_ROOT_DIR/datasets/seccode/python_simple_gen_val.parquet}
MODEL_PATH=${MODEL_PATH:-Qwen/Qwen3-8B}
ACTOR_CKPT_SAVE_CONTENTS=${ACTOR_CKPT_SAVE_CONTENTS:-"['model','optimizer','extra']"}
CKPT_ROOT=${CKPT_ROOT:-$PROJECT_DIR/checkpoints/$PROJECT_NAME/$EXPERIMENT_NAME}

# Merge actor checkpoints to Hugging Face format after training.
MERGE_AFTER_TRAIN=${MERGE_AFTER_TRAIN:-1}
MERGED_HF_ROOT=${MERGED_HF_ROOT:-/checkpoints/merged_hf_models/$PROJECT_NAME/$EXPERIMENT_NAME}

SAFETY_RATIO=${SAFETY_RATIO:-0.5}
UT_RATIO=${UT_RATIO:-0.7}
UNITTEST_TIMEOUT_SECONDS=${UNITTEST_TIMEOUT_SECONDS:-2.0}
N_GPUS=${N_GPUS:-4}
PPO_MICRO_BATCH_PER_GPU=${PPO_MICRO_BATCH_PER_GPU:-4}
LOGPROB_MICRO_BATCH_PER_GPU=${LOGPROB_MICRO_BATCH_PER_GPU:-4}
PPO_MINI_BATCH_SIZE=${PPO_MINI_BATCH_SIZE:-8}
ROLLOUT_N=${ROLLOUT_N:-16}

VAL_BATCH_SIZE=${VAL_BATCH_SIZE:-16}
VAL_MAX_SAMPLES=${VAL_MAX_SAMPLES:-64}
VAL_BEFORE_TRAIN=${VAL_BEFORE_TRAIN:-False}
TEST_FREQ=${TEST_FREQ:-50}
VAL_LOG_GENERATIONS=${VAL_LOG_GENERATIONS:-0}

REWARD_DEBUG=${REWARD_DEBUG:-0}
REWARD_DEBUG_CODE_MAX_CHARS=${REWARD_DEBUG_CODE_MAX_CHARS:-1200}

export SAFETY_RATIO
export UT_RATIO
export UNITTEST_TIMEOUT_SECONDS
export REWARD_DEBUG
export REWARD_DEBUG_CODE_MAX_CHARS

if [ "$MERGE_AFTER_TRAIN" = "1" ]; then
    shopt -s nullglob
    MERGER_SCRIPT="$PROJECT_DIR/scripts/legacy_model_merger.py"
    if [ ! -f "$MERGER_SCRIPT" ]; then
        echo "Merger script not found: $MERGER_SCRIPT"
        exit 1
    fi

    echo "Using CKPT_ROOT=$CKPT_ROOT"
    actor_dirs=("$CKPT_ROOT"/global_step_*/actor)
    echo "Found ${#actor_dirs[@]} actor checkpoint directories"
    if [ ${#actor_dirs[@]} -eq 0 ]; then
        echo "No actor checkpoints found under $CKPT_ROOT"
    else
        for actor_dir in "${actor_dirs[@]}"; do
            step_dir=$(basename "$(dirname "$actor_dir")")
            target_dir="$MERGED_HF_ROOT/$step_dir"
            echo "Merging: $actor_dir -> $target_dir"
            PYTHONPATH="$PROJECT_DIR:${PYTHONPATH}" python3 "$MERGER_SCRIPT" merge \
                --backend fsdp \
                --local_dir "$actor_dir" \
                --target_dir "$target_dir"
        done
    fi
fi
