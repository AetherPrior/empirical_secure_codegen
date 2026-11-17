set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR=${PROJECT_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}
cd "$PROJECT_DIR"
PROJECT_NAME=${PROJECT_NAME:-verl_grpo_codeguarder_outcome}
EXPERIMENT_NAME=${EXPERIMENT_NAME:-qwen3_8b_e2e_rl_seccode_gen}
MODEL_PATH=${MODEL_PATH:-Qwen/Qwen3-8B}
TOKENIZER_MODEL=${TOKENIZER_MODEL:-${TOKENIZER_MODEL:-'Qwen/Qwen3-8B'}}
IS_COT_MODEL=${IS_COT_MODEL:-True}
PATH_ROOT_DIR=${PATH_ROOT_DIR:-$PROJECT_DIR}
TRAIN_FILE=${TRAIN_FILE:-$PATH_ROOT_DIR/datasets/seccode/RL_seccode_gen_train.parquet}
VAL_FILE=${VAL_FILE:-$PATH_ROOT_DIR/datasets/seccode/RL_seccode_gen_val.parquet}

ACTOR_CKPT_SAVE_CONTENTS=${ACTOR_CKPT_SAVE_CONTENTS:-"['model','optimizer','extra']"}
CKPT_ROOT=${CKPT_ROOT:-/checkpoints/$PROJECT_NAME/$EXPERIMENT_NAME}

# Merge actor checkpoints to Hugging Face format after training.
MERGE_AFTER_TRAIN=${MERGE_AFTER_TRAIN:-1}
MERGED_HF_ROOT=${MERGED_HF_ROOT:-/checkpoints/merged_hf_models/$PROJECT_NAME/$EXPERIMENT_NAME}

OUTCOME_SECURITY_WEIGHT=${OUTCOME_SECURITY_WEIGHT:-0.5}
UNITTEST_TIMEOUT_SECONDS=${UNITTEST_TIMEOUT_SECONDS:-2.0}

export RAY_memory_monitor_refresh_ms=0

export SAFE_K_RLIMIT_AS_MIB=${SAFE_K_RLIMIT_AS_MIB:-1024}
export SAFE_K_RLIMIT_CPU_SECONDS=${SAFE_K_RLIMIT_CPU_SECONDS:-3}
export SAFE_K_RLIMIT_STACK_MIB=${SAFE_K_RLIMIT_STACK_MIB:-64}
export SAFE_K_RLIMIT_FSIZE_MIB=${SAFE_K_RLIMIT_FSIZE_MIB:-4}
# ASan reserves a huge virtual-address shadow, so native tasks use ASan's RSS
# limiter instead of SAFE_K_RLIMIT_AS_MIB (which remains for Python tasks).
export SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB=${SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB:-1024}


N_GPUS=${N_GPUS:-4}
PPO_MICRO_BATCH_PER_GPU=${PPO_MICRO_BATCH_PER_GPU:-4}
LOGPROB_MICRO_BATCH_PER_GPU=${LOGPROB_MICRO_BATCH_PER_GPU:-4}
PPO_MINI_BATCH_SIZE=${PPO_MINI_BATCH_SIZE:-12}
ROLLOUT_N=${ROLLOUT_N:-8}
ADV_ESTIMATOR=${ADV_ESTIMATOR:-grpo}
DAPO_FILTER_GROUPS=${DAPO_FILTER_GROUPS:-True}
# seq_reward: filter on harness score (pre-KL). Avoid seq_final_reward if use_kl_in_reward=True.
DAPO_FILTER_METRIC=${DAPO_FILTER_METRIC:-seq_reward}
DAPO_FILTER_MODE=${DAPO_FILTER_MODE:-single_step}
DAPO_MAX_NUM_GEN_BATCHES=${DAPO_MAX_NUM_GEN_BATCHES:-10}
DAPO_TARGET_PROMPT_GROUPS=${DAPO_TARGET_PROMPT_GROUPS:-null}
DAPO_MIN_PROMPT_POOL_SIZE=${DAPO_MIN_PROMPT_POOL_SIZE:-null}
DAPO_MAX_PROMPT_POOL_SIZE=${DAPO_MAX_PROMPT_POOL_SIZE:-64}
DAPO_ZERO_LEARNABLE_ACTION=${DAPO_ZERO_LEARNABLE_ACTION:-skip}
DAPO_CLIP_RATIO_LOW=${DAPO_CLIP_RATIO_LOW:-0.2}
DAPO_CLIP_RATIO_HIGH=${DAPO_CLIP_RATIO_HIGH:-0.28}
DAPO_LOSS_AGG_MODE=${DAPO_LOSS_AGG_MODE:-token-mean}

MAX_PROMPT_LENGTH=${MAX_PROMPT_LENGTH:-6144}
MAX_RESPONSE_LENGTH=${MAX_RESPONSE_LENGTH:-12000}
# Must be >= (max_prompt_length + max_response_length) for dynamic batching.
MAX_TOKEN_LEN_PER_GPU=${MAX_TOKEN_LEN_PER_GPU:-19000}

# vLLM 0.19+ reasoning: cap thinking tokens per rollout request (only used when rollout.name=vllm).
# If set and reasoning_config is unset, verl supplies a built-in ReasoningConfig in vllm_async_server.
THINKING_TOKEN_BUDGET=${THINKING_TOKEN_BUDGET:-8192}
# vLLM gpu_memory_utilization; raise when actor/ref use FSDP offload (frees VRAM for KV).
ROLLOUT_GPU_MEM_UTIL=${ROLLOUT_GPU_MEM_UTIL:-0.3}

VAL_BATCH_SIZE=${VAL_BATCH_SIZE:-16}
VAL_MAX_SAMPLES=${VAL_MAX_SAMPLES:-64}
VAL_BEFORE_TRAIN=${VAL_BEFORE_TRAIN:-False}
TEST_FREQ=${TEST_FREQ:-1000}
VAL_LOG_GENERATIONS=${VAL_LOG_GENERATIONS:-0}

SAFE_K_CFLAGS=${SAFE_K_CFLAGS:-"-O0 -Wall -Wextra -fsanitize=address -std=gnu11"}
SAFE_K_CXXFLAGS=${SAFE_K_CXXFLAGS:-"-O0 -Wall -Wextra -fsanitize=address -std=gnu++17"}
export SAFE_K_CFLAGS
export SAFE_K_CXXFLAGS

REWARD_DEBUG=${REWARD_DEBUG:-1}
REWARD_DEBUG_CODE_MAX_CHARS=${REWARD_DEBUG_CODE_MAX_CHARS:-1200}
UPDATE_WEIGHTS_BUCKET_MB=${UPDATE_WEIGHTS_BUCKET_MB:-4096}

export OUTCOME_SECURITY_WEIGHT
export UNITTEST_TIMEOUT_SECONDS
export REWARD_DEBUG
export REWARD_DEBUG_CODE_MAX_CHARS
export TOKENIZER_MODEL
export IS_COT_MODEL

if [ ! -f "$TRAIN_FILE" ] || [ ! -f "$VAL_FILE" ]; then
    echo "Missing training dataset: TRAIN_FILE=$TRAIN_FILE VAL_FILE=$VAL_FILE"
    exit 1
fi

# Direct end-to-end GRPO: the standard RLHFDataset consumes each user prompt
# from the Parquet files unchanged.  No custom dataset or external context is
# configured in this launch command.

python3 -m verl.trainer.main_ppo \
    algorithm.adv_estimator=$ADV_ESTIMATOR \
    algorithm.filter_groups.enable=$DAPO_FILTER_GROUPS \
    algorithm.filter_groups.metric=$DAPO_FILTER_METRIC \
    algorithm.filter_groups.mode=$DAPO_FILTER_MODE \
    algorithm.filter_groups.max_num_gen_batches=$DAPO_MAX_NUM_GEN_BATCHES \
    algorithm.filter_groups.target_prompt_groups=$DAPO_TARGET_PROMPT_GROUPS \
    algorithm.filter_groups.min_prompt_pool_size=$DAPO_MIN_PROMPT_POOL_SIZE \
    algorithm.filter_groups.max_prompt_pool_size=$DAPO_MAX_PROMPT_POOL_SIZE \
    algorithm.filter_groups.zero_learnable_action=$DAPO_ZERO_LEARNABLE_ACTION \
    algorithm.span_credit_assignment=False \
    algorithm.span_credit_log_interval=10 \
    data.train_files=$TRAIN_FILE \
    data.val_files=$VAL_FILE \
    data.val_batch_size=$VAL_BATCH_SIZE \
    data.train_batch_size=$PPO_MINI_BATCH_SIZE \
    data.max_prompt_length=$MAX_PROMPT_LENGTH \
    data.max_response_length=$MAX_RESPONSE_LENGTH \
    data.filter_overlong_prompts=True \
    data.trust_remote_code=True \
    data.truncation='error' \
    data.shuffle=True \
    data.dataloader_num_workers=0 \
    custom_reward_function.path=$PROJECT_DIR/recipe/codeguarder_outcome/safe_k_reward.py \
    custom_reward_function.name=compute_score \
    actor_rollout_ref.model.path=$MODEL_PATH \
    actor_rollout_ref.actor.optim.lr=1e-6 \
    actor_rollout_ref.model.use_remove_padding=True \
    actor_rollout_ref.actor.ppo_mini_batch_size=$PPO_MINI_BATCH_SIZE \
    actor_rollout_ref.actor.ppo_micro_batch_size_per_gpu=$PPO_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.actor.clip_ratio_low=$DAPO_CLIP_RATIO_LOW \
    actor_rollout_ref.actor.clip_ratio_high=$DAPO_CLIP_RATIO_HIGH \
    actor_rollout_ref.actor.loss_agg_mode=$DAPO_LOSS_AGG_MODE \
    actor_rollout_ref.actor.use_kl_loss=True \
    actor_rollout_ref.actor.kl_loss_coef=0.01 \
    actor_rollout_ref.actor.use_dynamic_bsz=True \
    actor_rollout_ref.actor.ppo_max_token_len_per_gpu=$MAX_TOKEN_LEN_PER_GPU \
    actor_rollout_ref.actor.entropy_coeff=0.00 \
    actor_rollout_ref.actor.kl_loss_type=low_var_kl \
    actor_rollout_ref.model.enable_gradient_checkpointing=True \
    actor_rollout_ref.actor.fsdp_config.param_offload=True \
    actor_rollout_ref.actor.fsdp_config.optimizer_offload=True \
    actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.rollout.log_prob_max_token_len_per_gpu=$MAX_TOKEN_LEN_PER_GPU \
    actor_rollout_ref.rollout.tensor_model_parallel_size=4 \
    actor_rollout_ref.rollout.name=vllm \
    actor_rollout_ref.rollout.gpu_memory_utilization=$ROLLOUT_GPU_MEM_UTIL \
    actor_rollout_ref.rollout.thinking_token_budget=$THINKING_TOKEN_BUDGET \
    actor_rollout_ref.rollout.reasoning_parser=qwen3 \
    actor_rollout_ref.rollout.n=$ROLLOUT_N \
    actor_rollout_ref.rollout.val_kwargs.n=1 \
    actor_rollout_ref.rollout.checkpoint_engine.update_weights_bucket_megabytes=$UPDATE_WEIGHTS_BUCKET_MB \
    actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.ref.log_prob_max_token_len_per_gpu=$MAX_TOKEN_LEN_PER_GPU \
    actor_rollout_ref.ref.fsdp_config.param_offload=True \
    critic.optim.lr=1e-5 \
    critic.ppo_micro_batch_size_per_gpu=4 \
    algorithm.kl_ctrl.kl_coef=0.000 \
    trainer.critic_warmup=0 \
    trainer.logger="['console','wandb']" \
    trainer.val_before_train=$VAL_BEFORE_TRAIN \
    trainer.log_val_generations=$VAL_LOG_GENERATIONS \
    trainer.default_hdfs_dir=null \
    trainer.default_local_dir=$CKPT_ROOT \
    trainer.project_name="$PROJECT_NAME" \
    trainer.experiment_name="$EXPERIMENT_NAME" \
    trainer.n_gpus_per_node=$N_GPUS \
    trainer.nnodes=1 \
    trainer.save_freq=100 \
    trainer.test_freq=$TEST_FREQ \
    trainer.rollout_data_dir=$CKPT_ROOT/rollouts \
    trainer.total_training_steps=700 \
    $@

# trainer.resume_from_path=True \

if [ "$MERGE_AFTER_TRAIN" = "1" ]; then
    shopt -s nullglob
    actor_dirs=("$CKPT_ROOT"/global_step_*/actor)
    if [ ${#actor_dirs[@]} -eq 0 ]; then
        echo "No actor checkpoints found under $CKPT_ROOT"
    else
        for actor_dir in "${actor_dirs[@]}"; do
            step_dir=$(basename "$(dirname "$actor_dir")")
            target_dir="$MERGED_HF_ROOT/$step_dir"
            python3 "$PROJECT_DIR/scripts/legacy_model_merger.py" merge \
                --backend fsdp \
                --local_dir "$actor_dir" \
                --target_dir "$target_dir"
        done
    fi
fi
