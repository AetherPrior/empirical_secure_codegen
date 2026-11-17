set -x

# Outcome-only GRPO (LoRA) for purpcode/purpcode-32b-rule-sft on the 4-language
# RL_seccode_gen split (HF anonymous/RL_seccode_gen @ 5f1183e6, see
# datasets/seccode/RL_seccode_gen_manifest.json).
# Runs inside the verl_vllm18 container: /workspace/verl is the repo,
# /checkpoints is the checkpoint volume.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR=${PROJECT_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}
cd "$PROJECT_DIR"
PROJECT_NAME=${PROJECT_NAME:-verl_grpo_codeguarder_outcome}
EXPERIMENT_NAME=${EXPERIMENT_NAME:-purpcode_32b_rulesft_lora_outcome_rl700_$(date -u +%Y%m%dT%H%M%SZ)}
MODEL_PATH=${MODEL_PATH:-$PROJECT_DIR/models/purpcode-32b-rule-sft}
TOKENIZER_MODEL=${TOKENIZER_MODEL:-$MODEL_PATH}
# PurpCode is not a Qwen3 thinking model: no <think> parsing.
IS_COT_MODEL=${IS_COT_MODEL:-False}
PATH_ROOT_DIR=${PATH_ROOT_DIR:-$PROJECT_DIR}
TRAIN_FILE=${TRAIN_FILE:-$PATH_ROOT_DIR/datasets/seccode/RL_seccode_gen_train.parquet}
VAL_FILE=${VAL_FILE:-$PATH_ROOT_DIR/datasets/seccode/RL_seccode_gen_val256.parquet}

CKPT_ROOT=${CKPT_ROOT:-/checkpoints/$PROJECT_NAME/$EXPERIMENT_NAME}

OUTCOME_SECURITY_WEIGHT=${OUTCOME_SECURITY_WEIGHT:-0.5}
UNITTEST_TIMEOUT_SECONDS=${UNITTEST_TIMEOUT_SECONDS:-2.0}

export RAY_memory_monitor_refresh_ms=0

# The container ships a CUDA 12.9 compat libcuda (driver 575) that ld.so finds before
# the injected host libcuda; with the host on driver 595 that gives CUDA error 803.
# Put the host library directory first so the real driver library is used.
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH}

export SAFE_K_RLIMIT_AS_MIB=${SAFE_K_RLIMIT_AS_MIB:-1024}
export SAFE_K_RLIMIT_CPU_SECONDS=${SAFE_K_RLIMIT_CPU_SECONDS:-3}
export SAFE_K_RLIMIT_STACK_MIB=${SAFE_K_RLIMIT_STACK_MIB:-64}
export SAFE_K_RLIMIT_FSIZE_MIB=${SAFE_K_RLIMIT_FSIZE_MIB:-4}
# ASan reserves a huge virtual-address shadow, so native tasks use ASan's RSS
# limiter instead of SAFE_K_RLIMIT_AS_MIB (which remains for Python tasks).
export SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB=${SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB:-1024}

N_GPUS=${N_GPUS:-4}
# 32B: micro-batches of 1 (the 32B LoRA runs peaked at ~74/80 GB reserved).
PPO_MICRO_BATCH_PER_GPU=${PPO_MICRO_BATCH_PER_GPU:-1}
LOGPROB_MICRO_BATCH_PER_GPU=${LOGPROB_MICRO_BATCH_PER_GPU:-1}
PPO_MINI_BATCH_SIZE=${PPO_MINI_BATCH_SIZE:-12}
ROLLOUT_N=${ROLLOUT_N:-8}
ADV_ESTIMATOR=${ADV_ESTIMATOR:-grpo}
DAPO_FILTER_GROUPS=${DAPO_FILTER_GROUPS:-True}
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

# Same lengths as the 32B LoRA run that reached step 100 (2026-06-01).
# Prompts in this dataset are <=1153 tokens, so 2048 loses none.
MAX_PROMPT_LENGTH=${MAX_PROMPT_LENGTH:-2048}
MAX_RESPONSE_LENGTH=${MAX_RESPONSE_LENGTH:-12000}
# Must be >= (max_prompt_length + max_response_length) for dynamic batching.
MAX_TOKEN_LEN_PER_GPU=${MAX_TOKEN_LEN_PER_GPU:-15000}

LORA_RANK=${LORA_RANK:-32}
LORA_ALPHA=${LORA_ALPHA:-64}
# LoRA needs a larger LR than full fine-tuning (the 8B scripts use 1e-6).
LR=${LR:-1e-5}

ROLLOUT_GPU_MEM_UTIL=${ROLLOUT_GPU_MEM_UTIL:-0.3}

VAL_BATCH_SIZE=${VAL_BATCH_SIZE:-16}
# Fixed CWE-stratified 256-row val subset (built from RL_seccode_gen_val.parquet, seed 42); -1 = use it whole, no re-sampling.
VAL_MAX_SAMPLES=${VAL_MAX_SAMPLES:--1}
VAL_BEFORE_TRAIN=${VAL_BEFORE_TRAIN:-False}
TEST_FREQ=${TEST_FREQ:-100}
SAVE_FREQ=${SAVE_FREQ:-100}
TOTAL_TRAINING_STEPS=${TOTAL_TRAINING_STEPS:-700}
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

for f in "$TRAIN_FILE" "$VAL_FILE" "$MODEL_PATH/config.json"; do
    if [ ! -f "$f" ]; then
        echo "Missing required file: $f"
        exit 1
    fi
done

# Direct end-to-end GRPO: the standard RLHFDataset consumes each user prompt
# from the Parquet files unchanged.
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
    data.val_max_samples=$VAL_MAX_SAMPLES \
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
    actor_rollout_ref.model.lora_rank=$LORA_RANK \
    actor_rollout_ref.model.lora_alpha=$LORA_ALPHA \
    actor_rollout_ref.model.target_modules=all-linear \
    actor_rollout_ref.actor.optim.lr=$LR \
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
    actor_rollout_ref.actor.fsdp_config.model_dtype=bfloat16 \
    actor_rollout_ref.actor.fsdp_config.param_offload=True \
    actor_rollout_ref.actor.fsdp_config.optimizer_offload=True \
    actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.rollout.log_prob_max_token_len_per_gpu=$MAX_TOKEN_LEN_PER_GPU \
    actor_rollout_ref.rollout.tensor_model_parallel_size=4 \
    actor_rollout_ref.rollout.name=vllm \
    actor_rollout_ref.rollout.gpu_memory_utilization=$ROLLOUT_GPU_MEM_UTIL \
    actor_rollout_ref.rollout.load_format=safetensors \
    actor_rollout_ref.rollout.layered_summon=True \
    actor_rollout_ref.rollout.n=$ROLLOUT_N \
    actor_rollout_ref.rollout.val_kwargs.n=1 \
    actor_rollout_ref.rollout.checkpoint_engine.update_weights_bucket_megabytes=$UPDATE_WEIGHTS_BUCKET_MB \
    actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.ref.log_prob_max_token_len_per_gpu=$MAX_TOKEN_LEN_PER_GPU \
    actor_rollout_ref.ref.fsdp_config.model_dtype=bfloat16 \
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
    trainer.save_freq=$SAVE_FREQ \
    trainer.test_freq=$TEST_FREQ \
    trainer.rollout_data_dir=$CKPT_ROOT/rollouts \
    trainer.total_training_steps=$TOTAL_TRAINING_STEPS \
    $@

# Not merged automatically: legacy_model_merger.py has not been verified on
# LoRA-adapter FSDP checkpoints. Merge a step-100 checkpoint by hand first.
