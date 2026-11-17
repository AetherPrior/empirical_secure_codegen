set -x

PROJECT_DIR="$(pwd)"
PROJECT_NAME=${PROJECT_NAME:-verl_grpo_security_harness}
EXPERIMENT_NAME=${EXPERIMENT_NAME:-codellama_7b_safe_k_reward_instruct_real_style_lora_ft}

#PATH_ROOT_DIR=${PATH_ROOT_DIR:-/workspace/verisec/code_reason/prosec/security-test-case/SDPO}
PATH_ROOT_DIR=${PATH_ROOT_DIR:-/workspace/verl}
TRAIN_FILE=${TRAIN_FILE:-$PATH_ROOT_DIR/datasets/seccode/cwe_502_train.parquet}
VAL_FILE=${VAL_FILE:-$PATH_ROOT_DIR/datasets/seccode/cwe_502_val.parquet}
MODEL_PATH=${MODEL_PATH:-codellama/CodeLlama-7b-Instruct-hf}
ACTOR_CKPT_SAVE_CONTENTS=${ACTOR_CKPT_SAVE_CONTENTS:-"['model','optimizer','extra']"}
CKPT_ROOT=${CKPT_ROOT:-$PROJECT_DIR/checkpoints/$PROJECT_NAME/$EXPERIMENT_NAME}

# Merge actor checkpoints to Hugging Face format after training.
MERGE_AFTER_TRAIN=${MERGE_AFTER_TRAIN:-1}
MERGED_HF_ROOT=${MERGED_HF_ROOT:-$PROJECT_DIR/merged_hf_models/$EXPERIMENT_NAME}

SECURITY_RATIO=${SECURITY_RATIO:-0.5}
UT_RATIO=${UT_RATIO:-0.7}
UNITTEST_TIMEOUT_SECONDS=${UNITTEST_TIMEOUT_SECONDS:-2.0}
N_GPUS=${N_GPUS:-4}
PPO_MICRO_BATCH_PER_GPU=${PPO_MICRO_BATCH_PER_GPU:-4}
LOGPROB_MICRO_BATCH_PER_GPU=${LOGPROB_MICRO_BATCH_PER_GPU:-4}
PPO_MINI_BATCH_SIZE=${PPO_MINI_BATCH_SIZE:-8}
ROLLOUT_N=${ROLLOUT_N:-4}
ROLLOUT_LOAD_FORMAT=${ROLLOUT_LOAD_FORMAT:-safetensors}

VAL_BATCH_SIZE=${VAL_BATCH_SIZE:-16}
VAL_MAX_SAMPLES=${VAL_MAX_SAMPLES:-64}
VAL_BEFORE_TRAIN=${VAL_BEFORE_TRAIN:-False}
TEST_FREQ=${TEST_FREQ:-27}
VAL_LOG_GENERATIONS=${VAL_LOG_GENERATIONS:-0}

REWARD_DEBUG=${REWARD_DEBUG:-0}
REWARD_DEBUG_CODE_MAX_CHARS=${REWARD_DEBUG_CODE_MAX_CHARS:-1200}

export SECURITY_RATIO
export UT_RATIO
export UNITTEST_TIMEOUT_SECONDS
export REWARD_DEBUG
export REWARD_DEBUG_CODE_MAX_CHARS

python3 -m verl.trainer.main_ppo \
    algorithm.adv_estimator=grpo \
    reward_manager.name=batch \
    data.train_files=$TRAIN_FILE \
    data.val_files=$VAL_FILE \
    data.val_batch_size=$VAL_BATCH_SIZE \
    data.train_batch_size=64 \
    data.max_prompt_length=4096 \
    data.max_response_length=2048 \
    data.val_max_samples=$VAL_MAX_SAMPLES \
    data.filter_overlong_prompts=True \
    data.trust_remote_code=True \
    data.truncation='error' \
    data.shuffle=True \
    custom_reward_function.path=$PROJECT_DIR/recipe/security_harness/safe_k_reward.py \
    custom_reward_function.name=compute_score \
    actor_rollout_ref.model.path=$MODEL_PATH \
    actor_rollout_ref.actor.optim.lr=1e-6 \
    actor_rollout_ref.model.use_remove_padding=True \
    actor_rollout_ref.actor.ppo_mini_batch_size=$PPO_MINI_BATCH_SIZE \
    actor_rollout_ref.actor.ppo_micro_batch_size_per_gpu=$PPO_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.model.lora_rank=16 \
    actor_rollout_ref.model.lora_alpha=32 \
    actor_rollout_ref.actor.use_kl_loss=False \
    actor_rollout_ref.actor.kl_loss_coef=0.000 \
    actor_rollout_ref.actor.use_dynamic_bsz=True \
    actor_rollout_ref.actor.ppo_max_token_len_per_gpu=8192 \
    actor_rollout_ref.actor.entropy_coeff=0.001 \
    actor_rollout_ref.actor.kl_loss_type=low_var_kl \
    actor_rollout_ref.model.enable_gradient_checkpointing=True \
    actor_rollout_ref.actor.fsdp_config.param_offload=False \
    actor_rollout_ref.actor.fsdp_config.optimizer_offload=False \
    actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.rollout.tensor_model_parallel_size=1 \
    actor_rollout_ref.rollout.name=vllm \
    actor_rollout_ref.rollout.load_format=$ROLLOUT_LOAD_FORMAT \
    actor_rollout_ref.rollout.layered_summon=True \
    actor_rollout_ref.rollout.gpu_memory_utilization=0.8 \
    actor_rollout_ref.rollout.n=$ROLLOUT_N \
    actor_rollout_ref.rollout.val_kwargs.n=1 \
    actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=$LOGPROB_MICRO_BATCH_PER_GPU \
    actor_rollout_ref.ref.fsdp_config.param_offload=True \
    critic.optim.lr=1e-5 \
    critic.ppo_micro_batch_size_per_gpu=4 \
    algorithm.kl_ctrl.kl_coef=0.000 \
    trainer.critic_warmup=0 \
    trainer.logger="['console','wandb']" \
    trainer.val_before_train=$VAL_BEFORE_TRAIN \
    trainer.log_val_generations=$VAL_LOG_GENERATIONS \
    trainer.default_hdfs_dir=null \
    trainer.project_name="$PROJECT_NAME" \
    trainer.experiment_name="$EXPERIMENT_NAME" \
    trainer.n_gpus_per_node=$N_GPUS \
    trainer.nnodes=1 \
    trainer.save_freq=54 \
    trainer.test_freq=$TEST_FREQ \
    trainer.resume_from_path=False \
    trainer.total_epochs=140 \
    $@

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
