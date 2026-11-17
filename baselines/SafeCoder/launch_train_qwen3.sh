#!/usr/bin/env bash
# SafeCoder LoRA training on Qwen3-8B with the settings of the SafeCoder paper's LoRA runs (r=16, alpha=32, dropout 0.1,
# lr 1e-3, 5 epochs; non-thinking ChatML prompt), once on SafeCoder's data (with its evol utility data) and once on all VeriSec pairs (no evol: every pair passes executable functionality tests).
# Data parallel over the given GPUs (effective batch stays batch_size 1 x grad_acc 16). Usage: bash launch_train_qwen3.sh <orig|ours> <gpus, e.g. 0,1>
set -u
cd "$(dirname "$0")/scripts"
PY=/workspace/verisec/baselines_extended/dpo/.venv/bin/python
export PYTHONPATH=$(cd .. && pwd):$(cd .. && pwd)/pylibs:${PYTHONPATH:-} CUDA_VISIBLE_DEVICES=$2 HF_HOME=/workspace/hf_home PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false WANDB_DISABLED=true
case $1 in
  orig) NAME=safecoder-orig; DS="evol sec-desc sec-new-desc" ;;
  ours) NAME=safecoder-verisec; DS="sec-verisec" ;;
  ours-sub) NAME=safecoder-verisec-sub; DS="evol sec-verisec-sub" ;;   # 1,141 stratified pairs + SafeCoder's utility data (see scripts/subsample_verisec_for_safecoder.py)
esac
$PY -m torch.distributed.run --standalone --nproc-per-node=$(echo $2 | tr ',' '\n' | wc -l) train.py --pretrain_name qwen3-8b --output_name $NAME --datasets $DS --lora --r 16 --lora_alpha 32 --lora_dropout 0.1 \
   --learning_rate 1e-3 --num_train_epochs 5 --model_dir ../trained/ >> ../trained_$NAME.log 2>&1
