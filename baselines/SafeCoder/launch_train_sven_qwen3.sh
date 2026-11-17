#!/usr/bin/env bash
# SVEN prefix-tuning on Qwen3-8B (frozen base, 10 prefix tokens per layer, secure/vulnerable controls), SVEN's loss
# (LM on secure + contrastive + KL, kl weight 1600), lr 1e-2, 5 epochs, raw code samples as in SVEN.
# Usage: bash launch_train_sven_qwen3.sh <orig|ours> <gpu>
set -u
cd "$(dirname "$0")/scripts"
PY=/workspace/verisec/baselines_extended/dpo/.venv/bin/python
export PYTHONPATH=$(cd .. && pwd):$(cd .. && pwd)/pylibs:${PYTHONPATH:-} CUDA_VISIBLE_DEVICES=$2 HF_HOME=/workspace/hf_home PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false WANDB_DISABLED=true
case $1 in
  orig) NAME=sven-orig; DS="sec-desc" ;;
  ours) NAME=sven-verisec; DS="sec-verisec" ;;
esac
$PY train.py --pretrain_name qwen3-8b --output_name $NAME --datasets $DS --sven --kl_loss_weight 1600 \
   --learning_rate 1e-2 --num_train_epochs 5 --model_dir ../trained/ >> ../trained_$NAME.log 2>&1
