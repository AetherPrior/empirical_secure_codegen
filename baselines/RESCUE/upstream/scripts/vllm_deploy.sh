#! /bin/bash
MODEL=$1
SERVED_MODEL_NAME=$2
PORT=$3

vllm serve $MODEL --max_model_len 4096  --port $PORT  --api-key "${VLLM_API_KEY:-token-placeholder}" --trust-remote-code  --dtype bfloat16 --served-model-name $SERVED_MODEL_NAME

# The `MODEL` represents the model name or model path.
# The `SERVED_MODEL_NAME` means the name you prefer and will be used in requestion.
# The `PORT` means your exposed port for accessing this model.
# Set the VLLM_API_KEY environment variable to customize the API key (default: token-placeholder).
# One example is below:
# vllm serve deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct --max_model_len 4096  --port 9160  --api-key "${VLLM_API_KEY:-token-placeholder}" --trust-remote-code  --dtype bfloat16 --served-model-name Deepseek-Coder-V2-Lite-Instruct