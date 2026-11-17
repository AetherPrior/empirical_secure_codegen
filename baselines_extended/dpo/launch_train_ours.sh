#!/usr/bin/env bash
# ProSec-style DPO on VeriSec pairs (same hyperparameters as the ProSec-data run). Needs GPUs 0-3.
cd "$(dirname "$0")"; .venv/bin/python run_qwen3_prosec.py --config configs/qwen3_8b_prosec_ours_400step.json
