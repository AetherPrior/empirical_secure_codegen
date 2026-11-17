Qwen3-8B ProSec-style DPO on all languages
========================================

Dataset: `prosecalign/prosec-mixed-clm7b-inst` at revision
`d4f17919b3d946bcd393d87c15dfecfa13aaf566`.
All 61,166 rows are retained: Python 19,079; Java 18,558;
JavaScript 10,078; C++ 9,187; C 4,264. Code fences use each row's own
language. A deterministic seed-42 split reserves 2% for validation.

Model: `Qwen/Qwen3-8B` at revision
`b968826d9c46dd6066d109eabc6255188de91218`.
Explicit no-thinking prompt template; 400 optimizer steps; effective
batch size 64 (2 × 4 GPUs × 8 accumulation steps); learning rate 5e-6;
DPO beta 0.05; LoRA rank 8, alpha 16, dropout 0.05, on q/k/v/o and
gate/up/down projections. BF16 and gradient checkpointing are enabled.
Prompt length is limited to 2,048 tokens and total length to 4,096.
The base model with its adapter disabled provides reference log-probabilities.

This is the requested 400-step Qwen3 adaptation. Hyperparameter reference:
https://raw.githubusercontent.com/mlresearch/v267/main/assets/xu25aa/xu25aa.pdf.

Artifacts: `outputs/qwen3_8b_prosec_all_400step/`, including run manifest,
training log, adapter, checkpoints and status. Checkpoints are saved
every 50 steps, retaining two. Validation runs every 100 steps.
All baseline artifacts stay within this directory tree.
BaxBench remains on hold. The our-data arm is pending its input dataset.
