Qwen3-8B ProSec-style DPO, 400 steps
==================================

Run with `.venv/bin/python run_qwen3_prosec.py` from this baseline directory.
The launcher resumes the latest saved checkpoint if present.

The input is the Python subset of
`prosecalign/prosec-mixed-clm7b-inst` at revision
`d4f17919b3d946bcd393d87c15dfecfa13aaf566`: 19,079 preference
pairs. A deterministic seed-42 split reserves 382 pairs for validation and
uses 18,697 for training. The model is `Qwen/Qwen3-8B` at revision
`b968826d9c46dd6066d109eabc6255188de91218`.

This is a ProSec-style adaptation to Qwen3, using the user's requested
400-step setting. The source for the
DPO hyperparameters is Table 6 of
https://raw.githubusercontent.com/mlresearch/v267/main/assets/xu25aa/xu25aa.pdf.

The effective batch size is 64 (2 pairs/device × 4 GPUs × 8 accumulation
steps). Learning rate is 5e-6 and DPO beta is 0.05. LoRA rank is 8,
alpha 16, dropout 0.05; target modules are q/k/v/o and gate/up/down
projections. Both the policy and reference use the pinned base checkpoint;
TRL evaluates the reference by disabling the policy's adapter.

Prompts explicitly use Qwen's no-thinking template. Length limits are 2,048
prompt tokens and 4,096 total tokens. BF16, gradient checkpointing and
PyTorch SDPA are enabled; cuDNN SDPA is disabled because it fails for
some padded training shapes on the local H100s. No quantization is used.

Outputs are in `outputs/qwen3_8b_prosec_python_400step/`: the adapter,
training log, run manifest and status. Checkpoints are saved every 50
steps, retaining two. Validation runs every 100 steps. The environment
package versions are captured in `environment.lock.txt`.

The training seed is 42. This is one trained model, not three training
replicates. Benchmark evaluation is separate; BaxBench remains on hold.
The our-data training arm is pending confirmation of its input dataset.
