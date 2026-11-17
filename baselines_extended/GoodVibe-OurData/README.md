# GoodVibe trained on our paired dataset

This experiment reuses GoodVibe's gradient-based neuron identification, gradient
clustering, tied updates to selected rows, and secure-code fine-tuning. It replaces
CyberNative training data with the 9,409 prompt/secure_code/vulnerable_code pairs
of the VeriSec-Retrieval KB, read from
`../Our-Retrieval/dataset/all_languages.jsonl` (its SHA-256 is pinned in each config).

Four language-specific Qwen3-8B models train independently: C (3,736 pairs), C++
(3,104), Python (1,905), JavaScript (664). Identification uses safe label 0 and
unsafe label 1; tuning uses secure responses. The existing GoodVibe settings are
retained: top 50 neurons per scored module, minimum silhouette 0.05, 2 epochs,
sequence length 1,024, seed 42, and the authors' 90/10 shuffled tuning split.
The original comment-removal behavior is retained; C explicitly uses C++ comment
syntax so that its #include directives survive preprocessing. No DPO/LoRA training
is substituted for the clustered-weight procedure. The upstream training code is
copied locally, as are the runner and training environment.

Run `.venv/bin/python -B run.py` from this directory, or use an absolute path.
The supervisor starts each language when its assigned GPU is idle, runs
identification then tuning, and exports checkpoints under outputs/<language>/.
Individual stages can resume from their saved identification/trainer checkpoints.

After training, evaluate all three repaired benchmarks with thinking enabled,
seeds 42/43/44, temperature 0.6, top-p 0.95, and 16,384 output tokens. Evaluators
operate on local benchmark copies and use Docker-assigned host ports. Evaluation
waits for existing campaigns to release their CPU slots; at most two new evaluation
jobs run concurrently, each with 64 workers. Language scores pool within each seed,
then report mean and sample SD in outputs/repaired/combined/.

The original-data GoodVibe baseline remains a separate experiment. This variant
also adds a native C model; the original-data C results used transfer from C++.
No files under benchmarks/ are modified.
