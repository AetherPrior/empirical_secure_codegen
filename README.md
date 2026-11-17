# Artifact: An Empirical Study of Secure Code Generation

| Folder | Contents |
|---|---|
| `benchmarks/` | Original and repaired SecCodePLT-Python, CWEval and BaxBench, the fuzz tests (`*_repaired/fuzzed/`), and the evaluation harness (`run_plain_vllm.py`). See `benchmarks/README.md`. |
| `benchmarks_fuzzing_oracle/` | Scorer for the fuzz tests. |
| `dataset_curation/simple_gen/` | VeriSec construction pipeline, stages 0–6 per language (`run_validate_<lang>.sh`). |
| `dataset_curation/data_annotation_files/` | Expert testing rubrics per language and CWE, the audit prompts used by stage 5, and annotation notes. |
| `dataset_curation/retrieval_kb/` | Builds the VeriSec-Retrieval knowledge base (also the VeriSec-Pairwise pairs). |
| `dataset_curation/verl/` | RL training code (GRPO with the outcome reward). |
| `baselines/` | Existing methods: CodeGuarder, RESCUE, CoSec, GoodVibe, SVEN and SafeCoder (`SafeCoder/`), PromSec, PurpCode, Qwen3-8B, and the OpenAI models. |
| `baselines_extended/` | Methods trained or retrieved with VeriSec: retrieval (`Our-Retrieval/`), GoodVibe (`GoodVibe-OurData/`), preference optimization (`dpo/`), outcome-only RL (`Outcome-Only-RL*/`), and the runs on languages outside VeriSec (`extra_runs/`). |
