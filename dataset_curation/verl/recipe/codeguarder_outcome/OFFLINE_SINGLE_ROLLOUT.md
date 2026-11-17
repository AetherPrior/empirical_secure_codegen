# Offline retrieval for one rollout

This optional path leaves the existing online implementation unchanged.

The builder preserves each original `prompt`, creates a separate
`retrieval_prompt`, and excludes KB rows matching the task's `extra_info.index`
against `source_index`. It also excludes matching `task_id` and normalized prompt
text as safeguards. Retrieval provenance is stored in
`offline_retrieval_metadata` for leakage audits.

Build both splits from the VeRL repository root:

```bash
mkdir -p datasets/seccode/offline_single_retrieval

python -m recipe.codeguarder_outcome.build_offline_single_rollout_dataset \
  --input datasets/seccode/python_cwe_GRPO_5cwe_train.parquet \
  --output datasets/seccode/offline_single_retrieval/python_cwe_GRPO_5cwe_train.parquet \
  --security-kb datasets/seccode/security_kb_python_5cwe_full.jsonl \
  --guidelines datasets/seccode/guidelines.json \
  --vector-db datasets/seccode/codeguarder_outcome_5cwe/security_kb.faiss \
  --embedding-device cpu

python -m recipe.codeguarder_outcome.build_offline_single_rollout_dataset \
  --input datasets/seccode/python_cwe_GRPO_5cwe_val.parquet \
  --output datasets/seccode/offline_single_retrieval/python_cwe_GRPO_5cwe_val.parquet \
  --security-kb datasets/seccode/security_kb_python_5cwe_full.jsonl \
  --guidelines datasets/seccode/guidelines.json \
  --vector-db datasets/seccode/codeguarder_outcome_5cwe/security_kb.faiss \
  --embedding-device cpu
```

Then run:

```bash
bash examples/grpo_trainer/run_qwen3_8b_grpo_security_harness_offline_single_retrieval.sh
```

The custom manager selects `rollout_n == 0` after VeRL expands every prompt by
`rollout.n`. The other seven rollouts receive the untouched original prompt.
Set `RETRIEVAL_ROLLOUT_INDEX` to another zero-based index if needed.
