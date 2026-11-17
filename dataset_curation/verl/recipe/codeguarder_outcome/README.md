# CodeGuarder outcome recipe

This recipe separates prompt-side security knowledge from reward-side supervision:

1. `build_retrieval_dataset.py` uses the recipe's local two-stage retriever and
   places retrieved CWE/guideline/root-cause/fixing-pattern context in each prompt.
2. `safe_k_reward.py` scores only observed functionality and security test pass
   rates. It does not import an LLM judge, PRM, format reward, or retrieved text.

Build an augmented input dataset before training. The input may be simple_gen JSONL,
GRPO-shaped JSONL, or GRPO-shaped Parquet; it must contain the task text in
`rewritten_prompt` (or `prompt`) and retain the test fields used by
`SecurityHarnessDataset`. Parquet augmentation changes only the `prompt` column and
preserves its existing schema and all other columns.

```bash
python -m recipe.codeguarder_outcome.build_retrieval_dataset \
  --input tasks.jsonl --output tasks.codeguarder.jsonl \
  --security-kb /path/to/Root_Causes.json \
  --guidelines /path/to/guidelines.json \
  --vector-db /path/to/cache/root_causes.faiss
```

The vector database is created locally on first use and reused by later dataset
builds. No other repository is needed at runtime.

## Online batched retrieval server

For online training, start one persistent Search-R1-style retrieval server from
the VeRL repository root:

```bash
python -m recipe.codeguarder_outcome.retrieval_server \
  --security-kb datasets/seccode/security_kb_python_5cwe_full.jsonl \
  --guidelines datasets/seccode/guidelines.json \
  --vector-db datasets/seccode/codeguarder_outcome_5cwe/security_kb.faiss \
  --embedding-device cpu \
  --port 8000
```

Then launch training in another shell:

```bash
RETRIEVAL_SERVER_URL=http://127.0.0.1:8000 \
  bash examples/grpo_trainer/run_qwen3_8b_grpo_security_harness.sh
```

`OnlineRetrievalDataset.__getitems__` sends an entire DataLoader batch in one
HTTP request. The server embeds all cache misses in one Jina forward pass, shares
one FAISS index and result cache, and returns one context list per prompt. This is
still online retrieval: contexts are selected when each training batch is read.
If `RETRIEVAL_SERVER_URL` is empty, the dataset uses the same batched retriever
in-process. The server owns `security_top_k`, `guideline_top_k`, context format,
and cache-size settings.

Configure VeRL with:

```text
data.custom_cls.path=$PROJECT_DIR/recipe/security_harness/rl_dataset.py
data.custom_cls.name=SecurityHarnessDataset
custom_reward_function.path=$PROJECT_DIR/recipe/codeguarder_outcome/safe_k_reward.py
custom_reward_function.name=compute_score
```

`OUTCOME_SECURITY_WEIGHT` controls the blend and defaults to `0.5`:
`reward = (1 - weight) * functionality_pass_rate + weight * security_pass_rate`.
Both suites must be present; a failed or incomplete test harness returns `-1` so it
cannot masquerade as a functionality-only reward.
