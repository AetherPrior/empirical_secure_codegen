# Original CodeGuarder with Qwen3-8B

Runs the original released standard-scenario CodeGuarder on SecCodePLT Python,
CWEval C/C++/Python/JavaScript, and BaxBench Python/JavaScript, using both original
and repaired benchmarks. Each benchmark report pools all requested languages.
All code, configurations, indexes, logs, frozen benchmark copies and results
live here. `benchmarks/` is read-only. Hugging Face uses `/workspace/hf_home`.

## Method and provenance

`upstream/` was extracted from the existing `/workspace/CodeGuarder_AE.zip`,
not the hierarchical CodeGuarder extension. `upstream/manifest.json` records
SHA256 hashes. The original `Defense_Standard.py` matches the existing original
checkout byte-for-byte. The paper is
[Give LLMs a Security Course](https://arxiv.org/abs/2504.16429).

The original artifact supplies 16,141 security knowledge records and 12,053
fixed-code reference examples. The copied Jina FAISS indexes were checked
record-by-record against those archived files. A fresh Jina encoding of the
first functionality has cosine similarity 0.99997 with its cached vector.

This adapter preserves the released standard pipeline:

1. Decompose the task into functional subtasks.
2. Retrieve five security entries per subtask using the original Jina v3
   embeddings and FAISS L2 index (normalized embeddings).
3. Select two entries per subtask in rank-major order and deduplicate while
   preserving order, exactly as `Defense_Standard.main` does.
4. Retrieve one fixed-code example from ReposVul using the whole task query.
5. Call the original `construct_prompt` function and generate with Qwen3-8B.

The paper discusses susceptibility-based re-ranking, but the released standard
script does not invoke such a reranker. We follow the released executable
selection policy rather than adding a new ranking algorithm.

Adaptations for these benchmarks are explicit:

- The artifact only includes precomputed decompositions for its own tasks.
  We generate new ones with Qwen3-8B, temperature 0, seed 42, thinking disabled,
  and a structured JSON schema. The adapter prompt is in `prepare.py`.
  A truncated/invalid decomposition is retried; it never silently falls back
  to an undecomposed query. Decompositions are reused across identical queries.
  Recovery retries explicitly isolate task instructions as data and constrain
  the response to at most 16 subtasks, each at most 512 characters, with up to
  three attempts. Initial invalid outputs are retained in
  `outputs/decomposition_retries/` for inspection. Previously valid results
  remain unchanged when resuming.
- Full benchmark instructions, signatures, setup and system messages are kept.
  The release's first-line truncation is unsuitable for these multiline tasks.
- BaxBench receives one final instruction to preserve its multi-file response
  format. Security knowledge and reference contents are unchanged.
- No additional hierarchy, fine-tuning, feedback revision or vulnerability
  judge is introduced. Qwen3-8B handles both decomposition and final generation.
- Security/reference retrieval is not language-filtered, matching the release.
- Prompt lengths are checked before generation; instructions and retrieved
  knowledge are not silently truncated.

## Configuration and execution

`configs/campaign.json` pins Qwen3-8B and Jina revisions. Final generation uses
thinking, temperature .6, top-p .95, seeds 42/43/44, 16,384 output tokens and
a 40,960-token context. The campaign uses only GPU 3, currently the free GPU,
with 256 concurrent generation sequences, 92% GPU memory allocation and 128
CPU/container evaluation workers. Other active GPU jobs are left alone.

The existing `vllm` environment handles generation/evaluation, and `cgp` handles
Jina retrieval. Base model files have been copied into `/workspace/hf_home`.

```bash
python baselines/CodeGuarder/test_adapter.py
python baselines/CodeGuarder/run.py --dry-run
python baselines/CodeGuarder/run.py --smoke
python -u baselines/CodeGuarder/run.py
```

`python -u baselines/CodeGuarder/launch.py` performs the smoke run and then starts
the full campaign automatically. It waits when GPU 3 lacks the memory needed
for the configured concurrency, without stopping other users' GPU processes.
See `outputs/launch_status.json`, `outputs_smoke/status.json`, and
`outputs/status.json` for the supervisor and individual phase status.

The smoke run freezes one task from each benchmark/variant, exercises
decomposition and retrieval for all of them, and completes generation and
evaluation for one original SecCodePLT task. It is not a quality estimate.

Full progress is in `outputs/status.json` and `outputs/logs/`. Results are
`outputs/{original,repaired}/{seccodeplt,cweval,baxbench}/summary.json`, with
task-level scores in each job's `evaluation/scores.json`. Prompt augmentation,
decomposition outputs, retrieval indexes/distances and injected knowledge are
saved for inspection. No benchmark answers or tests enter the retrieval KB.
