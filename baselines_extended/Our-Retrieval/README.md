# Our user-prompt retrieval baseline

Qwen3-8B with the VeriSec-Retrieval KB, evaluated
on original and repaired SecCodePLT Python, CWEval C/C++/Python/JavaScript, and
BaxBench Python/JavaScript. Reports pool all requested languages per benchmark.

The user selected **user-prompt retrieval**: fresh reasoning, no cached prefix,
no Wait forcing, and no intervention inside the reasoning stream. This uses
the same context formatting as `cache_retrieval_traces.conditioned_messages`.

## Retrieval

`dataset/all_languages.jsonl` is the KB (9,409 records covering 38 CWEs and four
languages), built by `dataset_curation/retrieval_kb/`. `dataset/retrieval_keys.json`
holds the manually written high-level guideline for each CWE. `indexes/` holds the
per-language functionality indexes used in the paper (Jina v3 vectors unchanged);
`prepare.py` checks each index's record IDs, language and functionality text against
the KB. `python build_index.py` rebuilds them from the KB. A rebuild returns the same
top-3 records for 2,328 of the 2,473 benchmark queries (the shipped indexes: 2,468),
because the Python records were originally embedded in different batches.

Jina v3 retrieves the top three records by task functionality **within the task's
language**. CWEval/BaxBench use the existing adapters' `query` fields; SecCodePLT
uses `task_description.description`. No task decomposition or separate functional
reference KB is used.

`format_security_context` (taken from `upstream/knowledge_retrieval.py`) renders
each record's CWE, the CWE's high-level `Guideline`, the root cause and fixing
descriptions, and the paired vulnerable/secure program slices. This reproduces the
prompts of the reported run exactly. All three contexts are appended to the final
user message using the existing introduction string. Empty slices are retained,
matching the experiment renderer. Original benchmark/system instructions remain.

## Execution

`configs/campaign.json` pins Qwen3-8B and Jina revisions. Thinking is enabled;
seeds are 42/43/44, temperature .6, top-p .95, and output limit 16,384 tokens.
Original sets run on GPU 2 and repaired sets on GPU 3. Generation concurrency is
256 per GPU and each variant gets 64 CPU/container workers. CPU scoring overlaps
the next benchmark's generation. Hugging Face uses `/workspace/hf_home`.

All new code, indexes, dataset snapshots, frozen benchmarks, caches, logs, and
results are within this directory. `benchmarks/` and the reasoning-injection
experiment tree are read-only inputs. Preparation rejects prompt context overflow
instead of silently truncating examples or task instructions.

```bash
python baselines_extended/Our-Retrieval/run.py --dry-run
python -u baselines_extended/Our-Retrieval/run.py
```

Status: `outputs/status.json`, plus each variant's `status.json` and stage files.
Retrieval preparation has a `retrieval_prepare_status.json` and corresponding log
inside each variant. Selected records, distances, contexts, and exact prompts are
saved in each benchmark's `prepared_cases.json`. The dataset hash is recorded in
`retrieval_provenance.json`.

Reports: `outputs/{original,repaired}/{seccodeplt,cweval,baxbench}/summary.json`.
Each reports mean and sample SD over three seeds, with task-level results saved
under its `evaluation/` directory. These scores use the same total generation
budget as the base, GoodVibe, and CodeGuarder campaigns; they do not reproduce
the separate native reasoning-budget sweeps in the injection experiment scripts.
