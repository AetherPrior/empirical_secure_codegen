# Single-sample GPT-4o and GPT-6.1-sol evaluation

Runs both requested API models on original and repaired SecCodePLT Python (819
tasks), CWEval C/C++/Python/JavaScript (100 tasks), and BaxBench Python/JavaScript
(224 tasks). One fresh generation per task, per model and benchmark variant.
All languages are pooled within each benchmark report.

Settings are in `configs/campaign.json`. Both models use the Responses API,
`store=false`, default service tier, no tools/retrieval, and a 16,384-token output
limit. GPT-4o uses temperature .6 and top-p .95. GPT-6.1-sol uses **high** reasoning
effort, with no unsupported temperature/top-p parameters. The limit includes
reasoning tokens for Sol. No API seed is supplied; `seed=42` is only the existing
evaluator's sample label. **One sample per task does not produce an across-seed SD.**

The endpoint and credential source match the existing Sol runner. The key is read
from `CodeGuarder_AE/.env` or the process environment; it is never copied into
this baseline, configs, logs, request artifacts or results. Raw API responses,
usage, response IDs, returned model IDs, request hashes and settings are saved.
The successful first-task API pilots are reused, avoiding an extra sample.

`job.py` preserves benchmark prompts, freezes source copies locally and imports
the same container evaluators used by our other baselines. Transport failures
are retried by the SDK; exhausted API/auth/model errors stop the arm for resume.
Empty/refused model answers are saved and scored as failed generations.
Evaluator failures remain zero outcomes in the benchmark rates.

`run.py` runs the two model campaigns concurrently, at 64 API workers each.
Each model has one CPU scoring queue with 64 workers, overlapping scoring with
its next arm's generation. GPU inference is not used. Runtime data stays here;
`benchmarks/` remains read-only and child processes disable bytecode writing.

```bash
/opt/conda/envs/vllm/bin/python baselines/OpenAI-Frontier/job.py --model gpt-4o --variant original --benchmark seccodeplt --operation pilot-evaluate
python -u baselines/OpenAI-Frontier/run.py
```

Reports: `outputs/<model>/<original|repaired>/<benchmark>/summary.json`.
They contain per-task rates with one evaluator sample label and **no SD**.
Task scores and API raw responses are retained alongside each report.
Status files exist at campaign, model, arm, and generation/evaluation levels.

Spreadsheet target: `Results-baselines`, `Methods w/ contributions` tab.
Original GPT-4o/Sol rows are 14/15; repaired rows are 31/32. Publish plain
percentage scores for C:E, G:I and K:L once each benchmark arm finishes,
with a single-run note rather than a fabricated zero SD.
