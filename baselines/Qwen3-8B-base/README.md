# Base Qwen3-8B benchmark evaluation

Evaluates the unmodified `Qwen/Qwen3-8B` checkpoint on both original and repaired
SecCodePLT Python (819 tasks), CWEval C/C++/Python/JavaScript (100 tasks), and
BaxBench Python/JavaScript (224 tasks). Each benchmark report includes all its
requested languages, pooled by task.

`configs/campaign.json` pins model revision
`b968826d9c46dd6066d109eabc6255188de91218`. Generation uses the benchmarks'
unaugmented prompts, thinking enabled, seeds 42/43/44, temperature .6, top-p .95,
and 16,384 output tokens. There is no retrieval, task decomposition, knowledge
injection, fine-tuning, or language-dependent checkpoint routing.

GPU 2 handles original benchmarks; GPU 3 handles repaired benchmarks. Each GPU
supports 256 concurrent sequences with 92% memory utilization. Each worker uses
64 CPU/container evaluation workers (128 total). Generation and CPU scoring
overlap. GPU memory checks wait for other workloads instead of stopping them.

All configuration, code, frozen benchmark copies, logs and results stay here.
The `benchmarks/` tree is read-only and Python bytecode writing is disabled in
workers. Hugging Face uses `/workspace/hf_home`; runtime compilation caches
are under `outputs/cache/`. BaxBench uses separate port bases 47000 and 48000.

The baseline-local evaluation runner and pinned container metadata were copied
from the validated CodeGuarder evaluator; prompt augmentation support has been
removed. Generation and scoring otherwise use the same benchmark adapters as
the GoodVibe and CodeGuarder campaigns. The context limit is 40,960 tokens,
matching the CodeGuarder configuration and leaving the same output-token budget.

```bash
python baselines/Qwen3-8B-base/run.py --dry-run
python -u baselines/Qwen3-8B-base/run.py
```

Progress: `outputs/status.json` and `outputs/{original,repaired}/status.json`.
Per-stage status and logs appear in each variant directory. A finished generation
can be rescored without a GPU; existing generation files are reused on restart.
Final reports: `outputs/{original,repaired}/{seccodeplt,cweval,baxbench}/summary.json`.
These contain mean and sample standard deviation across the three seeds, plus
per-seed scores and evaluator failure counts. Raw samples and task-level scores
are saved alongside them.
