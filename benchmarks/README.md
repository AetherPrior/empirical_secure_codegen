# Benchmarks

| Benchmark | Original | Repaired | Fuzz tests (paper) |
|---|---|---|---|
| SecCodePLT-Python | `seccodeplt/data/` (data), `secode-eval/` (evaluator) | `secode-eval_repaired/` (data + evaluator) | `secode-eval_repaired/fuzzed/` |
| CWEval | `cweval/` | `cweval_repaired/` | `cweval_repaired/fuzzed/` |
| BaxBench | `baxbench/` | `baxbench_repaired/` (`SCENARIO_REPAIRS.md`, `repair_revision.json`) | none (no reference implementations) |

The original folders hold only what the original benchmark provides and the evaluator needs. Diffing an original folder
with its repaired folder shows the repairs. The fuzz tests are in a `fuzzed/` subfolder of the repaired benchmark; its
README gives the scoring rule and the command.

`run_plain_vllm.py` generates and scores on either variant (`--variant original|repaired`). It first copies the chosen
variant to `<out>/frozen/`.
