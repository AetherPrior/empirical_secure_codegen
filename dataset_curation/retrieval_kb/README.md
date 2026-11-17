# VeriSec-Retrieval knowledge base

This is a minimal first-stage artifact for producing controlled negative examples
from `anonymous/RL_seccode_gen`:

```text
prompt + secure reference + CWE ──→ vulnerable-code generation
                                      │
hidden functionality/security tests ─┴─→ execute and filter
```

A candidate is retained only when it is syntactically valid, passes **all**
functionality tests, and fails **at least one** security test. The secure reference
is preflighted against both test partitions before generation.

The generator receives only the task, language, CWE, and secure reference. Test code
and setup remain hidden and are used only by the evaluator, reducing test-specific
and harness-aware generations.

## Files

- `generate.py`: dataset loading, OpenAI-compatible generation, parallel evaluation,
  filtering, resume support, and JSONL output.
- `extract.py`: a parallel `gpt-5.4-mini`
  structured extraction call for functionality, root cause, vulnerable snippet,
  fixing pattern, and secure snippet. The snippets are derived deterministically
  with RESCUE-style program slicing: changed statements seed two-hop forward and
  backward data/control-dependence slices in each Python version, then unchanged
  source lines are aligned across the pair. The LLM supplies only the semantic
  descriptions. Python uses RESCUE's Tree-sitter CFG/PDG slicer, and C/C++ use the
  same RESCUE C-family CFG/PDG routines with their native Tree-sitter grammars.
  Parsing/slicing is required; there is no diff-hunk fallback. With `--resume`, it
  checkpoints each completed record immediately and skips its `attempt_key` on a
  later invocation.
- `collect_c_cpp_js.sh`: resumable full C/C++/JavaScript collection wrapper. It
  loads the local `.env` without printing it and uses checkpointing for both stages.
- `program_slicing.py`: local copy of RESCUE's slicer implementation.
- `semantic_slicing.py`: Tree-sitter adapter that loads the local slicer copy and
  handles Python, C, and C++ grammar selection plus one-based KB line numbering.
- `retrieval_keys.json`: the manually written high-level guideline for each of the 38 CWEs. The
  retrieval prompt shows it as `Guideline:` with every record of that CWE.
- `harness.py`: self-contained Python, C, C++, and JavaScript execution harness,
  adapted from `simple_gen` (no imports from `simple_gen` or `verl`).
- `tests/test_artifact.py`: offline contract smoke tests.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Python tasks need Python; native tasks need `gcc`/`g++`, `libjwt`, `libsqlite3`,
OpenSSL, and `pytest`; JavaScript tasks need Node.js plus the dependencies in
`package.json` (`npm install`). Native compilation selects the required libraries
per CWE, matching the source harness.

## Run

From this directory:

```bash
export OPENAI_API_KEY=...
python generate.py \
  --generation-workers 16 \
  --eval-workers 8 \
  --attempts 2 \
  --output outputs/vulnerable.jsonl \
  --audit-output outputs/all_attempts.jsonl
```

Generation always uses `gpt-5.4-mini`. Set `OPENAI_BASE_URL` only when the
configured OpenAI endpoint requires it.

Run the second extraction stage on accepted rows:

```bash
python extract.py \
  --input outputs/vulnerable.jsonl \
  --output outputs/extractions.jsonl \
  --workers 8 \
  --resume
```

For the full C/C++/JavaScript collection, use the wrapper (it reads `.env` but
never echoes it):

```bash
# Stage 1 only; safely resumes from all_attempts.jsonl.
./collect_c_cpp_js.sh stage1

# Stage 2 only; appends and syncs every completed extraction, then resumes safely.
./collect_c_cpp_js.sh stage2

# Run Stage 1 to completion, then Stage 2.
./collect_c_cpp_js.sh all
```


Useful research controls:

```bash
# Inspect and preflight ten records without model calls.
python generate.py --dataset DATA.parquet --limit 10 --dry-run

# Select a language/CWE and resume completed attempt keys.
python generate.py --language python --cwe CWE-89 --limit 100 --resume
```

`vulnerable.jsonl` contains accepted samples. `all_attempts.jsonl` contains every
generation, its exact test counts, rejection reason, model name, secure-reference
preflight result, and the untouched source row. Results are appended after each
batch; `--resume` skips attempt keys already present in the audit file.

## Reproducibility and safety

The default seed is fixed, source ordering is stable, and outputs are sorted within
each batch. Record the model revision and server configuration separately when the
provider does not expose them through its API.

The harness uses temporary directories, subprocess timeouts, process groups, and
resource limits. These controls are **not a sandbox**. Generated code is untrusted;
run large experiments inside a disposable, network-restricted container or VM.

Run the offline tests with:

```bash
pytest -q
```

## From the KB to the retrieval index

The KB used in the paper (`all_languages.jsonl`, 9,409 records over 38 CWEs and four languages) is
the extraction output of this pipeline. It is shipped as
`baselines_extended/Our-Retrieval/dataset/all_languages.jsonl`, with `retrieval_keys.json` beside it.
The same records are the secure/vulnerable pairs of VeriSec-Pairwise. Build
the per-language FAISS indexes that `Our-Retrieval/prepare.py` reads with
`baselines_extended/Our-Retrieval/build_index.py`.
