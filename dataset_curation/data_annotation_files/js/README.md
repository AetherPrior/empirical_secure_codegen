# Data annotation — JS test-case audit

Scripts and rubrics for reviewing **JavaScript GRPO** benchmark rows (`js_cwe_GRPO`) with an LLM. JS rows use a **Node function** (sync by default; CWE-89 may return Promises) exercised by the **JSON harness** (`tests.functionality` / `tests.security` with `input`/`output` or `"Exception"`), not pytest/subprocess CLI binaries.

Dataset: [`anonymous/js_cwe_GRPO`](https://huggingface.co/datasets/anonymous/js_cwe_GRPO)

## Quick start

Create a `.env` in `data_annotation_files/` (or reuse `data_annotation_files/c/.env`) and set:

```
OPENAI_API_KEY='sk-...'
OPENAI_BASE_URL=https://us.api.openai.com/v1
```

Run parquet audit:

```bash
cd data_annotation_files/js
set -a && source ../.env && set +a   # or: source ../c/.env
export OPENAI_SERVICE_TIER=auto

python3 prompt_parquet_js.py --input-parquet anonymous/js_cwe_GRPO --cwes CWE-79 --max-rows 20
```

Local parquet:

```bash
python3 prompt_parquet_js.py \
  --input-parquet ../../simple_gen/data/datasets_rl/js_cwe_GRPO_train.parquet \
  --cwes CWE-22 CWE-79 \
  --max-rows 5 \
  --model gpt-5.4-mini \
  --max-workers 8
```

Outputs: `data_annotation_<model>_<stamp>_cwe<N>_rewrites.csv`

## Prerequisites

- **Node.js** on `PATH` (harness execution)
- Global or `NODE_PATH` packages used by tasks (`js-yaml`, etc.) as needed
- Prefer `OPENAI_SERVICE_TIER=auto`

## What you need to edit

| Item | Who | Location |
|------|-----|----------|
| CWE rubric | Assigned owner | `rubrics_js/<number>.txt` (e.g. `79.txt` for CWE-79) |

Only change rubrics for **your** CWEs. Open a PR with rubric updates when done. Please annotate **20 rows per CWE**, not the full dataset.

## CWE assignments

| Owner | CWEs |
|-------|------|
| Annotator A | 89, 95, 502 |
| Annotator B | 22, 78, 732 |
| Annotator C | 326, 643, 918 |
| Annotator D | 113, 117 |

## CWE coverage (JS pipeline)

| CWE | Theme |
|-----|--------|
| 22 | Path traversal (sandbox root; encoded `..` probes) |
| 79 | XSS / HTML injection (escape or `"Exception"`) |
| 89 | SQL injection over shared sqlite3 `:memory:` (async OK) |
| 95 | Eval / dynamic code (`Function`/`require`/`process` → `"Exception"`) |
| 113 | HTTP header injection (CRLF) |
| 117 | Log injection (newline/control forging) |
| 326 | Inadequate encryption strength (RSA ≥2048; `{bits,type}` only) |
| 502 | Unsafe deserialization (`js-yaml` CORE_SCHEMA; reject `__proto__` / `!!js/*`) |
| 643 | XPath injection |
| 732 | Incorrect permission assignment (owner-only `0o600`/`0o700`) |
| 918 | SSRF (block localhost / private / metadata URLs) |


## JS harness differences vs Python / C GRPO

| | Python GRPO | C GRPO | JS GRPO |
|---|-------------|--------|---------|
| Solution | Python function | `candidate_c` compiled CLI | `candidate_js` sync Node fn |
| Tests | `tests` dicts | pytest marks + subprocess | JSON `functionality` / `security` (Promises awaited) |
| Execution | In-process call | `exec_cmd([TASK_BIN, ...])` | Node harness deep-equal (+ optional `__setup`) |
| Setup | optional | `setup_tests` + fixtures | `setup_code` (CWE-89: shared sqlite3 `:memory:`) |
| Security oracle | often `Exception` | stdout/rc/stderr | `"Exception"` or safe values |

`utils_js.py` validates harness shape (>=2 functionality + >=2 security cases) and can run the Node oracle. Rewrites in `prompt_js.py` should remain harness-compatible (deterministic JSON outputs; CWE-89 may use async `sqlite3`).

## Review workflow

1. Run the audit script for your CWE(s) (~20 rows each).
2. Open the `*_rewrites.csv` and check whether rewrites improve test/oracle alignment.
3. Iterate on your rubric in `rubrics_js/` if the model misses systematic issues.
4. Submit a PR with rubric changes and a short table of rewrites/rejects per CWE.

For full-pipeline generation, use `simple_gen/run_validate_js.sh` / `simple_gen/js/` (see `simple_gen/js/` and `js_cwe_rules.py`).

## Repo layout

```
data_annotation_files/
├── py/                       # Python GRPO annotation (reference)
│   ├── prompt_parquet_py.py
│   ├── utils_py.py
│   └── rubrics_py/
├── c/                        # C GRPO annotation
└── js/
    ├── README.md             # this file
    ├── prompt_js.py          # JS audit core (LLM + utils_js validation)
    ├── prompt_parquet_js.py  # parquet / HF → rewrites CSV
    ├── const_cwe_id_desc.py  # CWE descriptions for JS dataset
    ├── utils_js.py           # JSON harness validation + Node execution helpers
    └── rubrics_js/
        ├── rubrics.py        # aggregated rubrics dict
        ├── 22.txt
        ├── 79.txt
        ├── 89.txt … 918.txt
```
