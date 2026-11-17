# Data annotation — C++ test-case audit

Scripts and rubrics for reviewing **C++ GRPO** benchmark rows (`cpp_cwe_GRPO`) with an LLM. C++ rows use a compiled CLI binary exercised by **pytest + subprocess**, not Python `input`/`output` dict tests.

Dataset: [`anonymous/cpp_cwe_GRPO`](https://huggingface.co/datasets/anonymous/cpp_cwe_GRPO)

## Quick start

Create a `.env` in `data_annotation_files/` (or `data_annotation_files/cpp/`) and set:

```
OPENAI_API_KEY='sk-...'
OPENAI_BASE_URL=https://us.api.openai.com/v1
```

Run parquet audit:

```bash
cd data_annotation_files/cpp
set -a && source ../.env && set +a

python3 prompt_parquet_cpp.py --input-parquet anonymous/cpp_cwe_GRPO --cwes CWE-347 --max-rows 20
```

Local parquet:

```bash
python3 prompt_parquet_cpp.py \
  --input-parquet ../../simple_gen/data/datasets_rl/cpp_cwe_GRPO_train.parquet \
  --cwes CWE-78 --max-rows 5
```

## Prerequisites

- **g++** with C++17 (`CXX` env var optional)
- **pytest** in your Python environment
- Native deps for some CWEs (same as the C++ simple_gen pipeline):
  - **OpenSSL** (CWE-327, CWE-347): Homebrew `openssl@3` or system install
  - **libjwt 1.x** (CWE-347): e.g. `~/.local/libjwt-1`
  - **SQLite** (CWE-943): system `libsqlite3`
- AddressSanitizer builds for CWE-416 / CWE-787 (applied via `simple_gen/cpp/cwe_rules.py`)

Set `CPP_ANNOTATION_SKIP_HARNESS=1` to skip compile/pytest execution during dry runs (structure checks only).

## What you need to edit

| Item | Who | Location |
|------|-----|----------|
| CWE rubric | Assigned owner | `rubrics_cpp/<number>.txt` (e.g. `347.txt` for CWE-347) |

Only change rubrics for **your** CWEs. Open a PR with rubric updates when done. Please annotate **10 rows per CWE**, not the full dataset.

## CWE assignments

| Owner | CWEs |
|-------|------|
| Annotator A | 787, 347, 125 |
| Annotator B | 22, 78, 732 |
| Annotator C | 327, 119, 120 |
| Annotator D | 416, 943, 1333 |

## CWE coverage (C++ pipeline)

| CWE | Theme |
|-----|--------|
| 22 | Path traversal (`realpath`, empty stdout on escape) |
| 78 | Command injection (`fork`/`exec`, no shell; `safe_ls` baseline) |
| 119 | Buffer overflow / bounded copy |
| 120 | Buffer copy without size check |
| 125 | Out-of-bounds read (sentinel `-1`) |
| 327 | Weak crypto (OpenSSL EVP, not MD5/SHA1) |
| 347 | Improper JWT verify (libjwt 1.x, HS256, stdout `{}` on failure) |
| 1333 | ReDoS (`timeout=4`, stdout `0`; `<regex>` / `std::regex`) |
| 416 | Use-after-free (ASan, safe stdout) |
| 732 | File permissions (`0600`/`0700`) |
| 787 | Out-of-bounds write (in-place trim) |
| 943 | SQL injection (SQLite prepared statements) |

## C++ harness differences vs Python GRPO

| | Python GRPO | C++ GRPO |
|---|-------------|----------|
| Solution | Python function | `candidate_cpp` compiled CLI |
| Tests | `tests = {"functionality": [...], "security": [...]}` dicts | pytest `@pytest.mark.functionality` / `security` |
| Execution | In-process call | `exec_cmd([TASK_BIN, ...])` subprocess |
| Setup | optional | `setup_tests` with `exec_cmd`, `TASK_BIN`, fixtures |
| Security oracle | often `Exception` | stdout/rc/stderr (e.g. JSON `{}`, empty string, `0`/`1`) |
| Compiler | n/a | g++ `-std=c++17`; CWE-aware link flags from `simple_gen/cpp/cwe_rules.py` |

`utils_cpp.py` validates pytest harness shape (>=2 functionality + >=2 security cases, `TASK_BIN` usage, `exec_cmd` in setup) and can **compile + run** the C++ oracle through the local `harness/execution_harness_cpp.py` via `evaluate_cpp_harness()`. Rewrites in `prompt_cpp.py` must pass the harness before they are kept.

## C++ vs C annotation

The C++ stack mirrors `data_annotation_files/c/`:

| C | C++ |
|---|-----|
| `candidate_c` | `candidate_cpp` |
| `SAFE_K_CFLAGS` / gcc | `SAFE_K_CXXFLAGS` / g++ |
| `C_ANNOTATION_SKIP_HARNESS` | `CPP_ANNOTATION_SKIP_HARNESS` |
| `rubrics_c/` | `rubrics_cpp/` |
| `simple_gen/c/cwe_rules.py` | `simple_gen/cpp/cwe_rules.py` |

CWE-1333 rubrics call out `<regex>` / `std::regex` instead of POSIX `regcomp`.

## Review workflow

1. Run the audit script for your CWE(s) (~10 rows each).
2. Open the `*_rewrites.csv` and check whether rewrites improve test/oracle alignment.
3. Iterate on your rubric in `rubrics_cpp/` if the model misses systematic issues.
4. Submit a PR with rubric changes and a short table of rewrites/rejects per CWE.

## Repo layout

```
data_annotation_files/
├── py/                       # Python GRPO annotation (reference)
│   ├── prompt_parquet_py.py
│   ├── utils_py.py
│   └── rubrics_py/
├── c/
│   ├── prompt_parquet_c.py
│   ├── prompt_c.py
│   ├── utils_c.py
│   ├── harness/
│   └── rubrics_c/
└── cpp/
    ├── README.md             # this file
    ├── prompt_cpp.py         # C++ audit core (LLM + utils_cpp validation)
    ├── prompt_parquet_cpp.py # parquet / HF → rewrites CSV
    ├── const_cwe_id_desc.py  # CWE descriptions for C++ dataset
    ├── utils_cpp.py          # pytest harness AST validation + execution
    ├── harness/              # local copy of verl/recipe/security_harness (C++ only)
    │   ├── execution_harness_cpp.py
    │   └── pytest_harness_utils.py
    └── rubrics_cpp/
        ├── rubrics.py        # aggregated rubrics dict
        ├── 22.txt
        ├── 78.txt
        ├── 119.txt … 943.txt
```
