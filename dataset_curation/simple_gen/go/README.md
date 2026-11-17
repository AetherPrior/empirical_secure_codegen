## Setup
```
# 0. Install Python dependencies
pip install openai tqdm datasets
pip install pytest

# 1. Install Go (1.23+ recommended)
# https://go.dev/doc/install

# 2. Ensure CGO is available (required for github.com/mattn/go-sqlite3)
# macOS: xcode-select --install
# Linux: apt install build-essential

# 3. Initialize the verl submodule (harness lives at verl/recipe/security_harness/)
git submodule update --init --recursive
```

## Run the data collection process
```
$ ./run_validate_cwe_list_go.sh

# the $NUM field controls the number of samples, set it to -1 for all samples
# the $WORKERS field controls the number of parallel generations, increase it for faster scraping
```

## Pipeline layout

Mirrors `simple_gen/js/`:

| Stage | Script | Output |
|-------|--------|--------|
| 0 | `0_generate_tasks_from_prosecalign.py` | `0_tasks.jsonl` |
| 1 | `1_generate_testcases.py` | `1_testcases.jsonl` |
| 2 | `2_harness_alignment.py` | `2_harness_aligned.jsonl` |
| 3 | `3_contract_smoke_test.py` | `3_filtered.jsonl` |
| 4 | `4_filter_valid_samples.py` | `4_valid.jsonl` (generates `candidate_go` + pytest harness) |

Harness evaluation uses `verl/recipe/security_harness/execution_harness_go.py`, which compiles
candidate Go with `go build` into `compiled/<function_name>_task` and runs the CWEval-style
pytest harness (`setup_tests` + `test_code`) which invokes the binary via `subprocess`.

Allowed third-party modules: `github.com/golang-jwt/jwt/v5`, `golang.org/x/crypto`,
`github.com/mattn/go-sqlite3`, `github.com/ChrisTrenkamp/goxpath`, `gopkg.in/yaml.v3`.
