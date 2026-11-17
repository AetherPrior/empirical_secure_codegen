## Setup
```
# 0. Install the OpenAI and tqdm package
pip install openai tqdm

# 1. Install nvm according to https://github.com/nvm-sh/nvm?tab=readme-ov-file#install--update-script
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

# 2. Configure node.js
nvm install --lts
nvm use --lts

# 3. Install dependencies globally
npm install -g escape-html node-rsa argon2 escape-string-regexp lodash js-yaml jsonwebtoken jsdom xpath sqlite3

# 4. Enable global dependencies in scripts
export NODE_PATH=$(npm root -g)
```

## Run the data collection process
```
$ ./run_validate_cwe_list_js.sh

# the $NUM field controls the number of samples, set it to -1 for all samples
# the $WORKERS field controls the number of parallel generations, increase it for faster scraping
```

Single-CWE example (sqlite3 async `:memory:` path for CWE-89):
```
bash run_validate_js.sh --cwe CWE-89 --num 100 --workers 16 --out-dir data/pipeline_runs
```

After filtering (`4_valid.jsonl`), the driver also runs:
- `5_rewrite_w_rubrics.py` → `5_rewritten.jsonl` (rubric audit + Node harness)

## Yield (pipeline retention)

| CWE | requested | filtered | valid (`5_valid`) | yield (valid/requested) | notes |
|-----|-----------|----------|-------------------|-------------------------|-------|
| CWE-89 | 100 | 99 | 55 | **55%** | async `sqlite3` `:memory:` + `__setup`; all 55 valid use sqlite3 (2026-08-06, gpt-5.4-mini) |

Per-run machine-readable summary: `data/pipeline_runs/js/cwe-89/yield.json`.

