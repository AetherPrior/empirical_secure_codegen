# C simple_gen pipeline

## System dependencies

### Linux

```bash
sudo apt install libssl-dev openssl libsqlite3-dev libjwt-dev
sudo apt install libarchive-dev zlib1g-dev
```

`libjwt-dev` on Ubuntu is **1.x** (`jwt_decode` API).

### macOS

Homebrew `libjwt` is **3.x** (incompatible with CWE-347 tasks that use `jwt_decode`). Install libjwt 1.x:

```bash
# system prefix (requires sudo)
sudo bash scripts/install_libjwt1.sh

# or user-local (no sudo)
LIBJWT1_PREFIX="$HOME/.local/libjwt-1" bash scripts/install_libjwt1.sh
```

Also install OpenSSL + jansson for the build:

```bash
brew install openssl@3 jansson
```

`run_validate_c.sh` auto-detects `LIBJWT1_PREFIX`, `/opt/libjwt-1`, or `~/.local/libjwt-1`.

Install script: `simple_gen/scripts/install_libjwt1.sh`

## CWE-specific compile behavior

`c/cwe_rules.py` + `c/native_deps.py` drive prompts, pytest rubrics, and compiler flags:

| CWE group | Libraries | Compiler |
|-----------|-----------|----------|
| 119/120/125 (memory) | stdlib only | `-fsanitize=address` |
| 327/347 (crypto) | OpenSSL; libjwt **1.x** for 347 | `-lssl -lcrypto -ljwt` |
| 400 (resource exhaustion) | stdlib (`<regex.h>`) | — |
| 732 (file permissions) | stdlib, real file I/O | — |
| 943 (SQL injection) | SQLite3 | `-lsqlite3` |

Override via `C_CFLAGS` / `C_LDFLAGS` or `SAFE_K_CFLAGS` / `SAFE_K_LDFLAGS`.

## Stage 5: rubric audit

`run_validate_c.sh` runs this after stage 4 (`4_valid.jsonl`): `c/5_rewrite_w_rubrics.py` → `5_rewritten.jsonl` (+ `5_rewritten.audit.jsonl`).

Manual equivalent:

```bash
cd simple_gen
RUN=data/pipeline_runs/c/cwe-347

# Stage 5: LLM audit + harness (uses c/rubrics_c/ + data_annotation_files/c/prompt_c.py)
python3 c/5_rewrite_w_rubrics.py \
  --input-jsonl "$RUN/4_valid.jsonl" \
  --output-jsonl "$RUN/5_rewritten.jsonl" \
  --audit-jsonl "$RUN/5_rewritten.audit.jsonl"
```

Set `C_ANNOTATION_SKIP_HARNESS=1` to skip compile/pytest in stage 5 (structure checks only).
Feed `5_rewritten.jsonl` to `6_gather_rl_datasets_per_cwe.py` instead of `4_valid.jsonl` when building an updated GRPO dataset.
