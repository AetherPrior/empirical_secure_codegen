#!/usr/bin/env bash
# Resumable full C/C++/JavaScript collection. Run from any directory.
set -euo pipefail

COLLECT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT_STAGE="${1:-all}"
COLLECT_OUTPUT_DIR="${2:-$COLLECT_SCRIPT_DIR/outputs/security_kb_c_cpp_js_full}"

if [[ ! -f "$COLLECT_SCRIPT_DIR/.env" ]]; then
  echo "missing $COLLECT_SCRIPT_DIR/.env" >&2
  exit 2
fi

# Do not print this file or its variables. It supplies endpoint configuration only.
set -a
. "$COLLECT_SCRIPT_DIR/.env"
set +a

: "${COLLECT_GENERATION_WORKERS:=16}"
: "${COLLECT_EVAL_WORKERS:=8}"
: "${COLLECT_BATCH_SIZE:=128}"
: "${COLLECT_ATTEMPTS:=1}"
: "${COLLECT_EXTRACTION_WORKERS:=8}"

mkdir -p "$COLLECT_OUTPUT_DIR"

run_stage1() {
  python3 "$COLLECT_SCRIPT_DIR/generate.py" \
    --language c --language cpp --language javascript \
    --generation-workers "$COLLECT_GENERATION_WORKERS" \
    --eval-workers "$COLLECT_EVAL_WORKERS" \
    --batch-size "$COLLECT_BATCH_SIZE" \
    --attempts "$COLLECT_ATTEMPTS" \
    --resume \
    --output "$COLLECT_OUTPUT_DIR/vulnerable.jsonl" \
    --audit-output "$COLLECT_OUTPUT_DIR/all_attempts.jsonl"
}

run_stage2() {
  if [[ ! -s "$COLLECT_OUTPUT_DIR/vulnerable.jsonl" ]]; then
    echo "no accepted Stage 1 records at $COLLECT_OUTPUT_DIR/vulnerable.jsonl" >&2
    exit 2
  fi
  python3 "$COLLECT_SCRIPT_DIR/extract.py" \
    --input "$COLLECT_OUTPUT_DIR/vulnerable.jsonl" \
    --output "$COLLECT_OUTPUT_DIR/extractions.jsonl" \
    --workers "$COLLECT_EXTRACTION_WORKERS" \
    --resume
}

case "$COLLECT_STAGE" in
  stage1) run_stage1 ;;
  stage2) run_stage2 ;;
  all) run_stage1; run_stage2 ;;
  *)
    echo "usage: $0 {stage1|stage2|all} [output-directory]" >&2
    exit 2
    ;;
esac
