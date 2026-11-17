#!/usr/bin/env bash
# Run run_validate_go.sh for each (language, CWE) pair.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_VALIDATE="${HERE}/run_validate_go.sh"

LANGUAGES=("go")
CWES=("79" "326" "732" "918")
MODEL="gpt-5.4-mini"
NUM="5"
WORKERS="8"
OUT_DIR="${HERE}/data/pipeline_runs_iter9"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --languages <csv>   Comma-separated output language folders (default: go)
  --cwes <csv>        Comma-separated CWE numbers or ids (default: 22,79,...)
  --model <name>      Model name for run_validate_go.sh
  --num <n>           Number of rows for stage 0 and cap for stages 5/6 (-1 = all)
  --workers <n>       Worker count for parallel stages
  --out-dir <path>    Output directory root (default: ${OUT_DIR})
  -h, --help          Show this help

Environment forwarded to each run_validate_go.sh:
  TASK_LANGUAGE, REQUEST_TIMEOUT
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --languages) IFS=',' read -r -a LANGUAGES <<< "$2"; shift 2 ;;
    --cwes) IFS=',' read -r -a CWES <<< "$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --num) NUM="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -f "$RUN_VALIDATE" ]] || { echo "missing $RUN_VALIDATE" >&2; exit 1; }

normalize_cwe() {
  local raw="$1"
  raw="${raw// /}"
  local upper
  upper="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
  if [[ "$upper" =~ ^CWE- ]]; then
    printf '%s' "$upper"
  else
    printf 'CWE-%s' "$raw"
  fi
}

for lang in "${LANGUAGES[@]}"; do
  for cwe in "${CWES[@]}"; do
    normalized_cwe="$(normalize_cwe "$cwe")"
    echo "================================================================"
    echo "Running pipeline for language=${lang}, cwe=${normalized_cwe}"
    echo "================================================================"
    bash "$RUN_VALIDATE" \
      --language "$lang" \
      --cwe "$normalized_cwe" \
      --model "$MODEL" \
      --num "$NUM" \
      --workers "$WORKERS" \
      --out-dir "$OUT_DIR"
  done
  echo
done
