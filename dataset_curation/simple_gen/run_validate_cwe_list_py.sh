#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_VALIDATE="${HERE}/run_validate_py.sh"

LANGUAGES=("python")
CWES=("918")  
# "78" "89" "22" "502" "352"
MODEL="gpt-5.4-mini"
NUM="-1"
WORKERS="8"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --languages <csv>   Comma-separated languages (default: python)
  --cwes <csv>        Comma-separated CWE numbers (default: 78,89,22)
  --model <name>      Model name for run_validate.sh
  --num <n>           Number of rows for stage 0 (-1 = all)
  --workers <n>       Worker count for stages 0/1/2
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --languages)
      IFS=',' read -r -a LANGUAGES <<< "$2"
      shift 2
      ;;
    --cwes)
      IFS=',' read -r -a CWES <<< "$2"
      shift 2
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --num)
      NUM="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! -x "$RUN_VALIDATE" ]]; then
  echo "run_validate.sh not found or not executable at $RUN_VALIDATE" >&2
  exit 1
fi

normalize_cwe() {
  local raw="$1"
  if [[ "$raw" =~ ^CWE- ]]; then
    printf '%s' "$raw"
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
    "$RUN_VALIDATE" \
      --language "$lang" \
      --cwe "$normalized_cwe" \
      --model "$MODEL" \
      --num "$NUM" \
      --workers "$WORKERS"
  done
  echo
done
