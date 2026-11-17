#!/usr/bin/env bash
# Run run_validate_cpp.sh for each (language, CWE) pair.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_VALIDATE="${HERE}/run_validate_cpp.sh"

LANGUAGES=("cpp")
CWES=("347")
MODEL="gpt-5.4-mini"
NUM="2000"
WORKERS="16"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --languages <csv>   Default: cpp
  --cwes <csv>        Default: 119
  --model <name>
  --num <n>
  --workers <n>
  -h, --help

Environment forwarded to each run_validate_cpp.sh:
  CONTRACT_COMPILE_SMOKE, CXX, CXXFLAGS,
  COMPILE_TIMEOUT_SECONDS, RUN_TIMEOUT_SECONDS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --languages) IFS=',' read -r -a LANGUAGES <<< "$2"; shift 2 ;;
    --cwes) IFS=',' read -r -a CWES <<< "$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --num) NUM="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -f "$RUN_VALIDATE" ]] || { echo "missing $RUN_VALIDATE" >&2; exit 1; }

normalize_cwe() {
  local raw="$1"
  raw="${raw// /}"
  local upper
  upper="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]')"
  if [[ "$upper" == CWE-* ]]; then
    printf '%s' "$upper"
  else
    printf 'CWE-%s' "$upper"
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
      --workers "$WORKERS"
  done
  echo
done
