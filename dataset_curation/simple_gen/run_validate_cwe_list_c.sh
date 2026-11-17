#!/usr/bin/env bash
# Run run_validate_c.sh for each (language, CWE) pair.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_VALIDATE="${HERE}/run_validate_c.sh"

# Prefer the ``local`` conda env (pytest, pyarrow, openai, …).
_LOCAL_CONDA_BIN="${LOCAL_CONDA_BIN:-${HOME}/miniconda3/envs/local/bin}"
if [[ -d "${_LOCAL_CONDA_BIN}" ]]; then
  export PATH="${_LOCAL_CONDA_BIN}:${PATH:-}"
fi
if command -v conda >/dev/null 2>&1; then
  CONDA_BASE="$(conda info --base 2>/dev/null || true)"
  if [[ -n "${CONDA_BASE}" && -f "${CONDA_BASE}/etc/profile.d/conda.sh" ]]; then
    # shellcheck disable=SC1090
    source "${CONDA_BASE}/etc/profile.d/conda.sh"
    conda activate local 2>/dev/null || true
  fi
fi
export CC="${CC:-$(command -v gcc 2>/dev/null || command -v clang 2>/dev/null || true)}"

LANGUAGES=("c")
CWES=("476")
# 120
MODEL="gpt-5.4-mini"
NUM="2000"
WORKERS="4"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --languages <csv>   Comma-separated languages (default: c)
  --cwes <csv>        Comma-separated CWE numbers or ids (default: 119)
  --model <name>      Model name for run_validate_c.sh
  --num <n>           Number of rows for stage 0 and cap for stages 5/6 (-1 = all)
  --workers <n>       Worker count for parallel stages
  -h, --help          Show this help

Environment (forwarded to each run_validate_c.sh invocation):
  C_CC, C_CFLAGS, C_LDFLAGS, PYTEST_TIMEOUT_SECONDS, COMPILE_TIMEOUT_SECONDS,
  CONTRACT_SMOKE_ROW_TIMEOUT
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

if [[ ! -f "$RUN_VALIDATE" ]]; then
  echo "run_validate_c.sh not found at $RUN_VALIDATE" >&2
  exit 1
fi

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
