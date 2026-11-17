#!/usr/bin/env bash
# Run C++ JSONL pipeline: tasks -> tests -> alignment -> contract -> filter -> rewrite.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load API key / service tier for all stages (0/1 do not load dotenv themselves).
if [[ -f "${HERE}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${HERE}/.env"
  set +a
fi

if command -v conda >/dev/null 2>&1; then
  CONDA_BASE="$(conda info --base 2>/dev/null || true)"
  if [[ -n "${CONDA_BASE}" && -f "${CONDA_BASE}/etc/profile.d/conda.sh" ]]; then
    # shellcheck disable=SC1090
    source "${CONDA_BASE}/etc/profile.d/conda.sh"
    conda activate vllm || true
  else
    eval "$(conda shell.bash hook)"
    conda activate vllm || true
  fi
fi

LANGUAGE="${LANGUAGE:-cpp}"
CWE="${CWE:-CWE-119}"
MODEL="${MODEL:-gpt-5.4-mini}"
NUM="${NUM:-10}"
WORKERS="${WORKERS:-16}"
CONTRACT_SMOKE_ROW_TIMEOUT="${CONTRACT_SMOKE_ROW_TIMEOUT:-5}"
PYTEST_COMPILE_SMOKE="${PYTEST_COMPILE_SMOKE:-0}"
CXX="${CXX:-}"
CXXFLAGS="${CXXFLAGS:--O0 -Wall -Wextra -Werror -Wno-error=unused-parameter}"
LDFLAGS="${LDFLAGS:-}"
PYTEST_TIMEOUT_SECONDS="${PYTEST_TIMEOUT_SECONDS:-60}"
COMPILE_TIMEOUT_SECONDS="${COMPILE_TIMEOUT_SECONDS:-60}"
OUT_DIR="${HERE}/data/pipeline_runs"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --language <name>   Default: ${LANGUAGE}
  --cwe <id>          Default: ${CWE}
  --model <name>      Default: ${MODEL}
  --num <n>           Stage 0 row cap; also passed to stages 5/6 (-1 = all)
  --workers <n>       Default: ${WORKERS}
  --out-dir <path>    Default: ${OUT_DIR}
  -h, --help

Environment:
  CONTRACT_SMOKE_ROW_TIMEOUT   RLIMIT_CPU for pytest children (default: ${CONTRACT_SMOKE_ROW_TIMEOUT})
  PYTEST_COMPILE_SMOKE         If 1, stage 4 runs --pytest-smoke --pytest-via-cxx-compile
  CXX, CXXFLAGS, LDFLAGS       Compiler flags for stages 4 (if compile smoke) and 5
  PYTEST_TIMEOUT_SECONDS       Wall timeout for pytest (default: ${PYTEST_TIMEOUT_SECONDS})
  COMPILE_TIMEOUT_SECONDS      g++ timeout (default: ${COMPILE_TIMEOUT_SECONDS})

Pipeline:
  0 -> 1 -> 2 -> 3_contract_smoke_test -> 4_filter_valid_samples
  -> 5_rewrite_w_rubrics

Outputs:
  .../3_filtered.jsonl
  .../4_valid.jsonl
  .../5_rewritten.jsonl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --language) LANGUAGE="$2"; shift 2 ;;
    --cwe) CWE="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --num) NUM="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 127; }

CWE_SLUG="$(printf '%s' "${CWE}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '_' | sed -E 's/^_+//; s/_+$//')"
RUN_DIR="${OUT_DIR}/${LANGUAGE}/${CWE_SLUG}"
mkdir -p "${RUN_DIR}"

# CWE-aware compiler defaults (AddressSanitizer, OpenSSL, SQLite, libjwt).
if command -v python3 >/dev/null 2>&1; then
  _CWE_CXXFLAGS="$(
    SIMPLE_GEN_CPP_DIR="${HERE}/cpp" python3 -c "
import os, sys
sys.path.insert(0, os.environ['SIMPLE_GEN_CPP_DIR'])
from cwe_rules import default_cxxflags_for_cwe, default_ldflags_for_cwe
cwe = '''${CWE}'''
cxxflags = '''${CXXFLAGS}'''
ldflags = '''${LDFLAGS}'''
print(default_cxxflags_for_cwe(cwe, cxxflags))
print(default_ldflags_for_cwe(cwe, ldflags))
"
  )" || true
  if [[ -n "${_CWE_CXXFLAGS}" ]]; then
    CXXFLAGS="$(printf '%s\n' "${_CWE_CXXFLAGS}" | sed -n '1p')"
    LDFLAGS="$(printf '%s\n' "${_CWE_CXXFLAGS}" | sed -n '2p')"
  fi
fi

FILTER_EXTRA=()
if [[ -n "${CXX}" ]]; then
  FILTER_EXTRA+=(--cxx "${CXX}")
fi
FILTER_EXTRA+=(--cxxflags="${CXXFLAGS}")
if [[ -n "${LDFLAGS}" ]]; then
  FILTER_EXTRA+=(--ldflags="${LDFLAGS}")
fi
FILTER_EXTRA+=(
  --timeout-seconds "${PYTEST_TIMEOUT_SECONDS}"
  --compile-timeout-seconds "${COMPILE_TIMEOUT_SECONDS}"
  --rlimit-cpu-seconds "${CONTRACT_SMOKE_ROW_TIMEOUT}"
)

REWRITE_EXTRA=()
if [[ -n "${CXX}" ]]; then
  REWRITE_EXTRA+=(--cxx "${CXX}")
fi
REWRITE_EXTRA+=(--cxxflags="${CXXFLAGS}")
if [[ -n "${LDFLAGS}" ]]; then
  REWRITE_EXTRA+=(--ldflags="${LDFLAGS}")
fi
REWRITE_EXTRA+=(--compile-timeout-seconds "${COMPILE_TIMEOUT_SECONDS}")

STAGE0_OUT="${RUN_DIR}/0_tasks.jsonl"
STAGE1_OUT="${RUN_DIR}/1_testcases.jsonl"
STAGE2_OUT="${RUN_DIR}/2_harness_aligned.jsonl"
STAGE4_REPORT="${RUN_DIR}/3_contract_report.json"
STAGE4_FILTERED="${RUN_DIR}/3_filtered.jsonl"
VALID_JSONL="${RUN_DIR}/4_valid.jsonl"
REWRITTEN_JSONL="${RUN_DIR}/5_rewritten.jsonl"
REWRITTEN_DEBUG_JSONL="${RUN_DIR}/5_all_eval.debug.jsonl"

echo "[pipeline] language=${LANGUAGE} cwe=${CWE} model=${MODEL}"
echo "[pipeline] out_dir=${RUN_DIR}"

echo "[0] tasks -> ${STAGE0_OUT}"
python3 "${HERE}/cpp/0_generate_tasks_from_prosecalign.py" \
  --lang "${LANGUAGE}" --cwe "${CWE}" --num "${NUM}" \
  --model "${MODEL}" --workers "${WORKERS}" --out "${STAGE0_OUT}"

echo "[1] testcases -> ${STAGE1_OUT}"
python3 "${HERE}/cpp/1_generate_testcases.py" \
  --input-jsonl "${STAGE0_OUT}" --output-jsonl "${STAGE1_OUT}" \
  --model "${MODEL}" --cwe "${CWE}" --max-workers "${WORKERS}" --language "${LANGUAGE}"

echo "[2] harness alignment -> ${STAGE2_OUT}"
python3 "${HERE}/cpp/2_harness_alignment.py" \
  --input-jsonl "${STAGE1_OUT}" --output-jsonl "${STAGE2_OUT}" \
  --model "${MODEL}" --max-workers "${WORKERS}"

STAGE4_INPUT="${STAGE2_OUT}"

echo "[3] contract smoke -> ${STAGE4_FILTERED}"
STAGE4_EXTRA=()
if [[ "${PYTEST_COMPILE_SMOKE}" == "1" ]]; then
  STAGE4_EXTRA=(--pytest-smoke --pytest-via-cxx-compile)
  if [[ -n "${CXX}" ]]; then
    STAGE4_EXTRA+=(--cxx "${CXX}")
  fi
  STAGE4_EXTRA+=(--cxxflags="${CXXFLAGS}")
  if [[ -n "${LDFLAGS}" ]]; then
    STAGE4_EXTRA+=(--ldflags="${LDFLAGS}")
  fi
  STAGE4_EXTRA+=(
    --pytest-timeout-seconds "${PYTEST_TIMEOUT_SECONDS}"
    --compile-timeout-seconds "${COMPILE_TIMEOUT_SECONDS}"
  )
fi
STAGE4_EXTRA+=(--rlimit-cpu-seconds "${CONTRACT_SMOKE_ROW_TIMEOUT}")
python3 "${HERE}/cpp/3_contract_smoke_test.py" \
  --input-jsonl "${STAGE4_INPUT}" \
  --out "${STAGE4_REPORT}" \
  --filtered-jsonl "${STAGE4_FILTERED}" \
  ${STAGE4_EXTRA[@]+"${STAGE4_EXTRA[@]}"}

echo "[4] filter valid -> ${VALID_JSONL}"
python3 "${HERE}/cpp/4_filter_valid_samples.py" \
  --input-jsonl "${STAGE4_FILTERED}" \
  --output-jsonl "${VALID_JSONL}" \
  --model "${MODEL}" --max-workers "16" --max-rows "${NUM}" \
  ${FILTER_EXTRA[@]+"${FILTER_EXTRA[@]}"}

echo "[5] audit-rewrite + harness -> ${REWRITTEN_JSONL}"
python3 "${HERE}/cpp/5_rewrite_w_rubrics.py" \
  --input-jsonl "${VALID_JSONL}" \
  --output-jsonl "${REWRITTEN_JSONL}" \
  --all-output-jsonl "${REWRITTEN_DEBUG_JSONL}" \
  --model "${MODEL}" --max-workers "${WORKERS}" --max-rows "${NUM}" \
  ${REWRITE_EXTRA[@]+"${REWRITE_EXTRA[@]}"}

echo
echo "Pipeline complete"
echo "  tasks:        ${STAGE0_OUT}"
echo "  testcases:    ${STAGE1_OUT}"
echo "  aligned:      ${STAGE2_OUT}"
echo "  contract:     ${STAGE4_REPORT}"
echo "  filtered:     ${STAGE4_FILTERED}"
echo "  valid:        ${VALID_JSONL}"
echo "  rewritten:    ${REWRITTEN_JSONL}"
