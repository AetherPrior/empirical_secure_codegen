#!/usr/bin/env bash
# Run C JSONL pipeline: tasks -> tests -> alignment -> contract -> filter -> rewrite.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v conda >/dev/null 2>&1; then
  CONDA_BASE="$(conda info --base 2>/dev/null || true)"
  if [[ -n "${CONDA_BASE}" && -f "${CONDA_BASE}/etc/profile.d/conda.sh" ]]; then
    # shellcheck disable=SC1090
    source "${CONDA_BASE}/etc/profile.d/conda.sh"
    conda activate local || true
  else
    eval "$(conda shell.bash hook)"
    conda activate local || true
  fi
fi

LANGUAGE="${LANGUAGE:-c}"
CWE="${CWE:-CWE-119}"
MODEL="${MODEL:-gpt-5.4-mini}"
NUM="${NUM:-10}"
WORKERS="${WORKERS:-8}"
CONTRACT_SMOKE_ROW_TIMEOUT="${CONTRACT_SMOKE_ROW_TIMEOUT:-5}"
C_CC="${C_CC:-}"
C_CFLAGS="${C_CFLAGS:--O0 -Wall -Wextra -Werror -Wno-error=unused-parameter}"
C_LDFLAGS="${C_LDFLAGS:-}"
# Keep these tight: hung pytest under ASan + high host load was wedging CWE-476 for hours.
PYTEST_TIMEOUT_SECONDS="${PYTEST_TIMEOUT_SECONDS:-20}"
COMPILE_TIMEOUT_SECONDS="${COMPILE_TIMEOUT_SECONDS:-20}"
OUT_DIR="${HERE}/data/pipeline_runs"

echo "[env] which python3: $(command -v python3 || echo 'python3 not found')"
python3 - <<'PY'
import sys
print("[env] sys.executable:", sys.executable)
try:
    import pytest  # noqa: F401
    print("[env] pytest: available")
except Exception as e:
    print("[env] pytest: missing:", type(e).__name__, e)
PY

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [options]

Options:
  --language <name>   Language for generation stages (default: ${LANGUAGE})
  --cwe <id>          CWE id, e.g. CWE-502 (default: ${CWE})
  --model <name>      Model name for generation/alignment (default: ${MODEL})
  --num <n>           Number of rows for stage 0 and cap for stages 5/6 (-1 = all, default: ${NUM})
  --workers <n>       Worker count for parallel stages (default: ${WORKERS})
  --out-dir <path>    Output directory root (default: ${OUT_DIR})
  -h, --help          Show this help

Environment:
  CONTRACT_SMOKE_ROW_TIMEOUT   RLIMIT_CPU seconds for pytest children in stage 5 (default: ${CONTRACT_SMOKE_ROW_TIMEOUT})
  C_CC, C_CFLAGS, C_LDFLAGS    Compiler flags for stage 5 harness (default includes CWE-aware ASan/libs)
  LIBJWT1_PREFIX                 libjwt 1.x install prefix (default: /opt/libjwt-1); see scripts/install_libjwt1.sh
  PYTEST_TIMEOUT_SECONDS       Wall timeout for pytest in stage 5 (default: ${PYTEST_TIMEOUT_SECONDS})
  COMPILE_TIMEOUT_SECONDS      gcc timeout in stage 5 (default: ${COMPILE_TIMEOUT_SECONDS})

Pipeline:
  0_generate_tasks_from_prosecalign.py
    -> 1_generate_testcases.py
    -> 2_harness_alignment.py
    -> 3_contract_smoke_test.py   (static harness validation only)
    -> 4_filter_valid_samples.py  (generates candidate_c + runs pytest harness)
    -> 5_rewrite_w_rubrics.py              (rubric audit + harness)

Final output:
  <out-dir>/<language>/<cwe_slug>/3_filtered.jsonl
  <out-dir>/<language>/<cwe_slug>/4_valid.jsonl
  <out-dir>/<language>/<cwe_slug>/5_rewritten.jsonl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --language)
      LANGUAGE="$2"
      shift 2
      ;;
    --cwe)
      CWE="$2"
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
    --out-dir)
      OUT_DIR="$2"
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

if [[ -z "${LANGUAGE}" ]]; then
  echo "--language cannot be empty" >&2
  exit 2
fi

if [[ -z "${CWE}" ]]; then
  echo "--cwe cannot be empty" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found in PATH" >&2
  exit 127
fi

# shellcheck source=c/setup_native_deps.sh
source "${HERE}/c/setup_native_deps.sh"
export CWE
apply_native_deps_env "${HERE}"

FILTER_EXTRA=()
if [[ -n "${C_CC}" ]]; then
  FILTER_EXTRA+=(--cc "${C_CC}")
fi
FILTER_EXTRA+=(--cflags="${C_CFLAGS}")
if [[ -n "${C_LDFLAGS}" ]]; then
  FILTER_EXTRA+=(--ldflags="${C_LDFLAGS}")
fi
FILTER_EXTRA+=(
  --timeout-seconds "${PYTEST_TIMEOUT_SECONDS}"
  --compile-timeout-seconds "${COMPILE_TIMEOUT_SECONDS}"
  --rlimit-cpu-seconds "${CONTRACT_SMOKE_ROW_TIMEOUT}"
)

CWE_SLUG="$(printf '%s' "${CWE}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '_' | sed -E 's/^_+//; s/_+$//')"
RUN_DIR="${OUT_DIR}/${LANGUAGE}/${CWE_SLUG}"
mkdir -p "${RUN_DIR}"

# CWE-aware compiler defaults (AddressSanitizer, OpenSSL, SQLite, libjwt).
if command -v python3 >/dev/null 2>&1; then
  _CWE_CFLAGS="$(
    SIMPLE_GEN_C_DIR="${HERE}/c" python3 -c "
import os, sys
sys.path.insert(0, os.environ['SIMPLE_GEN_C_DIR'])
from cwe_rules import default_cflags_for_cwe, default_ldflags_for_cwe
cwe = '''${CWE}'''
cflags = '''${C_CFLAGS}'''
ldflags = '''${C_LDFLAGS}'''
print(default_cflags_for_cwe(cwe, cflags))
print(default_ldflags_for_cwe(cwe, ldflags))
"
  )" || true
  if [[ -n "${_CWE_CFLAGS}" ]]; then
    C_CFLAGS="$(printf '%s\n' "${_CWE_CFLAGS}" | sed -n '1p')"
    C_LDFLAGS="$(printf '%s\n' "${_CWE_CFLAGS}" | sed -n '2p')"
  fi
fi

STAGE0_OUT="${RUN_DIR}/0_tasks.jsonl"
STAGE1_OUT="${RUN_DIR}/1_testcases.jsonl"
STAGE2_OUT="${RUN_DIR}/2_harness_aligned.jsonl"
STAGE4_REPORT="${RUN_DIR}/3_contract_report.json"
STAGE4_FILTERED_JSONL="${RUN_DIR}/3_filtered.jsonl"
VALID_JSONL="${RUN_DIR}/4_valid.jsonl"
REWRITTEN_JSONL="${RUN_DIR}/5_rewritten.jsonl"
REWRITE_AUDIT_JSONL="${RUN_DIR}/5_rewritten.audit.jsonl"

echo "[pipeline] language=${LANGUAGE} cwe=${CWE} model=${MODEL}"
echo "[pipeline] out_dir=${RUN_DIR}"

echo "[0] generating tasks -> ${STAGE0_OUT}"
python3 "${HERE}/c/0_generate_tasks_from_prosecalign.py" \
  --lang "${LANGUAGE}" \
  --cwe "${CWE}" \
  --num "${NUM}" \
  --model "${MODEL}" \
  --workers "${WORKERS}" \
  --out "${STAGE0_OUT}"

echo "[1] generating testcases -> ${STAGE1_OUT}"
python3 "${HERE}/c/1_generate_testcases.py" \
  --input-jsonl "${STAGE0_OUT}" \
  --output-jsonl "${STAGE1_OUT}" \
  --model "${MODEL}" \
  --cwe "${CWE}" \
  --max-workers "${WORKERS}" \
  --language "${LANGUAGE}"

echo "[2] harness alignment -> ${STAGE2_OUT}"
python3 "${HERE}/c/2_harness_alignment.py" \
  --input-jsonl "${STAGE1_OUT}" \
  --output-jsonl "${STAGE2_OUT}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}"

echo "[3] contract validation -> ${STAGE4_FILTERED_JSONL}"
python3 "${HERE}/c/3_contract_smoke_test.py" \
  --input-jsonl "${STAGE2_OUT}" \
  --out "${STAGE4_REPORT}" \
  --filtered-jsonl "${STAGE4_FILTERED_JSONL}"

echo "[4] filtering valid samples -> ${VALID_JSONL}"
python3 "${HERE}/c/4_filter_valid_samples.py" \
  --input-jsonl "${STAGE4_FILTERED_JSONL}" \
  --output-jsonl "${VALID_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}" \
  ${FILTER_EXTRA[@]+"${FILTER_EXTRA[@]}"}

echo "[5] audit-rewrite + harness -> ${REWRITTEN_JSONL}"
python3 "${HERE}/c/5_rewrite_w_rubrics.py" \
  --input-jsonl "${VALID_JSONL}" \
  --output-jsonl "${REWRITTEN_JSONL}" \
  --audit-jsonl "${REWRITE_AUDIT_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}"

echo
echo "Pipeline complete"
echo "  stage0 tasks:       ${STAGE0_OUT}"
echo "  stage1 testcases:   ${STAGE1_OUT}"
echo "  stage2 aligned:     ${STAGE2_OUT}"
echo "  stage4 report:      ${STAGE4_REPORT}"
echo "  stage4 filtered:    ${STAGE4_FILTERED_JSONL}"
echo "  valid samples:      ${VALID_JSONL}"
echo "  rewritten:          ${REWRITTEN_JSONL}"
echo "  rewrite audit:      ${REWRITE_AUDIT_JSONL}"
