#!/usr/bin/env bash
# Run Python JSONL pipeline: tasks -> tests -> alignment -> contract -> filter -> rewrite.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v conda >/dev/null 2>&1; then
  eval "$(conda shell.bash hook)"
  conda activate vllm
fi

LANGUAGE="${LANGUAGE:-python}"
CWE="${CWE:-CWE-79}"
MODEL="${MODEL:-gpt-5.4-mini}"
NUM="${NUM:--1}"
WORKERS="${WORKERS:-16}"
# Per-row wall clock for exec(parse_tests) + dummy kwargs probe (0 = unlimited).
CONTRACT_SMOKE_ROW_TIMEOUT="${CONTRACT_SMOKE_ROW_TIMEOUT:-5}"
OUT_DIR="${HERE}/data/pipeline_runs"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [options]

Options:
  --language <name>   Language for generation stages (default: ${LANGUAGE})
  --cwe <id>          CWE id, e.g. CWE-502 (default: ${CWE})
  --model <name>      Model name for generation/alignment (default: ${MODEL})
  --num <n>           Number of rows for stage 0 (-1 = all, default: ${NUM})
  --workers <n>       Worker count for stages 0/1/2 (default: ${WORKERS})
  --out-dir <path>    Output directory root (default: ${OUT_DIR})
  -h, --help          Show this help

Environment:
  CONTRACT_SMOKE_ROW_TIMEOUT   Seconds per row for stage 3 (default: ${CONTRACT_SMOKE_ROW_TIMEOUT}; 0 = no limit)

Pipeline:
  0_generate_tasks_from_prosecalign.py
    -> 1_generate_testcases.py
    -> 2_harness_alignment.py
    -> 3_contract_smoke_test.py

Final output:
  <out-dir>/<language>/<cwe_slug>/3_filtered.jsonl
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

CWE_SLUG="$(printf '%s' "${CWE}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '_' | sed -E 's/^_+//; s/_+$//')"
RUN_DIR="${OUT_DIR}/${LANGUAGE}/${CWE_SLUG}"
mkdir -p "${RUN_DIR}"

STAGE0_OUT="${RUN_DIR}/0_tasks.jsonl"
STAGE1_OUT="${RUN_DIR}/1_testcases.jsonl"
STAGE2_OUT="${RUN_DIR}/2_harness_aligned.jsonl"
STAGE3_REPORT="${RUN_DIR}/3_contract_report.json"
STAGE3_FILTERED_JSONL="${RUN_DIR}/3_filtered.jsonl"
FINAL_JSONL="${RUN_DIR}/4_valid.jsonl"
REWRITTEN_JSONL="${RUN_DIR}/5_rewritten.jsonl"
REWRITTEN_DEBUG_JSONL="${RUN_DIR}/5_all_eval.debug.jsonl"

echo "[pipeline] language=${LANGUAGE} cwe=${CWE} model=${MODEL}"
echo "[pipeline] out_dir=${RUN_DIR}"

echo "[0] generating tasks -> ${STAGE0_OUT}"
python3 "${HERE}/py/0_generate_tasks_from_prosecalign.py" \
  --lang "${LANGUAGE}" \
  --cwe "${CWE}" \
  --num "${NUM}" \
  --model "${MODEL}" \
  --workers "${WORKERS}" \
  --out "${STAGE0_OUT}"

echo "[1] generating testcases -> ${STAGE1_OUT}"
python3 "${HERE}/py/1_generate_testcases.py" \
  --input-jsonl "${STAGE0_OUT}" \
  --output-jsonl "${STAGE1_OUT}" \
  --model "${MODEL}" \
  --cwe "${CWE}" \
  --max-workers "${WORKERS}" \
  --language "${LANGUAGE}"

echo "[2] harness alignment -> ${STAGE2_OUT}"
python3 "${HERE}/py/2_harness_alignment.py" \
  --input-jsonl "${STAGE1_OUT}" \
  --output-jsonl "${STAGE2_OUT}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}"

echo "[3] contract smoke + filtering -> ${STAGE3_FILTERED_JSONL}"
python3 "${HERE}/py/3_contract_smoke_test.py" \
  --input-jsonl "${STAGE2_OUT}" \
  --out "${STAGE3_REPORT}" \
  --filtered-jsonl "${STAGE3_FILTERED_JSONL}" \
  --row-timeout-seconds "${CONTRACT_SMOKE_ROW_TIMEOUT}"

echo "[4] filtering valid samples -> ${FINAL_JSONL}"
python3 "${HERE}/py/4_filter_valid_samples.py" \
  --input-jsonl "${STAGE3_FILTERED_JSONL}" \
  --output-jsonl "${FINAL_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}"

echo "[5] audit-rewrite + harness -> ${REWRITTEN_JSONL}"
python3 "${HERE}/py/5_rewrite_w_rubrics.py" \
  --input-jsonl "${FINAL_JSONL}" \
  --output-jsonl "${REWRITTEN_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}"



echo "Pipeline complete"
echo "  stage0 tasks:       ${STAGE0_OUT}"
echo "  stage1 testcases:   ${STAGE1_OUT}"
echo "  stage2 aligned:     ${STAGE2_OUT}"
echo "  stage3 report:      ${STAGE3_REPORT}"
echo "  final filtered:     ${FINAL_JSONL}"
echo "  rewritten:         ${REWRITTEN_JSONL}"


