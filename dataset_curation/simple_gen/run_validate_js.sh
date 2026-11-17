#!/usr/bin/env bash
# Run JavaScript JSONL pipeline: tasks -> tests -> alignment -> contract -> filter -> rewrite.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v conda >/dev/null 2>&1; then
  CONDA_BASE="$(conda info --base 2>/dev/null || true)"
  if [[ -n "${CONDA_BASE}" && -f "${CONDA_BASE}/etc/profile.d/conda.sh" ]]; then
    # shellcheck disable=SC1090
    source "${CONDA_BASE}/etc/profile.d/conda.sh"
  else
    eval "$(conda shell.bash hook)"
  fi
  # Prefer local (annotation/simple_gen); fall back to vllm if present.
  conda activate local 2>/dev/null || conda activate vllm 2>/dev/null || true
fi

export PATH="/Users/anonymous/miniconda3/envs/local/bin:/opt/homebrew/bin:${PATH:-}"
# Harness deps (xpath/jsdom/sqlite3) live under ~/.npm-global on this host.
# Prefer that tree even if NODE_PATH is already set to a bare npm root-g without them.
_NPM_GLOBAL_MODULES="${HOME}/.npm-global/lib/node_modules"
_node_can_require() {
  local mod="$1"
  NODE_PATH="${NODE_PATH:-}" node -e "require('${mod}')" >/dev/null 2>&1
}
if [[ -d "${_NPM_GLOBAL_MODULES}/xpath" && -d "${_NPM_GLOBAL_MODULES}/jsdom" ]]; then
  if [[ -z "${NODE_PATH:-}" ]] || ! _node_can_require xpath || ! _node_can_require jsdom; then
    export NODE_PATH="${_NPM_GLOBAL_MODULES}"
  fi
elif [[ -z "${NODE_PATH:-}" ]] && command -v npm >/dev/null 2>&1; then
  export NODE_PATH="$(npm root -g)"
fi
unset _NPM_GLOBAL_MODULES
unset -f _node_can_require 2>/dev/null || true

load_dotenv_file() {
  local env_file="$1"
  [[ -f "${env_file}" ]] || return 0
  local line key value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" == export\ * ]] && line="${line#export }"
    [[ "${line}" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    [[ -n "${key}" && -z "${!key:-}" ]] && export "${key}=${value}"
  done < "${env_file}"
}

load_dotenv_file "${HERE}/.env"
load_dotenv_file "${HERE}/js/.env"

LANGUAGE="${LANGUAGE:-js}"
TASK_LANGUAGE="${TASK_LANGUAGE:-javascript}"
CWE="${CWE:-CWE-79}"
MODEL="${MODEL:-gpt-5.4-mini}"
NUM="${NUM:--1}"
WORKERS="${WORKERS:-16}"
OUT_DIR="${HERE}/data/pipeline_runs"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-120}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --language <name>       Output language folder (default: ${LANGUAGE})
  --task-language <name>  Language sent to task generator (default: ${TASK_LANGUAGE})
  --cwe <id>              CWE id, e.g. CWE-79 (default: ${CWE})
  --model <name>          Model name for generation/alignment (default: ${MODEL})
  --num <n>               Stage 0 row cap; also passed to stages 5-8 (-1 = all)
  --workers <n>           Worker count for parallel stages (default: ${WORKERS})
  --out-dir <path>        Output directory root (default: ${OUT_DIR})
  -h, --help              Show this help

Environment:
  REQUEST_TIMEOUT            OpenAI request timeout for stages 5-8 (default: ${REQUEST_TIMEOUT})
  NODE_PATH                  Node module path for harness deps (default: ~/.npm-global/lib/node_modules if present)

Pipeline:
  0_generate_tasks_from_prosecalign.py
    -> 1_generate_testcases.py
    -> 2_harness_alignment.py
    -> 3_contract_smoke_test.py
    -> 4_filter_valid_samples.py
    -> 5_rewrite_w_rubrics.py

Final output:
  <out-dir>/<language>/<cwe_slug>/3_filtered.jsonl
  <out-dir>/<language>/<cwe_slug>/4_valid.jsonl
  <out-dir>/<language>/<cwe_slug>/5_rewritten.jsonl
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --language) LANGUAGE="$2"; shift 2 ;;
    --task-language) TASK_LANGUAGE="$2"; shift 2 ;;
    --cwe) CWE="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --num) NUM="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "${LANGUAGE}" ]] || { echo "--language cannot be empty" >&2; exit 2; }
[[ -n "${TASK_LANGUAGE}" ]] || { echo "--task-language cannot be empty" >&2; exit 2; }
[[ -n "${CWE}" ]] || { echo "--cwe cannot be empty" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "python3 not found in PATH" >&2; exit 127; }
command -v node >/dev/null 2>&1 || { echo "node not found in PATH; JS harness requires Node.js" >&2; exit 127; }

CWE_SLUG="$(printf '%s' "${CWE}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '_' | sed -E 's/^_+//; s/_+$//')"
RUN_DIR="${OUT_DIR}/${LANGUAGE}/${CWE_SLUG}"
mkdir -p "${RUN_DIR}"

STAGE0_OUT="${RUN_DIR}/0_tasks.jsonl"
STAGE1_OUT="${RUN_DIR}/1_testcases.jsonl"
STAGE2_OUT="${RUN_DIR}/2_harness_aligned.jsonl"
STAGE4_REPORT="${RUN_DIR}/3_contract_report.json"
STAGE4_FILTERED_JSONL="${RUN_DIR}/3_filtered.jsonl"
VALID_JSONL="${RUN_DIR}/4_valid.jsonl"
REWRITTEN_JSONL="${RUN_DIR}/5_rewritten.jsonl"

echo "[pipeline] language=${LANGUAGE} task_language=${TASK_LANGUAGE} cwe=${CWE} model=${MODEL}"
echo "[pipeline] out_dir=${RUN_DIR}"
echo "[pipeline] NODE_PATH=${NODE_PATH:-}"

echo "[0] generating tasks -> ${STAGE0_OUT}"
python3 "${HERE}/js/0_generate_tasks_from_prosecalign.py" \
  --lang "${TASK_LANGUAGE}" \
  --cwe "${CWE}" \
  --num "${NUM}" \
  --model "${MODEL}" \
  --workers "${WORKERS}" \
  --out "${STAGE0_OUT}"

echo "[1] generating testcases -> ${STAGE1_OUT}"
python3 "${HERE}/js/1_generate_testcases.py" \
  --input-jsonl "${STAGE0_OUT}" \
  --output-jsonl "${STAGE1_OUT}" \
  --model "${MODEL}" \
  --cwe "${CWE}" \
  --max-workers "${WORKERS}"

echo "[2] harness alignment -> ${STAGE2_OUT}"
python3 "${HERE}/js/2_harness_alignment.py" \
  --input-jsonl "${STAGE1_OUT}" \
  --output-jsonl "${STAGE2_OUT}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}"

STAGE4_INPUT="${STAGE2_OUT}"

echo "[3] contract smoke -> ${STAGE4_FILTERED_JSONL}"
python3 "${HERE}/js/3_contract_smoke_test.py" \
  --input-jsonl "${STAGE4_INPUT}" \
  --out "${STAGE4_REPORT}" \
  --filtered-jsonl "${STAGE4_FILTERED_JSONL}"

echo "[4] filtering valid samples -> ${VALID_JSONL}"
python3 "${HERE}/js/4_filter_valid_samples.py" \
  --input-jsonl "${STAGE4_FILTERED_JSONL}" \
  --output-jsonl "${VALID_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}" \
  --request-timeout "${REQUEST_TIMEOUT}"

echo "[5] audit-rewrite + harness -> ${REWRITTEN_JSONL}"
python3 "${HERE}/js/5_rewrite_w_rubrics.py" \
  --input-jsonl "${VALID_JSONL}" \
  --output-jsonl "${REWRITTEN_JSONL}" \
  --model "${MODEL}" \
  --max-workers "${WORKERS}" \
  --max-rows "${NUM}" \
  --request-timeout "${REQUEST_TIMEOUT}"

echo
echo "Pipeline complete"
echo "  stage0 tasks:        ${STAGE0_OUT}"
echo "  stage1 testcases:    ${STAGE1_OUT}"
echo "  stage2 aligned:      ${STAGE2_OUT}"
echo "  stage4 report:       ${STAGE4_REPORT}"
echo "  stage4 filtered:     ${STAGE4_FILTERED_JSONL}"
echo "  valid samples:       ${VALID_JSONL}"
echo "  rewritten:           ${REWRITTEN_JSONL}"
