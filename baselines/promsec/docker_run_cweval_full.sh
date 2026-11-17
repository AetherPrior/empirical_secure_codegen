#!/bin/bash
# PromSec CWEval: generation (Docker) + CWEval pipeline evaluation.
#
# Usage:
#   bash docker_run_cweval_full.sh [--eval_path PATH] [--iter_num N] [--skip_gen]
#
# Examples:
#   bash docker_run_cweval_full.sh
#   bash docker_run_cweval_full.sh --eval_path secure_reasoning/CWEval/evals/promsec_qwen3_8b_rerun
#   bash docker_run_cweval_full.sh --skip_gen   # eval only on existing eval_path

set -e

PROMSEC_DIR="/workspace/PromSec"
CWEVAL_DIR="${PROMSEC_DIR}/secure_reasoning/CWEval"
IMAGE="verlai/verl:vllm018.dev1"
EVAL_PATH=""
ITER_NUM=""
SKIP_GEN=0
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --eval_path) EVAL_PATH="$2"; shift 2 ;;
        --iter_num)  ITER_NUM="$2";  shift 2 ;;
        --skip_gen)  SKIP_GEN=1; shift ;;
        *) EXTRA_ARGS+=("$1"); shift ;;
    esac
done

if [[ -z "${EVAL_PATH}" ]]; then
    TS=$(date +%Y%m%d_%H%M%S)
    EVAL_PATH="${CWEVAL_DIR}/evals/promsec_qwen3_8b_${TS}"
fi
if [[ "${EVAL_PATH}" != /* ]]; then
    EVAL_PATH="${PROMSEC_DIR}/${EVAL_PATH}"
fi

GEN_ARGS=(--benchmark cweval --eval_path "${EVAL_PATH}")
[[ -n "${ITER_NUM}" ]] && GEN_ARGS+=(--iter_num "${ITER_NUM}")
GEN_ARGS+=("${EXTRA_ARGS[@]}")

echo "=== PromSec CWEval full run ==="
echo "    Eval path: ${EVAL_PATH}"
echo ""

if [[ "${SKIP_GEN}" -eq 0 ]]; then
    echo "[1/2] Generation + vet (Docker) ..."
    bash "${PROMSEC_DIR}/docker_run.sh" "${GEN_ARGS[@]}"
else
    echo "[1/2] Skipping generation (--skip_gen)"
fi

if [[ ! -d "${EVAL_PATH}/generated_0/core/py" ]]; then
    echo "ERROR: No generated files at ${EVAL_PATH}/generated_0/core/py"
    exit 1
fi

echo ""
echo "[2/2] CWEval pipeline (co1lin/cweval Docker, root for file perms) ..."
REL_EVAL_PATH="${EVAL_PATH#${CWEVAL_DIR}/}"
REL_EVAL_PATH="${REL_EVAL_PATH#/}"

docker run --rm --user root \
    -v "${CWEVAL_DIR}:/home/ubuntu/CWEval" \
    co1lin/cweval \
    bash -c "chmod -R a+rwX /home/ubuntu/CWEval/${REL_EVAL_PATH} && \
        source /home/ubuntu/miniforge3/bin/activate && cd /home/ubuntu/CWEval && \
        source .env && \
        python cweval/evaluate.py pipeline --eval_path ${REL_EVAL_PATH} --num_proc 8 --docker False && \
        python cweval/evaluate.py report_pass_at_k --eval_path ${REL_EVAL_PATH}"

echo ""
echo "=== Done ==="
echo "    Eval path : ${EVAL_PATH}"
echo "    Results   : ${EVAL_PATH}/res_all.json"
