#!/bin/bash
# Run PromSec experiment inside Docker container.
#
# Usage:
#   bash docker_run.sh [--benchmark BENCHMARK] [--hf_token TOKEN] [options]
#
# Benchmarks:
#   seccodeplt (default)  script/run_promsec_secodeplt.py
#   cweval | promsec_cweval   script/run_promsec_cweval.py
#   promsec_rerun_vet     script/run_promsec_rerun_vet.py
#
# Examples:
#   bash docker_run.sh --benchmark seccodeplt --hf_token hf_xxx
#   bash docker_run.sh --benchmark cweval --max_tasks 3
#   bash docker_run.sh --benchmark promsec_rerun_vet --python_only --resume

set -e

IMAGE="verlai/verl:vllm018.dev1"
PROMSEC_DIR="/workspace/PromSec"

BENCHMARK="seccodeplt"
HF_TOKEN_VAL=""
REMAINING_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --benchmark)
            BENCHMARK="$2"
            shift 2
            ;;
        --hf_token)
            HF_TOKEN_VAL="$2"
            shift 2
            ;;
        *)
            REMAINING_ARGS+=("$1")
            shift
            ;;
    esac
done

case "${BENCHMARK}" in
    cweval|promsec_cweval)
        SCRIPT="script/run_promsec_cweval.py"
        ;;
    promsec_rerun_vet)
        SCRIPT="script/run_promsec_rerun_vet.py"
        ;;
    seccodeplt|promsec_secodeplt|*)
        SCRIPT="script/run_promsec_secodeplt.py"
        ;;
esac

echo "=== PromSec [${BENCHMARK}] ==="
echo "    Script: ${SCRIPT}"
echo "    Args  : ${REMAINING_ARGS[*]}"
echo ""

HF_TOKEN_ARG=()
if [[ -n "${HF_TOKEN_VAL}" && "${SCRIPT}" == "script/run_promsec_secodeplt.py" ]]; then
    HF_TOKEN_ARG=("--hf_token" "${HF_TOKEN_VAL}")
fi

docker run --rm \
    --gpus all \
    -v /workspace:/workspace \
    -v /workspace:/workspace \
    --workdir "${PROMSEC_DIR}" \
    -e PYTHONPATH="${PROMSEC_DIR}:${PROMSEC_DIR}/script" \
    -e HF_HOME="/workspace/dabstep/cache" \
    -e MY_HF_TOKEN="${HF_TOKEN_VAL}" \
    "${IMAGE}" \
    bash -c "pip install -q torch_geometric scikit-learn bandit prettytable accelerate natsort 2>&1 | tail -2 && \
             python ${SCRIPT} ${REMAINING_ARGS[*]} ${HF_TOKEN_ARG[*]}"
