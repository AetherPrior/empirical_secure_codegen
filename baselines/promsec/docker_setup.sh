#!/bin/bash
# Install missing dependencies inside verl_vllm18 container.
# Run once before starting experiments.
#
# Usage:
#   bash docker_setup.sh

set -e

CONTAINER="verl_vllm18"

echo "=== Installing missing packages inside ${CONTAINER} ==="

docker exec ${CONTAINER} pip install \
    torch_geometric \
    scikit-learn \
    bandit \
    prettytable \
    accelerate \
    --quiet

echo "=== Verifying installation ==="
docker exec ${CONTAINER} python -c "
import torch_geometric
import sklearn
import bandit
import accelerate
from prettytable import PrettyTable
print('torch_geometric:', torch_geometric.__version__)
print('sklearn OK')
print('bandit OK')
print('accelerate OK')
print('prettytable OK')
print('=== All packages ready ===')
"
