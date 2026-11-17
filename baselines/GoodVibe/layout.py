"""Repository locations and the upstream artifact naming convention."""
from pathlib import Path

CODE = Path(__file__).resolve().parent
BENCHMARKS = CODE.parents[1] / 'benchmarks'
STATE = CODE


def artifact_language(config):
    return 'cpp' if config['language'] == 'c++' else config['language']


def checkpoint_path(config):
    name = 'Qwen3-8B_' + artifact_language(config)
    return STATE / config['output'] / 'fine_tuned_cluster_models/cluster/train_model' / name / 'final_checkpoint' / name
