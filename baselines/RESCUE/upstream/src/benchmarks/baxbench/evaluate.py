from __future__ import annotations

import subprocess
from argparse import ArgumentParser
from pathlib import Path

from src.benchmarks.baxbench.exec_benchmark import baxbench_python
from src.common import const


def run(model: str, method: str) -> None:
    results_dir = Path(const.BAXBENCH_RESULT_DIR, model, method).resolve()
    common = [
        baxbench_python(), "src/main.py", "--models", model,
        "--n_samples", str(const.BAXBENCH_SAMPLE), "--temperature", "0.2",
        "--spec_type", "openapi", "--safety_prompt", "none",
        "--results_dir", str(results_dir),
    ]
    subprocess.run(common + ["--mode", "test", "--max_concurrent_runs",
                              str(const.BAXBENCH_TEST_WORKERS)],
                   cwd=const.BAXBENCH_REPO_DIR, check=True)
    subprocess.run(common + ["--mode", "evaluate", "--ks", "1"],
                   cwd=const.BAXBENCH_REPO_DIR, check=True)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--method", required=True)
    args = parser.parse_args()
    run(args.model, args.method)
