from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from src.benchmarks.benchmark import Benchmark, BenchmarkItem
from src.common import const


def baxbench_python() -> str:
    override = os.environ.get("BAXBENCH_PYTHON")
    if override:
        return override
    candidate = Path("/workspace/virtualenvs/baxbench/bin/python")
    return str(candidate) if candidate.exists() else "python3.12"


@dataclass
class BaxBenchItem(BenchmarkItem):
    env_id: str = ""
    scenario_id: str = ""
    sample: int = 0


class BaxBenchBenchmark(Benchmark):
    def __init__(self, model_name: str, method_name: str) -> None:
        super().__init__(model_name, method_name)
        self.output_dir = Path(const.BAXBENCH_RESULT_DIR, model_name, method_name).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.task_file = self.output_dir / "tasks.json"
        subprocess.run([
            baxbench_python(), "src/rescue_bridge.py", "export",
            "--output", str(self.task_file), "--spec-type", "openapi",
            "--safety-prompt", "none",
        ], cwd=const.BAXBENCH_REPO_DIR, check=True)

    def load_data(self) -> List[BaxBenchItem]:
        rows = json.loads(self.task_file.read_text())
        items = []
        for row in rows:
            language = const.BAXBENCH_LANGUAGE_MAP.get(row["language"], row["language"])
            for sample in range(const.BAXBENCH_SAMPLE):
                items.append(BaxBenchItem(
                    benchmark="BaxBench", model_name=self.model_name,
                    language=language, code_snippet=row["prompt"], func=self.func,
                    env_id=row["env"], scenario_id=row["scenario"], sample=sample,
                ))
        return items

    @staticmethod
    def single_case_running(item: BaxBenchItem) -> Dict[str, Any]:
        response = item.func(item.to_func_args())
        return {"env": item.env_id, "scenario": item.scenario_id,
                "sample": item.sample,
                "raw_generation": response.get("final_prediction", "")}

    def save_result(self, results: List[Dict[str, Any]]) -> None:
        generations = self.output_dir / "generations.jsonl"
        with generations.open("w") as handle:
            for result in sorted(results, key=lambda x: (x["env"], x["scenario"], x["sample"])):
                handle.write(json.dumps(result) + "\n")
        subprocess.run([
            baxbench_python(), "src/rescue_bridge.py", "materialize",
            "--generations", str(generations),
            "--results-dir", str(self.output_dir),
            "--model", self.model_name, "--temperature", "0.2",
            "--spec-type", "openapi", "--safety-prompt", "none",
        ], cwd=const.BAXBENCH_REPO_DIR, check=True)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--method", required=True)
    args = parser.parse_args()
    BaxBenchBenchmark(args.model, args.method).run()
