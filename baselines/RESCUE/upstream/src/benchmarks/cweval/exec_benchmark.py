from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from natsort import natsorted

from src.benchmarks.benchmark import Benchmark, BenchmarkItem
from src.common import const, utils


@dataclass
class CWEvalItem(BenchmarkItem):
    generated_dir: str = ""
    raw_rel_path: str = ""
    task_rel_path: str = ""
    sample_id: int = 0

    _exclude_from_func_args = frozenset({
        "func", "generated_dir", "raw_rel_path", "task_rel_path", "sample_id",
    })


class CWEvalBenchmark(Benchmark):
    BEGIN_PROMPT = "BEGIN PROMPT"
    BEGIN_SOLUTION = "BEGIN SOLUTION"

    def __init__(self, model_name: str, method_name: str) -> None:
        super().__init__(model_name, method_name)
        self.benchmark_dir = Path(const.CWEVAL_BENCHMARK_DIR).resolve()
        if not self.benchmark_dir.exists():
            raise FileNotFoundError(
                f"CWEval benchmark directory not found: {self.benchmark_dir}. Did you pull the submodule?"
            )

        self.eval_base_dir = (Path(const.CWEVAL_RESULT_DIR) / model_name / method_name).resolve()
        self.eval_base_dir.mkdir(parents=True, exist_ok=True)
        self.eval_runs_dir = self.eval_base_dir / "evals"
        self.eval_runs_dir.mkdir(parents=True, exist_ok=True)
        self.eval_name = datetime.now().strftime("eval_%y%m%d_%H%M%S")
        self.eval_path = self.eval_runs_dir / self.eval_name
        self.eval_path.mkdir(parents=True, exist_ok=True)
        self.eval_path = self.eval_path.resolve()
        self.sample_size = const.CWEVAL_SAMPLE
        self.supported_langs = set(const.CWEVAL_SUPPORTED_LANGS)
        self.latest_eval_file = self.eval_base_dir / "latest_eval_path.txt"
        self.case_metadata: List[Dict[str, str]] = []

    def load_data(self) -> List[CWEvalItem]:
        dataset: List[CWEvalItem] = []
        for root, _, files in os.walk(self.benchmark_dir):
            if "__pycache__" in root:
                continue
            for file_name in natsorted(files):
                task_path = Path(root, file_name)
                if not task_path.is_file():
                    continue
                if not task_path.stem.endswith("_task"):
                    continue
                lang = task_path.suffix.lstrip(".")
                if lang not in self.supported_langs:
                    continue

                print(f'[DEBUG] {task_path}')
                code_prompt = self._extract_prompt(task_path.read_text())
                rel_task_path = task_path.relative_to(self.benchmark_dir)
                raw_rel_path = rel_task_path.as_posix().replace("_task.", "_raw.")

                for sample_idx in range(self.sample_size):
                    generated_dir = self.eval_path / f"generated_{sample_idx}"
                    generated_dir.mkdir(parents=True, exist_ok=True)
                    item = CWEvalItem(
                        benchmark="CWEval",
                        model_name=self.model_name,
                        language=lang,
                        code_snippet=code_prompt,
                        func=self.func,
                        generated_dir=str(generated_dir),
                        raw_rel_path=raw_rel_path,
                        task_rel_path=rel_task_path.as_posix(),
                        sample_id=sample_idx,
                    )
                    dataset.append(item)
                    self.case_metadata.append({
                        "task_rel_path": rel_task_path.as_posix(),
                        "raw_rel_path": raw_rel_path,
                        "language": lang,
                        "sample_id": sample_idx,
                    })
        if not dataset:
            raise RuntimeError("No CWEval tasks were discovered. Check supported languages and dataset path.")
        return dataset

    @classmethod
    def _extract_prompt(cls, task_content: str) -> str:
        if cls.BEGIN_SOLUTION not in task_content:
            raise ValueError("Malformed CWEval task file; missing prompt anchors.")
        prompt_section = task_content.split(cls.BEGIN_PROMPT, 1)[-1]
        prompt_section = prompt_section.split(cls.BEGIN_SOLUTION, 1)[0]
        return prompt_section.strip()

    @staticmethod
    def single_case_running(item: CWEvalItem) -> None:
        temp_path = Path(item.generated_dir).joinpath(item.raw_rel_path)
        if temp_path.exists():
            return
        temp_path.parent.mkdir(parents=True, exist_ok=True)

        response_kv = item.func(item.to_func_args())

        prediction = response_kv.get("final_prediction", "")
        if isinstance(prediction, list):
            prediction = "\n".join(prediction)
        temp_path.write_text(prediction)

    def save_result(self, results: List) -> None:
        manifest = {
            "model": self.model_name,
            "method": self.method_name,
            "eval_path": str(self.eval_path),
            "num_cases": len(results),
            "cases": self.case_metadata,
        }
        manifest_path = self.eval_base_dir / f"{self.eval_name}_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        self.latest_eval_file.write_text(str(self.eval_path))
        print(f"Saved CWEval manifest to {manifest_path}")
        print(f"Latest eval path recorded at {self.latest_eval_file}")


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--method", required=True)
    args = parser.parse_args()

    bench = CWEvalBenchmark(args.model, args.method)
    bench.run()


if __name__ == "__main__":
    main()
