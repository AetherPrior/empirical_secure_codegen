from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from datasets import Dataset, load_dataset

from src.benchmarks.benchmark import Benchmark, BenchmarkItem
from src.common import const


def build_prompt(row: Dict[str, Any]) -> str:
    """Match SeCode-Eval's natural-language SecCodePLT prompt."""
    desc = row["task_description"]
    prompt = f"{desc['description'].strip('.')}. "
    prompt += f"The function's name should be {desc['function_name'].strip('.')}. "
    arguments = desc["arguments"]
    count = 0 if arguments in ("", "None") else arguments.count("\n") + 1
    if count == 0:
        prompt += "The function should take no arguments. "
    else:
        args = arguments.replace("\n", ", ").strip(".")
        prompt += f"The function should take {count} argument(s), i.e., {args}. "
    prompt += f"The function returns: {desc['return'].strip('.')}. "
    if desc["raise"] not in ("", "None"):
        prompt += f"The function raises: {desc['raise'].strip('.')}. "
    prompt += f"\n\nThe following setup code will be provided to you:\n```\n{row['unittest']['setup']}\n```"
    context = desc["context"].strip("\n").replace("\n", ", ").strip(".")
    prompt += f"\n\nHere's some additional context about the imported packages and global variables: {context} "
    prompt += "\n\nPlease implement the function according to the description and setup above. Output the code in a markdown code block, i.e., between triple backticks (```) with the language specified as Python."
    return prompt


def load_seccodeplt(data_path: str) -> Dataset:
    if os.path.isfile(data_path) and data_path.endswith(".arrow"):
        dataset = Dataset.from_file(data_path)
    else:
        try:
            dataset = load_dataset(data_path, split="insecure_coding")
        except Exception:
            dataset = load_dataset("json", data_files=data_path, split="train")
    return dataset.filter(lambda row: row["use_rule"] is False)


@dataclass
class SecCodePLTItem(BenchmarkItem):
    index: int = 0


class SecCodePLTBenchmark(Benchmark):
    def __init__(self, model_name: str, method_name: str) -> None:
        super().__init__(model_name, method_name)
        self.data_path = os.environ.get("SECCODEPLT_DATASET", const.SECCODEPLT_DATASET)
        self.output_dir = Path(const.SECCODEPLT_RESULT_DIR, model_name, method_name)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def load_data(self) -> List[SecCodePLTItem]:
        dataset = load_seccodeplt(self.data_path)
        items = []
        for index, row in enumerate(dataset):
            for _ in range(const.SECCODEPLT_SAMPLE):
                items.append(SecCodePLTItem(
                    benchmark="SecCodePLT", model_name=self.model_name,
                    language="py", code_snippet=build_prompt(dict(row)),
                    func=self.func, index=index,
                ))
        return items

    @staticmethod
    def single_case_running(item: SecCodePLTItem) -> Dict[str, Any]:
        response = item.func(item.to_func_args())
        return {"index": item.index, "raw_generation": response.get("final_prediction", "")}

    def save_result(self, results: List[Dict[str, Any]]) -> None:
        results.sort(key=lambda result: result["index"])
        output_path = self.output_dir / "generations.jsonl"
        with output_path.open("w") as handle:
            for result in results:
                handle.write(json.dumps(result) + "\n")
        (self.output_dir / "manifest.json").write_text(json.dumps({
            "dataset": self.data_path, "samples": const.SECCODEPLT_SAMPLE,
            "num_generations": len(results),
        }, indent=2))
        print(f"Saved SecCodePLT generations to {output_path}")


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--method", required=True)
    args = parser.parse_args()
    SecCodePLTBenchmark(args.model, args.method).run()
