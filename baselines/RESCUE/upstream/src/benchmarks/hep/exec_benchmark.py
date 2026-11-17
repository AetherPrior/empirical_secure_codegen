from evalplus.data import get_human_eval_plus, write_jsonl
from dataclasses import dataclass
from pathlib import Path
from typing import List

from src.common import const
from src.benchmarks.benchmark import Benchmark, BenchmarkItem


@dataclass
class HumanEvalPlusItem(BenchmarkItem):
    number: int = 0
    task_id: str = ""
    generation_dir: str = ""

    _exclude_from_func_args = frozenset({"func", "generation_dir"})


class HumanEvalPlusBenchmark(Benchmark):
    def __init__(self, model_name, method_name):
        super().__init__(model_name, method_name)
        self.generation_dir = Path(const.HUMAN_EVAL_PLUS_RESULT_DIR, model_name, method_name)
        if not self.generation_dir.exists():
            self.generation_dir.mkdir(parents=True)

    def load_data(self) -> List[HumanEvalPlusItem]:
        dataset = get_human_eval_plus()
        sampling_num = const.HUMAN_EVAL_PLUS_SAMPLE
        output_list = []
        for task_id, problem in dataset.items():
            task_dir = Path(self.generation_dir, task_id.replace("/", "_"))
            if not task_dir.exists():
                task_dir.mkdir(parents=True)
            for num in range(sampling_num):
                item = HumanEvalPlusItem(
                    benchmark="HumanEvalPlus",
                    model_name=self.model_name,
                    language="py",
                    number=num,
                    code_snippet=problem["prompt"],
                    func=self.func,
                    generation_dir=str(self.generation_dir),
                    task_id=task_id,
                )
                output_list.append(item)
        return output_list

    @staticmethod
    def single_case_running(item: HumanEvalPlusItem):
        temp_path = Path(item.generation_dir).joinpath(
            item.task_id.replace("/", "_"), f"{item.number}.py"
        )
        if temp_path.exists():
            return

        try:
            response_kv = item.func(item.to_func_args())
            prompt = item.code_snippet
            prediction = response_kv["final_prediction"]
            if prompt in prediction or item.model_name in ["gpt-4o-mini", "Deepseek-V3"]:
                temp_path.write_text(prediction)
            else:
                temp_path.write_text(prompt + prediction)
        except Exception as e:
            print(f'Something wrong happened. {e}')

    def save_result(self, results):
        return


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--model")
    parser.add_argument("--method")

    args = parser.parse_args()
    bench = HumanEvalPlusBenchmark(args.model, args.method)
    bench.run()
