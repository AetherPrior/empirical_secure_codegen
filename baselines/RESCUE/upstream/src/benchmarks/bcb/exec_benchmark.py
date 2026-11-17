from bigcodebench.data import get_bigcodebench
from dataclasses import dataclass
from pathlib import Path
from typing import List

from src.common import const
from src.benchmarks.benchmark import Benchmark, BenchmarkItem


@dataclass
class BigCodeBenchItem(BenchmarkItem):
    number: int = 0
    task_id: str = ""
    generation_dir: str = ""

    _exclude_from_func_args = frozenset({"func", "generation_dir"})


class BigCodeBenchBenchmark(Benchmark):
    def __init__(self, model_name, method_name):
        super().__init__(model_name, method_name)
        self.generation_dir = Path(const.BIGCODEBENCH_RESULT_DIR, model_name, method_name)
        if not self.generation_dir.exists():
            self.generation_dir.mkdir(parents=True)

    def load_data(self) -> List[BigCodeBenchItem]:
        dataset = get_bigcodebench()
        sampling_num = const.BIGCODEBENCH_SAMPLE
        output_list = []
        for task_id, problem in dataset.items():
            task_dir = Path(self.generation_dir, task_id.replace("/", "_"))
            if not task_dir.exists():
                task_dir.mkdir(parents=True)
            for num in range(sampling_num):
                item = BigCodeBenchItem(
                    benchmark="BigCodeBench",
                    model_name=self.model_name,
                    language="py",
                    number=num,
                    code_snippet=problem["complete_prompt"],
                    func=self.func,
                    generation_dir=str(self.generation_dir),
                    task_id=task_id,
                )
                output_list.append(item)
        return output_list

    @staticmethod
    def single_case_running(item: BigCodeBenchItem):
        temp_path = Path(item.generation_dir).joinpath(
            item.task_id.replace("/", "_"), f"{item.number}.py"
        )
        if temp_path.exists():
            return

        try:
            response_kv = item.func(item.to_func_args())
            if item.code_snippet in response_kv["final_prediction"]:
                temp_path.write_text(response_kv["final_prediction"])
            else:
                temp_path.write_text(item.code_snippet + response_kv["final_prediction"])
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
    bench = BigCodeBenchBenchmark(args.model, args.method)
    bench.run()
