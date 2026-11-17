from dataclasses import dataclass
from pathlib import Path
import json
from typing import List

from src.common.utils import get_live_code_bench, get_code_from_livecodebench_python
from src.common import const
from src.benchmarks.benchmark import Benchmark, BenchmarkItem


@dataclass
class LiveCodeBenchItem(BenchmarkItem):
    question_id: str = ""
    question_content: str = ""
    starter_code: str = ""
    number: int = 0
    generation_dir: str = ""

    _exclude_from_func_args = frozenset({"func", "generation_dir"})


class LiveCodeBenchBenchmark(Benchmark):
    def __init__(self, model_name, method_name):
        super().__init__(model_name, method_name)
        self.generation_dir = Path(const.LIVECODEBENCH_RESULT_DIR, model_name, method_name)
        if not self.generation_dir.exists():
            self.generation_dir.mkdir(parents=True)

    def load_data(self) -> List[LiveCodeBenchItem]:
        dataset = get_live_code_bench()
        sampling_num = const.LIVECODEBENCH_SAMPLE
        output_list = []
        for raw_item in dataset:
            ques_dir = Path(self.generation_dir, raw_item["question_id"])
            if not ques_dir.exists():
                ques_dir.mkdir()
            for num in range(sampling_num):
                item = LiveCodeBenchItem(
                    benchmark="LiveCodeBench",
                    model_name=self.model_name,
                    language="py",
                    code_snippet="",
                    question_id=raw_item["question_id"],
                    question_content=raw_item["question_content"],
                    starter_code=raw_item["starter_code"],
                    number=num,
                    func=self.func,
                    generation_dir=str(self.generation_dir),
                )
                output_list.append(item)
        return output_list

    @staticmethod
    def single_case_running(item: LiveCodeBenchItem):
        temp_path = Path(item.generation_dir).joinpath(
            item.question_id.replace("/", "_"), f"{item.number}.py"
        )
        if temp_path.exists():
            return

        try:
            response_kv = item.func(item.to_func_args())
            Path(temp_path).write_text(response_kv["final_prediction"])
        except Exception as e:
            print(f'Something wrong happened. {e}')

    def save_result(self, results):
        code_completion_output_list = []
        for ques_dir in self.generation_dir.glob("*"):
            if ques_dir.is_dir():
                model_outputs = [x.read_text() for x in ques_dir.glob("*")]
                model_outputs = [get_code_from_livecodebench_python(i, self.model_name) for i in model_outputs]
                question_id = ques_dir.name
                result = {
                    "question_id": question_id,
                    "code_list": model_outputs
                }
                code_completion_output_list.append(result)

        # Put all the generation output together
        self.generation_dir.joinpath("output.json").write_text(
            json.dumps(code_completion_output_list, indent=2)
        )


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--model")
    parser.add_argument("--method")

    args = parser.parse_args()
    bench = LiveCodeBenchBenchmark(args.model, args.method)
    bench.run()
