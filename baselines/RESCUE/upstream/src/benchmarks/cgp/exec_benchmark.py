from dataclasses import dataclass
from pathlib import Path
import json
from typing import List

from src.common.utils import load_json, write_jsonl_gzip
from src.common import const
from src.benchmarks.benchmark import Benchmark, BenchmarkItem


@dataclass
class CodeGuardPlusItem(BenchmarkItem):
    cwe: str = ""
    scenario: str = ""
    number: int = 0
    gen_cache_dir: str = ""

    _exclude_from_func_args = frozenset({"func", "gen_cache_dir"})


class CodeGuardPlusBenchmark(Benchmark):
    def __init__(self, model_name, method_name):
        super().__init__(model_name, method_name)
        self.gen_cache_dir = Path(const.RESULT_GENERATION_DIR, model_name, method_name, "cache")
        if not self.gen_cache_dir.exists():
            self.gen_cache_dir.mkdir(parents=True)

    def load_data(self) -> List[CodeGuardPlusItem]:
        dataset = load_json(const.CODEGUARDPLUS_DATASET_PATH)
        sampling_num = const.CODEGUARDPLUS_SAMPLING_NUM
        output_list = []
        for elem in dataset:
            for num in range(sampling_num):
                item = CodeGuardPlusItem(
                    benchmark="CodeGuardPlus",
                    model_name=self.model_name,
                    language=elem["language"],
                    cwe=elem["cwe"],
                    scenario=elem["scenario"],
                    number=num,
                    code_snippet=elem["prompt"],
                    func=self.func,
                    gen_cache_dir=str(self.gen_cache_dir),
                )
                output_list.append(item)
        return output_list

    @staticmethod
    def single_case_running(item: CodeGuardPlusItem):
        temp_path = Path(item.gen_cache_dir).joinpath(
            f'{item.cwe}_{item.scenario}_{item.number}.json'
        )
        if temp_path.exists():
            return

        response_kv = item.func(item.to_func_args())
        save_temp_data = {
            "cwe": item.cwe,
            "scenario": item.scenario,
            "number": item.number,
            **response_kv
        }
        temp_path.write_text(json.dumps(save_temp_data))

    def save_result(self, results):
        all_cached_data = [load_json(r) for r in self.gen_cache_dir.glob("*json")]
        write_jsonl_gzip(self.gen_cache_dir.parent.joinpath("final_results.jsonl.gz"), all_cached_data)


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("--model")
    parser.add_argument("--method")

    args = parser.parse_args()
    bench = CodeGuardPlusBenchmark(args.model, args.method)
    bench.run()
