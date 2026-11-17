"""
This file defines the standard process for running benchmarks.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, fields
from typing import Any, Callable, ClassVar, Dict, List
import os
import multiprocessing as mp
mp.set_start_method("spawn", force=True)
from tqdm import tqdm

from src.rescue.retrieval.hmr import warm_up_retrieval
from src.baselines import zero_shot
from src.rescue import augmented_code_generation

METHOD_DICT = {
    "zero_shot": zero_shot.run,
    "rescue": augmented_code_generation.run,
}


@dataclass
class BenchmarkItem:
    """Base dataclass for benchmark items passed to worker processes.

    Subclasses should override ``_exclude_from_func_args`` to list fields
    that are only used by ``single_case_running`` (e.g. output paths) and
    should NOT be forwarded to the method function (``func``).
    """
    benchmark: str
    model_name: str
    language: str
    code_snippet: str
    func: Callable

    _exclude_from_func_args: ClassVar[frozenset] = frozenset({"func"})

    def to_func_args(self) -> Dict[str, Any]:
        """Build the dict passed to ``func()`` by excluding non-domain fields."""
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name not in self._exclude_from_func_args
        }


class Benchmark(ABC):
    def __init__(self, model_name, method_name):
        self.model_name = model_name
        self.method_name = method_name
        self.func = METHOD_DICT[self.method_name]

    @abstractmethod
    def load_data(self) -> List[BenchmarkItem]:
        """This method defines how to load specific data for a benchmark."""
        pass

    @staticmethod
    def single_case_running(item: BenchmarkItem):
        """This method is used to run each problem."""
        pass

    @abstractmethod
    def save_result(self, results):
        pass

    def run(self):
        print("Loading dataset...")
        dataset = self.load_data()

        print("Begin running this benchmark...")
        init = warm_up_retrieval if self.method_name == "rescue" else None
        workers = int(os.environ.get("BENCHMARK_WORKERS", "5"))
        with mp.Pool(processes=workers, initializer=init) as pool:
            results = list(tqdm(pool.imap_unordered(self.single_case_running, dataset), total=len(dataset)))
        print("Finish running this benchmark.")
        self.save_result(results)
