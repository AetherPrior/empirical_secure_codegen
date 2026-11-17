import copy
import json
from typing import Any

import datasets
import numpy as np

from verl.utils.dataset.rl_dataset import RLHFDataset


def _to_prompt_messages(row: dict[str, Any]) -> list[dict[str, str]]:
    prompt = row.get("prompt")
    if isinstance(prompt, list) and all(isinstance(item, dict) for item in prompt):
        return prompt
    text = row.get("rewritten_prompt") or row.get("prompt") or ""
    if not isinstance(text, str):
        text = str(text)
    return [{"role": "user", "content": text}]


def _ground_truth_from_raw(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "function_name": row["function_name"].strip(),
        "test_code": row["test_code"],
        "setup_tests": row["setup_tests"] if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
    }
    for key in ("arguments", "return", "raises", "cwe"):
        if row.get(key) is not None:
            out[key] = row[key]
    return out


class SecurityHarnessDataset(RLHFDataset):
    def _read_json_records(self, data_file: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with open(data_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
        return records

    def _read_files_and_tokenize(self):
        dataframes = []
        index_offset = 0

        def _convert_row(row: dict[str, Any], idx: int) -> dict[str, Any]:
            if isinstance(row.get("prompt"), list) and isinstance(row.get("reward_model"), dict):
                extra = copy.deepcopy(row.get("extra_info")) if row.get("extra_info") else {}
                if not isinstance(extra, dict):
                    extra = {}
                if "index" not in extra:
                    extra["index"] = idx
                return {
                    "data_source": row.get("data_source", "security_harness"),
                    "prompt": row["prompt"],
                    "ability": row.get("ability", "code_security"),
                    "reward_model": row["reward_model"],
                    "extra_info": extra,
                }

            fn = row.get("function_name")
            tc = row.get("test_code")
            if not (isinstance(fn, str) and fn.strip() and isinstance(tc, str) and tc.strip()):
                raise ValueError(
                    "Each row must be GRPO-shaped (prompt + reward_model) or simple_gen "
                    f"(function_name + test_code). Bad row index {idx}."
                )

            prompt = _to_prompt_messages(row)
            extra_info: dict[str, Any] = {"index": idx}
            if row.get("cwe_id") is not None:
                extra_info["cwe_id"] = row.get("cwe_id")
            if row.get("cwe") is not None:
                extra_info["cwe"] = row.get("cwe")
            if isinstance(row.get("unittest"), dict):
                extra_info["unittest"] = row["unittest"]
            if isinstance(row.get("task_description"), dict):
                extra_info["task_description"] = row["task_description"]
            return {
                "data_source": row.get("data_source", "security_harness"),
                "prompt": prompt,
                "ability": row.get("ability", "code_security"),
                "reward_model": {"style": "rule", "ground_truth": _ground_truth_from_raw(row)},
                "extra_info": extra_info,
            }

        for data_file in self.data_files:
            if data_file.endswith(".parquet"):
                raw_dataset = datasets.load_dataset("parquet", data_files=data_file)["train"]
                records = [dict(item) for item in raw_dataset]
            elif data_file.endswith(".json") or data_file.endswith(".jsonl"):
                records = self._read_json_records(data_file)
            else:
                raise ValueError(f"Unsupported file format: {data_file}")

            converted = [_convert_row(row, index_offset + local_idx) for local_idx, row in enumerate(records)]
            index_offset += len(converted)
            dataframes.append(datasets.Dataset.from_list(converted))

        self.dataframe: datasets.Dataset = datasets.concatenate_datasets(dataframes)

        total = len(self.dataframe)
        print(f"dataset len: {total}")

        if self.max_samples > 0 and self.max_samples < total:
            if self.shuffle:
                rngs_args = (self.seed,) if self.seed is not None else ()
                rng = np.random.default_rng(*rngs_args)
                indices = rng.choice(total, size=self.max_samples, replace=False)
            else:
                indices = np.arange(self.max_samples)
            self.dataframe = self.dataframe.select(indices.tolist())
            print(f"selected {self.max_samples} random samples out of {total}")

        self.dataframe = self.maybe_filter_out_long_prompts(self.dataframe)
