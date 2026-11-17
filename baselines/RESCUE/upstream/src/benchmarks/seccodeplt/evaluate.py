from __future__ import annotations

import csv
import json
import sys
from argparse import ArgumentParser
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List

from src.benchmarks.seccodeplt.exec_benchmark import load_seccodeplt
from src.common import const

SECODE_EVAL_DIR = Path("/workspace/verisec/SeCode-Eval")


def main(model: str, method: str) -> None:
    output_dir = Path(const.SECCODEPLT_RESULT_DIR, model, method)
    manifest = json.loads((output_dir / "manifest.json").read_text())
    generations = [json.loads(line) for line in (output_dir / "generations.jsonl").read_text().splitlines()]
    dataset = load_seccodeplt(manifest["dataset"])
    sys.path.insert(0, str(SECODE_EVAL_DIR))
    from evaluate_dataset import execute_tests_w_traceback, process_test_results
    from helpers import extract_generated_code

    results: List[Dict[str, Any]] = []
    for generation in generations:
        row = dict(dataset[generation["index"]])
        code, _ = extract_generated_code(generation["raw_generation"])
        test = execute_tests_w_traceback(
            code=code, setup=row["unittest"]["setup"],
            testcases=row["unittest"]["testcases"],
            func_name=row["task_description"]["function_name"],
            install_requires=row.get("install_requires", []),
        )
        results.append({"index": generation["index"], "generated_code": code,
                        **process_test_results(test)})

    (output_dir / "results.json").write_text(json.dumps(results, indent=2))
    with (output_dir / "results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    summary = {
        "num_examples": len(results),
        "capability_score": mean(result["capability_score"] for result in results),
        "safety_score": mean(result["safety_score"] for result in results),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--method", required=True)
    args = parser.parse_args()
    main(args.model, args.method)
