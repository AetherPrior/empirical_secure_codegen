#!/usr/bin/env python3
"""Audit all CWEval task/test contracts with gpt-6.1-sol.

This mirrors the contract audit used for SecCodePLT: the model sees each
task's extracted prompt and its frozen test file, then labels the contract as
aligned, underspecified, ambiguous, or contradictory.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from openai import OpenAI


RUBRIC = """Audit whether each CWEval programming prompt clearly specifies the behavior asserted by its frozen functionality and security tests. Do not assess candidate solutions.
Use a relaxed practical rubric. ALIGNED means a competent implementation using the obvious language-standard primitive naturally produces the tested behavior. Accept conventional spelling, normal language/library idioms, harmless formatting or representation details, and security behavior that is directly inferable from the prompt and CWE context. UNDERSPECIFIED means a material tested behavior is absent and a reasonable conventional secure implementation could differ and fail. AMBIGUOUS means the prompt admits two materially different interpretations. CONTRADICTION means the tests or harness conflict with the prompt, signature, types, or stated behavior. Only the latter three are clear mismatches. Be conservative, but flag hidden non-inferable API names, exact separators/layout, allowlist policy, rejection thresholds or length caps, materially different return forms, unsafe-vs-secure behavior conflicts, and signature/type conflicts. Judge every task individually."""


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def extract_prompt(task_text: str) -> str:
    if "BEGIN PROMPT" in task_text:
        task_text = task_text.split("BEGIN PROMPT", 1)[1]
    if "BEGIN SOLUTION" not in task_text:
        raise ValueError("task has no BEGIN SOLUTION marker")
    return task_text.split("BEGIN SOLUTION", 1)[0].strip()


def cwe_from_path(path: Path) -> str:
    match = re.search(r"cwe_(\d+)", path.name)
    if not match:
        raise ValueError(f"cannot extract CWE from {path}")
    return match.group(1).lstrip("0") or "0"


def test_path(task_path: Path) -> Path:
    return task_path.with_name(task_path.name.rsplit("_task", 1)[0] + "_test.py")


def collect_tasks(benchmark_dir: Path) -> list[dict[str, Any]]:
    tasks = []
    for index, task_path in enumerate(sorted(benchmark_dir.rglob("*_task.*"))):
        test_file = test_path(task_path)
        if not test_file.exists():
            raise FileNotFoundError(f"missing test file for {task_path}: {test_file}")
        task_text = task_path.read_text(encoding="utf-8", errors="replace")
        test_text = test_file.read_text(encoding="utf-8", errors="replace")
        tasks.append(
            {
                "index": index,
                "cwe": cwe_from_path(task_path),
                "language": task_path.suffix.lstrip("."),
                "task_file": str(task_path.relative_to(benchmark_dir.parent)),
                "prompt": extract_prompt(task_text),
                "tests": test_text,
            }
        )
    return tasks


def parse_json(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.I)
    if fenced:
        text = fenced.group(1).strip()
    return json.loads(text)


def audit_batch(batch: list[dict[str, Any]], model: str) -> list[dict[str, Any]]:
    payload = [
        {
            "index": item["index"],
            "cwe": item["cwe"],
            "language": item["language"],
            "task_file": item["task_file"],
            "prompt": item["prompt"],
            "tests": item["tests"],
        }
        for item in batch
    ]
    request = (
        RUBRIC
        + "\nReturn only a JSON array in input order with fields index,cwe,label "
        + "(aligned|underspecified|ambiguous|contradiction),clear_mismatch,short_reason,family. "
        + "The short_reason must identify the specific missing, ambiguous, or conflicting contract.\n"
        + "TASKS:\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            kwargs: dict[str, Any] = {}
            if os.getenv("OPENAI_SERVICE_TIER"):
                kwargs["service_tier"] = os.environ["OPENAI_SERVICE_TIER"]
            response = OpenAI().responses.create(
                model=model, input=request, max_output_tokens=3000, **kwargs
            )
            result = parse_json(response.output_text)
            expected = [item["index"] for item in batch]
            actual = [int(item["index"]) for item in result]
            if actual != expected or len(result) != len(batch):
                raise ValueError(f"batch shape/index mismatch: expected {expected}, got {actual}")
            for item in result:
                item["label"] = str(item["label"]).lower()
                if item["label"] not in {"aligned", "underspecified", "ambiguous", "contradiction"}:
                    raise ValueError(f"unknown label: {item['label']}")
                item["clear_mismatch"] = item["label"] != "aligned"
            return result
        except Exception as error:  # retry transient API/JSON failures
            last_error = error
            time.sleep(2**attempt)
    raise RuntimeError(last_error)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "cweval" / "benchmark",
        help="CWEval benchmark source directory.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "contract_audit")
    parser.add_argument("--env-file", type=Path, default=None, help="Optional dotenv file containing OpenAI credentials.")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    if args.env_file is not None:
        load_env(args.env_file)
    tasks = collect_tasks(args.benchmark_dir)
    assert len(tasks) == 119, len(tasks)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "raw_tasks.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["index", "cwe", "language", "task_file", "prompt", "tests"])
        writer.writeheader()
        writer.writerows(tasks)

    batches = [tasks[i : i + args.batch_size] for i in range(0, len(tasks), args.batch_size)]
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(audit_batch, batch, args.model) for batch in batches]
        for completed, future in enumerate(as_completed(futures), 1):
            results.extend(future.result())
            print(f"completed {completed}/{len(futures)}", flush=True)

    results.sort(key=lambda item: int(item["index"]))
    assert [int(item["index"]) for item in results] == list(range(len(tasks)))
    with (args.output_dir / "results.jsonl").open("w", encoding="utf-8") as handle:
        for item in results:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    annotations = {int(item["index"]): item for item in results}
    annotated_fields = [
        "index", "cwe", "language", "task_file", "prompt", "tests",
        "label", "clear_mismatch", "short_reason", "family",
    ]
    with (args.output_dir / "all_tasks.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=annotated_fields)
        writer.writeheader()
        for task in tasks:
            annotation = annotations[task["index"]]
            writer.writerow({field: annotation.get(field, task.get(field, "")) for field in annotated_fields})

    labels = ["aligned", "underspecified", "ambiguous", "contradiction"]
    summary: dict[str, Any] = {}
    for cwe in sorted({item["cwe"] for item in tasks}, key=int):
        subset = [item for item in results if item["cwe"] == cwe]
        summary[cwe] = {
            "tasks": len(subset),
            **{label: sum(item["label"] == label for item in subset) for label in labels},
            "clear_mismatch": sum(item["clear_mismatch"] for item in subset),
        }
    summary["total"] = {
        "tasks": len(results),
        **{label: sum(item["label"] == label for item in results) for label in labels},
        "clear_mismatch": sum(item["clear_mismatch"] for item in results),
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
