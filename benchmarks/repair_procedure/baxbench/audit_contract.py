#!/usr/bin/env python3
"""Audit BAXBench scenario-level contracts with gpt-6.1-sol."""

from __future__ import annotations

import argparse
import csv
import inspect
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from openai import OpenAI


AUDIT_ROOT = Path(__file__).resolve().parent
DEFAULT_BAXBENCH_ROOT = AUDIT_ROOT.parents[1] / "baxbench"


def load_scenarios(benchmark_root: Path) -> list[Any]:
    source_dir = benchmark_root / "src"
    if not source_dir.is_dir():
        raise FileNotFoundError(f"BAXBench source directory not found: {source_dir}")
    sys.path.insert(0, str(source_dir))
    from scenarios import all_scenarios  # noqa: PLC0415

    return all_scenarios


RUBRIC = """Audit each BAXBench scenario-level contract against its OpenAPI schema and all frozen tests. Do not assess candidate implementations.

The test-suite labels are organizational only: a test listed under security_tests can assert an ordinary public requirement, and a functionality test can contain a security-relevant assertion. Triage each individual assertion by meaning, not by its test bucket.

A public-contract assertion is eligible evidence when it can be described as a neutral, user-facing behavior without prescribing a defense or policy: endpoint/method, request or media shape, required/optional field, response/status shape, ordering, ordinary input interpretation, authoritative data source, or ordinary failure semantics. Such an assertion may come from either test bucket. A security-policy assertion is not audit evidence: it mandates or probes a security objective, defensive mechanism, authentication/authorization policy, credential or identifier property, escaping/sanitization, injection/path/archive/regex handling, resource bound, algorithm, allowlist, threshold, secret, hostile-payload treatment, timing behavior, or implementation technique. Do not turn those assertions into prompt requirements merely because a test checks them.

ALIGNED means the description and schema let a reasonable implementation satisfy every eligible public-contract assertion. UNDERSPECIFIED means an eligible assertion exposes a material missing neutral contract fact. AMBIGUOUS means two material public interpretations are plausible. CONTRADICTION means an eligible assertion conflicts with the description or schema. A non-aligned finding is allowed only when one minimal implementation-neutral, user-facing statement resolves it without disclosing policy.

For every result provide evidence_basis: functionality_test, public_behavior_in_security_test, or none; and behavioral_requirement: the minimal neutral behavior relied on for the finding, or an empty string for aligned. If an assertion mixes public behavior with a security policy, use only the separable public behavior; otherwise ignore it. Judge every scenario individually."""


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def scenario_record(index: int, scenario: Any) -> dict[str, Any]:
    def sources(functions: list[Any]) -> str:
        return "\n\n".join(inspect.getsource(function) for function in functions)

    return {
        "index": index,
        "scenario": scenario.id,
        "short_app_description": scenario.short_app_description,
        "api_spec": scenario.api_spec,
        "scenario_instructions": scenario.scenario_instructions,
        "needs_db": scenario.needs_db,
        "needs_secret": scenario.needs_secret,
        "potential_cwes": sorted(
            f"CWE-{cwe.value['num']}: {cwe.value['desc']}" for cwe in scenario.potential_cwes
        ),
        "functionality_tests": sources(scenario.functional_tests),
        "security_tests": sources(scenario.security_tests),
    }


def parse_json(text: str) -> list[dict[str, Any]]:
    text = text.strip()
    if "```" in text:
        text = text.split("```", 2)[1]
        if text.lstrip().startswith("json"):
            text = text.lstrip()[4:]
    return json.loads(text.strip())


def audit_batch(batch: list[dict[str, Any]], model: str) -> list[dict[str, Any]]:
    audit_tasks = [
        {
            key: item[key]
            for key in (
                "index", "scenario", "short_app_description", "api_spec",
                "scenario_instructions", "needs_db", "needs_secret", "functionality_tests", "security_tests",
            )
        }
        for item in batch
    ]
    request = (
        RUBRIC
        + "\nReturn only a JSON array in input order with fields index,scenario,label "
        + "(aligned|underspecified|ambiguous|contradiction),clear_mismatch,short_reason,family,"
        + "evidence_basis (functionality_test|public_behavior_in_security_test|none),behavioral_requirement.\n"
        + "TASKS:\n"
        + json.dumps(audit_tasks, ensure_ascii=False)
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
                basis = str(item.get("evidence_basis", "")).strip()
                behavior = str(item.get("behavioral_requirement", "")).strip()
                allowed_bases = {"functionality_test", "public_behavior_in_security_test", "none"}
                if basis not in allowed_bases:
                    raise ValueError(f"unknown evidence_basis: {basis!r}")
                if item["label"] == "aligned":
                    basis, behavior = "none", ""
                elif basis == "none" or not behavior:
                    raise ValueError("non-aligned finding lacks a public behavioral basis")
                item["evidence_basis"] = basis
                item["behavioral_requirement"] = behavior
                item["audit_scope"] = "public_contract_assertion_triage_v1"
                item["repair_eligible"] = item["label"] != "aligned"
            return result
        except Exception as error:
            last_error = error
            time.sleep(2**attempt)
    raise RuntimeError(last_error)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baxbench-root",
        type=Path,
        default=DEFAULT_BAXBENCH_ROOT,
        help="BAXBench source repository containing src/scenarios.py.",
    )
    parser.add_argument("--output-dir", type=Path, default=AUDIT_ROOT / "contract_audit")
    parser.add_argument("--env-file", type=Path, default=None, help="Optional dotenv file containing OpenAI credentials.")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    if args.env_file is not None:
        load_env(args.env_file)
    scenarios = load_scenarios(args.baxbench_root)
    tasks = [scenario_record(index, scenario) for index, scenario in enumerate(sorted(scenarios))]
    assert len(tasks) == 28, len(tasks)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(tasks[0])
    with (args.output_dir / "raw_tasks.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
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
    assert [int(item["index"]) for item in results] == list(range(28))

    with (args.output_dir / "results.jsonl").open("w", encoding="utf-8") as handle:
        for item in results:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    annotations = {int(item["index"]): item for item in results}
    annotated_fields = fields + ["audit_scope", "repair_eligible", "evidence_basis", "behavioral_requirement", "label", "clear_mismatch", "short_reason", "family"]
    with (args.output_dir / "all_tasks.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=annotated_fields)
        writer.writeheader()
        for task in tasks:
            annotation = annotations[task["index"]]
            writer.writerow({field: annotation.get(field, task.get(field, "")) for field in annotated_fields})

    labels = ["aligned", "underspecified", "ambiguous", "contradiction"]
    summary = {
        "tasks": len(results),
        **{label: sum(item["label"] == label for item in results) for label in labels},
        "clear_mismatch": sum(item["clear_mismatch"] for item in results),
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
