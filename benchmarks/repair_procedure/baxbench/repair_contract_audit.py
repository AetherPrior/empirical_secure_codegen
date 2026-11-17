#!/usr/bin/env python3
"""Repair non-aligned BAXBench API contracts using frozen test evidence."""

from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
BENCHMARK = 'BAXBench'
AUDIT_CSV = ROOT / 'contract_audit' / "all_tasks.csv"
EDITABLE_FIELDS = ('short_app_description', 'api_spec', 'scenario_instructions')
EVIDENCE_FIELDS = ('functionality_tests',)
IDENTIFIER = 'scenario'
NON_ALIGNED = {"underspecified", "ambiguous", "contradiction"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-csv", type=Path, default=AUDIT_CSV)
    parser.add_argument("--output", type=Path, default=ROOT / "repaired_non_aligned.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "repair_manifest.jsonl")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"index", "label", "family", "short_reason", "audit_scope", "repair_eligible", "evidence_basis", "behavioral_requirement", *EDITABLE_FIELDS, *EVIDENCE_FIELDS}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"{path} lacks required columns: {sorted(missing)}")
    if any(row["audit_scope"] != "public_contract_assertion_triage_v1" for row in rows):
        raise ValueError(
            "This audit lacks public-contract assertion triage. Re-run audit_contract.py before repairing; "
            "only neutral behavioral requirements extracted from either test bucket may be repaired."
        )
    return [
        row for row in rows
        if row["label"].casefold() in NON_ALIGNED and row["repair_eligible"].casefold() == "true"
    ]


def make_manifest(row: dict[str, str]) -> dict[str, Any]:
    return {
        "benchmark": BENCHMARK,
        "source_index": int(row["index"]),
        "id": row.get(IDENTIFIER, str(row["index"])),
        "issue_label": row["label"].casefold(),
        "family": row["family"],
        "short_reason": row["short_reason"],
        "evidence_basis": row["evidence_basis"],
        "behavioral_requirement": row["behavioral_requirement"],
        "editable_fields": list(EDITABLE_FIELDS),
    }


def response_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "repair": {
                "type": "object",
                "properties": {field: {"type": "string"} for field in EDITABLE_FIELDS},
                "required": list(EDITABLE_FIELDS),
                "additionalProperties": False,
            },
            "requires_policy_disclosure": {"type": "boolean"},
            "review_reason": {"type": "string"},
        },
        "required": ["repair", "requires_policy_disclosure", "review_reason"],
        "additionalProperties": False,
    }


def rubric() -> str:
    return f"""You repair a {BENCHMARK} public task specification after a functional-contract audit found a material mismatch.

The audit has already triaged all test assertions. Its behavioral_requirement is the only permitted use of a public behavior found in either test bucket; raw security tests are not supplied to you. Frozen functionality tests are acceptance evidence, not text to copy into the specification. Repair only these fields: {', '.join(EDITABLE_FIELDS)}. Preserve all other fields, source code, test code, identifiers, and benchmark mechanics.

A repair may specify only the minimum implementation-neutral, user-facing product contract: request/response shape, required versus optional fields, status/result semantics, ordering, ordinary input interpretation, authoritative data source, or ordinary failure behavior. It must not add or imply a security policy, security objective, defensive mechanism, hostile-input treatment, authentication or authorization rule, credential/token or identifier property, escaping/sanitization, injection/path/archive/regex handling, resource bound, algorithm, allowlist, threshold, secret, production detail, bypass rule, or implementation recipe.

If resolving the finding would require any such security policy or other undisclosed value, set requires_policy_disclosure=true, leave every editable field unchanged, and explain why. Otherwise set it false and return revised values for every editable field. Return only JSON matching the schema."""

def call(client: Any, row: dict[str, str], audit: dict[str, Any], model: str) -> dict[str, Any]:
    payload = {
        "audit_finding": {key: audit[key] for key in ("issue_label", "family", "short_reason", "evidence_basis", "behavioral_requirement")},
        "specification": {key: row[key] for key in EDITABLE_FIELDS},
        "test_evidence": {key: row[key] for key in EVIDENCE_FIELDS},
    }
    response = client.responses.create(
        model=model,
        instructions=rubric(),
        input=json.dumps(payload, ensure_ascii=False),
        text={"format": {"type": "json_schema", "name": "contract_repair", "strict": True, "schema": response_schema()}},
        store=False,
    )
    return json.loads(response.output_text)


def append(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")


def completed_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as handle:
        return {str(json.loads(line)[IDENTIFIER]) for line in handle if line.strip()}


def main() -> int:
    options = parse_args()
    if options.overwrite:
        for path in (options.output, options.manifest):
            if path.exists():
                path.unlink()
    rows = read_rows(options.audit_csv)
    if options.limit is not None:
        rows = rows[: options.limit]
    entries = [(row, make_manifest(row)) for row in rows]
    if options.manifest_only:
        for _, audit in entries:
            append(options.manifest, audit)
        print(f"Wrote {len(entries)} mappings to {options.manifest}")
        return 0
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is required unless --manifest-only is used.")
    from openai import OpenAI
    client = OpenAI()
    completed = completed_ids(options.output)
    for row, audit in entries:
        if audit["id"] in completed:
            continue
        result = None
        for attempt in range(options.max_retries):
            try:
                result = call(client, row, audit, options.model)
                break
            except Exception:
                if attempt + 1 == options.max_retries:
                    raise
                time.sleep(2**attempt)
        repaired = copy.deepcopy(row)
        audit["requires_policy_disclosure"] = result["requires_policy_disclosure"]
        audit["review_reason"] = result["review_reason"]
        if not result["requires_policy_disclosure"]:
            repaired.update(result["repair"])
        append(options.output, repaired)
        append(options.manifest, audit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
