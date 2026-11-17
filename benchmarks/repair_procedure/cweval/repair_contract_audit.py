#!/usr/bin/env python3
"""Repair non-aligned CWEval prompt contracts using frozen test evidence."""

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
BENCHMARK = 'CWEval'
AUDIT_CSV = ROOT / 'contract_audit' / "all_tasks.csv"
EDITABLE_FIELDS = ('prompt',)
EVIDENCE_FIELDS = ('tests',)
IDENTIFIER = 'task_file'
NON_ALIGNED = {"underspecified", "ambiguous", "contradiction"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-csv", type=Path, default=AUDIT_CSV)
    parser.add_argument("--output", type=Path, default=ROOT / "repaired_non_aligned.jsonl")
    parser.add_argument("--manifest", type=Path, default=ROOT / "repair_manifest.jsonl")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--policy-mode", choices=("generic", "behavioral"), default="generic")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"index", "label", "family", "short_reason", *EDITABLE_FIELDS, *EVIDENCE_FIELDS}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"{path} lacks required columns: {sorted(missing)}")
    return [row for row in rows if row["label"].casefold() in NON_ALIGNED]


def make_manifest(row: dict[str, str]) -> dict[str, Any]:
    return {
        "benchmark": BENCHMARK,
        "source_index": int(row["index"]),
        "id": row.get(IDENTIFIER, str(row["index"])),
        "issue_label": row["label"].casefold(),
        "family": row["family"],
        "short_reason": row["short_reason"],
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


def rubric(policy_mode: str) -> str:
    policy = (
        "Do not infer or enumerate concrete policy values solely from tests: no production hosts, "
        "identities, credentials, allowlists, algorithm lists, thresholds, payloads, bypass mechanics, "
        "or implementation recipes. Refer to an existing named policy/configuration abstraction."
        if policy_mode == "generic"
        else
        "State only the minimum behavioral rule needed to reconcile the specification and tests; never add "
        "production secrets, infrastructure details, bypass mechanics, or implementation recipes."
    )
    return f"""You repair a {BENCHMARK} task specification after a contract audit found a material mismatch.

Frozen functionality and security tests are acceptance evidence, not text to copy into the specification.
Repair only these fields: {', '.join(EDITABLE_FIELDS)}. Preserve all other fields, source code, test
code, identifiers, and benchmark mechanics. Resolve the reported omission, ambiguity, or contradiction
at the contract level: inputs, authoritative state/data source, output/status shape, and failure behavior
must be determinable. Keep the specification implementation-neutral.

{policy}

If the only accurate repair would disclose an absent concrete policy, set requires_policy_disclosure=true,
return each editable field unchanged, and explain why. Otherwise set it false and return revised values for
every editable field. Return only JSON matching the schema."""


def call(client: Any, row: dict[str, str], audit: dict[str, Any], model: str, policy_mode: str) -> dict[str, Any]:
    payload = {
        "audit_finding": {key: audit[key] for key in ("issue_label", "family", "short_reason")},
        "specification": {key: row[key] for key in EDITABLE_FIELDS},
        "test_evidence": {key: row[key] for key in EVIDENCE_FIELDS},
    }
    response = client.responses.create(
        model=model,
        instructions=rubric(policy_mode),
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
                result = call(client, row, audit, options.model, options.policy_mode)
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
