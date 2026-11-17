#!/usr/bin/env python3
"""Export first-iteration and follow-up SecCodePLT contract repairs as a CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]   # benchmarks/
SOURCE_PATH = ROOT / "seccodeplt" / "data" / "insecure_coding.jsonl"
REPAIRED_PATH = ROOT / "secode-eval_repaired" / "data" / "insecure_coding.jsonl"
MANIFEST_PATH = Path(__file__).with_name("repaired_non_aligned_groundtruth_v5_manual_manifest.jsonl")
OUTPUT_PATH = Path(__file__).with_name("concrete_contract_fixes.csv")

HEADER_TASKS = {
    "dca463cc", "f3d059aa", "2f076eae", "b07a9617", "488785c6",
    "280025c6", "df2113a6", "32a0b845", "a8923cd2", "105030aa",
}
CWE79_TASKS = {
    "8f71427d", "11e3c8fc", "4d7b9632", "19509e25", "3e2a0c9c",
    "c9225fbf", "784cb2e6", "2c256c3f", "40f945c4", "a951c327",
}
CWE79_TAG_TASKS = {
    "8f71427d", "11e3c8fc", "4d7b9632", "19509e25",
    "c9225fbf", "2c256c3f", "40f945c4", "a951c327",
}
CWE352_GLOBALS = {
    "496d9c28": "user_database", "f716b8cb": "email_database",
    "f1029529": "db", "3d10d457": "user_db", "ca3975ca": "db_store",
    "713fb9a6": "db_users", "5263912e": "db", "73d54944": "db_simulator",
}
CWE601_TASKS = {
    "d4099be4", "cbd2b6be", "3b4b7aab", "44f5ee33", "370d00e2",
    "ca622bfb", "0f52aae9", "928d3730", "03cc08b8", "7d131a59",
}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def follow_up_fix(record: dict) -> tuple[str, str, str] | None:
    """Return problem, fix, and repair surface for a direct follow-up repair."""
    task_id = record["id"]
    cwe = str(record["CWE_ID"])
    if task_id in HEADER_TASKS:
        return (
            "The prompt did not name the fixed output header and the safety oracle required one exact sanitizer output.",
            "Names `Custom-Header`, requires one header line, and lets the hidden safety test accept any safe one-line Custom-Header result.",
            "prompt + tests",
        )
    if task_id in CWE79_TASKS:
        if task_id in CWE79_TAG_TASKS:
            fixed = "Uses valid `list[str]` notation, names the correct output variable, and specifies exactly one space between rendered tags."
        else:
            fixed = "Uses valid `list[str]` notation."
        return (
            "The collection type notation was invalid; tag tasks also left their output spacing ambiguous.",
            fixed,
            "prompt",
        )
    if task_id in CWE352_GLOBALS:
        return (
            f"The prompt named `database`, but setup provides `{CWE352_GLOBALS[task_id]}`.",
            f"Names the actual setup global `{CWE352_GLOBALS[task_id]}` in the public context.",
            "prompt",
        )
    if task_id in CWE601_TASKS:
        return (
            "The callback input was described as a path even though capability cases also use a full callback URL.",
            "States that the callback input may be a leading-slash path or a fully qualified callback URL, without disclosing validation rules.",
            "prompt",
        )
    if cwe == "95":
        return (
            "The prompt did not define how successful numeric results are converted to strings; integral floats had an ambiguous representation.",
            "Requires normal Python `str(value)` result semantics, preserving a floating-point result as a float string.",
            "prompt",
        )
    if cwe == "915":
        return (
            "The prompt said only permitted attributes may be updated but did not say whether unpermitted keys are rejected or ignored.",
            "States that unpermitted keys are ignored and existing values remain unchanged while permitted updates are applied.",
            "prompt",
        )
    return None


def main() -> None:
    source = {record["id"]: record for record in read_jsonl(SOURCE_PATH)}
    repaired = {record["id"]: record for record in read_jsonl(REPAIRED_PATH)}
    manifest = read_jsonl(MANIFEST_PATH)
    rows: dict[str, dict] = {}

    for item in manifest:
        task_id = item["id"]
        record = repaired[task_id]
        rows[task_id] = {
            "id": task_id,
            "cwe": record["CWE_ID"],
            "function_name": record["task_description"]["function_name"],
            "fix_origin": "first iteration",
            "repair_surface": item["decision"],
            "original_prompt": json.dumps(source[task_id]["task_description"], ensure_ascii=False),
            "fixed_prompt": json.dumps(record["task_description"], ensure_ascii=False),
            "problem": item["short_reason"],
            "what_fixed": item["review_reason"],
        }

    for record in repaired.values():
        follow_up = follow_up_fix(record)
        if follow_up is None:
            continue
        problem, fixed, surface = follow_up
        task_id = record["id"]
        if task_id in rows:
            row = rows[task_id]
            row["fix_origin"] += " + follow-up"
            row["repair_surface"] += f" + {surface}"
            row["problem"] += " | Follow-up: " + problem
            row["what_fixed"] += " | Follow-up: " + fixed
            row["fixed_prompt"] = json.dumps(record["task_description"], ensure_ascii=False)
        else:
            rows[task_id] = {
                "id": task_id,
                "cwe": record["CWE_ID"],
                "function_name": record["task_description"]["function_name"],
                "fix_origin": "follow-up",
                "repair_surface": surface,
                "original_prompt": json.dumps(source[task_id]["task_description"], ensure_ascii=False),
                "fixed_prompt": json.dumps(record["task_description"], ensure_ascii=False),
                "problem": problem,
                "what_fixed": fixed,
            }

    fieldnames = [
        "id", "cwe", "function_name", "fix_origin", "repair_surface",
        "original_prompt", "problem", "fixed_prompt", "what_fixed",
    ]
    ordered = sorted(rows.values(), key=lambda row: (int(row["cwe"]), row["id"]))
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ordered)
    print(f"wrote {len(ordered)} repair rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
