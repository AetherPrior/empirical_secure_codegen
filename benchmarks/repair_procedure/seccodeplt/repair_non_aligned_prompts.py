#!/usr/bin/env python3
"""Plan and selectively apply prompt-side SecCodePLT contract repairs while preserving dataset records.

The output is JSONL.  Every line is a source dataset record with exactly the
same top-level shape as the input record; only selected ``task_description``
text fields may change.  A separate manifest records the issue-to-taxonomy
mapping and the model's review decision.

By default the script loads ``anonymous/SecCodePLT``'s ``insecure_coding``
split.  It can instead read a JSON or JSONL export with ``--input``.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable


REPAIRABLE_FIELDS = ("arguments", "context", "description", "raise", "return")
IMMUTABLE_FIELDS = ("function_name", "security_policy")
NON_ALIGNED_LABELS = {"underspecified", "contradiction", "ambiguous"}
HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--issues-csv",
        type=Path,
        default=Path(__file__).with_name("all_tasks.csv"),
        help="CSV containing index, cwe, label, family, and short_reason columns.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--input",
        type=Path,
        help="JSON or JSONL dataset export. Records must retain SecCodePLT's top-level fields.",
    )
    source.add_argument(
        "--dataset",
        default="anonymous/SecCodePLT",
        help="Hugging Face dataset repository to load (default: %(default)s).",
    )
    parser.add_argument("--split", default="insecure_coding", help="Dataset split to load.")
    parser.add_argument("--revision", help="Optional immutable Hugging Face revision.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name("repaired_non_aligned.jsonl"),
        help="JSONL output containing only non-aligned source records in their original schema.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("non_aligned_prompt_map.jsonl"),
        help="JSONL audit manifest; labels and model-review metadata are written here, never into dataset records.",
    )
    parser.add_argument("--model", default="gpt-6.1-sol", help="OpenAI model used for repair.")
    parser.add_argument("--service-tier", choices=("auto", "default", "flex", "priority"), default="auto", help="Responses API service tier.")
    parser.add_argument("--limit", type=int, help="Process at most this many non-aligned records.")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum API attempts per record.")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent API repair requests.")
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Write the complete issue-to-repair-basis mapping without calling an LLM or writing repaired records.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing output and manifest files. Otherwise existing IDs are skipped for resumability.",
    )
    return parser.parse_args()


def read_records(path: Path | None, dataset_name: str, split: str, revision: str | None) -> list[dict[str, Any]]:
    if path is None:
        try:
            from datasets import load_dataset
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise SystemExit("Install `datasets` or pass --input with a JSON/JSONL export.") from exc
        kwargs: dict[str, Any] = {"split": split}
        if revision:
            kwargs["revision"] = revision
        return [dict(record) for record in load_dataset(dataset_name, **kwargs)]

    with path.open(encoding="utf-8") as handle:
        if path.suffix.lower() == ".jsonl":
            return [json.loads(line) for line in handle if line.strip()]
        loaded = json.load(handle)
    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict) and isinstance(loaded.get("records"), list):
        return loaded["records"]
    raise ValueError("JSON input must be a list of records or an object containing a 'records' list.")


def read_issues(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"index", "cwe", "label", "family", "short_reason"}
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"Issue CSV is missing required columns: {sorted(missing)}")
    issues = [row for row in rows if row["label"] in NON_ALIGNED_LABELS]
    if len(issues) != len({row["index"] for row in issues}):
        raise ValueError("Issue CSV contains duplicate non-aligned indexes.")
    return sorted(issues, key=lambda row: int(row["index"]))


def assert_record_shape(record: dict[str, Any], source_index: int) -> None:
    expected = {
        "id",
        "CWE_ID",
        "task_description",
        "ground_truth",
        "unittest",
        "install_requires",
        "rule",
        "use_rule",
    }
    missing = expected.difference(record)
    if missing:
        raise ValueError(f"Record {source_index} is missing SecCodePLT fields: {sorted(missing)}")
    task = record["task_description"]
    if not isinstance(task, dict) or any(field not in task for field in (*REPAIRABLE_FIELDS, *IMMUTABLE_FIELDS)):
        raise ValueError(f"Record {source_index} has an incompatible task_description object.")
    if not isinstance(record["unittest"], dict):
        raise ValueError(f"Record {source_index} has an incompatible unittest object.")


def prepare_manifest_entry(issue: dict[str, str], record: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_index": int(issue["index"]),
        "id": record["id"],
        "cwe": issue["cwe"],
        "issue_label": issue["label"],
        "family": issue["family"],
        "short_reason": issue["short_reason"],
        "repair_basis": "short_reason_only",
    }

def output_schema() -> dict[str, Any]:
    prompt_patch = {
        "type": "object",
        "properties": {field: {"type": "string"} for field in REPAIRABLE_FIELDS},
        "required": list(REPAIRABLE_FIELDS),
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["prompt", "setup", "tests", "hybrid", "reject"]},
            "prompt_patch": prompt_patch,
            "setup_patch": {
                "type": "string",
                "description": "Unified diff for public unittest.setup; empty when unchanged.",
            },
            "test_patch": {
                "type": "string",
                "description": "Unified diff for private unittest.testcases; empty when unchanged.",
            },
            "ground_truth_compatible": {
                "type": "boolean",
                "description": "True only when the unchanged private ground truth remains the intended behavior.",
            },
            "reason": {"type": "string"},
            "requires_manual_review": {"type": "boolean"},
        },
        "required": [
            "decision", "prompt_patch", "setup_patch", "test_patch", "ground_truth_compatible",
            "reason", "requires_manual_review",
        ],
        "additionalProperties": False,
    }


def build_instructions() -> str:
    return """Align this benchmark task using its short_reason.

visibility:
- public_prompt_fields and public_setup_code are shown to the solver.
- private_test_code and private_reference are hidden.

Ground truth is immutable. Never propose or rely on a ground-truth change. Every non-reject plan must be
compatible with the unchanged ground truth. Never move private rules, tests, or expected solutions into a
public field.

Choose one decision:
- prompt: clarify neutral public behavior;
- setup: fix neutral public setup code;
- tests: fix private test code;
- hybrid: combine necessary changes;
- reject: no allowed change can align the task with unchanged ground truth without disclosure.

Public edits may state only ordinary interfaces, types, formats, names, and errors already supported by
public artifacts.  

An expert should reasonably solve capability tests from public fields. If capability tests depend on unrealistic assumptions from the prompt/setup, state it in the prompt; that is not disclosure.
A safety test edit must retain or strengthen meaningful security coverage; do not delete, skip, or replace it with generic functionality. Do not disclose any safety rule in the prompt. 
If the public prompt says something that the private tests contradict, rewrite that statement so it is true, using a general qualifier ("checks for type") rather than naming the specific hidden rule (such as "harmful types" or "unauthorized roles").
If a test can only be passed by someone who already knows the hidden rule, and no general qualifier would make the correct behavior derivable, choose "reject" instead of weakening the test or revealing the rule.

Authorization rules (such as who can edit) is public and may be stated in the prompt.
Sensitive fields for object records is public and may be stated in the prompt.
Resource bounds may be stated hand wavily for clarity (eg. state approximately <=1e6 or <=10000).

Return unified diffs for setup_patch and test_patch; use empty strings for unchanged patches.
For prompt_patch, each non-empty value is the complete replacement for that public field. An empty
string means that field is unchanged and its source value will be preserved.
Keep prompt_patch unchanged unless decision is prompt or hybrid. Return only schema-valid JSON."""


def normalize_reject_plan(result: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """A reject is always a no-edit outcome, regardless of extraneous model patches."""
    if result["decision"] != "reject":
        return result
    normalized = dict(result)
    normalized["prompt_patch"] = {
        field: record["task_description"][field] for field in REPAIRABLE_FIELDS
    }
    normalized["setup_patch"] = ""
    normalized["test_patch"] = ""
    return normalized


def preserve_empty_prompt_fields(result: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Materialize sparse prompt patches without allowing empty fields to erase the source."""
    if result["decision"] not in {"prompt", "hybrid"}:
        return result
    normalized = dict(result)
    normalized["prompt_patch"] = {
        field: result["prompt_patch"][field] or record["task_description"][field]
        for field in REPAIRABLE_FIELDS
    }
    return normalized


def apply_unified_diff(source: str, patch: str) -> str:
    """Apply a unified diff to one text field, rejecting stale or malformed patches."""
    if not patch:
        return source
    source_lines = source.splitlines()
    patch_lines = patch.splitlines()
    result: list[str] = []
    source_cursor = 0
    patch_cursor = 0
    saw_hunk = False

    while patch_cursor < len(patch_lines):
        line = patch_lines[patch_cursor]
        match = HUNK_HEADER.match(line)
        if not match:
            if line.startswith(("--- ", "+++ ")):
                patch_cursor += 1
                continue
            raise ValueError(f"Malformed unified diff line: {line!r}")
        saw_hunk = True
        old_start = int(match.group(1))
        target_start = old_start - 1
        hunk_end = patch_cursor + 1
        expected_old: list[str] = []
        while hunk_end < len(patch_lines) and not patch_lines[hunk_end].startswith("@@ "):
            candidate = patch_lines[hunk_end]
            if candidate and candidate[0] in " -":
                expected_old.append(candidate[1:])
            hunk_end += 1
        if (
            expected_old
            and source_lines[target_start:target_start + len(expected_old)] != expected_old
        ):
            matches = [
                offset for offset in range(source_cursor, len(source_lines) - len(expected_old) + 1)
                if source_lines[offset:offset + len(expected_old)] == expected_old
            ]
            if len(matches) != 1:
                raise ValueError("Unified diff does not uniquely apply to the current source text.")
            target_start = matches[0]
        if target_start < source_cursor or target_start > len(source_lines):
            raise ValueError("Unified diff hunk is out of order or outside the source text.")
        result.extend(source_lines[source_cursor:target_start])
        source_cursor = target_start
        patch_cursor += 1
        while patch_cursor < len(patch_lines) and not patch_lines[patch_cursor].startswith("@@ "):
            hunk_line = patch_lines[patch_cursor]
            if hunk_line.startswith("\\ No newline at end of file"):
                patch_cursor += 1
                continue
            if not hunk_line or hunk_line[0] not in " +-":
                raise ValueError(f"Malformed unified diff hunk line: {hunk_line!r}")
            kind, text = hunk_line[0], hunk_line[1:]
            if kind in " -":
                if source_cursor >= len(source_lines) or source_lines[source_cursor] != text:
                    raise ValueError("Unified diff does not apply to the current source text.")
                source_cursor += 1
            if kind in " +":
                result.append(text)
            patch_cursor += 1
    if not saw_hunk:
        raise ValueError("Unified diff contains no hunks.")
    result.extend(source_lines[source_cursor:])
    return "\n".join(result) + ("\n" if source.endswith("\n") else "")


def validate_plan(result: dict[str, Any], record: dict[str, Any]) -> None:
    """Reject plans that violate immutable-ground-truth or patch-surface invariants."""
    decision = result["decision"]
    prompt_unchanged = all(
        result["prompt_patch"][field] == record["task_description"][field]
        for field in REPAIRABLE_FIELDS
    )
    setup_changed = bool(result["setup_patch"])
    tests_changed = bool(result["test_patch"])

    if decision != "reject" and not result["ground_truth_compatible"]:
        raise ValueError("A non-reject plan must preserve the unchanged ground truth.")
    if decision == "prompt" and (prompt_unchanged or setup_changed or tests_changed):
        raise ValueError("A prompt plan may change only public prompt fields.")
    if decision == "setup" and (not prompt_unchanged or not setup_changed or tests_changed):
        raise ValueError("A setup plan may change only public setup code.")
    if decision == "tests" and (not prompt_unchanged or setup_changed or not tests_changed):
        raise ValueError("A tests plan may change only private test code.")
    if decision == "hybrid" and (prompt_unchanged and not setup_changed and not tests_changed):
        raise ValueError("A hybrid plan must change at least one allowed surface.")
    if decision == "reject" and (not prompt_unchanged or setup_changed or tests_changed):
        raise ValueError("A reject plan must not propose edits.")


def repair_task(client: Any, *, record: dict[str, Any], manifest: dict[str, Any], model: str, service_tier: str) -> dict[str, Any]:
    task = record["task_description"]
    payload = {
        "issue": {"label": manifest["issue_label"], "short_reason": manifest["short_reason"]},
        "public_prompt_fields": {
            field: task[field] for field in (*REPAIRABLE_FIELDS, "function_name")
        },
        "public_setup_code": record["unittest"]["setup"],
        "private_test_code": record["unittest"]["testcases"],
        "private_reference": {
            "security_policy": task["security_policy"],
            "ground_truth": record["ground_truth"],
            "install_requires": record["install_requires"],
            "rule": record["rule"],
        },
    }
    response = client.responses.create(
        model=model,
        service_tier=service_tier,
        instructions=build_instructions(),
        input=json.dumps(payload, ensure_ascii=False),
        text={"format": {"type": "json_schema", "name": "alignment_repair_plan", "strict": True, "schema": output_schema()}},
        store=False,
    )
    return json.loads(response.output_text)

def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as handle:
        return {json.loads(line)["id"] for line in handle if line.strip()}


def main() -> int:
    args = parse_args()
    if args.overwrite:
        for path in (args.output, args.manifest):
            if path.exists():
                path.unlink()

    records = read_records(args.input, args.dataset, args.split, args.revision)
    issues = read_issues(args.issues_csv)
    if max(int(issue["index"]) for issue in issues) >= len(records):
        raise ValueError(
            f"Dataset has {len(records)} records but the issue file references index "
            f"{max(int(issue['index']) for issue in issues)}. Use the full SecCodePLT split."
        )

    selected: list[tuple[dict[str, str], dict[str, Any], dict[str, Any]]] = []
    for issue in issues:
        source_index = int(issue["index"])
        record = records[source_index]
        assert_record_shape(record, source_index)
        if str(record["CWE_ID"]) != issue["cwe"]:
            raise ValueError(
                f"Source index {source_index} has CWE-{record['CWE_ID']}, expected CWE-{issue['cwe']}. "
                "The input ordering does not match all_tasks.csv."
            )
        selected.append((issue, record, prepare_manifest_entry(issue, record)))
    if args.limit is not None:
        selected = selected[: args.limit]

    if args.manifest_only:
        for _, _, manifest in selected:
            append_jsonl(args.manifest, manifest)
        print(f"Wrote {len(selected)} mappings to {args.manifest}")
        return 0

    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is required unless --manifest-only is used.")
    from openai import OpenAI

    client = OpenAI()
    completed = existing_ids(args.output)
    pending = [(record, manifest) for _, record, manifest in selected if record["id"] not in completed]

    def repair_one(record: dict[str, Any], manifest: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        result: dict[str, Any] | None = None
        last_error: Exception | None = None
        for attempt in range(args.max_retries):
            try:
                result = repair_task(
                    client,
                    record=record,
                    manifest=manifest,
                    model=args.model,
                    service_tier=args.service_tier,
                )
                break
            except Exception as exc:  # network and service errors are retried
                last_error = exc
                if attempt + 1 < args.max_retries:
                    time.sleep(2**attempt)
        if result is None:
            raise RuntimeError(f"Repair failed for {record['id']}: {last_error}") from last_error
        result = normalize_reject_plan(result, record)
        result = preserve_empty_prompt_fields(result, record)
        try:
            validate_plan(result, record)
            repaired = copy.deepcopy(record)
            if result["decision"] in {"prompt", "hybrid"}:
                for field in REPAIRABLE_FIELDS:
                    repaired["task_description"][field] = result["prompt_patch"][field]
            if result["setup_patch"]:
                repaired["unittest"]["setup"] = apply_unified_diff(
                    repaired["unittest"]["setup"], result["setup_patch"]
                )
            if result["test_patch"]:
                repaired["unittest"]["testcases"] = apply_unified_diff(
                    repaired["unittest"]["testcases"], result["test_patch"]
                )
        except ValueError as exc:
            # A plan that contradicts its selected patch surface is not safe to
            # apply. Preserve the immutable record and retain it as a no-edit
            # outcome instead of aborting the independent batch.
            result = normalize_reject_plan({**result, "decision": "reject"}, record)
            result["reason"] = f"Rejected malformed repair plan: {exc}"
            validate_plan(result, record)
            repaired = copy.deepcopy(record)
        manifest = dict(manifest)
        manifest.update({
            "decision": result["decision"],
            "setup_patch": result["setup_patch"],
            "test_patch": result["test_patch"],
            "ground_truth_compatible": result["ground_truth_compatible"],
            "review_reason": result["reason"],
            "requires_manual_review": result["requires_manual_review"],
            "setup_patch_applied": bool(result["setup_patch"]),
            "test_patch_applied": bool(result["test_patch"]),
        })
        return repaired, manifest

    processed = 0
    if args.workers < 1:
        raise ValueError("--workers must be positive")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(repair_one, record, manifest) for record, manifest in pending]
        for future in as_completed(futures):
            repaired, manifest = future.result()
            append_jsonl(args.output, repaired)
            append_jsonl(args.manifest, manifest)
            processed += 1
            print(f"[{processed}/{len(pending)}] {repaired['id']} ({manifest['repair_basis']})", file=sys.stderr)

    print(f"Wrote {processed} repaired records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
