#!/usr/bin/env python3
"""Convert our preference pairs into SafeCoder security-training JSONL.

SafeCoder's security loader expects rows with at least:

  description, func_src_before, func_src_after, file_name, vul_type

For our execution-filtered preference data, the rejected response is the
vulnerable/insecure implementation and the chosen response is the secure
implementation. This script preserves that mapping so SafeCoder's CE +
unlikelihood objective can be applied without changing the training method.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path
from typing import Any


FENCE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _content(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("content")
                if isinstance(text, str):
                    pieces.append(text)
            elif isinstance(item, str):
                pieces.append(item)
        return "\n".join(pieces).strip()
    return ""


def _extract_code(value: Any) -> str:
    text = _content(value)
    match = FENCE_RE.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()


def _metadata(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata")
    return meta if isinstance(meta, dict) else {}


def _cwe(meta: dict[str, Any], row: dict[str, Any], idx: int) -> str:
    raw = meta.get("cwe") or row.get("cwe") or row.get("CWE_ID") or "unknown"
    text = str(raw).strip().lower().replace("cwe_", "cwe-").replace("cwe ", "cwe-")
    if text and not text.startswith("cwe-") and text != "unknown":
        text = f"cwe-{text}"
    return text or f"unknown-{idx}"


def _func_name(meta: dict[str, Any], idx: int) -> str:
    name = meta.get("function_name") or meta.get("func_name")
    return str(name).strip() if name else f"sample_{idx}"


def convert_row(row: dict[str, Any], idx: int) -> dict[str, Any] | None:
    prompt = _content(row.get("prompt") or row.get("messages") or row.get("conversations"))
    chosen_code = _extract_code(row.get("chosen"))
    rejected_code = _extract_code(row.get("rejected"))
    if not prompt or not chosen_code or not rejected_code:
        return None

    meta = _metadata(row)
    cwe = _cwe(meta, row, idx)
    func_name = _func_name(meta, idx)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", func_name)[:80] or f"sample_{idx}"

    return {
        "func_name": func_name,
        "func_src_before": rejected_code,
        "func_src_after": chosen_code,
        "line_changes": {},
        "char_changes": {},
        "commit_link": None,
        "file_name": f"{cwe}_{idx:06d}_{safe_name}.py",
        "vul_type": cwe,
        "commit_msg": "converted from execution-filtered preference pair",
        "parent_commit": None,
        "description": prompt,
        "source": "our_execution_filtered_refneg_preferences",
        "source_metadata": meta,
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(value)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare our data for SafeCoder-style SFT/security training.")
    parser.add_argument("--input-jsonl", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True, help="SafeCoder data_train_val directory.")
    parser.add_argument("--dataset-name", default="sec-our-refneg")
    parser.add_argument("--val-ratio", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=-1)
    args = parser.parse_args()

    raw_rows = read_jsonl(args.input_jsonl)
    converted = []
    skipped = 0
    for idx, row in enumerate(raw_rows):
        converted_row = convert_row(row, idx)
        if converted_row is None:
            skipped += 1
            continue
        converted.append(converted_row)
        if args.max_rows > 0 and len(converted) >= args.max_rows:
            break

    rng = random.Random(args.seed)
    rng.shuffle(converted)
    n_val = int(round(len(converted) * args.val_ratio)) if converted else 0
    n_val = max(1, n_val) if len(converted) > 1 and args.val_ratio > 0 else n_val
    val_rows = converted[:n_val]
    train_rows = converted[n_val:]

    train_path = args.output_root / "train" / f"{args.dataset_name}.jsonl"
    val_path = args.output_root / "val" / f"{args.dataset_name}.jsonl"
    write_jsonl(train_path, train_rows)
    write_jsonl(val_path, val_rows)

    print(f"input: {args.input_jsonl}")
    print(f"converted: {len(converted)}")
    print(f"skipped_missing_fields: {skipped}")
    print(f"train: {len(train_rows)} -> {train_path}")
    print(f"val: {len(val_rows)} -> {val_path}")
    print(f"dataset argument for SafeCoder: --datasets evol {args.dataset_name}")


if __name__ == "__main__":
    main()
