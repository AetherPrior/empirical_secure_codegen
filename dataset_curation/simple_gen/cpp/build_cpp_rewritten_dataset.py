#!/usr/bin/env python3
"""Build a reproducible C++ GRPO dataset from every stage-6 rewritten record.

The stage-6 records have passed the C++ harness.  This script retains every
convertible record from ``pipeline_runs/cpp/*/5_rewritten.jsonl``, converts it
to the public ``anonymous/cpp_cwe_GRPO`` schema, and produces a deterministic
90/10 train/validation split.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
from collections import Counter
from pathlib import Path
from types import ModuleType


def _load_converter() -> ModuleType:
    path = Path(__file__).with_name("6_gather_rl_datasets_per_cwe.py")
    spec = importlib.util.spec_from_file_location("cpp_grpo_converter", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load converter from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_rows(run_root: Path, converter: ModuleType) -> list[dict]:
    rows: list[dict] = []
    sources = sorted(run_root.glob("cwe-*/5_rewritten.jsonl"))
    if not sources:
        raise FileNotFoundError(f"No stage-6 C++ outputs found under {run_root}")

    for source in sources:
        cwe = source.parent.name
        converted = 0
        for fallback_index, row in enumerate(converter._read_jsonl(source)):
            if not converter._is_simple_gen_row(row):
                continue
            prompt = converter._to_prompt(row)
            if not converter._prompt_has_text(prompt):
                continue
            rows.append(
                converter._convert_row(
                    row,
                    fallback_index,
                    data_source=f"simple_gen_{cwe}",
                    extra_info={"cwe": cwe},
                )
            )
            converted += 1
        print(f"{cwe}: {converted} rows from {source}")
    return rows


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-root",
        type=Path,
        default=root / "data" / "pipeline_runs" / "cpp",
        help="Directory holding cwe-*/5_rewritten.jsonl files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=root / "data" / "datasets_rl",
        help="Directory for the combined and split Parquet files.",
    )
    parser.add_argument("--seed", type=int, default=20260929)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    args = parser.parse_args()

    if not 0 < args.val_ratio < 1:
        raise ValueError("--val-ratio must be strictly between zero and one")

    import pyarrow as pa
    import pyarrow.parquet as pq

    converter = _load_converter()
    rows = _build_rows(args.run_root.resolve(), converter)
    function_names = [r["reward_model"]["ground_truth"]["function_name"] for r in rows]
    if len(function_names) != len(set(function_names)):
        raise ValueError("Stage-6 source contains duplicate function names")

    rng = random.Random(args.seed)
    rng.shuffle(rows)
    val_count = int(len(rows) * args.val_ratio)
    train_rows, val_rows = rows[:-val_count], rows[-val_count:]

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    all_path = output_dir / "cpp_cwe_GRPO_rewritten.parquet"
    train_path = output_dir / "cpp_cwe_GRPO_rewritten_train.parquet"
    validation_path = output_dir / "cpp_cwe_GRPO_rewritten_validation.parquet"
    for path, payload in ((all_path, rows), (train_path, train_rows), (validation_path, val_rows)):
        pq.write_table(pa.Table.from_pylist(payload), path, compression="zstd")

    counts = Counter(r["reward_model"]["ground_truth"]["cwe"] for r in rows)
    manifest = {
        "source": str(args.run_root.resolve()),
        "source_artifact": "cwe-*/5_rewritten.jsonl",
        "seed": args.seed,
        "validation_ratio": args.val_ratio,
        "all_rows": len(rows),
        "train_rows": len(train_rows),
        "validation_rows": len(val_rows),
        "unique_function_names": len(set(function_names)),
        "rows_by_cwe": dict(sorted(counts.items())),
        "files": {
            "all": str(all_path),
            "train": str(train_path),
            "validation": str(validation_path),
        },
    }
    manifest_path = output_dir / "cpp_cwe_GRPO_rewritten_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
