#!/usr/bin/env python3
"""Build and optionally publish an oversampled RegexEval dataset on Hugging Face."""

from __future__ import annotations

import argparse
from pathlib import Path

from datasets import Dataset, DatasetDict, load_dataset

SOURCE_DATASET = "s2e-lab/RegexEval"
TARGET_REPO = "anonymous/RegexEval"
DEFAULT_SIZE = 2000
DEFAULT_SEED = 42

README = """---
license: mit
language:
- en
tags:
- security
- regex
- redos
- cwe-1333
size_categories:
- 1K<n<10K
---

# RegexEval (oversampled)

This dataset is an **oversampled** version of [`s2e-lab/RegexEval`](https://huggingface.co/datasets/s2e-lab/RegexEval) (Re(gEx|DoS)Eval).

The upstream dataset contains **762** curated regex prompts from real users, with match/non-match test strings. This repo repeats those rows with replacement to provide **{size}** prompts for seeding CWE-1333 secure-coding task generation.

## Provenance

- **Source:** [s2e-lab/RegexEval](https://huggingface.co/datasets/s2e-lab/RegexEval)
- **Method:** Random oversampling with replacement (`seed={seed}`)
- **Original unique rows:** {unique}
- **Oversampled rows:** {size}

## Schema

Same columns as the source dataset, plus:

- `source_id`: original RegexEval `id`
- `oversample_index`: row index in this oversampled split (0..{size_minus_one})

## Citation

If you use the underlying benchmark, please cite the Re(gEx|DoS)Eval paper (ICSE 2024) and reference the original dataset.
"""


def build_oversampled(size: int, seed: int) -> Dataset:
    src = load_dataset(SOURCE_DATASET, split="train")
    if size <= 0:
        raise ValueError("size must be positive")
    if size < len(src):
        raise ValueError(f"size {size} is smaller than source ({len(src)} rows); use source directly")

    rng = __import__("random").Random(seed)
    indices = [rng.randrange(len(src)) for _ in range(size)]

    rows = []
    for oversample_index, src_idx in enumerate(indices):
        row = dict(src[src_idx])
        row["source_id"] = row["id"]
        row["id"] = oversample_index + 1
        row["oversample_index"] = oversample_index
        rows.append(row)

    return Dataset.from_list(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build oversampled anonymous/RegexEval dataset")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output-dir", type=Path, default=None, help="Optional local export directory")
    parser.add_argument("--push", action="store_true", help="Push to Hugging Face as anonymous/RegexEval")
    args = parser.parse_args()

    ds = build_oversampled(args.size, args.seed)
    src_len = len(load_dataset(SOURCE_DATASET, split="train"))
    readme = README.format(
        size=args.size,
        seed=args.seed,
        unique=src_len,
        size_minus_one=args.size - 1,
    )

    if args.output_dir:
        out = args.output_dir
        out.mkdir(parents=True, exist_ok=True)
        ds.to_parquet(out / "RegexEval.parquet")
        (out / "README.md").write_text(readme, encoding="utf-8")
        print(f"wrote {len(ds)} rows to {out}")

    if args.push:
        dsd = DatasetDict({"train": ds})
        dsd.push_to_hub(
            TARGET_REPO,
            commit_message=f"Oversample {SOURCE_DATASET} to {args.size} rows (seed={args.seed})",
        )
        from huggingface_hub import HfApi

        HfApi().upload_file(
            path_or_fileobj=readme.encode("utf-8"),
            path_in_repo="README.md",
            repo_id=TARGET_REPO,
            repo_type="dataset",
            commit_message="Add dataset card",
        )
        print(f"pushed to https://huggingface.co/datasets/{TARGET_REPO}")

    if not args.output_dir and not args.push:
        print(f"built {len(ds)} rows (use --output-dir or --push)")


if __name__ == "__main__":
    main()
