#!/usr/bin/env python3
"""Random per-(lang, cwe) subsample baseline for python GRPO parquets (no KMeans)."""

from __future__ import annotations

import argparse
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from concat_cluster_parquets import (
    DATASETS_DIR,
    _load_groups,
    _prompt_text,
    _resolve_inputs,
    _write_parquet,
)

DEFAULT_OUTPUT = "python_cwe_GRPO_random_200.parquet"


def _random_subsample_group(
    rows: list[dict[str, Any]],
    *,
    num_samples: int,
    seed: int,
) -> list[dict[str, Any]]:
    by_text: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        text = _prompt_text(row)
        if text:
            by_text[text].append(row)

    unique = sorted(by_text)
    if not unique:
        return []

    picked = set(random.Random(seed).sample(unique, min(num_samples, len(unique))))

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        text = _prompt_text(row)
        if text in picked and text not in seen:
            out.append(row)
            seen.add(text)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", type=Path, default=DATASETS_DIR)
    parser.add_argument("--inputs", nargs="*", default=[])
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--per-group", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    groups = _load_groups(_resolve_inputs(base_dir, args.inputs))
    print(f"loaded {sum(len(g) for g in groups.values())} rows, {len(groups)} groups")

    selected: list[dict[str, Any]] = []
    for (lang, cwe), group in sorted(groups.items()):
        part = _random_subsample_group(group, num_samples=args.per_group, seed=args.seed)
        selected.extend(part)
        print(f"  {lang} / {cwe}: {len(group)} -> {len(part)}")

    output = (args.output or (base_dir / DEFAULT_OUTPUT)).resolve()
    _write_parquet(output, selected)
    print(f"wrote {len(selected)} rows -> {output}")


if __name__ == "__main__":
    main()
