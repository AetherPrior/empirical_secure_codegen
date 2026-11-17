#!/usr/bin/env python3
"""Figure-4-style plot: mean prompt similarity before vs after clustering.

ProSec measures average pairwise fuzzy string similarity per (language, CWE).
Lower similarity after clustering => higher diversity. Points should fall below y=x.

  conda activate vllm
  cd py
  python plot_cluster_diversity.py --num-clusters 200
"""

from __future__ import annotations

import argparse
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from concat_cluster_parquets import (
    DATASETS_DIR,
    _cluster_group,
    _load_groups,
    _make_encoder,
    _prompt_text,
    _read_parquet,
    _resolve_inputs,
    _row_cwe,
    _row_lang,
)

DEFAULT_PLOT = "cluster_diversity_fig4_python_200.png"


def _mean_pairwise_similarity(
    texts: list[str],
    *,
    max_pairs: int,
    seed: int,
) -> float:
    from rapidfuzz.fuzz import ratio

    n = len(texts)
    if n < 2:
        return float("nan")

    total = n * (n - 1) // 2
    if total <= max_pairs:
        pairs = [(i, j) for i in range(n) for j in range(i + 1, n)]
    else:
        rng = random.Random(seed)
        pairs_set: set[tuple[int, int]] = set()
        while len(pairs_set) < max_pairs:
            i, j = rng.randrange(n), rng.randrange(n)
            if i < j:
                pairs_set.add((i, j))
        pairs = list(pairs_set)

    return sum(ratio(texts[i], texts[j]) for i, j in pairs) / len(pairs)


def _unique_prompts(rows: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        text = _prompt_text(row)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _plot_figure4(
    points: list[tuple[str, float, float, int, int]],
    out_path: Path,
) -> None:
    import matplotlib.pyplot as plt

    before = [p[1] for p in points]
    after = [p[2] for p in points]
    lo = min(min(before), min(after)) - 0.02
    hi = max(max(before), max(after)) + 0.02

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.scatter(before, after, alpha=0.55, s=70, c="#d62728", edgecolors="none")
    ax.plot([lo, hi], [lo, hi], "--", color="#aec7e8", linewidth=2, label="y = x")
    ax.set_xlim(lo, hi)
    ax.set_ylim(lo, hi)
    ax.set_xlabel("Avg. Similarity before Clustering")
    ax.set_ylabel("Avg. Similarity after Clustering")
    ax.set_title("Effectiveness of instruction clustering")
    ax.set_aspect("equal", adjustable="box")
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"wrote {out_path}")


def _load_after_groups(path: Path) -> dict[tuple[str, str], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in _read_parquet(path):
        row = dict(row)
        groups[(_row_lang(row), _row_cwe(row))].append(row)
    return groups


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", type=Path, default=DATASETS_DIR)
    parser.add_argument("--inputs", nargs="*", default=[])
    parser.add_argument(
        "--after-parquet",
        type=Path,
        default=None,
        help="Use pre-clustered parquet for 'after'. Otherwise cluster in memory.",
    )
    parser.add_argument("--num-clusters", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-pairs", type=int, default=5000, help="Cap pairwise samples per group.")
    parser.add_argument("--model", type=str, default="BAAI/bge-m3")
    parser.add_argument(
        "--cluster-backend",
        choices=("bge", "tfidf"),
        default="bge",
        help="Embedding for KMeans when --after-parquet is not set.",
    )
    parser.add_argument("--device", type=str, default="cuda")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--plot-out", type=Path, default=DATASETS_DIR / DEFAULT_PLOT)
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    groups = _load_groups(_resolve_inputs(base_dir, args.inputs))

    after_by_key: dict[tuple[str, str], list[dict[str, Any]]] | None = None
    encode = None
    if args.after_parquet:
        after_by_key = _load_after_groups(args.after_parquet.resolve())
    else:
        encode = _make_encoder(args.cluster_backend, args.model, args.device, args.batch_size)

    points: list[tuple[str, float, float, int, int]] = []
    for key in sorted(groups):
        lang, cwe = key
        before_rows = groups[key]
        if after_by_key is not None:
            after_rows = after_by_key.get(key, [])
            if not after_rows and before_rows:
                print(f"  warning: no after rows matched {key}")
        else:
            after_rows = _cluster_group(
                before_rows,
                num_clusters=args.num_clusters,
                encode=encode,
            )

        before_texts = _unique_prompts(before_rows)
        after_texts = _unique_prompts(after_rows)
        if len(before_texts) < 2:
            continue

        b_sim = _mean_pairwise_similarity(before_texts, max_pairs=args.max_pairs, seed=args.seed)
        a_sim = _mean_pairwise_similarity(
            after_texts if len(after_texts) >= 2 else before_texts[:1],
            max_pairs=args.max_pairs,
            seed=args.seed + 1,
        )
        if len(after_texts) < 2:
            a_sim = float("nan")

        label = f"{lang}/{cwe}"
        points.append((label, b_sim / 100.0, a_sim / 100.0, len(before_texts), len(after_texts)))
        print(
            f"{label}: n {len(before_texts)} -> {len(after_texts)} | "
            f"avg sim {b_sim:.1f} -> {a_sim:.1f}"
        )

    if not points:
        raise SystemExit("no groups with enough prompts to plot")

    _plot_figure4(points, args.plot_out.resolve())
    below = sum(1 for _, b, a, _, _ in points if a < b)
    print(f"{below}/{len(points)} groups have lower similarity after clustering")


if __name__ == "__main__":
    main()
