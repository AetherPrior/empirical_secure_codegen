#!/usr/bin/env python3
"""Cluster C GRPO parquets with ProSec-style prompt subsampling per (lang, cwe).

GPU clustering with BGE (recommended):
  conda activate xfinder_env
  cd c
  python concat_cluster_parquets.py --num-clusters 250 --cluster-backend bge --device cuda
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

DEFAULT_INPUT = "c_cwe_GRPO.parquet"
DEFAULT_OUTPUT = "c_cwe_GRPO_clustered_250.parquet"

C_DIR = Path(__file__).resolve().parent
SIMPLE_GEN_DIR = C_DIR.parent
DATASETS_DIR = SIMPLE_GEN_DIR / "data" / "datasets_rl"

_LANG_ALIASES = {"c": "c"}


def _read_parquet(path: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq  # type: ignore

    return pq.read_table(path).to_pylist()


def _write_parquet(path: Path, rows: list[dict[str, Any]]) -> None:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore

    path.parent.mkdir(parents=True, exist_ok=True)
    shuffled = list(rows)
    random.Random(42).shuffle(shuffled)
    pq.write_table(pa.Table.from_pylist(shuffled), str(path), compression="zstd")


def _extra(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("extra_info") or row.get("extra_info_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _prompt_text(row: dict[str, Any]) -> str:
    extra = _extra(row)
    for key in ("user_prompt", "task_description", "task"):
        value = extra.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    prompt = row.get("prompt") or row.get("prompt_json")
    if isinstance(prompt, str) and prompt.strip():
        try:
            prompt = json.loads(prompt)
        except json.JSONDecodeError:
            return prompt.strip()
    if isinstance(prompt, list):
        for msg in prompt:
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    return content.strip()
    return ""


def _row_lang(row: dict[str, Any]) -> str:
    for source in (row, _extra(row)):
        lang = source.get("lang")
        if isinstance(lang, str) and lang.strip():
            return _LANG_ALIASES.get(lang.strip(), lang.strip())
    raise ValueError("row missing lang (expected top-level or extra_info.lang)")


def _row_cwe(row: dict[str, Any]) -> str:
    extra = _extra(row)
    for key in ("cwe", "cwe_id"):
        value = extra.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    reward = row.get("reward_model") or row.get("reward_model_json")
    if isinstance(reward, dict):
        gt = reward.get("ground_truth")
        if isinstance(gt, dict):
            value = gt.get("cwe") or gt.get("cwe_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(reward, str) and reward.strip():
        try:
            gt = json.loads(reward).get("ground_truth", {})
            if isinstance(gt, dict):
                value = gt.get("cwe") or gt.get("cwe_id")
                if isinstance(value, str) and value.strip():
                    return value.strip()
        except json.JSONDecodeError:
            pass
    return "UNKNOWN"


def _resolve_inputs(base_dir: Path, paths: list[str]) -> list[Path]:
    if paths:
        return [Path(p).resolve() for p in paths]
    return [(base_dir / DEFAULT_INPUT).resolve()]


def _load_groups(paths: list[Path]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        for row in _read_parquet(path):
            row = dict(row)
            groups[(_row_lang(row), _row_cwe(row))].append(row)
    return groups


def _make_encoder(backend: str, model: str, device: str, batch_size: int):
    if backend == "tfidf":
        def encode(texts: list[str]):
            from sklearn.feature_extraction.text import TfidfVectorizer

            return TfidfVectorizer(max_features=8192).fit_transform(texts).toarray()

        return encode

    from sentence_transformers import SentenceTransformer  # type: ignore

    st_model = SentenceTransformer(model, device=device)
    return lambda texts: st_model.encode(
        list(texts),
        batch_size=batch_size,
        show_progress_bar=len(texts) > 256,
    )


def _cluster_group(
    rows: list[dict[str, Any]],
    *,
    num_clusters: int,
    encode,
) -> list[dict[str, Any]]:
    by_text: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        text = _prompt_text(row)
        if text:
            by_text[text].append(row)

    unique = sorted(by_text)
    if not unique:
        return []

    k = min(num_clusters, len(unique))
    import numpy as np
    from sklearn.cluster import KMeans

    embeddings = np.asarray(encode(unique))
    km = KMeans(n_clusters=k, random_state=0, n_init=10)
    labels = km.fit_predict(embeddings)

    picked: set[str] = set()
    for cluster_id in range(k):
        member_idx = np.where(labels == cluster_id)[0]
        if len(member_idx) == 0:
            continue
        dists = np.linalg.norm(embeddings[member_idx] - km.cluster_centers_[cluster_id], axis=1)
        picked.add(unique[member_idx[int(np.argmin(dists))]])

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
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=[],
        help=f"Optional parquet path(s). Default: --base-dir/{DEFAULT_INPUT}",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--num-clusters", type=int, default=250)
    parser.add_argument("--per-cluster", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model", type=str, default="BAAI/bge-m3")
    parser.add_argument("--cluster-backend", choices=("bge", "tfidf"), default="bge")
    parser.add_argument("--device", type=str, default="cuda")
    parser.add_argument("--batch-size", type=int, default=64)
    args = parser.parse_args()

    base_dir = args.base_dir.resolve()
    paths = _resolve_inputs(base_dir, args.inputs)
    groups = _load_groups(paths)
    print(f"concat: {sum(len(g) for g in groups.values())} rows from {len(paths)} file(s)")

    encode = _make_encoder(args.cluster_backend, args.model, args.device, args.batch_size)

    selected: list[dict[str, Any]] = []
    for (lang, cwe), group in sorted(groups.items()):
        part = _cluster_group(
            group,
            num_clusters=args.num_clusters,
            encode=encode,
        )
        selected.extend(part)
        print(f"  {lang} / {cwe}: {len(group)} -> {len(part)}")

    output = (args.output or (base_dir / DEFAULT_OUTPUT)).resolve()
    _write_parquet(output, selected)
    print(f"wrote {len(selected)} rows -> {output}")


if __name__ == "__main__":
    main()
