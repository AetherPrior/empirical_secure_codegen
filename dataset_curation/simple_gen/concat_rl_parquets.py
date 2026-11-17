#!/usr/bin/env python3
"""Concatenate C/C++/Python GRPO RL datasets into one VeRL-ready dataset."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


DEFAULT_INPUTS = (
    ("c", "c_cwe_GRPO.parquet"),
    ("cpp", "cpp_cwe_GRPO.parquet"),
    ("py", "python_cwe_GRPO.parquet"),
)


def _json_loads_any(raw: Any, fallback: Any) -> Any:
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return fallback
    if raw is None:
        return fallback
    return raw


def _json_loads_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            return {}
    return {}


def _normalize_lang_for_reward(lang: str) -> str:
    if lang == "py":
        return "python"
    return lang


def _normalize_row(row: dict[str, Any], *, lang: str) -> dict[str, Any]:
    prompt_payload = row.get("prompt_json") if "prompt_json" in row else row.get("prompt", [])
    reward_payload = row.get("reward_model_json") if "reward_model_json" in row else row.get("reward_model", {})
    extra_payload = row.get("extra_info_json") if "extra_info_json" in row else row.get("extra_info", {})

    prompt = _json_loads_any(prompt_payload, [])
    if isinstance(prompt, dict):
        prompt = [prompt]
    if not isinstance(prompt, list):
        prompt = [{"role": "user", "content": str(prompt or "")}]

    reward_model = _json_loads_object(reward_payload)
    extra_info = _json_loads_object(extra_payload)

    reward_model.setdefault("style", "rule")
    ground_truth = reward_model.get("ground_truth")
    if not isinstance(ground_truth, dict):
        ground_truth = {}
        reward_model["ground_truth"] = ground_truth
    ground_truth["language"] = _normalize_lang_for_reward(lang)

    extra_info["lang"] = lang
    extra_info["language"] = _normalize_lang_for_reward(lang)
    return {
        "data_source": str(row.get("data_source", "")),
        "prompt": prompt,
        "ability": str(row.get("ability", "")),
        "reward_model": reward_model,
        "extra_info": extra_info,
        "lang": lang,
    }


def _split_rows(rows: list[dict[str, Any]], *, val_ratio: float, seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if val_ratio <= 0:
        return list(rows), []
    if val_ratio >= 1:
        return [], list(rows)
    shuffled = list(rows)
    random.Random(seed).shuffle(shuffled)
    val_count = int(len(shuffled) * val_ratio)
    return shuffled[: len(shuffled) - val_count], shuffled[len(shuffled) - val_count :]


def _default_split_path(output: Path, split_name: str) -> Path:
    return output.with_name(f"{output.stem}_{split_name}{output.suffix}")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def _row_cwe_id(row: dict[str, Any]) -> str:
    """Best-effort CWE id for grouping/sampling."""
    extra = row.get("extra_info")
    if isinstance(extra, dict):
        for key in ("cwe", "cwe_id", "cweID", "cwe-id"):
            value = extra.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    reward = row.get("reward_model")
    if isinstance(reward, dict):
        gt = reward.get("ground_truth")
        if isinstance(gt, dict):
            for key in ("cwe", "cwe_id"):
                value = gt.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _cwe_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        cwe = _row_cwe_id(row) or "UNKNOWN"
        counts[cwe] = counts.get(cwe, 0) + 1
    return counts


def _print_cwe_stats(*, label: str, counts: dict[str, int]) -> None:
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    total = sum(count for _, count in items)
    print(f"{label}: {total} rows across {len(items)} cwes")
    for cwe, count in items:
        print(f"  {cwe}: {count}")


def _sample_and_split_per_cwe(
    rows: list[dict[str, Any]],
    *,
    per_cwe_max: int,
    val_ratio: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Cap each CWE, then 90/10 train/val within each CWE. Returns (sampled_all, train, val)."""
    rng = random.Random(seed)
    by_cwe: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        cwe = _row_cwe_id(row) or "UNKNOWN"
        by_cwe.setdefault(cwe, []).append(row)

    sampled: list[dict[str, Any]] = []
    train_rows: list[dict[str, Any]] = []
    val_rows: list[dict[str, Any]] = []
    for cwe in sorted(by_cwe):
        group = list(by_cwe[cwe])
        rng.shuffle(group)
        cap = min(per_cwe_max, len(group)) if per_cwe_max > 0 else len(group)
        group = group[:cap]
        sampled.extend(group)
        train_part, val_part = _split_rows(group, val_ratio=val_ratio, seed=rng.randint(0, 2**31 - 1))
        train_rows.extend(train_part)
        val_rows.extend(val_part)
    return sampled, train_rows, val_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Concatenate C/C++/Python GRPO Parquets into one RL dataset")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "data" / "datasets_rl",
        help="Directory containing c_cwe_GRPO.parquet, cpp_cwe_GRPO.parquet, and python_cwe_GRPO.parquet.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output parquet path. Default: <base-dir>/all_cwe_GRPO.parquet",
    )
    parser.add_argument(
        "--jsonl-output",
        type=Path,
        default=None,
        help="Normalized JSONL output. Default: same path as --output with .jsonl suffix.",
    )
    parser.add_argument("--train-output", type=Path, default=None, help="Train split parquet output.")
    parser.add_argument("--val-output", type=Path, default=None, help="Validation split parquet output.")
    parser.add_argument("--val-ratio", type=float, default=0.1, help="Validation split ratio (default: 0.1).")
    parser.add_argument("--seed", type=int, default=42, help="Shuffle seed for train/val split.")
    parser.add_argument(
        "--per-cwe-max",
        type=int,
        default=500,
        help="After concat, sample at most this many rows per CWE before per-CWE train/val split.",
    )
    args = parser.parse_args()

    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise RuntimeError("pyarrow is required. Install it with `pip install pyarrow`.") from exc

    base_dir = args.base_dir.resolve()
    output = args.output or (base_dir / "all_cwe_GRPO.parquet")
    if not output.is_absolute():
        output = base_dir / output
    jsonl_output = args.jsonl_output or output.with_suffix(".jsonl")
    if not jsonl_output.is_absolute():
        jsonl_output = base_dir / jsonl_output

    train_output = args.train_output or _default_split_path(output, "train")
    val_output = args.val_output or _default_split_path(output, "val")
    if not train_output.is_absolute():
        train_output = base_dir / train_output
    if not val_output.is_absolute():
        val_output = base_dir / val_output

    inputs = [(lang, base_dir / filename) for lang, filename in DEFAULT_INPUTS]
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}

    for lang, path in inputs:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"missing input for lang={lang}: {path}")
        table = pq.read_table(path)
        records = table.to_pylist()
        counts[lang] = counts.get(lang, 0) + len(records)
        rows.extend(_normalize_row(row, lang=lang) for row in records)

    output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), str(output), compression="zstd")
    _write_jsonl(jsonl_output, rows)

    _print_cwe_stats(label="concat (full)", counts=_cwe_counts(rows))

    sampled_rows, train_rows, val_rows = _sample_and_split_per_cwe(
        rows,
        per_cwe_max=int(args.per_cwe_max),
        val_ratio=float(args.val_ratio),
        seed=int(args.seed),
    )
    train_output.parent.mkdir(parents=True, exist_ok=True)
    val_output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(train_rows), str(train_output), compression="zstd")
    pq.write_table(pa.Table.from_pylist(val_rows), str(val_output), compression="zstd")

    _print_cwe_stats(label="sampled (per-cwe cap)", counts=_cwe_counts(sampled_rows))
    _print_cwe_stats(label="train", counts=_cwe_counts(train_rows))
    _print_cwe_stats(label="val", counts=_cwe_counts(val_rows))

    print(f"wrote {len(rows)} rows -> {output}")
    print(f"wrote train split ({len(train_rows)} rows) -> {train_output}")
    print(f"wrote val split ({len(val_rows)} rows) -> {val_output}")
    print(f"wrote jsonl -> {jsonl_output}")
    for lang, count in sorted(counts.items()):
        print(f"  {lang}: {count}")


if __name__ == "__main__":
    main()
