import argparse
import json
from pathlib import Path
from typing import Any


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_parquet(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write VeRL-ready Parquet with native prompt/reward_model/extra_info columns."""
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "pyarrow is required to write parquet. Install it (e.g. `pip install pyarrow`)."
        ) from exc

    out_rows: list[dict[str, Any]] = []
    for r in rows:
        out_rows.append(
            {
                "data_source": r.get("data_source", ""),
                "ability": r.get("ability", ""),
                "prompt": r.get("prompt", []),
                "reward_model": r.get("reward_model", {}),
                "extra_info": r.get("extra_info", {}),
            }
        )

    table = pa.Table.from_pylist(out_rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, str(path), compression="zstd")


def _to_prompt(row: dict[str, Any]) -> list[dict[str, str]]:
    prompt = row.get("prompt")
    if isinstance(prompt, list) and all(isinstance(item, dict) for item in prompt):
        normalized: list[dict[str, str]] = []
        for item in prompt:
            role = item.get("role", "user")
            content = item.get("content", "")
            if not isinstance(role, str):
                role = str(role)
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False, default=str)
            normalized.append({"role": role, "content": content})
        return normalized

    text = row.get("rewritten_prompt") or row.get("prompt") or ""
    if not isinstance(text, str):
        text = str(text)
    return [{"role": "user", "content": text}]


def _prompt_has_text(prompt: list[dict[str, str]]) -> bool:
    for m in prompt:
        c = m.get("content", "")
        if isinstance(c, str) and c.strip():
            return True
    return False


def _is_simple_gen_row(row: dict[str, Any]) -> bool:
    fn = row.get("function_name")
    tc = row.get("test_code")
    return isinstance(fn, str) and bool(fn.strip()) and isinstance(tc, str) and bool(tc.strip())


def _ground_truth(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "function_name": row["function_name"].strip(),
        "test_code": row["test_code"],
        "setup_tests": row["setup_tests"] if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
    }


def _convert_row(
    row: dict[str, Any],
    fallback_index: int,
    *,
    data_source: str,
) -> dict[str, Any]:
    prompt = _to_prompt(row)
    ground_truth = _ground_truth(row)

    extra_info: dict[str, Any] = {
        "index": row.get("index", fallback_index),
    }

    if row.get("cwe_id") is not None:
        extra_info["cwe_id"] = str(row.get("cwe_id"))
    if row.get("cwe") is not None:
        extra_info["cwe"] = str(row.get("cwe"))

    return {
        "data_source": data_source,
        "prompt": prompt,
        "ability": "code_security",
        "reward_model": {
            "style": "rule",
            "ground_truth": ground_truth,
        },
        "extra_info": extra_info,
    }


def _split_rows(rows: list[dict[str, Any]], val_ratio: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if val_ratio <= 0:
        return rows, []
    if val_ratio >= 1:
        return [], rows

    total = len(rows)
    val_count = int(total * val_ratio)
    train_count = total - val_count
    return rows[:train_count], rows[train_count:]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert simple_gen JSONL (function_name + test_code + prompt) into GRPO RLHF JSONL/Parquet."
    )
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL file")
    parser.add_argument("--output", type=Path, required=True, help="Output GRPO JSONL file")
    parser.add_argument("--parquet-out", type=Path, default=None, help="Optional Parquet output")
    parser.add_argument("--train-output", type=Path, default=None, help="Optional train split output JSONL")
    parser.add_argument("--val-output", type=Path, default=None, help="Optional val split output JSONL")
    parser.add_argument("--train-parquet-out", type=Path, default=None, help="Optional train split output Parquet")
    parser.add_argument("--val-parquet-out", type=Path, default=None, help="Optional val split output Parquet")
    parser.add_argument("--val-ratio", type=float, default=0.1, help="Validation ratio for optional split outputs")
    parser.add_argument(
        "--data-source",
        type=str,
        default="security_harness",
        help="Value for output `data_source`.",
    )
    args = parser.parse_args()

    rows = _read_jsonl(args.input)

    converted: list[dict[str, Any]] = []
    filtered_out = 0
    for idx, row in enumerate(rows):
        if not _is_simple_gen_row(row):
            filtered_out += 1
            continue
        prompt = _to_prompt(row)
        if not _prompt_has_text(prompt):
            filtered_out += 1
            continue
        converted.append(_convert_row(row, idx, data_source=args.data_source))

    _write_jsonl(args.output, converted)
    if args.parquet_out is not None:
        _write_parquet(args.parquet_out, converted)

    if (
        args.train_output is not None
        or args.val_output is not None
        or args.train_parquet_out is not None
        or args.val_parquet_out is not None
    ):
        train_rows, val_rows = _split_rows(converted, args.val_ratio)
        if args.train_output is not None:
            _write_jsonl(args.train_output, train_rows)
        if args.val_output is not None:
            _write_jsonl(args.val_output, val_rows)
        if args.train_parquet_out is not None:
            _write_parquet(args.train_parquet_out, train_rows)
        if args.val_parquet_out is not None:
            _write_parquet(args.val_parquet_out, val_rows)

    print(f"Input rows: {len(rows)}")
    print(f"Converted rows: {len(converted)}")
    print(f"Filtered out during conversion: {filtered_out}")
    print(f"Main output: {args.output}")
    if args.parquet_out is not None:
        print(f"Parquet output: {args.parquet_out}")
    if args.train_output is not None:
        print(f"Train output: {args.train_output}")
    if args.val_output is not None:
        print(f"Val output: {args.val_output}")
    if args.train_parquet_out is not None:
        print(f"Train parquet: {args.train_parquet_out}")
    if args.val_parquet_out is not None:
        print(f"Val parquet: {args.val_parquet_out}")


if __name__ == "__main__":
    main()
