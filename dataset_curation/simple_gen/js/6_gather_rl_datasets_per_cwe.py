#!/usr/bin/env python3
"""Convert per-CWE JavaScript simple_gen rows into GRPO RLHF JSONL/Parquet."""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path
from typing import Any

# Appended last, after the setup code block -- the end of the prompt is what the
# model reads immediately before generating, and ending on a bare code block
# (rather than this instruction) was found to make multi-code-block responses
# more likely. Language-agnostic wording so the same constant can be reused
# verbatim across every per-language gather script.
OUTPUT_FORMAT_INSTRUCTION = (
    "Output code in one code block containing your implementation between "
    "triple backticks (```) in the language specified."
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _rows_for_parquet(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize nested fields so pyarrow can infer a uniform schema.

    ``tests_json`` mixes ints/strings/nulls across rows (e.g. output: 20 vs
    ``\"Exception\"``), which breaks ``Table.from_pylist``. Store it as JSON text
    in parquet; JSONL keeps the nested dict via ``_write_jsonl``.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        r = dict(row)
        rm = row.get("reward_model")
        if isinstance(rm, dict):
            rm = dict(rm)
            gt = rm.get("ground_truth")
            if isinstance(gt, dict):
                gt = dict(gt)
                tj = gt.get("tests_json")
                if tj is not None and not isinstance(tj, str):
                    gt["tests_json"] = json.dumps(tj, ensure_ascii=False)
                rm["ground_truth"] = gt
            r["reward_model"] = rm
        out.append(r)
    return out


def _write_parquet(path: Path, rows: list[dict[str, Any]]) -> None:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise RuntimeError("pyarrow is required to write parquet") from exc

    table = pa.Table.from_pylist(_rows_for_parquet(rows))
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, str(path), compression="zstd")


def _normalize_arguments(args: Any) -> list[dict[str, str]]:
    if args is None:
        return []
    if isinstance(args, dict):
        args = [args]
    if not isinstance(args, list):
        return []
    out: list[dict[str, str]] = []
    for arg in args:
        if isinstance(arg, dict):
            out.append(
                {
                    "name": str(arg.get("name", "")),
                    "type": str(arg.get("type", "")),
                    "description": str(arg.get("description", "")),
                }
            )
        else:
            out.append({"name": str(arg), "type": "", "description": ""})
    return out


def _normalize_scalar_text(x: Any) -> str:
    if x is None:
        return ""
    return x if isinstance(x, str) else str(x)


def _strip_markdown_fences(text: str) -> str:
    lines = text.strip().splitlines()
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip().startswith("```"):
        return "\n".join(lines[1:-1]).strip()
    return text.strip()


def _setup_code_block(row: dict[str, Any], *, lang: str) -> str:
    setup = row.get("setup_code")
    if not isinstance(setup, str):
        return ""
    setup = _strip_markdown_fences(setup)
    if not setup:
        return ""
    return (
        "\n\n## Provided setup (use as-is; do not redefine)\n"
        f"```{lang}\n{setup.rstrip()}\n```\n"
    )


def _prompt_to_text(prompt: Any) -> str:
    if prompt is None:
        return ""
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, list):
        parts: list[str] = []
        for item in prompt:
            if isinstance(item, dict):
                content = item.get("content", "")
                if isinstance(content, str) and content.strip():
                    parts.append(content.strip())
            elif isinstance(item, str) and item.strip():
                parts.append(item.strip())
        return "\n\n".join(parts)
    return str(prompt)


def _to_prompt(row: dict[str, Any]) -> list[dict[str, str]]:
    def _contract_block() -> str:
        try:
            args_s = json.dumps(row.get("arguments", []), ensure_ascii=False, default=str)
        except Exception:
            args_s = str(row.get("arguments", []))
        try:
            ret_s = json.dumps(row.get("return", ""), ensure_ascii=False, default=str)
        except Exception:
            ret_s = str(row.get("return", ""))
        raises = row.get("raises", "")
        raises_s = raises if isinstance(raises, str) else str(raises)
        return (
            "\n\n---\n"
            "Contract:\n"
            f"- function_name: {row.get('function_name', '')}\n"
            f"- arguments: {args_s}\n"
            f"- return: {ret_s}\n"
            f"- raises: {raises_s}\n"
        )

    def _prompt_suffix() -> str:
        return (
            _contract_block()
            + _setup_code_block(row, lang="javascript")
            + "\n\n"
            + OUTPUT_FORMAT_INSTRUCTION
        )

    prompt = row.get("prompt")
    if isinstance(prompt, list) and all(isinstance(item, dict) for item in prompt):
        normalized: list[dict[str, str]] = []
        injected = False
        for item in prompt:
            role = item.get("role", "user")
            content = item.get("content", "")
            if not isinstance(role, str):
                role = str(role)
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False, default=str)
            if not injected and role == "user":
                content = content + _prompt_suffix()
                injected = True
            normalized.append({"role": role, "content": content})
        if not injected:
            normalized.append({"role": "user", "content": _prompt_suffix().lstrip()})
        return normalized

    text = row.get("rewritten_prompt") or row.get("prompt") or ""
    if not isinstance(text, str):
        text = str(text)
    return [{"role": "user", "content": text + _prompt_suffix()}]


def _prompt_has_text(prompt: list[dict[str, str]]) -> bool:
    return any(isinstance(msg.get("content"), str) and msg["content"].strip() for msg in prompt)


def _extract_user_prompt(prompt: list[dict[str, str]]) -> str:
    for msg in prompt:
        if msg.get("role") == "user" and isinstance(msg.get("content"), str) and msg["content"].strip():
            return msg["content"]
    return ""


def _oracle_solution(row: dict[str, Any]) -> str:
    for key in ("candidate_js", "generated_code"):
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _is_simple_gen_row(row: dict[str, Any]) -> bool:
    fn = row.get("function_name")
    has_tests_json = isinstance(row.get("tests_json"), dict)
    has_test_code = isinstance(row.get("test_code"), str) and bool(row.get("test_code", "").strip())
    return isinstance(fn, str) and bool(fn.strip()) and (has_tests_json or has_test_code)


def _ground_truth(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "function_name": row["function_name"].strip(),
        "test_code": row.get("test_code", "") if isinstance(row.get("test_code"), str) else "",
        "setup_tests": row.get("setup_tests", "") if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
        "tests_json": row.get("tests_json", None),
        "prompt": _prompt_to_text(row.get("prompt", "")),
        "arguments": _normalize_arguments(row.get("arguments", [])),
        "return": _normalize_scalar_text(row.get("return", "")),
        "raises": _normalize_scalar_text(row.get("raises", "")),
        "cwe": row.get("cwe", row.get("cwe_id", "")),
        "language": row.get("language", "javascript"),
    }


def normalize_cwe(cwe: Any) -> str:
    if cwe is None:
        return ""
    if isinstance(cwe, str):
        match = re.search(r"(\d+)", cwe)
        if match:
            return f"CWE-{match.group(1)}"
        return cwe.strip().upper()
    if isinstance(cwe, int):
        return f"CWE-{cwe}"
    return str(cwe)




def _convert_row(
    row: dict[str, Any],
    fallback_index: int,
    *,
    data_source: str,
    extra_info: dict[str, Any],
) -> dict[str, Any]:
    prompt = _to_prompt(row)

    extra_info["index"] = row.get("index", fallback_index)
    if row.get("cwe") is not None:
        extra_info["cwe"] = str(row.get("cwe"))
    if row.get("cwe_id") is not None:
        extra_info["cwe_id"] = str(row.get("cwe_id"))

    cwe_id = normalize_cwe(row.get("cwe_id") or row.get("cwe"))
    if cwe_id:
        extra_info["feedback"] = f"\nCWE ID: {cwe_id}\n"


    oracle = _oracle_solution(row)
    if oracle:
        extra_info["candidate_js"] = oracle
        extra_info["generated_code"] = oracle

    if isinstance(row.get("function_name"), str):
        extra_info["function_name"] = row["function_name"]
    extra_info["arguments"] = _normalize_arguments(row.get("arguments", []))
    if row.get("return") is not None:
        extra_info["return"] = _normalize_scalar_text(row.get("return"))
    if row.get("raises") is not None:
        extra_info["raises"] = _normalize_scalar_text(row.get("raises"))
    extra_info["user_prompt"] = _extract_user_prompt(prompt)

    return {
        "data_source": data_source,
        "prompt": prompt,
        "ability": "code_security",
        "reward_model": {"style": "rule", "ground_truth": _ground_truth(row)},
        "extra_info": extra_info,
    }


def _split_rows(rows: list[dict[str, Any]], val_ratio: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if val_ratio <= 0:
        return rows, []
    if val_ratio >= 1:
        return [], rows
    shuffled = list(rows)
    random.shuffle(shuffled)
    val_count = int(len(shuffled) * val_ratio)
    return shuffled[: len(shuffled) - val_count], shuffled[len(shuffled) - val_count :]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert per-CWE JS pipeline JSONL (prefer stage-6 rewritten guidelines) into RL JSONL/Parquet"
    )
    parser.add_argument("--lang", type=str, default="js", help="Pipeline run language folder, e.g. js")
    parser.add_argument("--cwe-list", type=str, nargs="*", default=None)
    parser.add_argument("--output-suffix", type=str, default="simple_gen")
    parser.add_argument(
        "--stage",
        type=str,
        default="5",
        choices=("5", "4", "auto"),
        help="Which artifact to gather: 5=5_rewritten, "
        "4=4_valid, auto=prefer 5 then 4",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    in_path = base_dir / "data" / "pipeline_runs" / args.lang
    cwe_filter = set(cwe.lower() for cwe in args.cwe_list) if args.cwe_list else None
    out_jsonl = base_dir / "data" / "datasets_rl" / f"{args.lang}_{args.output_suffix}.jsonl"
    out_parquet = base_dir / "data" / "datasets_rl" / f"{args.lang}_{args.output_suffix}.parquet"

    def resolve_input(cwe_dir: Path) -> Path | None:
        if args.stage == "4":
            candidates = ["4_valid.jsonl"]
        elif args.stage == "5":
            candidates = ["5_rewritten.jsonl"]
        else:
            candidates = ["5_rewritten.jsonl", "4_valid.jsonl"]
        for name in candidates:
            path = cwe_dir / name
            if path.is_file() and path.stat().st_size > 0:
                return path
        return None

    cwe_dirs = [d for d in in_path.iterdir() if d.is_dir() and (cwe_filter is None or d.name.lower() in cwe_filter)]
    print(f"Found {len(cwe_dirs)} CWE dirs under {in_path}")

    all_converted: list[dict[str, Any]] = []
    for cwe_dir in sorted(cwe_dirs, key=lambda p: p.name):
        jsonl_path = resolve_input(cwe_dir)
        if jsonl_path is None:
            print(f"Warning: no stage-{args.stage} JSONL under {cwe_dir}, skipping")
            continue
        rows = _read_jsonl(jsonl_path)
        converted: list[dict[str, Any]] = []
        for idx, row in enumerate(rows):
            if not _is_simple_gen_row(row):
                continue
            prompt = _to_prompt(row)
            if not _prompt_has_text(prompt):
                continue
            converted.append(
                _convert_row(
                    row,
                    idx,
                    data_source=f"simple_gen_{cwe_dir.name}",
                    extra_info={"cwe": cwe_dir.name, "source_file": jsonl_path.name},
                )
            )
        all_converted.extend(converted)
        print(f"Converted {len(converted)} from {jsonl_path}")

    random.seed(42)
    random.shuffle(all_converted)
    _write_jsonl(out_jsonl, all_converted)
    _write_parquet(out_parquet, all_converted)
    train_rows, val_rows = _split_rows(all_converted, 0.1)
    train_path = out_parquet.parent / f"{out_parquet.stem}_train{out_parquet.suffix}"
    val_path = out_parquet.parent / f"{out_parquet.stem}_val{out_parquet.suffix}"
    _write_parquet(train_path, train_rows)
    _write_parquet(val_path, val_rows)
    print(f"wrote {len(all_converted)} rows -> {out_parquet}")
    print(f"wrote train ({len(train_rows)}) -> {train_path}")
    print(f"wrote val ({len(val_rows)}) -> {val_path}")
    print(f"wrote jsonl -> {out_jsonl}")


if __name__ == "__main__":
    main()
