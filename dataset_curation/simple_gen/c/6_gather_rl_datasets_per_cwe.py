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
    """Write VeRL-ready Parquet.

    This writes the row dictionaries as-is (nested structures preserved).
    """
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "pyarrow is required to write parquet. Install it (e.g. `pip install pyarrow`)."
        ) from exc

    table = pa.Table.from_pylist(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, str(path), compression="zstd")


def _prompt_to_text(prompt: Any) -> str:
    """Convert various prompt encodings into a single text string (for metadata fields)."""
    if prompt is None:
        return ""
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, list):
        parts: list[str] = []
        for item in prompt:
            if isinstance(item, dict):
                c = item.get("content", "")
                if isinstance(c, str) and c.strip():
                    parts.append(c.strip())
            elif isinstance(item, str) and item.strip():
                parts.append(item.strip())
        return "\n\n".join(parts)
    return str(prompt)


def _normalize_arguments(args: Any) -> list[dict[str, str]]:
    """Force arguments into list[{'name','type','description'}] with string values."""
    if args is None:
        return []
    if isinstance(args, dict):
        args = [args]
    if not isinstance(args, list):
        return []
    out: list[dict[str, str]] = []
    for a in args:
        if isinstance(a, dict):
            out.append(
                {
                    "name": str(a.get("name", "")),
                    "type": str(a.get("type", "")),
                    "description": str(a.get("description", "")),
                }
            )
        elif isinstance(a, str):
            out.append({"name": a, "type": "", "description": ""})
        else:
            out.append({"name": str(a), "type": "", "description": ""})
    return out


def _normalize_scalar_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    return str(x)


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


def _to_prompt(row: dict[str, Any]) -> list[dict[str, str]]:
    def _stringify(x: Any) -> str:
        if x is None:
            return ""
        if isinstance(x, str):
            return x
        return str(x)

    def _format_arguments(args: Any) -> list[str]:
        if args is None or args == "":
            return ["- (none)"]
        if isinstance(args, dict):
            args = [args]
        if isinstance(args, list):
            lines: list[str] = []
            for a in args:
                if isinstance(a, dict):
                    name = _stringify(a.get("name", "")).strip() or "arg"
                    typ = _stringify(a.get("type", "")).strip()
                    desc = _stringify(a.get("description", "")).strip()
                    head = f"{name}" + (f" ({typ})" if typ else "")
                    lines.append(f"- {head}" + (f": {desc}" if desc else ""))
                else:
                    s = _stringify(a).strip()
                    if s:
                        lines.append(f"- {s}")
            return lines or ["- (none)"]
        s = _stringify(args).strip()
        return [f"- {s}"] if s else ["- (none)"]

    def _format_returns(ret: Any) -> list[str]:
        if ret is None or ret == "":
            return ["- (unspecified)"]
        if isinstance(ret, dict):
            typ = _stringify(ret.get("type", "")).strip()
            desc = _stringify(ret.get("description", "")).strip()
            head = typ or "value"
            return [f"- {head}" + (f": {desc}" if desc else "")]
        s = _stringify(ret).strip()
        return [f"- {s}"] if s else ["- (unspecified)"]

    def _format_raises(raises: Any) -> list[str]:
        if raises is None or raises == "":
            return ["- (none)"]
        if isinstance(raises, str):
            parts = [p.strip() for p in raises.replace(";", ",").split(",")]
            parts = [p for p in parts if p]
            return [f"- {p}" for p in parts] or ["- (none)"]
        if isinstance(raises, list):
            parts = [_stringify(x).strip() for x in raises]
            parts = [p for p in parts if p]
            return [f"- {p}" for p in parts] or ["- (none)"]
        s = _stringify(raises).strip()
        return [f"- {s}"] if s else ["- (none)"]

    def _sig_block() -> str:
        fn = _stringify(row.get("function_name", "")).strip()
        args = row.get("arguments", [])
        ret = row.get("return", "")
        raises = row.get("raises", "")

        args_lines = "\n".join(_format_arguments(args))
        ret_lines = "\n".join(_format_returns(ret))
        raises_lines = "\n".join(_format_raises(raises))

        return (
            "\n\n## CLI contract\n"
            f"argv arguments (after program name):\n{args_lines}\n\n"
            f"stdout output / return value:\n{ret_lines}\n\n"
            f"Errors / contract:\n{raises_lines}\n"
        )

    def _prompt_suffix() -> str:
        return (
            _sig_block()
            + _setup_code_block(row, lang="c")
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
                content = _stringify(content)
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
    for m in prompt:
        c = m.get("content", "")
        if isinstance(c, str) and c.strip():
            return True
    return False


def _extract_user_prompt(prompt: list[dict[str, str]]) -> str:
    for msg in prompt:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")
        content = msg.get("content")
        if role == "user" and isinstance(content, str) and content.strip():
            return content
    return ""


def _oracle_solution(row: dict[str, Any]) -> str:
    for key in ("candidate_c", "generated_code"):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _is_simple_gen_row(row: dict[str, Any]) -> bool:
    fn = row.get("function_name")
    tc = row.get("test_code")
    ok_tests = isinstance(tc, str) and bool(tc.strip())
    return isinstance(fn, str) and bool(fn.strip()) and ok_tests


def _ground_truth(row: dict[str, Any]) -> dict[str, Any]:
    """Return a harness bundle for the reward model.

    This is intentionally *richer* than the minimal harness requirements so downstream
    stages (e.g. solution generation / filtering) can recover the full task contract
    without having to join against the original pipeline JSONL.
    """
    return {
        # Required for simple_gen-style harness execution:
        "function_name": row["function_name"].strip(),
        #  pytest harness (Python) that executes compiled C via subprocess:
        "test_code": row.get("test_code", "") if isinstance(row.get("test_code"), str) else "",
        "setup_tests": row.get("setup_tests", "") if isinstance(row.get("setup_tests"), str) else "",
        "setup_code": row["setup_code"] if isinstance(row.get("setup_code"), str) else "",
        # Helpful task metadata (may be missing / non-canonical in some pipeline stages):
        "prompt": _prompt_to_text(row.get("prompt", "")),
        "arguments": _normalize_arguments(row.get("arguments", [])),
        "return": _normalize_scalar_text(row.get("return", "")),
        "raises": _normalize_scalar_text(row.get("raises", "")),
        "cwe": row.get("cwe", row.get("cwe_id", "")),
        "language": row.get("language", "c"),
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

    ground_truth = _ground_truth(row)

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
        extra_info["candidate_c"] = oracle
        extra_info["generated_code"] = oracle

    # Keep task signature metadata at top-level extra_info as well for quick filtering/debug.
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
    shuffled = list(rows)
    random.shuffle(shuffled)
    return shuffled[:train_count], shuffled[train_count:]


def main() -> None:
    #
    parser = argparse.ArgumentParser(
        description="Convert per-CWE ``5_rewritten.jsonl`` (fallback: ``4_valid.jsonl``) into GRPO RLHF JSONL/Parquet. "
        "Rows must carry the oracle ``candidate_c``."
    )
    parser.add_argument(
        "--lang",
        type=str,
        required=True,
        help="Programming language (e.g. 'c')",
    )
    parser.add_argument(
        '--cwe-list',
        type=str,
        nargs='*',
        default=None,
        help='Optional list of CWE IDs to filter by (e.g. --cwe-list cwe-79 cwe-89). If not provided, all CWEs will be included.',
    )
    parser.add_argument(
        "--output-suffix",
        type=str,
        default="simple_gen",
    )

    args = parser.parse_args()
    base_dir = Path(__file__).resolve().parents[1]  # .../simple_gen/
    in_path = base_dir / "data" / "pipeline_runs" / f"{args.lang}"

    cwe_filter = set(cwe.lower() for cwe in args.cwe_list) if args.cwe_list else None
    out_jsonl = base_dir / "data" / "datasets_rl" / f"{args.lang}_{args.output_suffix}.jsonl"
    out_parquet = base_dir / "data" / "datasets_rl" / f"{args.lang}_{args.output_suffix}.parquet"

    # find all cwe dirs in in_path
    cwe_dirs = [d for d in in_path.iterdir() if d.is_dir() and (cwe_filter is None or d.name.lower() in cwe_filter)]
    print(f"Found {len(cwe_dirs)} CWE directories in {in_path} after filtering: {[d.name for d in cwe_dirs]}")

    all_converted: list[dict[str, Any]] = []
    for cwe_dir in cwe_dirs:
        rewritten, fallback = cwe_dir / "5_rewritten.jsonl", cwe_dir / "4_valid.jsonl"
        jsonl_path = rewritten if rewritten.is_file() else fallback   # rubric-rewritten rows when present
        if not jsonl_path.is_file():
            print(f"Warning: Missing required file {jsonl_path}, skipping this CWE directory.")
            continue
        print(f"Processing {jsonl_path}...")
        rows = _read_jsonl(jsonl_path)
        converted: list[dict[str, Any]] = []
        for idx, row in enumerate(rows):
            if not _is_simple_gen_row(row):
                continue
            prompt = _to_prompt(row)
            if not _prompt_has_text(prompt):
                continue
            converted.append(_convert_row(row, idx, data_source=f"simple_gen_{cwe_dir.name}", extra_info={"cwe": cwe_dir.name}))

        all_converted.extend(converted)
        print(f"Converted {len(converted)} rows from {jsonl_path}.")

    random.shuffle(all_converted)
    _write_jsonl(out_jsonl, all_converted)
    _write_parquet(out_parquet, all_converted)

    train_out_parquet = out_parquet.parent / f"{out_parquet.stem}_train{out_parquet.suffix}"
    val_out_parquet = out_parquet.parent / f"{out_parquet.stem}_val{out_parquet.suffix}"
    train_rows, val_rows = _split_rows(all_converted, val_ratio=0.1)
    _write_parquet(train_out_parquet, train_rows)
    _write_parquet(val_out_parquet, val_rows)


    # parser.add_argument("--input", type=Path, required=True, help="Input JSONL file")
    # parser.add_argument("--output", type=Path, required=True, help="Output GRPO JSONL file")
    # parser.add_argument("--parquet-out", type=Path, default=None, help="Optional Parquet output")
    # parser.add_argument("--train-output", type=Path, default=None, help="Optional train split output JSONL")
    # parser.add_argument("--val-output", type=Path, default=None, help="Optional val split output JSONL")
    # parser.add_argument("--train-parquet-out", type=Path, default=None, help="Optional train split output Parquet")
    # parser.add_argument("--val-parquet-out", type=Path, default=None, help="Optional val split output Parquet")
    # parser.add_argument("--val-ratio", type=float, default=0.1, help="Validation ratio for optional split outputs")
    # parser.add_argument(
    #     "--data-source",
    #     type=str,
    #     default="security_harness",
    #     help="Value for output `data_source`.",
    # )
    # args = parser.parse_args()

    # rows = _read_jsonl(args.input)

    # converted: list[dict[str, Any]] = []
    # filtered_out = 0
    # for idx, row in enumerate(rows):
    #     if not _is_simple_gen_row(row):
    #         filtered_out += 1
    #         continue
    #     prompt = _to_prompt(row)
    #     if not _prompt_has_text(prompt):
    #         filtered_out += 1
    #         continue
    #     converted.append(_convert_row(row, idx, data_source=args.data_source))

    # _write_jsonl(args.output, converted)
    # if args.parquet_out is not None:
    #     _write_parquet(args.parquet_out, converted)

    # if (
    #     args.train_output is not None
    #     or args.val_output is not None
    #     or args.train_parquet_out is not None
    #     or args.val_parquet_out is not None
    # ):
    #     train_rows, val_rows = _split_rows(converted, args.val_ratio)
    #     if args.train_output is not None:
    #         _write_jsonl(args.train_output, train_rows)
    #     if args.val_output is not None:
    #         _write_jsonl(args.val_output, val_rows)
    #     if args.train_parquet_out is not None:
    #         _write_parquet(args.train_parquet_out, train_rows)
    #     if args.val_parquet_out is not None:
    #         _write_parquet(args.val_parquet_out, val_rows)

    # print(f"Input rows: {len(rows)}")
    # print(f"Converted rows: {len(converted)}")
    # print(f"Filtered out during conversion: {filtered_out}")
    # print(f"Main output: {args.output}")
    # if args.parquet_out is not None:
    #     print(f"Parquet output: {args.parquet_out}")
    # if args.train_output is not None:
    #     print(f"Train output: {args.train_output}")
    # if args.val_output is not None:
    #     print(f"Val output: {args.val_output}")
    # if args.train_parquet_out is not None:
    #     print(f"Train parquet: {args.train_parquet_out}")
    # if args.val_parquet_out is not None:
    #     print(f"Val parquet: {args.val_parquet_out}")


if __name__ == "__main__":
    main()
