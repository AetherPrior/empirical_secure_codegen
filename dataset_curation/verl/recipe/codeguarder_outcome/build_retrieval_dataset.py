"""Augment simple_gen/GRPO JSONL prompts using local security-KB retrieval."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from recipe.codeguarder_outcome.retrieval import build_retriever
except ImportError:
    from retrieval import build_retriever


def format_codeguarder_prompt(
    task: str, security: list[str], security_context_format: str = "markdown"
) -> str:
    """Use the same security-only prompt structure as SecCodePLT integration."""
    if security_context_format == "markdown":
        knowledge = "\n".join(context for context in security if context.strip())
    elif security_context_format == "json":
        knowledge = json.dumps(
            {"security_knowledge": [json.loads(context) for context in security]},
            ensure_ascii=False,
            indent=2,
        )
    else:
        raise ValueError(f"unsupported security context format: {security_context_format}")
    return (
        "Your task is to generate secure code for the following functionality. "
        "Before writing the code, review the security knowledge below and use "
        "it to avoid common security flaws.\n\n"
        f"### Security Knowledge:\n{knowledge}\n---\n\n"
        f"### Task:\n{task}\n\n"
        "Use the security knowledge when it is relevant, while preserving all "
        "functional requirements and the requested output format."
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _task_and_messages(row: dict[str, Any], task_field: str) -> tuple[str, list[dict[str, str]]]:
    explicit = row.get(task_field)
    if isinstance(explicit, str) and explicit.strip():
        task = explicit.strip()
    else:
        prompt = row.get("prompt")
        if isinstance(prompt, str) and prompt.strip():
            task = prompt.strip()
        elif isinstance(prompt, list):
            user_messages = [
                item.get("content", "") for item in prompt
                if isinstance(item, dict) and item.get("role", "user") == "user"
            ]
            task = str(user_messages[-1]).strip() if user_messages else ""
        else:
            task = ""
    if not task:
        raise ValueError(f"row has no task text in {task_field!r} or prompt")

    original = row.get("prompt")
    messages = [dict(message) for message in original if isinstance(message, dict)] if isinstance(original, list) else []
    return task, messages


def _augment_row(
    row: dict[str, Any], retriever: Any, task_field: str, security_context_format: str = "markdown"
) -> dict[str, Any]:
    task, messages = _task_and_messages(row, task_field)
    security, _snippets = retriever.retrieve(task)
    return _augment_row_with_security(row, task, messages, security, security_context_format)


def _augment_row_with_security(
    row: dict[str, Any],
    task: str,
    messages: list[dict[str, str]],
    security: list[str],
    security_context_format: str = "markdown",
) -> dict[str, Any]:
    """Inject already-retrieved contexts, used by batched online retrieval."""
    prompt = format_codeguarder_prompt(task, security, security_context_format)
    augmented = dict(row)
    if messages:
        # Retain system/developer instructions; replace the final user task.
        last_user = max(
            (index for index, message in enumerate(messages) if message.get("role", "user") == "user"),
            default=-1,
        )
        if last_user >= 0:
            messages[last_user] = {"role": "user", "content": prompt}
        else:
            messages.append({"role": "user", "content": prompt})
        augmented["prompt"] = messages
    else:
        augmented["prompt"] = [{"role": "user", "content": prompt}]
    return augmented


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--security-kb", type=Path, required=True)
    parser.add_argument("--guidelines", type=Path, required=True)
    parser.add_argument("--embedding-model", default="jinaai/jina-embeddings-v3")
    parser.add_argument("--vector-db", type=Path, required=True)
    parser.add_argument("--security-top-k", type=int, default=3)
    parser.add_argument("--guideline-top-k", type=int, default=3)
    parser.add_argument("--embedding-device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--security-context-format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--task-field", default="rewritten_prompt")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.security_top_k < 1 or args.guideline_top_k < 1:
        raise ValueError("--security-top-k and --guideline-top-k must be positive")
    retriever = build_retriever(
        security_kb_path=args.security_kb,
        guidelines_path=args.guidelines,
        embedding_model_path=args.embedding_model,
        vector_db_path=args.vector_db,
        security_top_k=args.security_top_k,
        guideline_top_k=args.guideline_top_k,
        embedding_device=args.embedding_device,
        security_context_format=args.security_context_format,
    )
    if args.input.suffix.lower() == ".parquet":
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as exc:
            raise RuntimeError("pyarrow is required to augment Parquet datasets") from exc
        table = pq.read_table(args.input)
        rows = [
            _augment_row(row, retriever, args.task_field, args.security_context_format)
            for row in table.to_pylist()
        ]
        prompt_index = table.schema.get_field_index("prompt")
        if prompt_index < 0:
            raise ValueError("Parquet input has no prompt column")
        prompts = pa.array(
            [row["prompt"] for row in rows],
            type=table.schema.field("prompt").type,
        )
        output_table = table.set_column(prompt_index, "prompt", prompts)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(output_table, args.output, compression="zstd")
    elif args.input.suffix.lower() in {".json", ".jsonl"}:
        rows = [
            _augment_row(row, retriever, args.task_field, args.security_context_format)
            for row in _read_jsonl(args.input)
        ]
        _write_jsonl(args.output, rows)
    else:
        raise ValueError("--input must be JSONL, JSON, or Parquet")
    print(f"Wrote {len(rows)} retrieval-augmented rows to {args.output}")


if __name__ == "__main__":
    main()
