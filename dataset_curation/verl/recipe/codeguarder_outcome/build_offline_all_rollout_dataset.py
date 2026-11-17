"""Build identity-excluding offline retrieval prompts for every rollout."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from recipe.codeguarder_outcome.build_offline_single_rollout_dataset import (
    IdentityExcludingOfflineRetriever,
    _row_identity,
)
from recipe.codeguarder_outcome.build_retrieval_dataset import (
    _augment_row_with_security,
    _task_and_messages,
)
from recipe.codeguarder_outcome.retrieval import build_retriever


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
    parser.add_argument("--embedding-device", choices=("auto", "cpu", "cuda"), default="cpu")
    parser.add_argument("--security-context-format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--task-field", default="rewritten_prompt")
    parser.add_argument("--embedding-batch-size", type=int, default=64)
    parser.add_argument("--exclusion-overfetch", type=int, default=32)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.input.suffix.lower() != ".parquet" or args.output.suffix.lower() != ".parquet":
        raise ValueError("offline all-rollout datasets must use Parquet input and output")
    if args.security_top_k < 1 or args.guideline_top_k < 1:
        raise ValueError("retrieval top-k values must be positive")

    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pq.read_table(args.input)
    if "base_prompt" in table.column_names:
        raise ValueError("input already has a base_prompt column")
    rows = table.to_pylist()
    tasks_and_messages = [_task_and_messages(row, args.task_field) for row in rows]
    tasks = [item[0] for item in tasks_and_messages]
    identities = [_row_identity(row, task) for row, task in zip(rows, tasks, strict=True)]

    retriever = IdentityExcludingOfflineRetriever(
        build_retriever(
            security_kb_path=args.security_kb,
            guidelines_path=args.guidelines,
            embedding_model_path=args.embedding_model,
            vector_db_path=args.vector_db,
            security_top_k=args.security_top_k,
            guideline_top_k=args.guideline_top_k,
            embedding_device=args.embedding_device,
            security_context_format=args.security_context_format,
            retrieval_cache_size=0,
        ),
        args.exclusion_overfetch,
    )
    retrieved = retriever.retrieve_many(tasks, identities, args.embedding_batch_size)

    prompts = []
    metadata = []
    for row, (task, messages), identity, (security, provenance) in zip(
        rows, tasks_and_messages, identities, retrieved, strict=True
    ):
        prompts.append(
            _augment_row_with_security(
                row, task, messages, security, args.security_context_format
            )["prompt"]
        )
        metadata.append(json.dumps(
            {"excluded": identity, "retrieved": provenance},
            ensure_ascii=False,
            separators=(",", ":"),
        ))

    prompt_index = table.schema.get_field_index("prompt")
    prompt_type = table.schema.field(prompt_index).type
    output = table.append_column("base_prompt", table.column(prompt_index))
    output = output.set_column(prompt_index, "prompt", pa.array(prompts, type=prompt_type))
    output = output.append_column("offline_retrieval_metadata", pa.array(metadata, type=pa.string()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(output, args.output, compression="zstd")
    print(f"Wrote {len(rows)} all-rollout retrieval rows to {args.output}")


if __name__ == "__main__":
    main()
