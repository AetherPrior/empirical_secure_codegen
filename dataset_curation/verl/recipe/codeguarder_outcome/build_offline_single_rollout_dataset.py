"""Build prompts with offline, identity-excluding security-KB retrieval.

The original ``prompt`` column is preserved.  The augmented prompt is written
to ``retrieval_prompt`` so a rollout-time manager can expose it to exactly one
completion in each GRPO group.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from recipe.codeguarder_outcome.build_retrieval_dataset import (
    _augment_row_with_security,
    _task_and_messages,
)
from recipe.codeguarder_outcome.retrieval import build_retriever, format_security_context


def _normalized_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _row_identity(row: dict[str, Any], task: str) -> dict[str, Any]:
    extra = row.get("extra_info") if isinstance(row.get("extra_info"), dict) else {}
    reward_model = row.get("reward_model") if isinstance(row.get("reward_model"), dict) else {}
    ground_truth = reward_model.get("ground_truth") if isinstance(reward_model.get("ground_truth"), dict) else {}
    source_index = extra.get("index", row.get("source_index"))
    task_id = extra.get("task_id", row.get("task_id"))
    source_prompt = extra.get("user_prompt") or ground_truth.get("prompt") or task
    return {
        "source_index": source_index,
        "task_id": str(task_id) if task_id is not None else None,
        "prompt": _normalized_text(source_prompt),
    }


class IdentityExcludingOfflineRetriever:
    """Batch retriever that rejects the source task before selecting top-k."""

    def __init__(self, retriever: Any, overfetch: int = 32) -> None:
        self.retriever = retriever
        self.overfetch = max(1, overfetch)

    @staticmethod
    def _same_source(kb_row: dict[str, Any], identity: dict[str, Any]) -> bool:
        source_index = identity.get("source_index")
        if source_index is not None and str(kb_row.get("source_index")) == str(source_index):
            return True
        task_id = identity.get("task_id")
        if task_id and str(kb_row.get("task_id")) == task_id:
            return True
        source_prompt = identity.get("prompt")
        return bool(source_prompt and _normalized_text(kb_row.get("prompt")) == source_prompt)

    def _search_one(
        self, embedding: Any, identity: dict[str, Any]
    ) -> tuple[list[str], list[dict[str, Any]]]:
        guideline_docs = self.retriever.guideline_db.similarity_search_by_vector(
            embedding,
            k=min(self.retriever.guideline_top_k, len(self.retriever.functionality_dbs)),
        )
        guideline_ids = []
        for document in guideline_docs:
            guideline_id = json.loads(document.page_content).get("guideline_id")
            if guideline_id in self.retriever.functionality_dbs:
                guideline_ids.append(guideline_id)

        candidates = []
        fetch_k = self.retriever.security_top_k + self.overfetch
        for guideline_id in guideline_ids:
            candidates.extend(
                self.retriever.functionality_dbs[guideline_id].similarity_search_with_score_by_vector(
                    embedding, k=fetch_k
                )
            )
        candidates.sort(key=lambda item: item[1])

        contexts: list[str] = []
        provenance: list[dict[str, Any]] = []
        for document, score in candidates:
            try:
                kb_row = json.loads(document.page_content)
                if self._same_source(kb_row, identity):
                    continue
                context = format_security_context(kb_row, self.retriever.security_context_format)
            except (json.JSONDecodeError, ValueError):
                continue
            contexts.append(context)
            provenance.append(
                {
                    "task_id": kb_row.get("task_id"),
                    "source_index": kb_row.get("source_index"),
                    "attempt_key": kb_row.get("attempt_key"),
                    "score": float(score),
                }
            )
            if len(contexts) >= self.retriever.security_top_k:
                break
        return contexts, provenance

    def retrieve_many(
        self,
        tasks: list[str],
        identities: list[dict[str, Any]],
        batch_size: int = 64,
    ) -> list[tuple[list[str], list[dict[str, Any]]]]:
        if len(tasks) != len(identities):
            raise ValueError("tasks and identities must have equal lengths")
        # GRPO datasets repeat source prompts. Embeddings depend only on task
        # text, while source exclusion is enforced below per row, so encode each
        # distinct task once and reuse that vector for every duplicate.
        unique_tasks = list(dict.fromkeys(tasks))
        embeddings_by_task: dict[str, Any] = {}
        for start in range(0, len(unique_tasks), batch_size):
            task_batch = unique_tasks[start : start + batch_size]
            embeddings = self.retriever.model.encode(task_batch)
            embeddings_by_task.update(zip(task_batch, embeddings, strict=True))

        return [
            self._search_one(embeddings_by_task[task], identity)
            for task, identity in zip(tasks, identities, strict=True)
        ]


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
        raise ValueError("offline single-rollout datasets must use Parquet input and output")

    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pq.read_table(args.input)
    rows = table.to_pylist()
    tasks_and_messages = [_task_and_messages(row, args.task_field) for row in rows]
    tasks = [item[0] for item in tasks_and_messages]
    identities = [_row_identity(row, task) for row, task in zip(rows, tasks, strict=True)]

    base_retriever = build_retriever(
        security_kb_path=args.security_kb,
        guidelines_path=args.guidelines,
        embedding_model_path=args.embedding_model,
        vector_db_path=args.vector_db,
        security_top_k=args.security_top_k,
        guideline_top_k=args.guideline_top_k,
        embedding_device=args.embedding_device,
        security_context_format=args.security_context_format,
        retrieval_cache_size=0,
    )
    retriever = IdentityExcludingOfflineRetriever(base_retriever, args.exclusion_overfetch)
    retrieved = retriever.retrieve_many(tasks, identities, args.embedding_batch_size)

    retrieval_prompts = []
    metadata = []
    for row, (task, messages), identity, (security, provenance) in zip(
        rows, tasks_and_messages, identities, retrieved, strict=True
    ):
        augmented = _augment_row_with_security(
            row, task, messages, security, args.security_context_format
        )
        retrieval_prompts.append(augmented["prompt"])
        metadata.append(
            json.dumps(
                {"excluded": identity, "retrieved": provenance},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )

    prompt_type = table.schema.field("prompt").type
    output = table.append_column("retrieval_prompt", pa.array(retrieval_prompts, type=prompt_type))
    output = output.append_column("offline_retrieval_metadata", pa.array(metadata, type=pa.string()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(output, args.output, compression="zstd")
    print(f"Wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
