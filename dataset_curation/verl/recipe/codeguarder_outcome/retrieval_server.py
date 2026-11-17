"""Search-R1-style HTTP server for batched CodeGuarder security retrieval."""

from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from recipe.codeguarder_outcome.retrieval import build_retriever


class QueryRequest(BaseModel):
    queries: list[str]


app = FastAPI()
retriever = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ready" if retriever is not None else "loading"}


@app.post("/retrieve")
def retrieve(request: QueryRequest) -> dict:
    if retriever is None:
        raise RuntimeError("retriever is not initialized")
    results = retriever.retrieve_many(request.queries)
    return {
        "result": [
            {"security": security, "snippets": snippets}
            for security, snippets in results
        ]
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--security-kb", type=Path, required=True)
    parser.add_argument("--guidelines", type=Path, required=True)
    parser.add_argument("--embedding-model", default="jinaai/jina-embeddings-v3")
    parser.add_argument("--vector-db", type=Path, required=True)
    parser.add_argument("--security-top-k", type=int, default=3)
    parser.add_argument("--guideline-top-k", type=int, default=3)
    parser.add_argument("--embedding-device", choices=("auto", "cpu", "cuda"), default="cpu")
    parser.add_argument("--security-context-format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--cache-size", type=int, default=4096)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser.parse_args()


def main() -> None:
    global retriever
    args = parse_args()
    retriever = build_retriever(
        security_kb_path=args.security_kb,
        guidelines_path=args.guidelines,
        embedding_model_path=args.embedding_model,
        vector_db_path=args.vector_db,
        security_top_k=args.security_top_k,
        guideline_top_k=args.guideline_top_k,
        embedding_device=args.embedding_device,
        security_context_format=args.security_context_format,
        retrieval_cache_size=args.cache_size,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
