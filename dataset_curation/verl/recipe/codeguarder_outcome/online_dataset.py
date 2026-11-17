"""RLHF dataset that injects CodeGuarder retrieval results at sample time."""

from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

import requests

from verl.utils.dataset.rl_dataset import RLHFDataset

from recipe.codeguarder_outcome.build_retrieval_dataset import (
    _augment_row,
    _augment_row_with_security,
    _task_and_messages,
)
from recipe.codeguarder_outcome.retrieval import build_retriever


_RETRIEVER_CACHE: dict[tuple[Any, ...], Any] = {}
_RETRIEVER_CACHE_LOCK = threading.Lock()


class RemoteSecurityKnowledgeRetriever:
    """Small Search-R1-style HTTP client with batch support."""

    def __init__(self, url: str, timeout: float = 120.0) -> None:
        self.url = url.rstrip("/") + "/retrieve" if not url.rstrip("/").endswith("/retrieve") else url
        self.timeout = timeout
        self.session = requests.Session()

    def retrieve_many(self, functionalities: list[str]) -> list[tuple[list[str], list[str]]]:
        response = self.session.post(self.url, json={"queries": functionalities}, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        results = payload.get("result")
        if not isinstance(results, list) or len(results) != len(functionalities):
            raise RuntimeError(f"retrieval server returned {len(results) if isinstance(results, list) else 'invalid'} results")
        return [(list(item.get("security", [])), list(item.get("snippets", []))) for item in results]

    def retrieve(self, functionality: str) -> tuple[list[str], list[str]]:
        return self.retrieve_many([functionality])[0]


class OnlineRetrievalDataset(RLHFDataset):
    """Retrieve security context immediately before a prompt enters rollout."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        retrieval = self.config.get("online_retrieval")
        if retrieval is None:
            raise ValueError("data.online_retrieval must be configured for OnlineRetrievalDataset")

        self.retrieval_server_url = str(retrieval.get("server_url", "")).strip()
        self.security_context_format = str(retrieval.get("security_context_format", "markdown"))
        if not self.retrieval_server_url:
            required = ("security_kb_path", "guidelines_path", "embedding_model_path", "vector_db_path")
            missing = [name for name in required if not retrieval.get(name)]
            if missing:
                raise ValueError(f"missing online retrieval settings: {', '.join(missing)}")
        self.retrieval_settings = {}
        if not self.retrieval_server_url:
            self.retrieval_settings = {
                "security_kb_path": Path(retrieval.security_kb_path),
                "guidelines_path": Path(retrieval.guidelines_path),
                "embedding_model_path": str(retrieval.embedding_model_path),
                "vector_db_path": Path(retrieval.vector_db_path),
                "security_top_k": int(retrieval.get("security_top_k", 3)),
                "guideline_top_k": int(retrieval.get("guideline_top_k", 3)),
                "embedding_device": str(retrieval.get("embedding_device", "cpu")),
                "security_context_format": self.security_context_format,
                "retrieval_cache_size": int(retrieval.get("retrieval_cache_size", 4096)),
            }
        self.retrieval_task_field = str(retrieval.get("task_field", "rewritten_prompt"))
        self.retrieval_server_timeout = float(retrieval.get("server_timeout", 120.0))
        self._retriever = None

    def _get_retriever(self):
        if self._retriever is not None:
            return self._retriever

        cache_key = (self.retrieval_server_url, self.retrieval_server_timeout) if self.retrieval_server_url else tuple(
            (key, str(value)) for key, value in self.retrieval_settings.items()
        )
        with _RETRIEVER_CACHE_LOCK:
            retriever = _RETRIEVER_CACHE.get(cache_key)
            if retriever is None:
                retriever = (
                    RemoteSecurityKnowledgeRetriever(self.retrieval_server_url, self.retrieval_server_timeout)
                    if self.retrieval_server_url
                    else build_retriever(**self.retrieval_settings)
                )
                _RETRIEVER_CACHE[cache_key] = retriever
        self._retriever = retriever
        return retriever

    def __getitem__(self, item):
        row = super().__getitem__(item)
        retrieval_input = dict(row)
        retrieval_input["prompt"] = copy.deepcopy(row["raw_prompt"])
        augmented = _augment_row(
            retrieval_input,
            self._get_retriever(),
            self.retrieval_task_field,
            self.security_context_format,
        )
        row["raw_prompt"] = augmented["prompt"]
        return row

    def __getitems__(self, items):
        """Fetch and retrieve a whole DataLoader batch in one encoder call."""
        base_getitem = super().__getitem__
        rows = [base_getitem(item) for item in items]
        retrieval_inputs = []
        tasks = []
        messages = []
        for row in rows:
            retrieval_input = dict(row)
            retrieval_input["prompt"] = copy.deepcopy(row["raw_prompt"])
            task, row_messages = _task_and_messages(retrieval_input, self.retrieval_task_field)
            retrieval_inputs.append(retrieval_input)
            tasks.append(task)
            messages.append(row_messages)

        retrieved = self._get_retriever().retrieve_many(tasks)
        for row, retrieval_input, task, row_messages, (security, _snippets) in zip(
            rows, retrieval_inputs, tasks, messages, retrieved, strict=True
        ):
            augmented = _augment_row_with_security(
                retrieval_input,
                task,
                row_messages,
                security,
                self.security_context_format,
            )
            row["raw_prompt"] = augmented["prompt"]
        return rows

    def __getstate__(self):
        state = super().__getstate__()
        state["_retriever"] = None
        return state
