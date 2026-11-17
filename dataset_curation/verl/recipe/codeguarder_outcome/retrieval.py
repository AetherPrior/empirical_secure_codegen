"""Two-stage retrieval over an annotated security knowledge base.

The implementation is local to this recipe so dataset creation does not rely
on another checkout. It retrieves candidate guidelines first, then retrieves
functionality-matched examples within those guidelines.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def load_security_kb(path: Path) -> list[dict[str, Any]]:
    """Read a JSON array or JSONL security knowledge base."""
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("security KB must be a JSON array or JSONL file")
    return data


def functionality_from_row(row: dict[str, Any]) -> str:
    if isinstance(row.get("functionality"), str) and row["functionality"].strip():
        return row["functionality"]
    extraction = row.get("extraction")
    if isinstance(extraction, dict) and isinstance(extraction.get("functionality"), str):
        return extraction["functionality"]
    raise ValueError("security KB row has no functionality field")


def guideline_id_from_row(row: dict[str, Any]) -> str:
    assignment = row.get("guideline_assignment")
    if isinstance(assignment, dict) and assignment.get("guideline_id"):
        return str(assignment["guideline_id"])
    if row.get("guideline_id"):
        return str(row["guideline_id"])
    raise ValueError("security KB row has no guideline_assignment.guideline_id")


def guideline_catalog(guidelines: dict[str, Any]) -> dict[str, str]:
    return {
        f"{cwe.upper()}#{index}": text
        for cwe, entry in guidelines.items()
        for index, text in enumerate(entry["guidelines"], start=1)
    }


def format_security_context(row: dict[str, Any], output_format: str = "markdown") -> str:
    """Render the security fields exposed to the generator."""
    assignment = row.get("guideline_assignment")
    extraction = row.get("extraction")
    if not isinstance(assignment, dict) or not isinstance(extraction, dict):
        raise ValueError("security KB row lacks guideline_assignment or extraction")
    root_cause = extraction.get("root_cause")
    fixing_pattern = extraction.get("fixing_pattern")
    if not isinstance(root_cause, dict) or not isinstance(fixing_pattern, dict):
        raise ValueError("security KB row lacks root_cause or fixing_pattern")

    cwe = row.get("cwe") or assignment.get("guideline_id", "").split("#", 1)[0]
    guideline = assignment.get("guideline")
    root_description = root_cause.get("description")
    vulnerable_snippet = root_cause.get("vulnerable_code_snippet")
    fixing_description = fixing_pattern.get("description")
    secure_snippet = fixing_pattern.get("secure_code_snippet")
    if not all(isinstance(value, str) and value.strip() for value in (
        cwe, guideline, root_description, vulnerable_snippet, fixing_description, secure_snippet
    )):
        raise ValueError("security KB row has incomplete prompt fields")
    if output_format == "json":
        return json.dumps(
            {
                "cwe": cwe,
                "guideline": guideline,
                "root_cause": {
                    "description": root_description,
                    "vulnerable_code_snippet": vulnerable_snippet,
                },
                "fixing_pattern": {
                    "description": fixing_description,
                    "secure_code_snippet": secure_snippet,
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    if output_format != "markdown":
        raise ValueError(f"unsupported security context format: {output_format}")
    language = row.get("language", "python")
    return f"""CWE: {cwe}
Guideline: {guideline}

Root cause:
{root_description}

Vulnerable code snippet:
```{language}
{vulnerable_snippet}
```

Fixing pattern:
{fixing_description}

Secure code snippet:
```{language}
{secure_snippet}
```"""


def _cache_name(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@contextmanager
def _block_flash_attention_imports():
    """Make Jina's optional CUDA-only imports fail as ordinary ImportErrors."""
    prefix = "flash_attn"
    saved = {name: module for name, module in sys.modules.items() if name == prefix or name.startswith(f"{prefix}.")}
    for name in saved:
        sys.modules.pop(name, None)
    # The remote Jina implementation catches ImportError and uses native Torch
    # paths. flash_attn itself raises RuntimeError when CUDA is unavailable,
    # so masking the package before importing the remote model is required.
    sys.modules[prefix] = None
    try:
        yield
    finally:
        sys.modules.pop(prefix, None)
        sys.modules.update(saved)


def _load_embedding_model(model_path: str, device: str = "auto") -> Any:
    import torch
    from transformers import AutoConfig, AutoModel

    target = "cuda" if device == "auto" and torch.cuda.is_available() else device
    config = AutoConfig.from_pretrained(model_path, trust_remote_code=True)
    if target == "cpu":
        # Jina v3 enables Triton kernels based on CUDA visibility during
        # construction, even when the model is moved to CPU afterwards.
        config.use_flash_attn = False
        config.fused_dropout_add_ln = False
        config.fused_bias_fc = False
    if target == "cpu":
        with _block_flash_attention_imports():
            model = AutoModel.from_pretrained(model_path, config=config, trust_remote_code=True)
    else:
        model = AutoModel.from_pretrained(model_path, config=config, trust_remote_code=True)
    return model.eval().to(torch.device(target))


def _build_vector_database(texts: list[str], contents: list[str], model: Any, batch_size: int = 64) -> Any:
    import torch
    from langchain_community.vectorstores import FAISS

    embeddings = []
    for start in range(0, len(texts), batch_size):
        with torch.no_grad():
            embeddings.extend(model.encode(texts[start : start + batch_size]))
    return FAISS.from_embeddings(list(zip(contents, embeddings)), model.encode)


class SecurityKnowledgeRetriever:
    """Retrieve contexts through a guideline search followed by a functionality search."""

    def __init__(
        self,
        *,
        security_kb_path: Path,
        guidelines_path: Path,
        embedding_model_path: str,
        vector_db_path: Path,
        security_top_k: int = 3,
        guideline_top_k: int = 3,
        embedding_device: str = "auto",
        security_context_format: str = "markdown",
        retrieval_cache_size: int = 4096,
    ) -> None:
        from langchain_community.vectorstores import FAISS

        self.security_top_k = security_top_k
        self.guideline_top_k = guideline_top_k
        self.security_context_format = security_context_format
        self.retrieval_cache_size = max(0, retrieval_cache_size)
        self._retrieval_cache: OrderedDict[str, tuple[tuple[str, ...], tuple[str, ...]]] = OrderedDict()
        self.lock = threading.Lock()
        rows = load_security_kb(security_kb_path)
        catalog = guideline_catalog(json.loads(guidelines_path.read_text(encoding="utf-8")))
        self.model = _load_embedding_model(embedding_model_path, embedding_device)

        guideline_db_path = Path(f"{vector_db_path}.guidelines")
        if guideline_db_path.exists():
            self.guideline_db = FAISS.load_local(
                str(guideline_db_path), self.model.encode, allow_dangerous_deserialization=True
            )
        else:
            guideline_db_path.parent.mkdir(parents=True, exist_ok=True)
            self.guideline_db = _build_vector_database(
                list(catalog.values()),
                [json.dumps({"guideline_id": key, "guideline": value}) for key, value in catalog.items()],
                self.model,
            )
            self.guideline_db.save_local(str(guideline_db_path))

        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            try:
                guideline_id = guideline_id_from_row(row)
                functionality_from_row(row)
            except ValueError:
                continue
            if guideline_id not in catalog:
                raise ValueError(f"KB row references unknown guideline {guideline_id!r}")
            grouped.setdefault(guideline_id, []).append(row)
        if not grouped:
            raise ValueError("security KB has no complete guideline-annotated functionality rows")

        self.functionality_dbs: dict[str, Any] = {}
        functionality_root = Path(f"{vector_db_path}.functionality")
        for guideline_id, grouped_rows in grouped.items():
            db_path = functionality_root / _cache_name(guideline_id)
            if db_path.exists():
                database = FAISS.load_local(str(db_path), self.model.encode, allow_dangerous_deserialization=True)
            else:
                database = _build_vector_database(
                    [functionality_from_row(row) for row in grouped_rows],
                    [json.dumps(row) for row in grouped_rows],
                    self.model,
                )
                db_path.parent.mkdir(parents=True, exist_ok=True)
                database.save_local(str(db_path))
            self.functionality_dbs[guideline_id] = database

    def retrieve(self, functionality: str) -> tuple[list[str], list[str]]:
        """Return retrieved security contexts; no reference code is injected."""
        return self.retrieve_many([functionality])[0]

    def _retrieve_with_embedding(self, query_embedding: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Search both FAISS stages using an already-computed query embedding."""
        guideline_docs = self.guideline_db.similarity_search_by_vector(
            query_embedding, k=min(self.guideline_top_k, len(self.functionality_dbs))
        )
        selected = [
            json.loads(document.page_content)["guideline_id"]
            for document in guideline_docs
            if json.loads(document.page_content)["guideline_id"] in self.functionality_dbs
        ]
        scored = []
        for guideline_id in selected:
            scored.extend(
                self.functionality_dbs[guideline_id].similarity_search_with_score_by_vector(
                    query_embedding, k=self.security_top_k
                )
            )
        scored.sort(key=lambda item: item[1])
        security = []
        for document, _ in scored[: self.security_top_k]:
            try:
                security.append(format_security_context(json.loads(document.page_content), self.security_context_format))
            except (json.JSONDecodeError, ValueError):
                continue
        return tuple(security), ()

    def retrieve_many(self, functionalities: list[str]) -> list[tuple[list[str], list[str]]]:
        """Retrieve a batch, encoding all cache misses in one model forward pass."""
        if not functionalities:
            return []
        with self.lock:
            missing = list(dict.fromkeys(query for query in functionalities if query not in self._retrieval_cache))
            if missing:
                # This is the main server-side speedup: a training batch becomes
                # one encoder forward pass rather than one pass per sample.
                embeddings = self.model.encode(missing)
                for query, embedding in zip(missing, embeddings, strict=True):
                    self._retrieval_cache[query] = self._retrieve_with_embedding(embedding)
                    self._retrieval_cache.move_to_end(query)

            results = []
            for functionality in functionalities:
                result = self._retrieval_cache[functionality]
                self._retrieval_cache.move_to_end(functionality)
                results.append((list(result[0]), list(result[1])))

            if self.retrieval_cache_size:
                while len(self._retrieval_cache) > self.retrieval_cache_size:
                    self._retrieval_cache.popitem(last=False)
            else:
                self._retrieval_cache.clear()
        return results


def build_retriever(
    *,
    security_kb_path: Path,
    guidelines_path: Path,
    embedding_model_path: str,
    vector_db_path: Path,
    security_top_k: int,
    guideline_top_k: int,
    embedding_device: str,
    security_context_format: str,
    retrieval_cache_size: int = 4096,
) -> SecurityKnowledgeRetriever:
    """Build this recipe's local security-KB retriever."""
    return SecurityKnowledgeRetriever(
        security_kb_path=security_kb_path,
        guidelines_path=guidelines_path,
        embedding_model_path=embedding_model_path,
        vector_db_path=vector_db_path,
        security_top_k=security_top_k,
        guideline_top_k=guideline_top_k,
        embedding_device=embedding_device,
        security_context_format=security_context_format,
        retrieval_cache_size=retrieval_cache_size,
    )
