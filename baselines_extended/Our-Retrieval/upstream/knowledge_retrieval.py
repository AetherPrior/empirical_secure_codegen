"""Retrieval helpers for the VeriSec-Retrieval baseline: KB loading, record rendering, and the FAISS builder.

Adapted from the knowledge retrieval module of our experiments; only the parts the baseline uses are kept.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_security_kb(path: Path) -> list[dict[str, Any]]:
    """Read either a JSON array or the JSONL emitted by ``extract.py``."""
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



def format_security_context(row: dict[str, Any], output_format: str = "markdown", *,
                            allow_empty_snippets: bool = False) -> str:
    """Render one retrieved record for the generation prompt.

    The prompt receives the CWE, the CWE-level guideline (``retrieval_key``, from
    dataset/retrieval_keys.json, attached to the row by the caller), and the root
    cause and fixing pattern with their paired security-focused program slices.
    """
    extraction = row.get("extraction")
    if not isinstance(extraction, dict):
        raise ValueError("security KB row lacks extraction")
    root_cause = extraction.get("root_cause")
    fixing_pattern = extraction.get("fixing_pattern")
    if not isinstance(root_cause, dict) or not isinstance(fixing_pattern, dict):
        raise ValueError("security KB row lacks root_cause or fixing_pattern")

    cwe = row.get("cwe")
    guideline = row.get("retrieval_key")
    root_description = root_cause.get("description")
    vulnerable_snippet = root_cause.get("vulnerable_code_snippet")
    fixing_description = fixing_pattern.get("description")
    secure_snippet = fixing_pattern.get("secure_code_snippet")
    if not all(isinstance(value, str) and value.strip() for value in (
        cwe, guideline, root_description, fixing_description
    )):
        raise ValueError("security KB row has incomplete prompt fields")
    if not all(isinstance(value, str) and (allow_empty_snippets or value.strip())
               for value in (vulnerable_snippet, secure_snippet)):
        raise ValueError("security KB row has incomplete prompt snippets")
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



def _build_vector_database(texts: list[str], contents: list[str], model: Any, batch_size: int = 64) -> Any:
    import torch
    from langchain_community.vectorstores import FAISS

    embeddings = []
    for start in range(0, len(texts), batch_size):
        with torch.no_grad():
            embeddings.extend(model.encode(texts[start : start + batch_size]))
    return FAISS.from_embeddings(list(zip(contents, embeddings)), model.encode)



def canonical_language(value: object) -> str | None:
    """Map benchmark and KB language labels to the four KB identifiers."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("_", "").replace("-", "")
    aliases = {
        "py": "python", "python": "python", "python3": "python",
        "c": "c",
        "cpp": "cpp", "c++": "cpp", "cxx": "cpp", "cplusplus": "cpp",
        "js": "javascript", "javascript": "javascript", "node": "javascript",
        "nodejs": "javascript", "node.js": "javascript",
    }
    return aliases.get(normalized)



def row_language(row: dict[str, Any]) -> str | None:
    """Return a row's language; unlabelled legacy rows are Python-only."""
    if "language" not in row or row.get("language") in (None, ""):
        return "python"
    return canonical_language(row.get("language"))
