"""Assign missing KB guideline IDs locally with the retrieval embedding model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from recipe.codeguarder_outcome.retrieval import (
    _load_embedding_model,
    functionality_from_row,
    guideline_catalog,
    load_security_kb,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--guidelines", type=Path, required=True)
    parser.add_argument("--embedding-model", default="jinaai/jina-embeddings-v3")
    parser.add_argument("--embedding-device", choices=("auto", "cpu", "cuda"), default="cpu")
    parser.add_argument("--batch-size", type=int, default=64)
    return parser.parse_args()


def _assignment_text(row: dict[str, Any]) -> str:
    extraction = row.get("extraction") if isinstance(row.get("extraction"), dict) else {}
    root = extraction.get("root_cause") if isinstance(extraction.get("root_cause"), dict) else {}
    fix = extraction.get("fixing_pattern") if isinstance(extraction.get("fixing_pattern"), dict) else {}
    return "\n".join(
        value for value in (
            functionality_from_row(row),
            root.get("description"),
            fix.get("description"),
        ) if isinstance(value, str) and value.strip()
    )


def _normalized(values: Any) -> np.ndarray:
    matrix = np.asarray(values, dtype=np.float32)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return matrix / np.maximum(norms, 1e-12)


def _is_complete(row: dict[str, Any]) -> bool:
    try:
        _assignment_text(row)
    except ValueError:
        return False
    extraction = row.get("extraction")
    return isinstance(extraction, dict)


def main() -> None:
    args = parse_args()
    rows = load_security_kb(args.input)
    guideline_data = json.loads(args.guidelines.read_text(encoding="utf-8"))
    catalog = guideline_catalog(guideline_data)
    model = _load_embedding_model(args.embedding_model, args.embedding_device)

    guideline_ids = list(catalog)
    guideline_vectors = _normalized(model.encode([catalog[key] for key in guideline_ids]))
    candidates_by_cwe = {
        cwe.upper(): [index for index, key in enumerate(guideline_ids) if key.startswith(f"{cwe.upper()}#")]
        for cwe in guideline_data
    }

    pending = [
        index for index, row in enumerate(rows)
        if _is_complete(row) and not isinstance(row.get("guideline_assignment"), dict)
    ]
    for start in range(0, len(pending), args.batch_size):
        batch_indices = pending[start : start + args.batch_size]
        batch_vectors = _normalized(model.encode([_assignment_text(rows[index]) for index in batch_indices]))
        for row_index, vector in zip(batch_indices, batch_vectors, strict=True):
            row = rows[row_index]
            cwe = str(row.get("cwe", "")).upper()
            candidate_indices = candidates_by_cwe.get(cwe, [])
            if not candidate_indices:
                raise ValueError(f"no guidelines found for row CWE {cwe!r}")
            best = max(candidate_indices, key=lambda index: float(vector @ guideline_vectors[index]))
            guideline_id = guideline_ids[best]
            row["guideline_assignment"] = {
                "guideline_id": guideline_id,
                "guideline": catalog[guideline_id],
                "assignment_method": "jina_embedding_cosine",
            }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    temporary.replace(args.output)
    skipped = sum(not _is_complete(row) for row in rows)
    print(
        f"Wrote {len(rows)} rows ({len(pending)} locally assigned, "
        f"{skipped} incomplete rows retained but not assigned) to {args.output}"
    )


if __name__ == "__main__":
    main()
