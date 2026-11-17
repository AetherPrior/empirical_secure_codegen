"""Per-CWE audit rubrics for JavaScript GRPO Node harnesses."""

from __future__ import annotations

import re
from pathlib import Path

_RUBRICS_DIR = Path(__file__).resolve().parent


def normalize_cwe(cwe: str) -> str:
    cwe = (cwe or "").strip().upper()
    if not cwe.startswith("CWE-"):
        m = re.search(r"(\d+)", cwe)
        if m:
            cwe = f"CWE-{m.group(1)}"
    return cwe


def load_rubric(cwe: str) -> str:
    """Load per-CWE rubric text from ``<number>.txt``."""
    m = re.search(r"(\d+)", normalize_cwe(cwe))
    if not m:
        return ""
    path = _RUBRICS_DIR / f"{m.group(1)}.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return ""
