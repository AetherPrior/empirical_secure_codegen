"""Utilities for simple_gen Go rows."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GO_CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)

PYTEST_MD_BLOCK_RE = re.compile(
    r"##\s*test setup\s*```python(.*?)```.*?##\s*pytest tests\s*```python(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def extract_go_source_from_markdown(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    matches = list(GO_CODE_BLOCK_RE.finditer(text))
    if not matches:
        return text
    for match in matches:
        fence = match.group(0).splitlines()[0].lower()
        body = match.group(1).strip()
        if any(tag in fence for tag in ("golang", "go")):
            return body
    return matches[-1].group(1).strip()


def extract_param_names(row: Dict[str, Any]) -> List[str]:
    args = row.get("arguments") or []
    if not isinstance(args, list):
        return []
    out: List[str] = []
    for arg in args:
        if not isinstance(arg, dict):
            continue
        name = arg.get("name")
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    return out


def prompt_to_text(prompt: Any) -> str:
    if prompt is None:
        return ""
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, list):
        parts: List[str] = []
        for item in prompt:
            if isinstance(item, dict):
                content = item.get("content", "")
                if isinstance(content, str) and content.strip():
                    parts.append(content.strip())
            elif isinstance(item, str) and item.strip():
                parts.append(item.strip())
        return "\n\n".join(parts)
    return str(prompt)


def harness_fully_passes(summary_ok: bool, ut_result: Dict[str, Any]) -> bool:
    if not summary_ok:
        return False
    fp, ft = ut_result.get("functionality", (0, 0))
    sp, st = ut_result.get("security", (0, 0))
    try:
        return int(ft) > 0 and int(st) > 0 and int(fp) == int(ft) and float(sp) + 1e-6 >= float(st)
    except (TypeError, ValueError):
        return False


def extract_pytest_blocks(raw: str) -> Tuple[str, str]:
    m = PYTEST_MD_BLOCK_RE.search(raw)
    if not m:
        raise ValueError("missing required markdown sections (test setup / pytest tests)")
    return m.group(1).strip(), m.group(2).strip()


def validate_pytest_source(setup_py: str, pytest_py: str) -> None:
    """Lightweight static validation for CWEval-style pytest modules."""
    setup_py = setup_py or ""
    pytest_py = pytest_py or ""
    try:
        ast.parse(setup_py)
        mod = ast.parse(pytest_py)
    except SyntaxError as e:
        raise ValueError(f"invalid python syntax: {e}") from e

    src = f"{setup_py}\n{pytest_py}"
    if "import pytest" not in src and "from pytest" not in src:
        raise ValueError("pytest tests must import pytest")
    if "import subprocess" not in src and "from subprocess" not in src:
        raise ValueError("pytest tests must import subprocess (CWEval-style native execution)")

    if pytest_py.count("pytest.mark.functionality") < 2:
        raise ValueError("need at least 2 @pytest.mark.functionality cases")
    if pytest_py.count("pytest.mark.security") < 2:
        raise ValueError("need at least 2 @pytest.mark.security cases")

    has_test = any(isinstance(n, ast.FunctionDef) and n.name.startswith("test_") for n in mod.body)
    if not has_test:
        raise ValueError("pytest tests must define at least one function named test_*")


def parse_and_validate_pytest(raw: str) -> Dict[str, str]:
    setup, tests = extract_pytest_blocks(raw)
    validate_pytest_source(setup, tests)
    return {"test_setup": setup, "pytest_code": tests}
