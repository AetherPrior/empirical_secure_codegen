"""Small helpers for CWEval-style pytest harness execution (self-contained in verl)."""

from __future__ import annotations

import re
from typing import List

_C_CODE_BLOCK_RE = re.compile(
    r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```",
    re.DOTALL | re.IGNORECASE,
)

_HARNESS_IMPORT_LINE_RE = re.compile(r"^\s*from\s+\.?test_\w+\s+import\b")


def extract_c_source_from_markdown(raw: str) -> str:
    """Best-effort extraction of C/C++ source from markdown fenced blocks."""
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    matches = [m.strip() for m in _C_CODE_BLOCK_RE.findall(text) if isinstance(m, str) and m.strip()]
    if not matches:
        return text
    for m in _C_CODE_BLOCK_RE.finditer(text):
        fence = m.group(0).splitlines()[0].lower()
        body = m.group(1).strip()
        if "```c" in fence or "cpp" in fence or "cc" in fence:
            return body
    return matches[-1]


def strip_redundant_harness_imports(test_code: str) -> str:
    """Remove ``from test_*`` lines before merging setup_tests + test_code."""
    if not test_code:
        return ""
    lines = test_code.splitlines(keepends=False)
    out_lines: List[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if _HARNESS_IMPORT_LINE_RE.match(line):
            rest = line.split("import", 1)[1] if "import" in line else ""
            depth = rest.count("(") - rest.count(")")
            i += 1
            while i < len(lines) and depth > 0:
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        out_lines.append(line)
        i += 1
    text = "\n".join(out_lines)
    if test_code.endswith("\n"):
        text += "\n"
    return text


def merge_cw_eval_pytest_single_file(setup_tests: str, test_code: str) -> str:
    """Concatenate setup + tests for a single pytest module (flat namespace)."""
    setup = (setup_tests or "").rstrip()
    code = strip_redundant_harness_imports(test_code or "").strip()
    if not code:
        raise ValueError("test_code is empty")
    if setup:
        return setup + "\n\n" + code + "\n"
    return code + "\n"
