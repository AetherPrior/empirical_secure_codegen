"""Helpers for validating JS GRPO test JSON during rewrite audits."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_JS_GEN = Path(__file__).resolve().parents[2] / "simple_gen" / "js"
if str(_JS_GEN) not in sys.path:
    sys.path.insert(0, str(_JS_GEN))

from js_utils import (  # noqa: E402
    extract_param_names,
    parse_and_validate_tests_json,
    validate_tests_json,
)


def format_tests_json(raw: str | dict[str, Any]) -> str:
    """Pretty-print tests JSON for CSV readability."""
    if isinstance(raw, dict):
        obj = raw
    else:
        text = (raw or "").strip()
        if not text:
            return ""
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return text
    return json.dumps(obj, ensure_ascii=False, indent=2)


def validate_rewritten_tests(
    test_code: str,
    *,
    arguments: Any = None,
) -> dict[str, Any]:
    """Parse + validate rewritten test_code; raise ValueError on failure."""
    param_names = None
    if arguments is not None:
        try:
            param_names = extract_param_names({"arguments": arguments})
        except Exception:
            param_names = None
    return parse_and_validate_tests_json(test_code, param_names=param_names or None)


__all__ = [
    "format_tests_json",
    "validate_rewritten_tests",
    "validate_tests_json",
    "parse_and_validate_tests_json",
]
