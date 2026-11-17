"""Utilities for simple_gen JavaScript rows."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)
JS_CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)


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


def extract_js_source_from_markdown(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    matches = list(JS_CODE_BLOCK_RE.finditer(text))
    if not matches:
        return text
    for match in matches:
        fence = match.group(0).splitlines()[0].lower()
        body = match.group(1).strip()
        if any(tag in fence for tag in ("javascript", "js", "node")):
            return body
    return matches[-1].group(1).strip()


def extract_first_json_object(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty output")
    if text.startswith("{") and text.endswith("}"):
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    match = JSON_BLOCK_RE.search(text)
    if match:
        obj = json.loads(match.group(1))
        if isinstance(obj, dict):
            return obj
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        obj = json.loads(text[start : end + 1])
        if isinstance(obj, dict):
            return obj
    raise ValueError("could not find a JSON object in output")


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


def validate_tests_json(obj: Dict[str, Any], *, param_names: Optional[List[str]] = None) -> Dict[str, Any]:
    tests = obj.get("tests")
    if not isinstance(tests, dict):
        raise ValueError("missing object field: tests")
    expected = set(param_names or [])
    for section in ("functionality", "security"):
        cases = tests.get(section)
        if not isinstance(cases, list) or len(cases) < 2:
            raise ValueError(f"tests.{section} must be a list with >= 2 items")
        for idx, case in enumerate(cases):
            if not isinstance(case, dict):
                raise ValueError(f"tests.{section}[{idx}] must be an object")
            if "input" not in case or "output" not in case:
                raise ValueError(f"tests.{section}[{idx}] must contain input and output")
            if not isinstance(case["input"], dict):
                raise ValueError(f"tests.{section}[{idx}].input must be an object")
            if param_names is not None:
                keys = set(case["input"].keys())
                if keys != expected:
                    raise ValueError(
                        f"tests.{section}[{idx}].input keys {sorted(keys)} must equal {sorted(expected)}"
                    )
    return obj


def parse_and_validate_tests_json(raw: str, *, param_names: Optional[List[str]] = None) -> Dict[str, Any]:
    return validate_tests_json(extract_first_json_object(raw), param_names=param_names)


def tests_json_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    testcases = row.get("testcases")
    if isinstance(testcases, dict):
        if "tests" in testcases:
            return validate_tests_json(testcases)
        return validate_tests_json({"tests": testcases})

    tests_json = row.get("tests_json")
    if isinstance(tests_json, dict):
        return validate_tests_json(tests_json if "tests" in tests_json else {"tests": tests_json})

    test_code = row.get("test_code")
    if isinstance(test_code, str) and test_code.strip():
        return parse_and_validate_tests_json(test_code)

    raise ValueError("missing JS tests_json/test_code")


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
