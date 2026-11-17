import ast
import contextlib
import io
import json
import multiprocessing as mp
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


MD_BLOCK_RE = re.compile(
    r"##\s*test setup\s*```python(.*?)```.*?##\s*tests\s*```python(.*?)```",
    re.DOTALL | re.IGNORECASE,
)

# C/C++ pipeline: tests are JSON (no exec, no Python AST).
# We keep the Python helpers above for legacy compatibility, but the `cpp/` scripts
# should prefer the JSON helpers below.
JSON_BLOCK_RE = re.compile(
    r"```(?:json)?\s*(\{[\s\S]*?\})\s*```",
    re.IGNORECASE,
)

_CPP_CODE_BLOCK_RE = re.compile(
    r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def extract_cpp_source_from_markdown(raw: str) -> str:
    """Best-effort extraction of C/C++ from markdown fences."""
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    matches = [m.strip() for m in _CPP_CODE_BLOCK_RE.findall(text) if isinstance(m, str) and m.strip()]
    if not matches:
        return text
    for m in _CPP_CODE_BLOCK_RE.finditer(text):
        fence = m.group(0).splitlines()[0].lower()
        body = m.group(1).strip()
        if "cpp" in fence or "c++" in fence or "```c" in fence or "cc" in fence:
            return body
    return matches[-1]

def extract_blocks(raw: str):
    m = MD_BLOCK_RE.search(raw)
    if not m:
        raise ValueError("missing required markdown sections")

    return m.group(1).strip(), m.group(2).strip()


def _extract_first_json_object(raw: str) -> Dict[str, Any]:
    """Extract and parse a JSON object from raw model output.

    Accepts either:
    - a bare JSON object
    - a fenced ```json ... ``` block containing a JSON object
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty output")

    # Fast path: raw itself is JSON.
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

    m = JSON_BLOCK_RE.search(text)
    if m:
        obj = json.loads(m.group(1))
        if not isinstance(obj, dict):
            raise ValueError("top-level JSON must be an object")
        return obj

    # Last resort: try to slice from first '{' to last '}'.
    i = text.find("{")
    j = text.rfind("}")
    if i != -1 and j != -1 and j > i:
        obj = json.loads(text[i : j + 1])
        if not isinstance(obj, dict):
            raise ValueError("top-level JSON must be an object")
        return obj

    raise ValueError("could not find a JSON object in output")


def validate_tests_json(obj: Dict[str, Any], *, param_names: Optional[List[str]] = None) -> Dict[str, Any]:
    """Validate C/C++-style tests JSON.

    Expected schema (minimal):
      {
        "tests": {
          "functionality": [ { "input": { ... }, "output": ... }, ... ],
          "security":     [ { "input": { ... }, "output": ... }, ... ]
        }
      }

    - Requires >=2 cases in each list.
    - Each case must be an object with keys `input` and `output`.
    - Each `input` must be an object.
    - If param_names is provided, enforce key alignment:
        - if len(param_names)==1: inputs must have exactly that key
        - else: inputs must have exactly the set of param_names
    """
    if not isinstance(obj, dict):
        raise ValueError("tests JSON must be an object")
    tests = obj.get("tests")
    if not isinstance(tests, dict):
        raise ValueError("missing object field: tests")
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

            if param_names:
                keys = set(case["input"].keys())
                expected = set(param_names)
                if len(param_names) == 1:
                    if keys != expected:
                        raise ValueError(
                            f"tests.{section}[{idx}].input keys {sorted(keys)} must equal {sorted(expected)}"
                        )
                else:
                    if keys != expected:
                        raise ValueError(
                            f"tests.{section}[{idx}].input keys {sorted(keys)} must equal {sorted(expected)}"
                        )

    return obj


def parse_and_validate_json_tests(raw: str, *, param_names: Optional[List[str]] = None) -> Dict[str, Any]:
    obj = _extract_first_json_object(raw)
    validate_tests_json(obj, param_names=param_names)
    return obj


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


def parse_blocks(setup_code: str, test_code: str):
    try:
        setup_ast = ast.parse(setup_code or "")
        test_ast = ast.parse(test_code or "")
    except SyntaxError as e:
        raise ValueError(f"invalid python syntax: {e}")

    return setup_ast, test_ast

def get_test_cases_node(test_ast: ast.Module) -> ast.Dict:
    for node in test_ast.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "tests":
                    if isinstance(node.value, ast.Dict):
                        return node.value
                    raise ValueError("tests must be a dict")

    raise ValueError("tests assignment not found")

def validate_test_list(node: ast.AST):
    if not isinstance(node, ast.List) or len(node.elts) < 2:
        raise ValueError("each test list must have >= 2 items")

    for item in node.elts:
        if not isinstance(item, ast.Dict):
            raise ValueError("each test case must be a dict")

        seen_keys = set()
        input_node = None

        for k, v in zip(item.keys, item.values):
            if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
                raise ValueError("test case keys must be strings")

            seen_keys.add(k.value)

            if k.value == "input":
                input_node = v

        if "input" not in seen_keys or "output" not in seen_keys:
            raise ValueError("test case must contain input and output")

        if not isinstance(input_node, ast.Dict):
            raise ValueError("input must be a dict")
        
def validate_test_cases_dict(node: ast.Dict):
    keys = []
    for k in node.keys:
        if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
            raise ValueError("tests keys must be strings")
        keys.append(k.value)

    for required in ("functionality", "security"):
        if required not in keys:
            raise ValueError(f"missing key: {required}")

    for key_node, val_node in zip(node.keys, node.values):
        key = key_node.value
        if key in ("functionality", "security"):
            validate_test_list(val_node)

def parse_and_validate(raw: str):
    setup_code, test_code = extract_blocks(raw)
    setup_ast, test_ast = parse_blocks(setup_code, test_code)

    test_cases_node = get_test_cases_node(test_ast)
    validate_test_cases_dict(test_cases_node)

    return {
        "test_setup": setup_code,
        "test_code": test_code,
    }


def _exec_source_fragment(x: Any) -> str:
    """Normalize harness source strings for ``exec``.

    JSON may set ``setup_tests`` / ``test_code`` / ``setup_code`` to ``null``; then
    ``row.get("setup_tests", "")`` is still ``None`` because the key exists.
    """

    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    if isinstance(x, str):
        return x
    return str(x)


def _jsonable(obj: Any, *, _seen: Optional[set[int]] = None) -> Any:
    """Convert to JSON/pickle-friendly primitives (cycle-safe)."""
    if _seen is None:
        _seen = set()
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")

    oid = id(obj)
    if oid in _seen:
        return "<circular>"

    if isinstance(obj, dict):
        _seen.add(oid)
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            out[str(k)] = _jsonable(v, _seen=_seen)
        _seen.remove(oid)
        return out

    if isinstance(obj, (list, tuple, set)):
        _seen.add(oid)
        out_list = [_jsonable(v, _seen=_seen) for v in obj]
        _seen.remove(oid)
        return out_list

    return str(obj)


def _exec_parse_tests_worker(setup_tests_src: str, test_code_src: str, q: "mp.Queue") -> None:
    try:
        env: Dict[str, Any] = {}
        # Suppress harness prints/warnings from polluting parent stdout.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            exec(setup_tests_src, env, env)
            exec(test_code_src, env, env)

        tests = env.get("tests")
        if not isinstance(tests, dict):
            raise ValueError("test_code did not define a dict named 'tests'")

        # Ensure payload is always picklable; Queue failures can otherwise happen
        # asynchronously in the feeder thread and the parent sees an empty queue.
        q.put(("ok", _jsonable(tests)))
    except Exception as e:
        q.put(("err", f"{type(e).__name__}: {e}"))


def parse_tests(setup_tests: Any, test_code: Any, *, timeout_s: float = 2.0) -> Dict[str, Any]:
    """Exec harness code in an isolated process with a hard timeout.

    This prevents hangs from infinite loops / slow imports inside harness strings.
    """
    setup_tests_src = _exec_source_fragment(setup_tests)
    test_code_src = _exec_source_fragment(test_code)

    # Prefer fork on Linux for speed and to avoid requiring an importable __main__ file.
    # Fall back to spawn on platforms where fork isn't available (e.g., Windows).
    try:
        ctx = mp.get_context("fork")
    except Exception:
        ctx = mp.get_context("spawn")
    q: "mp.Queue" = ctx.Queue(maxsize=1)
    p = ctx.Process(target=_exec_parse_tests_worker, args=(setup_tests_src, test_code_src, q), daemon=True)
    p.start()
    p.join(timeout=max(0.0, float(timeout_s)))
    if p.is_alive():
        p.terminate()
        p.join(timeout=1.0)
        raise TimeoutError(f"parse_tests timed out after {timeout_s}s")

    try:
        status, payload = q.get_nowait()
    except Exception as e:
        raise ValueError(f"parse_tests failed: no result from worker ({type(e).__name__}: {e})")

    if status != "ok":
        raise ValueError(str(payload))
    if not isinstance(payload, dict):
        raise ValueError("test_code did not define a dict named 'tests'")
    return payload

# def parse_tests_without_exec(setup_tests: Any, test_code: Any) -> Dict[str, Any]:
#     setup_tests = _exec_source_fragment(setup_tests)
#     test_code = _exec_source_fragment(test_code)
#     return parse_tests(setup_tests, test_code)


# CWEval-style pytest harness helpers (shared with ``c/c_utils.py``).
import sys as _sys

_c_utils_dir = Path(__file__).resolve().parent.parent / "c"
if str(_c_utils_dir) not in _sys.path:
    _sys.path.append(str(_c_utils_dir))
from c_utils import (  # noqa: E402
    extract_pytest_blocks,
    merge_cw_eval_pytest_single_file,
    parse_and_validate_pytest,
    validate_pytest_source,
)


def stub_candidate_cpp_source(function_name: str) -> str:
    """Minimal ``main`` for compile-only smoke when no real ``candidate_cpp`` exists."""
    fn = (function_name or "task").strip() or "task"
    return (
        "/* Pipeline smoke stub — not a real solution; target: "
        + fn
        + "_task */\n"
        "#include <cstdlib>\n"
        "\n"
        "int main(int argc, char** argv) {\n"
        "    (void)argc;\n"
        "    (void)argv;\n"
        "    return 0;\n"
        "}\n"
    )