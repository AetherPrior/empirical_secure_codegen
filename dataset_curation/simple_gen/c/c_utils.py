import ast
import contextlib
import io
import json
import multiprocessing as mp
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


MD_BLOCK_RE = re.compile(
    r"##\s*test setup\s*```python(.*?)```.*?##\s*tests\s*```python(.*?)```",
    re.DOTALL | re.IGNORECASE,
)

PYTEST_MD_BLOCK_RE = re.compile(
    r"##\s*test setup\s*```python(.*?)```.*?##\s*pytest tests\s*```python(.*?)```",
    re.DOTALL | re.IGNORECASE,
)

# C pipeline (CWEval-style): tests are **pytest modules** (Python) that execute native
# binaries via ``subprocess``. We still keep JSON helpers for legacy experiments.
JSON_BLOCK_RE = re.compile(
    r"```(?:json)?\s*(\{[\s\S]*?\})\s*```",
    re.IGNORECASE,
)

def extract_blocks(raw: str):
    m = MD_BLOCK_RE.search(raw)
    if not m:
        raise ValueError("missing required markdown sections")

    return m.group(1).strip(), m.group(2).strip()


def extract_pytest_blocks(raw: str) -> Tuple[str, str]:
    m = PYTEST_MD_BLOCK_RE.search(raw)
    if not m:
        raise ValueError("missing required markdown sections (test setup / pytest tests)")
    return m.group(1).strip(), m.group(2).strip()


_C_CODE_BLOCK_RE = re.compile(
    r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def extract_c_source_from_markdown(raw: str) -> str:
    """Best-effort extraction of C/C++ from markdown fences (same rules as ``run_pytest``)."""
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
    """Validate C-style tests JSON.

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


def validate_pytest_source(setup_py: str, pytest_py: str) -> None:
    """Lightweight static validation for CWEval-style pytest modules.

    Requirements:
    - valid Python syntax
    - imports pytest + subprocess (CWEval pattern)
    - contains pytest markers for functionality + security (at least twice each)
    - defines at least one test function (``def test_...``)
    """
    setup_py = setup_py or ""
    pytest_py = pytest_py or ""
    try:
        ast.parse(setup_py)
        mod = ast.parse(pytest_py)
    except SyntaxError as e:
        raise ValueError(f"invalid python syntax: {e}") from e

    # Setup is prepended into the same module at harness time; allow imports in either block.
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


_HARNESS_IMPORT_LINE_RE = re.compile(r"^\s*from\s+\.?test_\w+\s+import\b")


def strip_redundant_harness_imports(test_code: str) -> str:
    """Remove ``from test_*`` / ``from .test_*`` lines before merging with ``setup_tests``.

    Models often emit ``from test_setup import TASK_BIN`` even though the runner concatenates
    ``setup_tests`` and ``test_code`` into one module where those names are already defined.
    """
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


def stub_candidate_c_source(function_name: str) -> str:
    """Minimal C ``main`` for compile-only / pipeline smoke when no real ``candidate_c`` exists.

    Produces a normal executable named ``<function_name>_task`` after linking; it is not a
    correct implementation of the task. Use a real candidate for evaluation runs.
    """
    fn = (function_name or "task").strip() or "task"
    return (
        "/* Pipeline smoke stub — not a real solution; target: "
        + fn
        + "_task */\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "\n"
        "int main(int argc, char **argv) {\n"
        "    (void)argc;\n"
        "    (void)argv;\n"
        "    return 0;\n"
        "}\n"
    )