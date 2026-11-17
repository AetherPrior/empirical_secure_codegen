"""JavaScript simple_gen execution harness."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from recipe.security_harness.reward_config import UNITTEST_TIMEOUT_SECONDS, debug
except ImportError:
    from reward_config import UNITTEST_TIMEOUT_SECONDS, debug

_JS_CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)


def _extract_js_source(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    matches = list(_JS_CODE_BLOCK_RE.finditer(text))
    if not matches:
        return text
    for match in matches:
        fence = match.group(0).splitlines()[0].lower()
        body = match.group(1).strip()
        if any(tag in fence for tag in ("javascript", "js", "node")):
            return body
    return matches[-1].group(1).strip()


def _jsonable(obj: Any, *, _seen: set[int] | None = None) -> Any:
    if _seen is None:
        _seen = set()
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if obj is Exception:
        return "Exception"

    oid = id(obj)
    if oid in _seen:
        return "<circular>"
    if isinstance(obj, dict):
        _seen.add(oid)
        out = {str(k): _jsonable(v, _seen=_seen) for k, v in obj.items()}
        _seen.remove(oid)
        return out
    if isinstance(obj, (list, tuple, set)):
        _seen.add(oid)
        out = [_jsonable(v, _seen=_seen) for v in obj]
        _seen.remove(oid)
        return out
    return str(obj)


def _extract_first_json_object(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty tests JSON")
    if text.startswith("{") and text.endswith("}"):
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    match = _JSON_BLOCK_RE.search(text)
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
    raise ValueError("could not find tests JSON object")


def _exec_python_tests(setup_tests: Any, test_code: Any) -> dict[str, Any]:
    namespace: dict[str, Any] = {}
    setup_src = setup_tests if isinstance(setup_tests, str) else ""
    test_src = test_code if isinstance(test_code, str) else ""
    if setup_src.strip():
        exec(setup_src, namespace, namespace)
    if test_src.strip():
        exec(test_src, namespace, namespace)
    tests = namespace.get("tests")
    if not isinstance(tests, dict):
        raise ValueError("test_code did not define a dict named 'tests'")
    return _jsonable(tests)


def _tests_from_ground_truth(ground_truth: dict[str, Any]) -> dict[str, Any]:
    testcases = ground_truth.get("testcases")
    if isinstance(testcases, dict):
        return testcases

    tests_json = ground_truth.get("tests_json")
    if isinstance(tests_json, dict):
        tests = tests_json.get("tests", tests_json)
        if isinstance(tests, dict):
            return tests

    test_code = ground_truth.get("test_code")
    if isinstance(test_code, str) and test_code.strip():
        try:
            obj = _extract_first_json_object(test_code)
            tests = obj.get("tests", obj)
            if isinstance(tests, dict):
                return tests
        except Exception:
            pass
        return _exec_python_tests(ground_truth.get("setup_tests", ""), test_code)

    raise ValueError("missing JS tests")


def _param_names(ground_truth: dict[str, Any]) -> list[str]:
    args = ground_truth.get("arguments") or []
    if not isinstance(args, list):
        return []
    out: list[str] = []
    for arg in args:
        if isinstance(arg, dict):
            name = arg.get("name")
            if isinstance(name, str) and name.strip():
                out.append(name.strip())
    return out


def _node_subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    node_paths: list[str] = []
    existing = env.get("NODE_PATH")
    if existing:
        node_paths.extend(part for part in existing.split(os.pathsep) if part)

    home = Path.home()
    for candidate in (
        home / ".npm-global" / "lib" / "node_modules",
        home / ".local" / "lib" / "node_modules",
    ):
        if candidate.is_dir():
            node_paths.append(str(candidate))

    npm = shutil.which("npm")
    if npm:
        try:
            proc = subprocess.run([npm, "root", "-g"], capture_output=True, text=True, timeout=2.0)
            global_root = (proc.stdout or "").strip()
            if proc.returncode == 0 and global_root:
                node_paths.append(global_root)
        except Exception:
            pass

    if node_paths:
        env["NODE_PATH"] = os.pathsep.join(dict.fromkeys(node_paths))
    return env


def _node_runner_script(function_name: str, param_names: list[str], setup_code: str, candidate_code: str) -> str:
    return (
        "const payload = JSON.parse(process.env.SAFE_K_TEST_PAYLOAD || '{}');\n"
        "const tests = payload.tests || {};\n"
        "const CASE_TIMEOUT_MS = Math.max(1, Number(process.env.SAFE_K_JS_CASE_TIMEOUT_MS || 2000));\n"
        f"const functionName = {json.dumps(function_name)};\n"
        f"const paramNames = {json.dumps(param_names)};\n"
        f"{setup_code}\n"
        f"{candidate_code}\n"
        r"""
function lookupFunction(name) {
  let fn = undefined;
  try { fn = eval(name); } catch (_) {}
  if (typeof fn === "function") return fn;
  if (typeof globalThis[name] === "function") return globalThis[name];
  if (module && module.exports) {
    if (typeof module.exports === "function") return module.exports;
    if (typeof module.exports[name] === "function") return module.exports[name];
  }
  throw new Error(`Function ${name} not defined`);
}

function isExceptionExpected(expected) {
  return expected === "Exception" || expected === "__EXCEPTION__" ||
    (expected && typeof expected === "object" && (expected.exception === true || expected.type === "Exception"));
}

function deepEqual(a, b) {
  if (Object.is(a, b)) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
    return true;
  }
  const ak = Object.keys(a).sort();
  const bk = Object.keys(b).sort();
  if (!deepEqual(ak, bk)) return false;
  for (const k of ak) if (!deepEqual(a[k], b[k])) return false;
  return true;
}

function callArgs(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Test input must be an object");
  }
  if (paramNames.length > 0) return paramNames.map((name) => input[name]);
  return Object.keys(input).sort().map((name) => input[name]);
}

function withTimeout(promise, ms, label) {
  let timer;
  return new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`SAFE_K_TIMEOUT: ${label} after ${ms}ms`)), ms);
    Promise.resolve(promise).then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

async function awaitOptionalSetup() {
  if (typeof globalThis.__setup === "function") {
    await withTimeout(globalThis.__setup(), CASE_TIMEOUT_MS, "__setup");
    return;
  }
  if (typeof __setup === "function") {
    await withTimeout(__setup(), CASE_TIMEOUT_MS, "__setup");
    return;
  }
  const pending = globalThis.__harnessSetup;
  if (pending != null && typeof pending.then === "function") {
    await withTimeout(pending, CASE_TIMEOUT_MS, "__harnessSetup");
  }
}

async function runCase(fn, testCase) {
  const expected = testCase.output;
  try {
    const actual = await withTimeout(fn(...callArgs(testCase.input)), CASE_TIMEOUT_MS, "testcase");
    if (isExceptionExpected(expected)) return false;
    return deepEqual(actual, expected);
  } catch (err) {
    const msg = err && err.message ? String(err.message) : String(err);
    if (msg.startsWith("SAFE_K_TIMEOUT:")) return false;
    return isExceptionExpected(expected);
  }
}

(async () => {
  await awaitOptionalSetup();
  const fn = lookupFunction(functionName);
  const summary = {
    functionality_passed: 0,
    security_passed: 0,
    functionality_total: Array.isArray(tests.functionality) ? tests.functionality.length : 0,
    security_total: Array.isArray(tests.security) ? tests.security.length : 0,
  };
  for (const testCase of (tests.functionality || [])) {
    if (await runCase(fn, testCase)) summary.functionality_passed += 1;
  }
  for (const testCase of (tests.security || [])) {
    if (await runCase(fn, testCase)) summary.security_passed += 1;
  }
  console.log("SAFE_K_SUMMARY=" + JSON.stringify(summary));
  process.exit(0);
})().catch((err) => {
  console.error(String(err && err.stack || err));
  process.exit(1);
});
"""
    )


def run_simple_gen_js_harness_unittest(
    candidate_code: str, ground_truth: Any
) -> tuple[bool, dict[str, tuple[int | float, int]]]:
    if not isinstance(ground_truth, dict):
        debug("JS simple_gen harness unavailable: ground_truth is not a dict")
        return False, {}

    function_name = ground_truth.get("function_name")
    if not isinstance(function_name, str) or not function_name.strip():
        debug("JS simple_gen harness unavailable: missing function_name")
        return False, {}

    node = shutil.which("node")
    if not node:
        debug("JS simple_gen harness unavailable: node executable not found")
        return False, {}

    try:
        tests = _tests_from_ground_truth(ground_truth)
    except Exception as exc:
        debug(f"JS simple_gen harness unavailable: {type(exc).__name__}: {exc}")
        return False, {}

    source = _extract_js_source(candidate_code)
    if not source:
        debug("JS simple_gen harness unavailable: empty candidate source")
        return False, {}

    setup_code = ground_truth.get("setup_code", "")
    if not isinstance(setup_code, str):
        setup_code = ""
    script = _node_runner_script(function_name.strip(), _param_names(ground_truth), setup_code, source)

    payload = {"tests": tests}
    try:
        with tempfile.TemporaryDirectory(prefix="safe_k_js_") as tmp_cwd:
            script_path = Path(tmp_cwd) / "runner.js"
            script_path.write_text(script, encoding="utf-8")
            env = _node_subprocess_env()
            env["SAFE_K_TEST_PAYLOAD"] = json.dumps(payload, ensure_ascii=False)
            # Leave headroom under the subprocess timeout for multiple awaited cases + setup.
            case_timeout_ms = max(250, int(float(UNITTEST_TIMEOUT_SECONDS) * 1000 * 0.75))
            env["SAFE_K_JS_CASE_TIMEOUT_MS"] = str(case_timeout_ms)
            proc = subprocess.run(
                [node, str(script_path)],
                capture_output=True,
                text=True,
                timeout=UNITTEST_TIMEOUT_SECONDS,
                cwd=tmp_cwd,
                env=env,
            )
    except subprocess.TimeoutExpired:
        debug(f"JS simple_gen harness timed out after {UNITTEST_TIMEOUT_SECONDS}s")
        return False, {}
    except Exception as exc:
        debug(f"JS simple_gen harness subprocess launch failed: {type(exc).__name__}: {exc}")
        return False, {}

    if proc.returncode != 0:
        stderr_preview = (proc.stderr or "").strip().replace("\n", "\\n")[:400]
        stdout_preview = (proc.stdout or "").strip().replace("\n", "\\n")[:400]
        debug(f"JS simple_gen harness failed: rc={proc.returncode}, stdout={stdout_preview!r}, stderr={stderr_preview!r}")
        return False, {}

    summary = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("SAFE_K_SUMMARY="):
            try:
                summary = json.loads(line[len("SAFE_K_SUMMARY=") :])
            except Exception:
                summary = None
            break
    if not isinstance(summary, dict):
        debug(f"JS simple_gen harness missing summary output; stdout={(proc.stdout or '')[:400]!r}")
        return False, {}

    functionality_passed = summary.get("functionality_passed")
    functionality_total = summary.get("functionality_total")
    security_passed = summary.get("security_passed")
    security_total = summary.get("security_total")
    if not all(isinstance(v, (int, float)) for v in (functionality_passed, functionality_total, security_passed, security_total)):
        debug("JS simple_gen harness failed: invalid summary format")
        return False, {}

    debug(
        "JS simple_gen harness succeeded: "
        f"functionality={functionality_passed}/{functionality_total}, security={security_passed}/{security_total}"
    )
    return True, {
        "functionality": (int(functionality_passed), int(functionality_total)),
        "security": (float(security_passed), int(security_total)),
    }
