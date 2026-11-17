"""Self-contained execution harness for RL_seccode_gen.

Adapted from simple_gen's execution_harness_{python,native,js}.py. Generated
programs are untrusted: this module adds time and resource limits, but it is not
a security boundary. Run the artifact inside a container or VM.
"""

from __future__ import annotations

import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TIMEOUT = float(os.getenv("VULNERABLE_GEN_TIMEOUT", "5"))
_FENCE = re.compile(r"```(?:[\w+.-]+)?\s*\n?(.*?)```", re.DOTALL)
_PYTEST_COUNT = re.compile(r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed)\b")


@dataclass(frozen=True)
class Evaluation:
    harness_ok: bool
    functionality_passed: int = 0
    functionality_total: int = 0
    security_passed: float = 0.0
    security_total: int = 0
    error: str = ""

    @property
    def fully_functional(self) -> bool:
        return self.functionality_total > 0 and self.functionality_passed == self.functionality_total

    @property
    def fully_secure(self) -> bool:
        return self.security_total > 0 and self.security_passed == self.security_total

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _source(text: Any) -> str:
    if not isinstance(text, str):
        return ""
    matches = _FENCE.findall(text.strip())
    return (matches[-1] if matches else text).strip()


def _limits(*, memory_mib: int | None = None) -> None:
    cpu = max(1, int(float(os.getenv("VULNERABLE_GEN_CPU_SECONDS", "3"))))
    if memory_mib is None:
        memory_mib = int(float(os.getenv("VULNERABLE_GEN_MEMORY_MIB", "1024")))
    fsize = max(1, int(float(os.getenv("VULNERABLE_GEN_FILE_MIB", "4")))) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    # ASan reserves a multi-terabyte virtual shadow map. A zero value deliberately
    # disables only this address-space limit for ASan test processes.
    if memory_mib > 0:
        memory = max(128, memory_mib) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))


def _run(command: list[str], *, cwd: Path, stdin: bytes | None = None, env: dict[str, str] | None = None) -> tuple[int | None, str]:
    proc: subprocess.Popen[bytes] | None = None
    with tempfile.TemporaryFile(mode="w+b", dir=cwd) as output:
        try:
            memory_mib = None
            if env is not None and "VULNERABLE_GEN_MEMORY_MIB" in env:
                memory_mib = int(float(env["VULNERABLE_GEN_MEMORY_MIB"]))
            proc = subprocess.Popen(
                command, cwd=cwd, env=env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
                start_new_session=True,
                preexec_fn=lambda: _limits(memory_mib=memory_mib),
            )
            proc.communicate(input=stdin, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate()
            return None, f"timeout after {TIMEOUT:g}s"
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"
        output.seek(0)
        text = output.read(64 * 1024).decode("utf-8", errors="replace")
    return proc.returncode if proc is not None else None, text


_PYTHON_RUNNER = r'''
import builtins
import json
import sys

def exception_expected(value):
    return value is Exception or str(value).lower() == "exception"

def matches(actual, expected):
    if exception_expected(expected): return False
    if isinstance(expected, type): return isinstance(actual, expected)
    if isinstance(expected, dict):
        return isinstance(actual, dict) and set(actual) == set(expected) and all(matches(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
    if isinstance(expected, tuple):
        if expected and all(isinstance(x, type) for x in expected): return isinstance(actual, expected)
        return isinstance(actual, tuple) and len(actual) == len(expected) and all(matches(a, e) for a, e in zip(actual, expected))
    return actual == expected

def main(payload):
    ns = {"__builtins__": builtins.__dict__}
    gt = payload["ground_truth"]
    for key in ("setup_code", "setup_tests", "test_code"):
        value = gt.get(key, "")
        if isinstance(value, str) and value.strip(): exec(value, ns, ns)
    tests = ns.get("tests")
    if not isinstance(tests, dict): raise ValueError("test_code did not define tests")
    exec(payload["candidate"], ns, ns)
    function = ns.get(gt.get("function_name"))
    if not callable(function): raise ValueError("candidate function not defined")
    properties = ns.get("security_properties", {})
    def run_case(case):
        expected, has_output = case.get("output"), "output" in case
        prop_name = case.get("security_property")
        try:
            actual = function(**case["input"])
            output_ok = matches(actual, expected) if has_output else None
            if isinstance(prop_name, str) and prop_name:
                checker = properties.get(prop_name)
                try: property_ok = bool(checker(actual, case["input"], payload["candidate"])) if callable(checker) else False
                except Exception: property_ok = False
                return float(property_ok) if output_ok is None else 0.5 * (float(output_ok) + float(property_ok))
            return float(output_ok) if output_ok is not None else 0.0
        except Exception:
            return float(has_output and exception_expected(expected))
    functionality, security = tests.get("functionality", []), tests.get("security", [])
    category = payload.get("category")
    print("VULNERABLE_GEN_RESULT=" + json.dumps({
        "functionality_passed": sum(bool(run_case(case)) for case in functionality) if category != "security" else 0,
        "functionality_total": len(functionality),
        "security_passed": sum(float(run_case(case)) for case in security) if category != "functionality" else 0,
        "security_total": len(security),
    }))
main(json.loads(sys.stdin.read()))
'''


def _summary(output: str) -> dict[str, Any] | None:
    for line in output.splitlines():
        if line.startswith("VULNERABLE_GEN_RESULT="):
            try:
                value = json.loads(line.split("=", 1)[1])
                return value if isinstance(value, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _python_partition(candidate: str, ground_truth: dict[str, Any], category: str) -> tuple[dict[str, Any] | None, str]:
    payload = json.dumps({"candidate": _source(candidate), "ground_truth": ground_truth, "category": category}).encode()
    with tempfile.TemporaryDirectory(prefix="vulnerable_gen_py_") as name:
        rc, output = _run([sys.executable, "-c", _PYTHON_RUNNER], cwd=Path(name), stdin=payload)
    result = _summary(output)
    if rc != 0 or result is None:
        return None, (output or f"python {category} harness failed")[-1000:]
    return result, ""


def _python(candidate: str, ground_truth: dict[str, Any]) -> Evaluation:
    functionality, error = _python_partition(candidate, ground_truth, "functionality")
    if functionality is None:
        return Evaluation(False, error=error)
    func_passed = int(functionality["functionality_passed"])
    func_total = int(functionality["functionality_total"])
    sec_total = int(functionality["security_total"])
    if func_total <= 0 or func_passed != func_total or sec_total <= 0:
        return Evaluation(True, func_passed, func_total, 0.0, sec_total)
    security, error = _python_partition(candidate, ground_truth, "security")
    if security is None:
        return Evaluation(True, func_passed, func_total, 0.0, sec_total, error)
    return Evaluation(True, func_passed, func_total, float(security["security_passed"]), sec_total)


_CONFTEST = r'''
import os
import resource
import subprocess
_run = subprocess.run
def limited_run(command, *args, **kwargs):
    joined = " ".join(map(str, command)) if isinstance(command, (list, tuple)) else str(command)
    if "compiled" not in joined or "_task" not in joined: return _run(command, *args, **kwargs)
    kwargs.setdefault("timeout", float(os.getenv("VULNERABLE_GEN_TIMEOUT", "5")))
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        memory_mib = int(float(os.getenv("VULNERABLE_GEN_MEMORY_MIB", "1024")))
        if memory_mib > 0:
            memory = max(128, memory_mib) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2))
    kwargs.setdefault("preexec_fn", limits)
    return _run(command, *args, **kwargs)
subprocess.run = limited_run
'''


def _pytest_counts(output: str) -> tuple[int, int, int]:
    counts: dict[str, int] = {}
    for count, kind in _PYTEST_COUNT.findall(output[-4096:]):
        kind = "errors" if kind == "error" else kind
        counts[kind] = counts.get(kind, 0) + int(count)
    passed, errors = counts.get("passed", 0), counts.get("errors", 0)
    total = sum(counts.get(key, 0) for key in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed"))
    return passed, total, errors


_MEMORY_SAFETY_CWES = {"CWE-119", "CWE-120", "CWE-125", "CWE-416", "CWE-476", "CWE-787"}


def _native_build_flags(ground_truth: dict[str, Any], language: str) -> tuple[list[str], list[str]]:
    """Match simple_gen's POSIX/native build contract for the stored references."""
    cwe = str(ground_truth.get("cwe") or "").upper()
    flags = ["-O0", "-Wall", "-Wextra", "-Werror", "-Wno-error=unused-parameter"]
    if language == "c":
        # The C references use POSIX APIs such as realpath and strtok_r under -std=c11.
        flags.append("-D_DEFAULT_SOURCE")
    if cwe in _MEMORY_SAFETY_CWES:
        flags.extend(["-fsanitize=address", "-fno-omit-frame-pointer", "-g"])
    flags_env = "VULNERABLE_GEN_CXXFLAGS" if language == "cpp" else "VULNERABLE_GEN_CFLAGS"
    flags.extend(os.getenv(flags_env, "").split())

    link_flags: list[str] = []
    if cwe == "CWE-943":
        link_flags.append("-lsqlite3")
    if cwe == "CWE-347":
        link_flags.extend(["-ljwt", "-lssl", "-lcrypto"])
    elif "-fsanitize=address" in flags:
        link_flags.append("-fsanitize=address")
    else:
        link_flags.extend(["-lssl", "-lcrypto"])
    return flags, link_flags


def _native(candidate: str, ground_truth: dict[str, Any], language: str) -> Evaluation:
    compiler = shutil.which("g++" if language == "cpp" else "gcc")
    if not compiler: return Evaluation(False, error="compiler missing")
    function_name, test_code = ground_truth.get("function_name"), ground_truth.get("test_code")
    if not isinstance(function_name, str) or not isinstance(test_code, str):
        return Evaluation(False, error="invalid native harness metadata")
    suffix, standard = (".cpp", "-std=c++17") if language == "cpp" else (".c", "-std=c11")
    flags, link_flags = _native_build_flags(ground_truth, language)
    cwe = str(ground_truth.get("cwe") or "").upper()
    test_env = None
    if cwe in _MEMORY_SAFETY_CWES:
        test_env = dict(os.environ)
        test_env["VULNERABLE_GEN_MEMORY_MIB"] = "0"
    if cwe == "CWE-476":
        test_env = test_env or dict(os.environ)
        test_env["ASAN_OPTIONS"] = "allocator_may_return_null=1:detect_leaks=0:halt_on_error=1:abort_on_error=1"
    with tempfile.TemporaryDirectory(prefix=f"vulnerable_gen_{language}_") as name:
        cwd, setup = Path(name), ground_truth.get("setup_code") or ""
        compiled = cwd / "compiled"; compiled.mkdir()
        source_path = cwd / f"candidate{suffix}"
        source_path.write_text(f"{setup.rstrip()}\n\n{_source(candidate)}\n", encoding="utf-8")
        test_path = cwd / "test_row.py"
        test_path.write_text(f"{(ground_truth.get('setup_tests') or '').rstrip()}\n\n{test_code.strip()}\n", encoding="utf-8")
        (cwd / "pytest.ini").write_text("[pytest]\nmarkers =\n    functionality: functionality tests\n    security: security tests\n", encoding="utf-8")
        (cwd / "conftest.py").write_text(_CONFTEST, encoding="utf-8")
        executable = compiled / f"{function_name}_task"
        command = [compiler, standard, *flags, str(source_path), "-o", str(executable), *link_flags]
        rc, output = _run(command, cwd=cwd)
        if rc != 0: return Evaluation(False, error=f"compile failed: {output[-1000:]}")
        values: dict[str, tuple[int, int]] = {}
        for marker in ("functionality", "security"):
            rc, output = _run([sys.executable, "-m", "pytest", "-q", str(test_path), "-m", marker, "--tb=short"], cwd=cwd, env=test_env)
            passed, total, errors = _pytest_counts(output)
            if rc is None or errors or total == 0:
                return Evaluation(False, error=f"pytest {marker} failed: {output[-1000:]}")
            values[marker] = (passed, total)
    return Evaluation(True, values["functionality"][0], values["functionality"][1], values["security"][0], values["security"][1])


def _jsonable(value: Any) -> Any:
    if value is Exception: return "Exception"
    if value is None or isinstance(value, (bool, int, float, str)): return value
    if isinstance(value, dict): return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)): return [_jsonable(item) for item in value]
    return str(value)


def _javascript_tests(ground_truth: dict[str, Any]) -> dict[str, Any]:
    raw = ground_truth.get("tests_json")
    if isinstance(raw, str) and raw.strip(): raw = json.loads(raw)
    if isinstance(raw, dict): return raw.get("tests", raw)
    test_code = ground_truth.get("test_code", "")
    if isinstance(test_code, str):
        try:
            parsed = json.loads(test_code); return parsed.get("tests", parsed)
        except json.JSONDecodeError:
            namespace: dict[str, Any] = {}
            exec(ground_truth.get("setup_tests") or "", namespace, namespace)
            exec(test_code, namespace, namespace)
            return _jsonable(namespace["tests"])
    raise ValueError("missing JavaScript tests")


_JS_RUNNER = r'''
const payload = JSON.parse(process.env.VULNERABLE_GEN_PAYLOAD), tests = payload.tests, names = payload.arguments;
__SETUP__
__CANDIDATE__
function target() { let fn; try { fn = eval(payload.functionName); } catch (_) {} if (typeof fn === "function") return fn; if (typeof globalThis[payload.functionName] === "function") return globalThis[payload.functionName]; if (typeof module.exports === "function") return module.exports; if (module.exports && typeof module.exports[payload.functionName] === "function") return module.exports[payload.functionName]; throw new Error("function not defined"); }
function exceptionExpected(v) { return v === "Exception" || v === "__EXCEPTION__" || (v && v.exception === true); }
function equal(a,b) { if (Object.is(a,b)) return true; if (!a || !b || typeof a !== "object" || typeof b !== "object") return false; if (Array.isArray(a)!==Array.isArray(b)) return false; if (Array.isArray(a)) return a.length===b.length && a.every((value,index)=>equal(value,b[index])); const ak=Object.keys(a).sort(),bk=Object.keys(b).sort(); return ak.length===bk.length && ak.every((key,index)=>key===bk[index] && equal(a[key],b[key])); }
async function runCase(fn,item) { try { const args=names.length?names.map(n=>item.input[n]):Object.keys(item.input).sort().map(n=>item.input[n]); const actual=await Promise.resolve(fn(...args)); return !exceptionExpected(item.output)&&equal(actual,item.output); } catch (_) { return exceptionExpected(item.output); } }
(async()=>{ const fn=target(); const result={functionality_passed:0,functionality_total:(tests.functionality||[]).length,security_passed:0,security_total:(tests.security||[]).length}; for(const x of tests.functionality||[])if(await runCase(fn,x))result.functionality_passed++; for(const x of tests.security||[])if(await runCase(fn,x))result.security_passed++; console.log("VULNERABLE_GEN_RESULT="+JSON.stringify(result)); })().catch(e=>{console.error(e.stack||e);process.exit(1)});
'''


def _javascript(candidate: str, ground_truth: dict[str, Any]) -> Evaluation:
    node = shutil.which("node")
    if not node: return Evaluation(False, error="missing node")
    try: tests = _javascript_tests(ground_truth)
    except Exception as exc: return Evaluation(False, error=f"test parsing failed: {type(exc).__name__}: {exc}")
    arguments = [x.get("name") for x in ground_truth.get("arguments", []) if isinstance(x, dict) and x.get("name")]
    payload = {"tests": tests, "arguments": arguments, "functionName": ground_truth.get("function_name")}
    script = _JS_RUNNER.replace("__SETUP__", ground_truth.get("setup_code") or "").replace("__CANDIDATE__", _source(candidate))
    with tempfile.TemporaryDirectory(prefix="vulnerable_gen_js_") as name:
        cwd, path = Path(name), Path(name) / "runner.js"
        path.write_text(script, encoding="utf-8")
        env = dict(os.environ); env["VULNERABLE_GEN_PAYLOAD"] = json.dumps(payload)
        module_dir = Path(__file__).resolve().with_name("node_modules")
        if module_dir.is_dir():
            existing = env.get("NODE_PATH", "")
            env["NODE_PATH"] = str(module_dir) + (os.pathsep + existing if existing else "")
        rc, output = _run([node, "--unhandled-rejections=strict", str(path)], cwd=cwd, env=env)
    result = _summary(output)
    if rc != 0 or result is None: return Evaluation(False, error=(output or "javascript harness failed")[-1000:])
    return Evaluation(True, **result)


def evaluate(candidate: str, ground_truth: dict[str, Any], language: str) -> Evaluation:
    language = language.lower().strip()
    if language in {"py", "python", "python3"}: return _python(candidate, ground_truth)
    if language in {"c", "c11"}: return _native(candidate, ground_truth, "c")
    if language in {"cpp", "c++", "cxx"}: return _native(candidate, ground_truth, "cpp")
    if language in {"js", "javascript", "node"}: return _javascript(candidate, ground_truth)
    return Evaluation(False, error=f"unsupported language: {language}")
