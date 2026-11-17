"""Shared helpers for native simple_gen execution harnesses."""

from __future__ import annotations

import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from recipe.security_harness.reward_config import UNITTEST_TIMEOUT_SECONDS, debug
except ImportError:
    from reward_config import UNITTEST_TIMEOUT_SECONDS, debug

_NATIVE_CODE_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_+-]+)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)
_PYTEST_COUNT_RE = re.compile(
    r"(?P<count>\d{1,7})\s+(?P<kind>passed|failed|errors?|skipped|xfailed|xpassed)\b"
)
_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*$")

_BASE_NATIVE_CFLAGS = ["-O0", "-Wall", "-Wextra"]
_BASE_NATIVE_CXXFLAGS = ["-O0", "-Wall", "-Wextra"]
_BASE_NATIVE_LDFLAGS = ["-lcrypto"]
_FLAG_TAKES_ARG = frozenset({"-std", "-I", "-L", "-D", "-U", "-include", "-isystem"})

_PYTEST_CONFTEST = """\
import os
import resource
import subprocess

_TIMEOUT = float(os.environ.get("UNITTEST_TIMEOUT_SECONDS", "5"))
_ORIG_RUN = subprocess.run


def _env_int(name, default=0):
    try:
        return int(float(os.environ.get(name, str(default)) or default))
    except (TypeError, ValueError):
        return int(default)


def _task_preexec():
    # rlimits only — stay in pytest's process group so killpg(pytest) kills us too.
    cpu = _env_int("SAFE_K_RLIMIT_CPU_SECONDS", 0)
    as_mib = _env_int("SAFE_K_RLIMIT_AS_MIB", 0)
    stack_mib = _env_int("SAFE_K_RLIMIT_STACK_MIB", 0)
    fsize_mib = _env_int("SAFE_K_RLIMIT_FSIZE_MIB", 0)
    # ASan reserves a multi-terabyte virtual-address shadow, so RLIMIT_AS makes
    # every ASan binary fail at startup. Its own RSS monitor instead limits
    # resident memory while preserving that virtual reservation.
    asan_hard_rss_mib = _env_int("SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB", 0)
    if asan_hard_rss_mib > 0:
        existing = os.environ.get("ASAN_OPTIONS", "").strip(":")
        if "hard_rss_limit_mb=" not in existing:
            options = [existing] if existing else []
            options.extend(
                [
                    f"hard_rss_limit_mb={asan_hard_rss_mib}",
                    "allocator_may_return_null=1",
                ]
            )
            os.environ["ASAN_OPTIONS"] = ":".join(options)
        as_mib = 0
    if cpu > 0:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    if as_mib > 0:
        nbytes = as_mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
    if stack_mib > 0:
        nbytes = stack_mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_STACK, (nbytes, nbytes))
    if fsize_mib > 0:
        nbytes = fsize_mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (nbytes, nbytes))


def _should_timeout_command(cmd):
    if isinstance(cmd, (list, tuple)):
        parts = [str(part) for part in cmd]
    else:
        parts = [str(cmd)]
    joined = " ".join(parts)
    return "/compiled/" in joined or joined.endswith("_task") or "/compiled\\\\" in joined


def _run_with_timeout(cmd, *args, **kwargs):
    if not _should_timeout_command(cmd):
        return _ORIG_RUN(cmd, *args, **kwargs)

    timeout = kwargs.pop("timeout", _TIMEOUT)
    kwargs.pop("start_new_session", None)
    kwargs.pop("preexec_fn", None)
    preexec = _task_preexec
    if (
        _env_int("SAFE_K_RLIMIT_CPU_SECONDS", 0) <= 0
        and _env_int("SAFE_K_RLIMIT_AS_MIB", 0) <= 0
        and _env_int("SAFE_K_RLIMIT_STACK_MIB", 0) <= 0
        and _env_int("SAFE_K_RLIMIT_FSIZE_MIB", 0) <= 0
        and _env_int("SAFE_K_NATIVE_ASAN_HARD_RSS_LIMIT_MIB", 0) <= 0
    ):
        preexec = None

    secs = max(1, int(float(timeout)))
    if isinstance(cmd, (list, tuple)):
        wrapped = ["timeout", "-k", "2", str(secs), *[str(c) for c in cmd]]
    else:
        wrapped = ["timeout", "-k", "2", str(secs), str(cmd)]
    # IMPORTANT: no start_new_session — stay in pytest's group.
    return _ORIG_RUN(wrapped, *args, preexec_fn=preexec, **kwargs)


subprocess.run = _run_with_timeout
"""


def _extract_native_source(raw: str, language: str) -> str:
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""

    matches = list(_NATIVE_CODE_BLOCK_RE.finditer(text))
    if not matches:
        return text

    # Language is fixed per sample; models often use plain ```. Use the last fenced block.
    return matches[-1].group(1).strip()


def _strip_markdown_fences(text: str) -> str:
    if not isinstance(text, str):
        return ""
    lines = text.splitlines()
    if len(lines) >= 2 and _FENCE_RE.match(lines[0]) and _FENCE_RE.match(lines[-1]):
        return "\n".join(lines[1:-1]).strip() + ("\n" if text.endswith("\n") else "")
    return text


def _prepend_setup_code(*, ground_truth: dict[str, Any], source: str) -> str:
    setup = ground_truth.get("setup_code")
    if not isinstance(setup, str):
        return source
    setup = _strip_markdown_fences(setup).strip()
    if not setup:
        return source
    return setup.rstrip() + "\n\n" + (source or "").lstrip()


def _prepare_native_source_for_compile(
    *,
    candidate_source: str,
    ground_truth: dict[str, Any],
) -> str:
    """setup_code + candidate only (no auto-main; matches simple_gen run_pytest)."""
    return _prepend_setup_code(ground_truth=ground_truth, source=candidate_source)


def _tokenize_compiler_flags(raw: str) -> list[str]:
    return raw.split() if raw.strip() else []


def _merge_compiler_flags(base: list[str], extra: list[str]) -> list[str]:
    """Merge env compiler flags onto defaults; env may override -std.*."""
    merged = list(base)
    idx = 0
    while idx < len(extra):
        flag = extra[idx]
        if flag in _FLAG_TAKES_ARG and idx + 1 < len(extra):
            if flag == "-std":
                merged = [existing for existing in merged if not existing.startswith("-std") and existing != "-std"]
            merged.extend([flag, extra[idx + 1]])
            idx += 2
            continue
        if flag.startswith("-std="):
            merged = [existing for existing in merged if not existing.startswith("-std") and existing != "-std"]
        merged.append(flag)
        idx += 1
    return merged


def _kill_process_group(pid: int, sig: int = signal.SIGKILL) -> None:
    if pid <= 0:
        return
    try:
        os.killpg(os.getpgid(pid), sig)
    except ProcessLookupError:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass


def _kill_escaped_compiled_tasks(cwd: Path) -> None:
    """Kill candidate binaries that escaped pytest's process group.

    Generated native code can call ``setsid`` or double-fork.  Such a process is
    no longer reachable through the timeout wrapper's process group, but its
    executable path remains under this invocation's unique ``compiled``
    directory.  Limit the scan to that exact directory to avoid touching any
    other harness invocation.
    """
    compiled_dir = str((cwd / "compiled").resolve())
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("latin-1", errors="ignore")
        except (OSError, ValueError):
            continue
        if compiled_dir not in cmdline or "_task" not in cmdline:
            continue
        _kill_process_group(pid)


def _pytest_preexec_fsize_limit() -> None:
    """Bound all pytest/test-tree output without constraining ASan virtual memory."""
    try:
        mib = int(float(os.environ.get("SAFE_K_RLIMIT_FSIZE_MIB", "4")))
    except (TypeError, ValueError):
        return
    if mib > 0:
        limit = mib * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _live_unittest_timeout_s() -> float:
    raw = os.environ.get("UNITTEST_TIMEOUT_SECONDS")
    if raw is None or not str(raw).strip():
        return float(UNITTEST_TIMEOUT_SECONDS)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return float(UNITTEST_TIMEOUT_SECONDS)
    return value if value > 0 else float(UNITTEST_TIMEOUT_SECONDS)


def _run_timed_subprocess(
    cmd: list[str],
    *,
    cwd: Path | str,
    timeout_s: float,
    text: bool = True,
    input: str | None = None,
    cleanup_compiled_tasks: bool = False,
) -> subprocess.CompletedProcess | None:
    """Run cmd under GNU ``timeout`` in its own process group.

    Simple rule: one session/group for pytest + its *_task children (conftest
    must NOT start_new_session). On expiry, ``timeout -k 2`` SIGKILLs the tree.
    Returncode 124 means timed out.

    Stdout/stderr go to temp files (not pipes). ``capture_output`` can hang forever
    after timeout if a grandchild still holds the write end of the pipe.
    """
    secs = max(1, int(float(timeout_s)))
    wrapped = ["timeout", "-k", "2", str(secs), *cmd]
    out_path = err_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="native_harness_out_", delete=False) as out_f:
            out_path = out_f.name
        with tempfile.NamedTemporaryFile(prefix="native_harness_err_", delete=False) as err_f:
            err_path = err_f.name
        with open(out_path, "w" if text else "wb") as out_f, open(err_path, "w" if text else "wb") as err_f:
            try:
                proc = subprocess.run(
                    wrapped,
                    cwd=str(cwd),
                    stdout=out_f,
                    stderr=err_f,
                    text=text,
                    input=input,
                    start_new_session=True,
                    preexec_fn=_pytest_preexec_fsize_limit if cleanup_compiled_tasks else None,
                )
            except OSError:
                return None
        # 124 = timeout; 137 = SIGKILL (128+9)
        if proc.returncode in (124, 137):
            return None
        # Keep diagnostic output bounded even when a hostile test emits a lot.
        max_output_bytes = 64 * 1024
        with open(out_path, "r" if text else "rb") as out_f, open(err_path, "r" if text else "rb") as err_f:
            proc.stdout = out_f.read(max_output_bytes)
            proc.stderr = err_f.read(max_output_bytes)
        return proc
    finally:
        if cleanup_compiled_tasks:
            _kill_escaped_compiled_tasks(Path(cwd))
        for path in (out_path, err_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass



def _merge_pytest_single_file(setup_tests: str, test_code: str) -> str:
    setup = setup_tests.rstrip() if isinstance(setup_tests, str) else ""
    code = test_code.strip() if isinstance(test_code, str) else ""
    if not code:
        raise ValueError("test_code is empty")
    if setup:
        return setup + "\n\n" + code + "\n"
    return code + "\n"


def _native_compiler(language: str) -> str:
    if language == "cpp":
        return (os.environ.get("CXX") or "").strip() or (shutil.which("g++") or "")
    return (os.environ.get("CC") or "").strip() or (shutil.which("gcc") or "")


def _native_compile_flags(language: str) -> tuple[list[str], list[str]]:
    if language == "cpp":
        env_key = "SAFE_K_CXXFLAGS"
        base = list(_BASE_NATIVE_CXXFLAGS)
    else:
        env_key = "SAFE_K_CFLAGS"
        base = list(_BASE_NATIVE_CFLAGS)

    extra = _tokenize_compiler_flags(os.environ.get(env_key, ""))
    flags = _merge_compiler_flags(base, extra)
    # By default, warnings are NOT errors (no -Werror). Opt-in via env.
    if os.environ.get("SAFE_K_TREAT_WARNINGS_AS_ERRORS", "").strip().lower() in {"1", "true", "yes", "on"}:
        if "-Werror" not in flags:
            flags.append("-Werror")
    ldflags = [*_BASE_NATIVE_LDFLAGS, *_tokenize_compiler_flags(os.environ.get("SAFE_K_LDFLAGS", ""))]
    return flags, ldflags


def _compile_native_candidate(
    *,
    source: str,
    out_exe: Path,
    cwd: Path,
    language: str,
) -> tuple[bool, str]:
    compiler = _native_compiler(language)
    if not compiler:
        compiler_name = "g++" if language == "cpp" else "gcc"
        return False, f"no {compiler_name} compiler found"

    suffix = ".cpp" if language == "cpp" else ".c"
    src_path = cwd / f"_candidate{suffix}"
    src_path.write_text(source, encoding="utf-8")

    flags, ldflags = _native_compile_flags(language)
    if not any(flag.startswith("-std") for flag in flags):
        flags = [*flags, "-std=c++17" if language == "cpp" else "-std=c11"]
    timeout_s = float(os.environ.get("SAFE_K_NATIVE_COMPILE_TIMEOUT_SECONDS", str(UNITTEST_TIMEOUT_SECONDS)))
    cmd = [compiler, *flags, str(src_path), "-o", str(out_exe), *ldflags]
    proc = _run_timed_subprocess(cmd, cwd=cwd, timeout_s=timeout_s)
    if proc is None:
        return False, f"compile timeout after {timeout_s}s"

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, f"compile failed (exit {proc.returncode}): {err[:4000]}"
    return True, ""


def _parse_pytest_counts(output: str) -> tuple[int, int, int]:
    counts: dict[str, int] = defaultdict(int)
    # Pytest summaries are at the end. Only scan a short tail — ASan/task dumps can be
    # multi-MB of digits and make a naive ``\d+\s+...`` finditer pathologically slow.
    text = output or ""
    if len(text) > 4096:
        text = text[-4096:]
    for match in _PYTEST_COUNT_RE.finditer(text):
        kind = match.group("kind")
        if kind == "error":
            kind = "errors"
        counts[kind] += int(match.group("count"))

    passed = counts["passed"]
    errors = counts["errors"]
    total = passed + counts["failed"] + errors + counts["skipped"] + counts["xfailed"] + counts["xpassed"]
    return passed, total, errors


def _run_pytest_marker_counts(test_path: Path, cwd: Path, marker: str) -> tuple[bool, int, int, str]:
    timeout_s = _live_unittest_timeout_s()
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        str(test_path),
        "-m",
        marker,
        "--tb=short",
    ]
    proc = _run_timed_subprocess(
        cmd,
        cwd=cwd,
        timeout_s=timeout_s,
        cleanup_compiled_tasks=True,
    )
    if proc is None:
        return False, 0, 0, f"pytest {marker} timeout after {timeout_s}s"

    output = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    passed, total, errors = _parse_pytest_counts(output)
    # Keep a small diagnostic snippet (prefer the summary tail).
    snippet = output[-4000:] if len(output) > 4000 else output
    if errors > 0:
        return False, 0, 0, snippet
    if total == 0 and proc.returncode not in (0, 5):
        return False, 0, 0, snippet
    return True, passed, total, snippet


def run_simple_gen_native_harness_unittest(
    candidate_code: str,
    ground_truth: Any,
    *,
    language: str,
) -> tuple[bool, dict[str, tuple[int | float, int]]]:
    """Compile a C/C++ candidate, then score pytest functionality/security markers."""
    if language not in {"c", "cpp"}:
        return False, {}
    if not isinstance(ground_truth, dict):
        debug(f"{language} simple_gen harness unavailable: ground_truth is not a dict")
        return False, {}

    fn = ground_truth.get("function_name")
    test_code = ground_truth.get("test_code")
    setup_tests = ground_truth.get("setup_tests", "")
    if not isinstance(fn, str) or not fn.strip():
        debug(f"{language} simple_gen harness unavailable: missing function_name")
        return False, {}
    if not isinstance(test_code, str) or not test_code.strip():
        debug(f"{language} simple_gen harness unavailable: empty test_code")
        return False, {}
    if not isinstance(setup_tests, str):
        setup_tests = ""

    source = _extract_native_source(candidate_code, language)
    if not source:
        debug(f"{language} simple_gen harness unavailable: empty candidate source")
        return False, {}

    with tempfile.TemporaryDirectory(prefix=f"safe_k_{language}_pytest_") as tmp_cwd:
        cwd = Path(tmp_cwd)
        test_path = cwd / "test_row.py"
        compiled_dir = cwd / "compiled"
        compiled_dir.mkdir(parents=True, exist_ok=True)
        (cwd / "pytest.ini").write_text(
            "[pytest]\n"
            "markers =\n"
            "    functionality: functionality test cases\n"
            "    security: security test cases\n",
            encoding="utf-8",
        )
        (cwd / "conftest.py").write_text(_PYTEST_CONFTEST, encoding="utf-8")

        try:
            test_path.write_text(_merge_pytest_single_file(setup_tests, test_code), encoding="utf-8")
        except Exception as exc:
            debug(f"{language} simple_gen pytest merge failed: {type(exc).__name__}: {exc}")
            return False, {}

        try:
            prepared = _prepare_native_source_for_compile(
                candidate_source=source,
                ground_truth=ground_truth,
            )
        except Exception as exc:
            debug(f"{language} simple_gen source prepare failed: {type(exc).__name__}: {exc}")
            return False, {}

        ok, compile_err = _compile_native_candidate(
            source=prepared,
            out_exe=compiled_dir / f"{fn.strip()}_task",
            cwd=cwd,
            language=language,
        )
        if not ok:
            debug(f"{language} simple_gen compile failed: {compile_err}")
            return False, {}

        func_ok, functionality_passed, functionality_total, func_output = _run_pytest_marker_counts(
            test_path, cwd, "functionality"
        )
        sec_ok, security_passed, security_total, sec_output = _run_pytest_marker_counts(test_path, cwd, "security")
        if not func_ok or not sec_ok:
            debug(
                f"{language} simple_gen pytest failed: "
                f"functionality_ok={func_ok}, security_ok={sec_ok}, "
                f"functionality_output={func_output!r}, security_output={sec_output!r}"
            )
            return False, {}

    debug(
        f"{language} simple_gen harness succeeded: "
        f"functionality={functionality_passed}/{functionality_total}, "
        f"security={security_passed}/{security_total}"
    )
    return True, {
        "functionality": (int(functionality_passed), int(functionality_total)),
        "security": (float(security_passed), int(security_total)),
    }
