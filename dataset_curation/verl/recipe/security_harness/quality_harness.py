"""Static quality checks (mypy) for candidate code."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MYPY_REPRO_DIR = os.getenv("MYPY_REPRO_DIR", "/tmp/safe_k_reward_mypy_repro")
_REWARD_DEBUG = os.getenv("REWARD_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}


def _debug(msg: str) -> None:
    if _REWARD_DEBUG:
        print(f"[quality_harness] {msg}", file=sys.stderr, flush=True)


def _add_imports_for_mypy(code: str) -> str:
    import_header = "from typing import *\n"
    code = code.strip()
    if import_header not in code:
        code = f"{import_header}\n{code}"
    return code



def mypy_score(code: str) -> float:
    source = _add_imports_for_mypy(code)
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as temp_file:
        temp_file.write(source)
        temp_name = temp_file.name

    cache_dir = tempfile.mkdtemp(prefix="mypy_cache_")
    try:
        # Run mypy in a subprocess to fully capture output from internal crashes.
        # Use isolated cache dir + non-incremental mode to avoid cache races across workers.
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                temp_name,
                "--no-color-output",
                "--strict",
                "--no-incremental",
                "--show-traceback",
                "--cache-dir",
                cache_dir,
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        result = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        _debug("mypy timed out; returning -0.5")
        return -0.5
    except Exception as exc:
        _debug(f"mypy execution failed: {type(exc).__name__}: {exc}; returning -0.5")
        return -0.5
    finally:
        try:
            os.unlink(temp_name)
        except Exception:
            pass
        try:
            import shutil

            shutil.rmtree(cache_dir, ignore_errors=True)
        except Exception:
            pass

    if exit_code == 0:
        _debug("mypy passed with score=1.0")
        return 1.0
    if exit_code == 1:
        match = re.search(r"Found (\d+) error", result)
        error_count = int(match.group(1)) if match else 1
        score = max(0.0, 1.0 - 0.5 * max(1, error_count))
        _debug(f"mypy found errors={error_count}, score={score:.4f}")
        return score
    if "INTERNAL ERROR" in result:
        digest = hashlib.sha256(source.encode("utf-8", errors="ignore")).hexdigest()[:16]
        repro_path = Path(MYPY_REPRO_DIR) / f"mypy_crash_{digest}.py"
        try:
            repro_path.parent.mkdir(parents=True, exist_ok=True)
            repro_path.write_text(source, encoding="utf-8")
        except Exception as exc:
            _debug(f"failed to persist mypy repro file: {type(exc).__name__}: {exc}")

        try:
            version_proc = subprocess.run(
                [sys.executable, "-m", "mypy", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            version_text = ((version_proc.stdout or "") + (version_proc.stderr or "")).strip().replace("\n", " | ")
        except Exception as exc:
            version_text = f"failed to query mypy version: {type(exc).__name__}: {exc}"

        # Keep logs compact but actionable.
        err_preview = result[:1200].replace("\n", "\\n")
        _debug(
            "mypy internal error observed; "
            f"mypy_version={version_text!r}, "
            f"repro_file={str(repro_path)!r}, "
            "repro_cmd="
            f"{sys.executable} -m mypy --strict --no-incremental --show-traceback {repro_path!s}, "
            f"stderr_preview={err_preview!r}"
        )
        return -0.5
    _debug(f"mypy returned unexpected exit_code={exit_code}; score=-0.5")
    return -0.5



