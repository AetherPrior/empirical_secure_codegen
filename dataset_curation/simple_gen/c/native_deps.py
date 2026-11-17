"""Detect native library prefixes for the C pipeline (libjwt 1.x, Homebrew OpenSSL).

Used by ``cwe_rules`` and the stage-5 C harness so CWE-347 can compile against
``jwt_decode()`` (libjwt 1.x) instead of Homebrew's libjwt 3.x.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LIBJWT1_DEFAULT_PREFIX = "/opt/libjwt-1"
_LIBJWT1_API_MARKERS = ("jwt_decode", "jwt_get_grants_json")


def _normalize_cwe_id(cwe: str) -> str:
    raw = (cwe or "").strip().upper()
    if not raw:
        return ""
    if raw.startswith("CWE-"):
        return raw
    return f"CWE-{raw}"


def _header_has_libjwt1_api(jwt_h: Path) -> bool:
    try:
        text = jwt_h.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return all(marker in text for marker in _LIBJWT1_API_MARKERS)


def libjwt1_prefix() -> Optional[Path]:
    """Return install prefix when libjwt 1.x headers are present."""
    candidates: List[Path] = []
    env_prefix = (os.getenv("LIBJWT1_PREFIX") or "").strip()
    if env_prefix:
        candidates.append(Path(env_prefix))
    candidates.append(Path(LIBJWT1_DEFAULT_PREFIX))
    home = Path.home() / ".local" / "libjwt-1"
    candidates.append(home)

    seen: set[str] = set()
    for prefix in candidates:
        key = str(prefix.resolve()) if prefix.exists() else str(prefix)
        if key in seen:
            continue
        seen.add(key)
        jwt_h = prefix / "include" / "jwt.h"
        if jwt_h.is_file() and _header_has_libjwt1_api(jwt_h):
            return prefix
    return None


def _brew_prefix(formula: str) -> Optional[Path]:
    brew = shutil.which("brew")
    if not brew:
        return None
    try:
        proc = subprocess.run(
            [brew, "--prefix", formula],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    path = proc.stdout.strip()
    if not path:
        return None
    p = Path(path)
    return p if p.is_dir() else None


def openssl_prefix() -> Optional[Path]:
    explicit = (os.getenv("OPENSSL_PREFIX") or "").strip()
    if explicit:
        p = Path(explicit)
        if (p / "include" / "openssl").is_dir():
            return p
    brew = _brew_prefix("openssl@3")
    if brew and (brew / "include" / "openssl").is_dir():
        return brew
    return None


def jansson_prefix() -> Optional[Path]:
    explicit = (os.getenv("JANSSON_PREFIX") or "").strip()
    if explicit:
        p = Path(explicit)
        if (p / "include" / "jansson.h").is_file():
            return p
    brew = _brew_prefix("jansson")
    if brew and (brew / "include" / "jansson.h").is_file():
        return brew
    return None


def native_include_ld_flags(cwe: str) -> Tuple[str, str]:
    """Extra ``-I`` / ``-L`` flags for native dependencies required by CWE tasks."""
    c = _normalize_cwe_id(cwe)
    inc: List[str] = []
    ld: List[str] = []

    if c in ("CWE-327", "CWE-329", "CWE-347", "CWE-943", "CWE-89"):
        ossl = openssl_prefix()
        if ossl:
            inc.append(f"-I{ossl}/include")
            ld.append(f"-L{ossl}/lib")

    if c == "CWE-347":
        lj = libjwt1_prefix()
        if lj:
            inc.append(f"-I{lj}/include")
            ld.append(f"-L{lj}/lib")
        else:
            jan = jansson_prefix()
            if jan:
                inc.append(f"-I{jan}/include")
                ld.append(f"-L{jan}/lib")

    return " ".join(inc), " ".join(ld)


def _prepend_path(env_key: str, new_segment: str, env: Dict[str, str]) -> None:
    if not new_segment:
        return
    cur = env.get(env_key, "")
    parts = [p for p in cur.split(os.pathsep) if p]
    if new_segment not in parts:
        env[env_key] = new_segment + (os.pathsep + cur if cur else "")


def native_compile_env(cwe: str = "") -> Dict[str, str]:
    """Environment overrides for compile + pytest subprocess (runtime loader paths)."""
    env = dict(os.environ)
    c = _normalize_cwe_id(cwe)

    if c in ("CWE-327", "CWE-329", "CWE-347", "CWE-943", "CWE-89"):
        ossl = openssl_prefix()
        if ossl:
            _prepend_path("C_INCLUDE_PATH", str(ossl / "include"), env)
            _prepend_path("CPATH", str(ossl / "include"), env)
            for key in ("LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
                _prepend_path(key, str(ossl / "lib"), env)

    if c == "CWE-347":
        lj = libjwt1_prefix()
        if lj:
            _prepend_path("C_INCLUDE_PATH", str(lj / "include"), env)
            _prepend_path("CPATH", str(lj / "include"), env)
            for key in ("LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
                _prepend_path(key, str(lj / "lib"), env)
        else:
            jan = jansson_prefix()
            if jan:
                _prepend_path("C_INCLUDE_PATH", str(jan / "include"), env)
                for key in ("LIBRARY_PATH", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"):
                    _prepend_path(key, str(jan / "lib"), env)

    # CWE-476 CWEval-style huge malloc must return NULL under ASan (else ASan aborts
    # with allocation-size-too-big / thrash before the program can check the pointer).
    # log_path keeps the "failed to allocate" WARNING off stderr so pytest can assert stderr=="".
    if c == "CWE-476":
        existing = (env.get("ASAN_OPTIONS") or "").strip()
        extras = [
            "allocator_may_return_null=1",
            "detect_leaks=0",
            "halt_on_error=1",
            "abort_on_error=1",
            "log_path=/tmp/asan_simple_gen_cwe476",
        ]
        parts = [p for p in existing.split(":") if p] if existing else []
        for flag in extras:
            key = flag.split("=", 1)[0]
            if not any(p.startswith(key + "=") or p == key for p in parts):
                parts.append(flag)
        env["ASAN_OPTIONS"] = ":".join(parts)

    return env


def libjwt1_status_line() -> str:
    lj = libjwt1_prefix()
    if lj:
        return f"libjwt 1.x: {lj}"
    return "libjwt 1.x: not found (CWE-347 needs scripts/install_libjwt1.sh or apt libjwt-dev on Linux)"
