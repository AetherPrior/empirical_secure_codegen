#!/usr/bin/env bash
# Source from run_validate_c.sh / pilot scripts to export native dep paths.
# Detection logic lives in c/native_deps.py (single source of truth).

apply_native_deps_env() {
  local here="${1:-}"
  if [[ -z "${here}" ]]; then
    echo "apply_native_deps_env: missing simple_gen root path" >&2
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    return 0
  fi
  # shellcheck disable=SC1090
  eval "$(SIMPLE_GEN_DIR="${here}" python3 - <<'PY'
import os
import sys
from pathlib import Path

here = Path(os.environ["SIMPLE_GEN_DIR"])
sys.path.insert(0, str(here / "c"))
from native_deps import libjwt1_status_line, native_compile_env, openssl_prefix, libjwt1_prefix

cwe = os.environ.get("CWE", "")
env = native_compile_env(cwe)
lines = []
# Export whatever native_compile_env changed (includes ASAN_OPTIONS for CWE-476).
for key, val in env.items():
    if val != os.environ.get(key, ""):
        safe = val.replace("'", "'\\''")
        lines.append(f"export {key}='{safe}'")
lj = libjwt1_prefix()
if lj:
    lines.append(f"export LIBJWT1_PREFIX='{lj}'")
ossl = openssl_prefix()
if ossl:
    lines.append(f"export OPENSSL_PREFIX='{ossl}'")
print(f"echo '[native_deps] {libjwt1_status_line()}'")
asan = env.get("ASAN_OPTIONS") or ""
if asan:
    print(f"echo '[native_deps] ASAN_OPTIONS={asan}'")
print("\n".join(lines))
PY
)"
}
