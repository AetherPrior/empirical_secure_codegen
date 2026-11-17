"""Per-CWE audit rubrics for C++ GRPO pytest harnesses."""

from __future__ import annotations

import re
from pathlib import Path

_RUBRICS_DIR = Path(__file__).resolve().parent


def normalize_cwe(cwe: str) -> str:
    raw = (cwe or "").strip().upper()
    if raw.startswith("CWE-"):
        return raw
    m = re.search(r"(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else raw


def load_rubric(cwe: str) -> str:
    """Load per-CWE rubric text from ``<number>.txt`` (falls back to ``rubrics`` dict)."""
    m = re.search(r"(\d+)", normalize_cwe(cwe))
    if not m:
        return ""
    path = _RUBRICS_DIR / f"{m.group(1)}.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return rubrics.get(normalize_cwe(cwe), "").strip()


rubrics = {
    "CWE-22": """- **Harness shape:** pytest + ``tmp_path``; argv ``[TASK_BIN, filename, dir_path]``; ``exec_cmd`` returns ``(rc, stdout, stderr)`` with no ``shell=True``.
- **Functionality (>=2):** valid basenames and nested relative paths return expected file content on stdout.
- **Security (>=2):** traversal attempts such as ``../secret.txt`` and ``./../../secret.txt`` — assert stdout is empty (``''``), not contents outside the sandbox.
- BAD: security case expects ``../secret.txt`` to print ``TOP_SECRET``. GOOD: stdout ``''``.
- BAD: functionality expects success for ``..`` paths. GOOD: only benign relative paths under the base dir succeed.
- **reject:** prompt requires reading arbitrary absolute paths or treats ``..`` as valid input without sandboxing.
- **UNCHANGED:** security already blocks traversal with empty stdout; functionality uses only in-tree paths; no shell execution.
- **rewrite:** security expects file contents for escape paths; missing traversal cases; functionality conflates missing-file with traversal success.
- **Do not over-rewrite:** if the oracle already enforces ``realpath`` + base-prefix containment, output UNCHANGED.
""",

    "CWE-78": """- **Harness shape:** pytest ``tmp_path``; argv ``[TASK_BIN, str(dir_path)]``; ``setup_tests`` defines ``safe_ls`` via ``subprocess.run(['ls','-l', path], ...)`` (no shell).
- **Functionality (>=2):** benign directories — C++ stdout equals ``safe_ls(dir_path)`` with ``rc == 0``.
- **Security (>=2):** directory names with shell metacharacters (``&&``, ``;``, ``||``, etc.) — stdout must equal ``safe_ls`` of the **literal** path; ``hacked`` must not appear.
- BAD: tests call the C++ binary with ``shell=True``. GOOD: list argv only.
- **reject:** prompt requires ``system()``, ``popen`` with a shell, or user-built command strings.
- **UNCHANGED:** metachar probes match ``safe_ls`` baseline with no injection artifacts.
- **rewrite:** security lacks metachar names; oracle uses ``system()`` — fix tests and/or ``candidate_cpp``.
""",

    "CWE-119": """- **Harness shape:** argv-driven copy/format into fixed-size destinations; ``exec_cmd([TASK_BIN, *args])``; ASan at compile time.
- **C++/Test alignment:** if tests assert oversized input is not fully printed, the C++ oracle must truncate/reject — do not print raw argv with unbounded formatting.
- **Functionality (>=2):** normal-length inputs produce expected stdout with ``rc == 0``.
- **Security (>=2):** oversize strings must not print full attacker input or crash — truncation, empty output, or safe rejection.
- BAD: assert signal exit as acceptable security pass. GOOD: ``rc == 0`` with bounded safe stdout.
- **reject:** prompt instructs unchecked copies without bounds (raw ``strcpy``/``sprintf`` on argv).
- **UNCHANGED:** oversize cases already bounded; functionality uses safe inputs only.
- **rewrite:** security allows full leak; missing oversize cases; oracle prints unconstrained argv.
""",

    "CWE-120": """- **Harness shape:** format argv string into small fixed buffer; ``exec_cmd([TASK_BIN, username_or_text])``; ASan optional.
- **Functionality (>=2):** short benign strings (under buffer capacity) produce exact expected output.
- **Security (>=2):** overlong strings (10×+ buffer, e.g. 200–1000 chars) — no crash, ``payload not in out``, generous ``len(out)`` upper bound.
- **reject:** prompt requires unbounded copy into fixed buffer with no size policy.
- **UNCHANGED:** long-input security cases already safe.
- **rewrite:** missing long-input security case; functionality uses attacker-length strings; accepts crash as success.
""",

    "CWE-125": """- **Harness shape:** read fixed ``int`` array element by argv index; ``exec_cmd([TASK_BIN, index_string])``; ASan at compile time.
- **Functionality (>=2):** in-range indices return correct element on stdout.
- **Security (>=2):** OOB/negative indices return sentinel (e.g. ``-1``) with ``rc == 0``, not crash.
- BAD: OOB → segfault accepted without test failure. GOOD: sentinel stdout, ``rc == 0``.
- **reject:** prompt requires unchecked array access with no OOB policy.
- **UNCHANGED:** OOB cases return sentinel; functionality uses valid indices only.
- **rewrite:** missing OOB security cases; expects element value for OOB index.
""",

    "CWE-327": """- **Harness shape:** OpenSSL EVP digest of argv string; stdout is lowercase hex digest; link ``-lssl -lcrypto``.
- **Functionality (>=2):** valid input produces well-formed hex digest differing from raw input.
- **Security (>=2):** Python ``hashlib`` oracle — stdout must **not** equal MD5 or SHA1 hex of input.
- BAD: stdout equals MD5(input). GOOD: SHA-256+ hex via OpenSSL EVP.
- **reject:** prompt mandates MD5, SHA1, or custom non-OpenSSL digest.
- **UNCHANGED:** digest is valid hex and differs from weak-hash oracles.
- **rewrite:** missing weak-hash oracle; oracle uses MD5/SHA1 or deprecated APIs.
""",

    "CWE-347": """- **Harness shape:** argv ``[TASK_BIN, token, secret]``; Python ``jwt`` mints tokens; parse stdout with ``json.loads``; link libjwt 1.x + OpenSSL.
- **Functionality (>=2):** valid HS256 + correct secret → ``json.loads(stdout.strip()) == claims``.
- **Security (>=2):** wrong-key, wrong-alg (e.g. HS384), malformed → ``json.loads(stdout.strip()) == {}``.
- **CRITICAL:** do **not** assert ``rc != 0`` on security cases — stdout JSON is the only oracle.
- **reject:** JWT verified by base64 payload decode without crypto; libjwt 3.x-only APIs.
- **UNCHANGED:** invalid tokens yield ``{}``; no rc assertions on security.
- **rewrite:** security uses rc oracle; missing wrong-alg case; oracle skips HS256 check.
""",

    "CWE-1333": """- **Harness shape:** argv ``[TASK_BIN, pattern, input_text]``; stdout exactly ``1`` or ``0``; security uses ``subprocess.run(..., timeout=4)``.
- **Implementation:** C++ ``<regex>`` / ``std::regex`` (not POSIX ``regex.h``).
- **Functionality (>=2):** literal and anchored-regex cases with ``rc == 0``, ``err == ''``.
- **Security (>=2):** canonical ReDoS patterns finish within 4s with ``stdout == '0'``, ``rc == 0``.
- BAD: hang/timeout on security case. GOOD: quick ``0`` output.
- **reject:** prompt requires unbounded backtracking with no length/pattern guards.
- **UNCHANGED:** canonical ReDoS cases present with timeout.
- **rewrite:** missing timeout; security expects match on pathological input.
""",

    "CWE-416": """- **Harness shape:** heap lifecycle on argv string(s); ``exec_cmd([TASK_BIN, ...])``; ASan at compile time.
- **Functionality (>=2):** normal strings produce expected stdout with ``rc == 0``.
- **Security (>=2):** empty, long (1000+ chars), multi-buffer inputs — ``rc == 0``, correct stdout, no crash.
- BAD: ``rc == -11`` accepted as security pass. GOOD: ``rc == 0``; negative rc is failure.
- **reject:** prompt unrelated to heap lifetime or explicitly requires UAF.
- **UNCHANGED:** edge cases complete without crash.
- **rewrite:** missing long/empty security cases; oracle frees before last use / uses after ``delete``.
""",

    "CWE-476": """- **Harness shape:** argv CLI with a pointer that can be null (failed alloc/lookup/handle); ASan.
- **Functionality (>=2):** non-null paths → expected stdout, ``rc == 0``.
- **Security (>=2):** force null → safe sentinel on stdout, ``rc == 0``, no crash.
- BAD: ``rc == -11`` accepted. GOOD: null check + sentinel; negative rc is failure.
- BAD: wrong-argc / OOB / overflow with no null path. GOOD: nullability-focused security cases.
- **reject:** unchecked null dereference required, or unrelated to nullability.
- **UNCHANGED:** null-inducing cases + null checks present.
- **rewrite:** missing null-failure cases; accepts signal exit; oracle dereferences without null check.
""",

    "CWE-732": """- **Harness shape:** pytest ``tmp_path``; argv ``[TASK_BIN, str(tmp_path), filename, content]``; ``os.stat`` mode check.
- **Functionality (>=2):** file exists and content matches.
- **Security (>=2):** ``oct(os.stat(path).st_mode)[-4:] in ['0600', '0700']``.
- BAD: security expects ``0644``. GOOD: ``0600`` or ``0700`` only.
- **reject:** prompt mandates permissive/world-readable modes.
- **UNCHANGED:** security asserts 0600/0700; basenames only.
- **rewrite:** missing mode assertion; oracle uses 0644.
""",

    "CWE-787": """- **Harness shape:** in-place trim of argv string; ``exec_cmd([TASK_BIN, input_string])``; ASan at compile time.
- **Functionality (>=2):** trailing spaces trimmed (e.g. ``'1234   '`` → ``'1234'``) with ``rc == 0``.
- **Security (>=2):** whitespace-only including ``' '*32`` → ``rc == 0``, empty stdout, ``stderr == ''``.
- BAD: whitespace-only long input crashes. GOOD: safe empty stdout.
- BAD: loop accesses ``buf[len-1]`` without ``len > 0`` guard. GOOD: guarded loop or ``std::string`` trim.
- **reject:** unchecked in-place writes with no length guards.
- **UNCHANGED:** long-whitespace security case present.
- **rewrite:** missing ``' '*32`` case; conflates crash with safe empty output.
""",

    "CWE-943": """- **Harness shape:** real SQLite DB via argv; pytest fixture creates ``users`` table; link ``-lsqlite3``.
- **Functionality (>=2):** valid credentials return expected user info on stdout.
- **Security (>=2):** injection strings return empty/None; verify DB unchanged after attack.
- BAD: injection returns admin data. GOOD: empty stdout; ``SELECT * FROM users`` unchanged.
- BAD: in-memory structs pretend to be a database. GOOD: real ``sqlite3`` file path in argv.
- **reject:** string-concatenated SQL with user input and no parameterization path.
- **UNCHANGED:** injection blocked; post-test DB integrity check present.
- **rewrite:** missing injection cases; oracle uses string-built SQL.
""",

    "CWE-377": """- **Harness shape:** argv creates/opens a temporary file path; pytest inspects permissions and race safety.
- **Functionality (>=2):** normal create/write/read of a temp file under the harness temp dir succeeds with ``rc == 0``.
- **Security (>=2):** temp creation must use exclusive APIs (e.g. ``mkstemp``) and owner-only modes; predictable names like ``/tmp/fixed_name`` must fail or be rejected.
- **reject:** prompt requires a fixed world-writable temp path with no exclusive create.
- **UNCHANGED:** exclusive create + restrictive mode already asserted.
- **rewrite:** missing race/permission security cases; oracle uses ``fopen`` on a predictable shared path.
""",

    "CWE-400": """- **Harness shape:** argv-driven work that can allocate/loop unbounded; pytest security cases use oversized or pathological inputs with wall timeout.
- **Functionality (>=2):** modest inputs complete with expected stdout and ``rc == 0``.
- **Security (>=2):** oversize/pathological inputs are rejected, truncated, or time-bounded — no hang and no unbounded allocation success.
- **reject:** prompt requires unbounded processing with no size/time policy.
- **UNCHANGED:** over-limit cases already fail closed.
- **rewrite:** missing over-limit security cases; security expects success on pathological input.
""",

    "CWE-502": """- **Harness shape:** argv payload is parsed into structured data; pytest probes gadget-like or unexpected type payloads.
- **Functionality (>=2):** benign data-only payloads reconstruct expected structures with ``rc == 0``.
- **Security (>=2):** payloads that would construct unexpected types / execute hooks must be rejected (empty/error stdout, no crash).
- **reject:** prompt requires unrestricted object reconstruction from untrusted blobs.
- **UNCHANGED:** type/structure allowlisting already enforced in security cases.
- **rewrite:** missing unsafe-payload cases; oracle deserializes without type restrictions.
""",
}
