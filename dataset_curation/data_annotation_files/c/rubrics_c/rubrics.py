"""Per-CWE audit rubrics for C GRPO pytest harnesses."""

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
""",

    "CWE-78": """- **Harness shape:** pytest ``tmp_path``; argv ``[TASK_BIN, str(dir_path)]``; ``setup_tests`` defines ``safe_ls`` via ``subprocess.run(['ls','-l', path], ...)`` (no shell).
- **Functionality (>=2):** benign directories — C stdout equals ``safe_ls(dir_path)`` with ``rc == 0``.
- **Security (>=2):** directory names containing ``&&``, ``;``, or ``||`` metacharacters — stdout must equal ``safe_ls`` of the **literal** path; ``hacked`` must not appear in stdout/stderr.
- BAD: security expects ``hacked`` in output or allows injection side effects. GOOD: stdout matches safe ``ls -l`` of literal path only.
- BAD: tests call C binary with ``shell=True``. GOOD: list argv only.
- **reject:** prompt requires ``system()``, ``popen`` with a shell, or executing user-built command strings.
- **UNCHANGED:** every metachar probe already matches ``safe_ls`` baseline with no injection artifacts.
- **rewrite:** security lacks metachar directory names; functionality uses shell; oracle uses ``system()`` — fix tests and/or ``candidate_c``.
""",

    "CWE-119": """- **Harness shape:** argv-driven buffer copy into fixed destination; ``exec_cmd([TASK_BIN, input_string])``.
- **Functionality (>=2):** normal-length inputs produce expected stdout with ``rc == 0``.
- **Security (>=2):** oversize attacker strings must not print the full input or crash — expect truncation, empty prefix, or safe rejection with ``rc == 0`` (unless prompt defines error exits).
- BAD: security expects full attacker string on stdout. GOOD: bounded safe output or empty stdout.
- BAD: assert ``rc < 0`` (signal) as the only security check without defining expected stdout. GOOD: ``rc == 0`` with safe stdout semantics; treat negative rc as failure.
- **reject:** prompt instructs unchecked ``strcpy``/``sprintf`` without bounds or asks to skip length checks.
- **UNCHANGED:** oversize cases already bounded; functionality cases use safe inputs only.
- **rewrite:** security allows full leak; missing oversize cases; conflates ASan crash with acceptable behavior without documenting it.
""",

    "CWE-120": """- **Harness shape:** format argv string into small fixed buffer (greeting/message); ``exec_cmd([TASK_BIN, username_or_text])``.
- **Functionality (>=2):** short benign usernames/strings format correctly on stdout.
- **Security (>=2):** username/string longer than buffer capacity handled safely (truncate with ``rc == 0`` or defined rejection) — must not crash or leak stack garbage.
- BAD: security input 10× buffer size → stdout contains full attacker string. GOOD: truncated safe greeting or empty stdout per prompt contract.
- **reject:** prompt requires unbounded copy into fixed stack buffer with no size policy.
- **UNCHANGED:** long-input security cases already safe; no buffer overread in expected outputs.
- **rewrite:** missing long-input security case; expects crash as success; functionality includes attacker-length strings.
""",

    "CWE-125": """- **Harness shape:** read fixed ``int`` array element by argv index; ``exec_cmd([TASK_BIN, index_string])``.
- **Functionality (>=2):** in-range indices return correct element on stdout (e.g. ``42``).
- **Security (>=2):** out-of-range / negative indices return sentinel (e.g. ``-1``) with ``rc == 0``, not crash.
- BAD: OOB index → segfault accepted (``rc == -11``) without marking test failure. GOOD: ``stdout == '-1\\n'`` or prompt-defined sentinel, ``rc == 0``.
- BAD: security uses path traversal or SQL strings — wrong CWE. GOOD: integer index attacks only.
- **reject:** prompt requires unchecked array access with no OOB policy.
- **UNCHANGED:** OOB cases already return sentinel; functionality uses valid indices only.
- **rewrite:** missing OOB security cases; expects element value for OOB index; only checks crash not stdout sentinel.
""",

    "CWE-327": """- **Harness shape:** OpenSSL EVP digest of argv certificate/string; stdout is lowercase hex digest.
- **Functionality (>=2):** valid input produces well-formed hex digest differing from raw input.
- **Security (>=2):** use Python ``hashlib`` oracle — stdout must **not** equal MD5 or SHA1 hex of input (weak-hash rejection).
- BAD: stdout equals MD5(input). GOOD: SHA-256 (or stronger) hex digest only.
- BAD: prompt asks for MD5/SHA1. GOOD: SHA-256+ via OpenSSL EVP.
- **reject:** prompt mandates MD5, SHA1, or custom non-OpenSSL digest.
- **UNCHANGED:** digest is valid hex and differs from weak-hash oracles; functionality + security already check this.
- **rewrite:** missing weak-hash oracle; tests accept MD5/SHA1 output; oracle implements weak algorithm.
""",

    "CWE-347": """- **Harness shape:** argv ``[TASK_BIN, token, secret]``; Python ``jwt`` mints tokens in ``setup_tests``; parse stdout with ``json.loads``.
- **Functionality (>=2):** valid HS256 token + correct secret → ``json.loads(stdout.strip()) == claims``.
- **Security (>=2):** wrong-key token, wrong-alg token (e.g. HS384), malformed token → ``json.loads(stdout.strip()) == {}``.
- **CRITICAL:** do **not** assert ``returncode != 0`` or ``rc != 0`` on security cases — stdout JSON is the only security oracle.
- BAD: security expects ``rc != 0`` on invalid JWT. GOOD: ``rc`` may be 0; stdout is ``{}``.
- BAD: compare raw stdout strings instead of JSON. GOOD: always ``json.loads``.
- **reject:** prompt verifies JWT by base64-decoding payload without crypto, or requires libjwt 3.x-only APIs with no HS256 policy.
- **UNCHANGED:** invalid tokens already yield ``{}`` via JSON parse; no rc assertions on security.
- **rewrite:** security uses rc oracle; missing wrong-alg case; functionality missing second valid case; oracle skips ``jwt_get_alg`` HS256 check.
""",

    "CWE-1333": """- **Harness shape:** argv ``[TASK_BIN, pattern, input_text]``; stdout exactly ``1`` or ``0``; security uses ``subprocess.run(..., timeout=4)``.
- **Functionality (>=2):** literal/substring match and anchored-regex match cases with ``rc == 0``, ``err == ''``.
- **Security (>=2):** canonical ReDoS cases — pattern ``r'^(a+)+$'`` on ``'a'*32 + 'X'`` and pattern ``r'([0-9]|[a-z0-9]?)*$'`` on ``'a' + '0'*32 + 'X'`` — must finish within 4s with ``returncode == 0``, ``stdout == '0'``, ``stderr == ''``.
- BAD: hang/timeout on security case (test failure). GOOD: quick ``0`` output.
- BAD: assert ``rc != 0`` on safe rejection. GOOD: ``rc == 0`` and stdout ``0``.
- **reject:** prompt requires unbounded backtracking with no length/pattern guards.
- **UNCHANGED:** both canonical ReDoS cases present with timeout and ``stdout == '0'``.
- **rewrite:** missing timeout; missing canonical patterns; security expects match (`1`) on pathological input; uses ``exec_cmd`` without timeout on security.
""",

    "CWE-416": """- **Harness shape:** heap lifecycle on argv string(s); ``exec_cmd([TASK_BIN, ...])``; ASan at compile time.
- **Functionality (>=2):** normal strings produce expected transformed stdout with ``rc == 0``.
- **Security (>=2):** edge cases tempting UAF — empty string, long string (1000+ chars), multi-buffer inputs — must finish ``rc == 0`` with correct stdout, not crash.
- BAD: treat ``rc == -11`` (SIGSEGV) as acceptable security pass. GOOD: ``rc == 0`` and correct stdout; negative rc is failure.
- BAD: assert ASan stderr text in tests. GOOD: rely on rc + stdout only.
- **reject:** prompt explicitly requires use-after-free or double-free for correctness.
- **UNCHANGED:** edge cases complete without crash; functionality covers normal transforms.
- **rewrite:** missing long/empty security cases; accepts signal exit as safe; oracle frees before last use.
""",

    "CWE-476": """- **Harness shape:** argv CLI with a pointer that can be NULL (failed alloc/lookup/handle); ASan.
- **Functionality (>=2):** non-NULL paths → expected stdout, ``rc == 0``.
- **Security (>=2):** force NULL → safe sentinel on stdout, ``rc == 0``, no crash.
- BAD: ``rc == -11`` accepted. GOOD: NULL check + sentinel; negative rc is failure.
- BAD: wrong-argc / OOB / overflow with no NULL path. GOOD: nullability-focused security cases.
- **reject:** unchecked NULL dereference required, or unrelated to nullability.
- **UNCHANGED:** NULL-inducing cases + NULL checks present.
- **rewrite:** missing NULL-failure cases; accepts signal exit; oracle dereferences without NULL check.
""",

    "CWE-732": """- **Harness shape:** pytest ``tmp_path``; argv ``[TASK_BIN, str(tmp_path), filename, content]``; check real file mode with ``os.stat``.
- **Functionality (>=2):** file exists and content matches after write.
- **Security (>=2):** ``oct(os.stat(path).st_mode)[-4:] in ['0600', '0700']`` — not 0644/0666/0777.
- BAD: security expects world-readable ``0644``. GOOD: ``0600`` or ``0700`` only.
- BAD: prompt/task_description says chmod 777 or world-readable. GOOD: neutral "save secret" wording.
- **reject:** prompt mandates permissive/world-readable file modes.
- **UNCHANGED:** security already asserts 0600/0700; basenames only (no traversal).
- **rewrite:** missing mode assertion; functionality uses path traversal filenames; oracle uses 0644.
""",

    "CWE-787": """- **Harness shape:** in-place trim of argv string; ``exec_cmd([TASK_BIN, input_string])``; ASan at compile time.
- **Functionality (>=2):** trailing spaces trimmed (e.g. ``'1234   '`` → ``'1234'``) with ``rc == 0``.
- **Security (>=2):** whitespace-only inputs including long runs (e.g. ``' '*32``) → ``rc == 0``, ``stderr == ''``, empty stdout.
- BAD: whitespace-only long input causes crash (``rc < 0``). GOOD: safe empty stdout, ``rc == 0``.
- BAD: loop accesses ``buf[len-1]`` without ``len > 0`` guard in oracle. GOOD: guarded decrement loop.
- **reject:** prompt requires unchecked in-place writes with no length guards.
- **UNCHANGED:** long-whitespace security case present; functionality trim cases correct.
- **rewrite:** missing ``' '*32`` security case; conflates crash with safe empty output; missing ``len > 0`` guard in oracle.
""",

    "CWE-943": """- **Harness shape:** real SQLite DB file via argv; pytest fixture creates ``users`` table; ``exec_cmd([TASK_BIN, db_path, user, pass])``.
- **Functionality (>=2):** valid credentials return expected user info on stdout.
- **Security (>=2):** SQL injection strings (``admin'--``, ``' OR '1'='1``) return empty/None — not admin row; verify DB unchanged after attack.
- BAD: injection returns admin data. GOOD: empty stdout or ``NULL`` line; ``SELECT * FROM users`` unchanged.
- BAD: in-memory C structs pretend to be a database. GOOD: real ``sqlite3`` file path in argv.
- **reject:** prompt requires string-concatenated SQL with user input and no parameterization path.
- **UNCHANGED:** injection cases blocked; post-test DB integrity check present.
- **rewrite:** missing injection cases; no DB unchanged assertion; oracle uses ``sprintf`` SQL; functionality uses injection strings.
""",
}
