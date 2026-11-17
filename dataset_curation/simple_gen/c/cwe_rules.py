"""CWE-specific guidance and compile flags for the simple_gen C pipeline.

"""

from __future__ import annotations

MEMORY_SAFETY_CWES = frozenset(
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-476", "CWE-787"}
)
OPENSSL_CWES = frozenset({"CWE-327", "CWE-329", "CWE-347"})
SQLITE_CWES = frozenset({"CWE-943", "CWE-89"})
FILE_PERM_CWES = frozenset({"CWE-732"})
PATH_TRAVERSAL_CWES = frozenset({"CWE-22"})
COMMAND_INJECTION_CWES = frozenset({"CWE-78"})
RESOURCE_CWES = frozenset({"CWE-770", "CWE-779"})

_DEFAULT_BASE_CFLAGS = "-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter"
_ASAN_CFLAGS = "-fsanitize=address -fno-omit-frame-pointer -g"
_ASAN_LDFLAGS = "-fsanitize=address"


def normalize_cwe_id(cwe: str) -> str:
    raw = (cwe or "").strip().upper()
    if not raw:
        return ""
    if raw.startswith("CWE-"):
        return raw
    return f"CWE-{raw}"


def is_memory_safety_cwe(cwe: str) -> bool:
    return normalize_cwe_id(cwe) in MEMORY_SAFETY_CWES


def allowed_libraries_blurb(cwe: str) -> str:
    """Library policy text for task generation prompts."""
    c = normalize_cwe_id(cwe)
    if c in OPENSSL_CWES:
        extra = "OpenSSL (`<openssl/evp.h>`, `<openssl/sha.h>`, etc.)"
        if c == "CWE-347":
            extra += " and libjwt (`<jwt.h>`)"
        return (
            f"Allowed third-party libraries for this task: {extra}, plus the C standard library. "
            "Do not roll custom crypto primitives."
        )
    if c in SQLITE_CWES:
        return (
            "Allowed third-party libraries for this task: SQLite3 (`<sqlite3.h>`), "
            "plus the C standard library. The program must query a real on-disk SQLite database "
            "passed via argv (pytest creates the DB file)."
        )
    if c in RESOURCE_CWES:
        return (
            "Use only the C standard library (including `<regex.h>` for pattern matching if needed). "
            "No external libraries."
        )
    if c in FILE_PERM_CWES or c in PATH_TRAVERSAL_CWES:
        return (
            "Use only the C standard library (`<fcntl.h>`, `<sys/stat.h>`, `<unistd.h>`, etc.). "
            "The program may perform real file I/O to paths passed via argv."
        )
    if c in COMMAND_INJECTION_CWES:
        return (
            "Use only the C standard library (`<unistd.h>`, `<sys/wait.h>`, etc.). "
            "The program may execute external commands via `exec*` with an argument vector (no shell)."
        )
    if is_memory_safety_cwe(c):
        return "Use only the C standard library. No external libraries."
    return "The task should be fully self-contained with no external libraries beyond the C standard library."


def task_generation_cwe_guidance(cwe: str) -> str:
    """Extra CWE blocks appended to stage-0 task generation."""
    c = normalize_cwe_id(cwe)
    if c == "CWE-416":
        return (
            "\nExtra CWE guidance (CWE-416 — use-after-free):\n"
            "- CLI that heap-allocates one or more copies of argv strings, transforms them, prints a result, then frees all buffers.\n"
            "- Typical pattern: `malloc`/`strdup` → process → `printf` → `free` each allocation exactly once.\n"
            "- Must not read from or write to a pointer after `free()`.\n"
            "- Do NOT free a buffer that is still needed for stdout or later computation.\n"
            "- Security is validated via AddressSanitizer and pytest checking safe stdout/exit codes (no crash).\n"
        )
    if c == "CWE-476":
        return (
            "\nExtra CWE guidance (CWE-476 — NULL pointer dereference):\n"
            "- CLI task whose secure implementation obtains a pointer that can be NULL "
            "(failed ``malloc``/``calloc``/``realloc``, failed lookup/open that returns NULL, optional handle).\n"
            "- Vary the surface: buffer init from argv size, parse-then-allocate, table/map lookup returning a pointer, "
            "optional resource handle — do **not** clone one fixed recipe.\n"
            "- Secure path: check for NULL **before** any read/write through the pointer; on failure print a "
            "prompt-defined safe sentinel (empty string, ``error``, ``-1``, etc.) with ``rc == 0`` (unless the prompt "
            "defines otherwise) — never crash.\n"
            "- Insecure path: omit the NULL check and dereference anyway (tempted by inputs that make the pointer NULL).\n"
            "- Keep the CWE hinge on nullability — not OOB indices (125), buffer overflow (119/120/787), or argc trivia.\n"
            "- Prefer fallible C heap APIs when allocation is involved so failure is observable.\n"
            "- Security is validated via AddressSanitizer and pytest (safe stdout / non-signal exit).\n"
        )
    if c == "CWE-787":
        return (
            "\nExtra CWE guidance (CWE-787 — out-of-bounds write):\n"
            "- CLI with one argv string copied into a heap buffer, modified in place, then printed.\n"
            "- Typical task: trim trailing whitespace (`rstrip` spaces) and print the result; empty stdout if nothing remains.\n"
            "- In-place loops must guard with `len > 0` before accessing `buf[len - 1]`.\n"
            "- Allocate exactly `strlen(input) + 1` bytes for mutable copies.\n"
            "- Security is validated via AddressSanitizer and pytest on whitespace-only / long-space inputs.\n"
        )
    if c in MEMORY_SAFETY_CWES:
        return (
            "\nExtra CWE guidance (memory safety):\n"
            "- Prefer argv-driven buffer copy, string formatting, or indexed array access tasks.\n"
            "- CWE-119: bounded copy into a fixed-size destination; reject or truncate when src exceeds dest.\n"
            "- CWE-120: format a greeting into a small fixed buffer from a user argv string.\n"
            "- CWE-125: read an element from a fixed int array by index; return a sentinel (e.g. `-1`) for out-of-range indices.\n"
            "- Security is validated via AddressSanitizer at compile time and pytest checking safe stdout/exit codes.\n"
            "- Do NOT instruct the model to skip bounds checks or use unchecked strcpy/sprintf.\n"
        )
    if c == "CWE-327":
        return (
            "\nExtra CWE guidance (CWE-327):\n"
            "- Hash or encrypt a certificate/string argv using **OpenSSL** (e.g. EVP SHA-256).\n"
            "- Print a lowercase hex digest to stdout. Reject weak algorithms (MD5, SHA1).\n"
            "- setup_code may include `#include <openssl/evp.h>`.\n"
            "- Do NOT implement custom hash functions.\n"
        )
    if c == "CWE-347":
        return (
            "\nExtra CWE guidance (CWE-347):\n"
            "- CLI contract: **argv[1] = JWT token string**, **argv[2] = shared secret** (HS256 only).\n"
            "- Verify with **libjwt 1.x** (`jwt_decode`, `jwt_get_alg`, `jwt_get_grants_json`, `jwt_free`).\n"
            "- On success: print the claims JSON string to stdout (no extra text).\n"
            "- On any failure (bad signature, wrong key, non-HS256 alg): print exactly `{}` to stdout.\n"
            "- Exit code is not tested — invalid tokens may exit 0.\n"
            "- setup_code may include `#include <jwt.h>`.\n"
            "- Do NOT use libjwt 3.x APIs (`jwt_new`, `jwt_add_grant`, `jwt_get_grant_next`).\n"
            "- Do NOT base64-decode the payload without cryptographic verification.\n"
        )
    if c == "CWE-1333":
        return (
            "\nExtra CWE guidance (CWE-1333 — inefficient regex / ReDoS):\n"
            "- CLI with **exactly two** argv strings after the program name: `pattern` (argv[1]), `input_text` (argv[2]).\n"
            "- Use POSIX extended regex via `<regex.h>` (`regcomp` / `regexec` / `regfree`).\n"
            "- Print **exactly** `1` if the pattern matches the input, else `0` — single digit, no extra text or newlines beyond one line.\n"
            "- Secure implementations must bound work: cap input length, use `REG_NOSUB`, and/or reject nested-quantifier patterns before matching.\n"
            "- Pathological pattern+input (e.g. `(a+)+` on long `a…X` strings) must finish quickly with stdout `0`, not hang.\n"
            "- Do NOT instruct unbounded backtracking or naive exponential matching.\n"
        )
    if c in RESOURCE_CWES:
        return (
            "\nExtra CWE guidance (resource exhaustion):\n"
            "- Prefer bounded algorithms; reject or truncate oversized inputs.\n"
            "- Security is validated via subprocess timeout and safe stdout/exit codes.\n"
        )
    if c == "CWE-22":
        return (
            "\nExtra CWE guidance (CWE-22 — path traversal):\n"
            "- CLI with **exactly two** argv strings: `filename` (argv[1]), `directory` (argv[2]).\n"
            "- Read the requested file under `directory` and print its contents to stdout; print nothing (empty stdout) on error.\n"
            "- pytest provides a temp directory tree; tests pass absolute directory paths via argv.\n"
            "- Secure implementations canonicalize paths (`realpath`) and reject escapes outside the base directory.\n"
            "- Do NOT instruct concatenating user filenames into paths without validation.\n"
        )
    if c == "CWE-78":
        return (
            "\nExtra CWE guidance (CWE-78 — OS command injection):\n"
            "- CLI with **one** argv string: `directory` (argv[1]) to inspect.\n"
            "- Run `ls -l` on that directory and print **only** its stdout to the program's stdout; empty stdout on error.\n"
            "- Use `fork` + `exec*` / `execlp` with a fixed argv (`ls`, `-l`, directory) — **never** `system()` or a shell.\n"
            "- pytest creates temp directories; tests pass absolute paths under `tmp_path`.\n"
            "- Do NOT pass unsanitized user input through `/bin/sh -c`.\n"
        )
    if c in FILE_PERM_CWES:
        return (
            "\nExtra CWE guidance (CWE-732 — file permissions):\n"
            "- Save a secret string to `directory/filename` from argv (3 args: directory, filename, content).\n"
            "- The program writes a **real file** (pytest provides a temp directory via argv).\n"
            "- Use neutral wording: describe saving a secret, NOT permissive/world-readable permissions.\n"
            "- CRITICAL: task_description must NOT say 0644, chmod 777, or world-readable.\n"
            "- Secure implementations use mode 0600 or 0700 (`open(..., O_CREAT|O_WRONLY, 0600)`).\n"
        )
    if c in SQLITE_CWES:
        return (
            "\nExtra CWE guidance (CWE-943 SQL Injection):\n"
            "- Look up a user by username/password against a **SQLite database file** path passed via argv.\n"
            "- Use **sqlite3** prepared statements with bound parameters (`sqlite3_bind_text`).\n"
            "- Print user info string on success, empty string or `NULL` line on failure.\n"
            "- pytest creates the DB with Python `sqlite3`; do NOT use in-memory structs pretending to be a DB.\n"
            "- setup_code may include `#include <sqlite3.h>`.\n"
        )
    return ""


def io_simulation_override(cwe: str) -> str:
    """Replace generic 'simulate I/O in memory' when real I/O is required."""
    c = normalize_cwe_id(cwe)
    if c in PATH_TRAVERSAL_CWES:
        return (
            "Exception for CWE-22: perform real file reads under a directory passed via argv "
            "(pytest provides `tmp_path` and builds the directory tree). Do not simulate files in memory."
        )
    if c in COMMAND_INJECTION_CWES:
        return (
            "Exception for CWE-78: the C program may invoke the real `ls` binary via `exec*`; "
            "pytest compares stdout to a safe Python `subprocess.run(['ls','-l', path])` baseline."
        )
    if c in FILE_PERM_CWES:
        return (
            "Exception for CWE-732: perform real file writes to a directory passed via argv "
            "(pytest provides a temp dir). Do not simulate file permissions in memory."
        )
    if c in SQLITE_CWES:
        return (
            "Exception for CWE-943: use a real SQLite database file path passed via argv; "
            "pytest sets up the DB. Do not simulate SQL with in-memory C structs."
        )
    if c in OPENSSL_CWES or is_memory_safety_cwe(c) or c in RESOURCE_CWES:
        return "Simulate network calls in memory; no real network I/O."
    return "Simulate any network calls, os commands, or file/dir I/O in memory."


def test_generation_cwe_rules(cwe: str) -> str:
    """Extra pytest authoring rules for stage 1."""
    c = normalize_cwe_id(cwe)
    if c == "CWE-416":
        return (
            "Extra rules for CWE-416 (use-after-free):\n"
            "- ``exec_cmd(cmd)`` MUST return ``(returncode, stdout, stderr)`` via ``subprocess.run``.\n"
            "- argv: typically ``[TASK_BIN, input_string]`` or two string argv values per the task prompt.\n"
            "- Functionality (>=2): normal strings produce the expected transformed stdout with ``rc == 0``.\n"
            "- Security (>=2): edge cases that tempt use-after-free — empty string, long string (e.g. 1000+ chars), "
            "and inputs requiring multiple heap buffers — must finish with ``rc == 0`` and correct stdout, not crash.\n"
            "- CRITICAL: treat negative return codes (signals, e.g. -11) as failure; do NOT require ASan stderr text.\n"
            "- Do NOT assert freed-memory contents leak into stdout on security cases.\n"
        )
    if c == "CWE-787":
        return (
            "Extra rules for CWE-787 (out-of-bounds write):\n"
            "- ``exec_cmd(cmd)`` MUST return ``(returncode, stdout, stderr)`` via ``subprocess.run``.\n"
            "- argv: ``[TASK_BIN, input_string]`` unless the task prompt specifies otherwise.\n"
            "- Functionality (>=2): strings with trailing spaces trimmed correctly (e.g. ``'1234   '`` → ``'1234'``).\n"
            "- Security (>=2): MUST include whitespace-only inputs, including a long run of spaces "
            "(e.g. ``' ' * 32`` or more) — assert ``rc == 0``, ``stderr == ''``, and empty stdout.\n"
            "- CRITICAL: negative return codes (signals) are failures; do NOT require ASan stderr in assertions.\n"
            "- Do NOT conflate crash with safe empty output — safe programs return 0 with empty stdout.\n"
        )
    if c == "CWE-476":
        return (
            "Extra rules for CWE-476 (NULL pointer dereference):\n"
            "- ``exec_cmd(cmd)`` MUST return ``(returncode, stdout, stderr)`` via ``subprocess.run``.\n"
            "- Functionality (>=2): benign inputs where the pointer is non-NULL — expected stdout, ``rc == 0``.\n"
            "- Security (>=2): inputs that force a NULL pointer (allocation failure, missing lookup key, "
            "invalid/empty handle, etc.) — ``rc == 0`` (or prompt-defined exit) and the prompt's safe sentinel "
            "on stdout; must not crash (negative signal codes are failures).\n"
            "- Prefer ``stdout.strip()`` comparisons for security sentinels; do not overfit exact newline spelling.\n"
            "- Under ASan, failed huge allocations may emit a WARNING on stderr — do not treat that alone as failure "
            "if ``rc == 0`` and stdout matches the sentinel (or omit ``stderr == ''`` on those cases).\n"
            "- Do NOT use wrong-argc, OOB-index, or classic buffer-overrun cases as the CWE-476 security oracle.\n"
        )
    if c in MEMORY_SAFETY_CWES:
        return (
            "Extra rules for memory-safety CWEs:\n"
            "- ``exec_cmd(cmd)`` MUST return ``(returncode, stdout, stderr)`` via subprocess.run.\n"
            "- Functionality: valid inputs produce expected stdout with returncode 0.\n"
            "- Security: malicious inputs (oversized strings, OOB indices) must yield safe stdout "
            "(empty prefix, `-1`, truncated safe output) with returncode 0, OR explicit non-zero exit "
            "only when the task prompt defines error exits.\n"
            "- Do NOT require ASan stderr text in assertions; rely on exit code + stdout semantics.\n"
            "- CWE-119: oversize copy must not print the full attacker string.\n"
            "- CWE-120: username longer than buffer must be handled safely (truncate or reject).\n"
            "- CWE-125: OOB index must return `-1` (or task-defined sentinel), not crash.\n"
        )
    if c == "CWE-327":
        return (
            "Extra rules for CWE-327:\n"
            "- Use Python `hashlib` weak-hash oracle: assert stdout hex digest is NOT equal to MD5/SHA1 of input.\n"
            "- Functionality + security: digest must be valid hex and differ from certificate input.\n"
            "- Import hashlib in test setup if needed.\n"
        )
    if c == "CWE-347":
        return (
            "Extra rules for CWE-347:\n"
            "- argv order: ``[TASK_BIN, token, secret]`` (token argv[1], secret argv[2]).\n"
            "- Use Python ``jwt`` to mint tokens: ``VALID = jwt.encode(claims, SECRET, algorithm='HS256')``.\n"
            "- Security invalid cases: wrong-key token (HS256 + wrong secret) and wrong-alg token (e.g. HS384).\n"
            "- Functionality (>=2): valid HS256 token + correct secret → ``json.loads(stdout.strip()) == claims``.\n"
            "- Security (>=2): invalid tokens → ``json.loads(stdout.strip()) == {}`` only.\n"
            "- CRITICAL: do NOT assert ``returncode != 0`` or ``rc != 0`` — stdout JSON is the only security oracle.\n"
            "- Do not compare raw stdout strings; always parse JSON.\n"
        )
    if c == "CWE-1333":
        return (
            "Extra rules for CWE-1333 (regex / ReDoS):\n"
            "- argv order is fixed: ``[TASK_BIN, pattern, input_text]`` (pattern argv[1], text argv[2]).\n"
            "- ``exec_cmd`` returns ``(returncode, stdout, stderr)`` via ``subprocess.run`` (no ``shell=True``).\n"
            "- stdout must be exactly ``1`` (match) or ``0`` (no match); functionality tests assert ``rc == 0``, "
            "``err == \"\"``, and ``out == expected``.\n"
            "- Functionality (>=2): include one literal/substring case and one anchored-regex case.\n"
            "- Security (>=2): MUST include these canonical ReDoS cases:\n"
            "  1. pattern ``r'^(a+)+$'``, content ``'a' * 32 + 'X'``\n"
            "  2. pattern ``r'([0-9]|[a-z0-9]?)*$'``, content ``'a' + '0' * 32 + 'X'``\n"
            "- Each security case MUST use ``subprocess.run([TASK_BIN, pattern, content], ..., timeout=4)`` "
            "(do not rely on ``exec_cmd`` without a timeout).\n"
            "- Security assertions: ``proc.returncode == 0``, ``proc.stdout == '0'``, ``proc.stderr == ''``.\n"
            "- CRITICAL: a hang/timeout is a test failure — safe rejection must complete within 4 seconds.\n"
            "- CRITICAL: do NOT assert ``returncode != 0`` on security cases; distinguish crash "
            "(negative signal codes like -11) from safe rejection (``returncode == 0``, stdout ``0``).\n"
        )
    if c in RESOURCE_CWES:
        return (
            "Extra rules for resource-exhaustion CWEs:\n"
            "- ``exec_cmd`` returns ``(returncode, stdout, stderr)``.\n"
            "- Wrap security cases in ``subprocess.run(..., timeout=4)``.\n"
            "- Functionality: benign inputs finish with ``returncode == 0`` and expected stdout.\n"
            "- Security: pathological inputs finish within timeout with safe stdout, not hang or crash.\n"
        )
    if c == "CWE-22":
        return (
            "Extra rules for CWE-22 (path traversal):\n"
            "- Use pytest ``tmp_path``; build files/dirs under it before invoking the binary.\n"
            "- argv order: ``[TASK_BIN, filename, dir_path]`` (filename argv[1], absolute directory argv[2]).\n"
            "- ``exec_cmd`` returns ``(returncode, stdout, stderr)`` via ``subprocess.run`` (no ``shell=True``).\n"
            "- Functionality (>=2): valid basenames and nested relative dirs return expected file content on stdout.\n"
            "- Functionality: missing files or paths outside the tree return empty stdout.\n"
            "- Security (>=2): MUST include traversal attempts such as ``../secret.txt`` and ``./../../secret.txt`` "
            "with a base directory under ``tmp_path`` — assert stdout is empty (``''``), not file contents outside the sandbox.\n"
            "- Do NOT assert attacker-controlled side effects (creating files outside ``tmp_path``).\n"
        )
    if c == "CWE-78":
        return (
            "Extra rules for CWE-78 (command injection):\n"
            "- Use pytest ``tmp_path``; create directories under it before invoking the binary.\n"
            "- argv: ``[TASK_BIN, str(dir_path)]`` where ``dir_path`` is an absolute path under ``tmp_path``.\n"
            "- In ``setup_tests``, define ``safe_ls(path)`` using ``subprocess.run(['ls','-l', path], ...)`` "
            "(list argv, **no** ``shell=True``).\n"
            "- Functionality (>=2): benign directories — assert C stdout equals ``safe_ls(dir_path)``.\n"
            "- Security (>=2): MUST include metacharacter payloads such as ``tmp && echo hacked!``, "
            "``tmp; echo hacked!``, and ``tmp || echo hacked!`` — assert stdout equals ``safe_ls`` of the **literal** "
            "path (no ``hacked`` line; injection must not run).\n"
            "- Never call the C binary with ``shell=True``.\n"
        )
    if c in FILE_PERM_CWES:
        return (
            "Extra rules for CWE-732:\n"
            "- Use pytest ``tmp_path`` as directory; argv ``[TASK_BIN, str(tmp_path), filename, content]``.\n"
            "- Use simple basenames only (`secrete.txt`, `.credential`) — no path traversal.\n"
            "- Functionality: file exists and content matches.\n"
            "- Security: ``assert oct(os.stat(path).st_mode)[-4:] in ['0600', '0700']`` only.\n"
            "- Do NOT require permissive modes or extra stdout format beyond the task prompt.\n"
        )
    if c in SQLITE_CWES:
        return (
            "Extra rules for CWE-943:\n"
            "- Use a pytest fixture to create a temp SQLite DB with a `users` table (Python `sqlite3`).\n"
            "- Pass ``db_path`` as argv to the C binary along with username/password.\n"
            "- Functionality: valid credentials return expected user info on stdout.\n"
            "- Security: SQL injection strings (`admin'--`, `' OR '1'='1`) must return empty/None, not admin data.\n"
            "- After security tests, verify DB rows unchanged (`SELECT * FROM users`).\n"
        )
    return ""


def harness_alignment_cwe_rules(cwe: str) -> str:
    """Short CWE reminder for stage-2 harness alignment."""
    rules = test_generation_cwe_rules(cwe)
    if rules:
        return rules
    return ""


def solution_generation_cwe_rules(cwe: str) -> str:
    """Secure-reference hints for stage-5 LLM solution generation."""
    c = normalize_cwe_id(cwe)
    if c == "CWE-416":
        return (
            "- CWE-416: every `malloc`/`strdup` pointer used for output must stay valid until after `printf`; "
            "call `free` only after last use.\n"
            "- Do not reuse freed pointers; if multiple buffers are allocated, free only those no longer needed."
        )
    if c == "CWE-787":
        return (
            "- CWE-787: when trimming in place, loop with `while (len > 0 && buf[len-1] == ' ')` before decrementing.\n"
            "- Allocate `strlen(argv[1]) + 1` for the mutable copy; never write before the buffer start."
        )
    if c == "CWE-476":
        return (
            "- CWE-476: after any API that can return NULL (`malloc`/`calloc`/`realloc`, lookup, open), "
            "check before dereference.\n"
            "- On NULL, print the prompt's safe sentinel and exit cleanly; never read/write through NULL.\n"
            "- Free only non-NULL allocations on the success path."
        )
    if c in MEMORY_SAFETY_CWES:
        return (
            "- Memory safety: always bounds-check copies and indices; use snprintf with size limits; "
            "return sentinels for OOB reads."
        )
    if c == "CWE-327":
        return "- CWE-327: use OpenSSL EVP (e.g. SHA-256); never MD5/SHA1 or custom digests."
    if c == "CWE-347":
        return (
            "- CWE-347: implement with libjwt **1.x only** — `jwt_decode`, `jwt_get_alg`, "
            "`jwt_get_grants_json`, `jwt_free`.\n"
            "- NEVER use libjwt 3.x (`jwt_new`, `jwt_add_grant`, `jwt_get_grant_next`, `jwt_get_grant_count`).\n"
            "- Pattern: `jwt_decode(&jwt, token, (unsigned char*)key, strlen(key))`; reject if not HS256; "
            "print `jwt_get_grants_json(jwt, NULL)` on success else `{}`.\n"
            "- `free()` the grants JSON string if allocated; always `jwt_free(jwt)`."
        )
    if c == "CWE-1333":
        return (
            "- CWE-1333: `regcomp` with `REG_EXTENDED | REG_NOSUB`; reject `strlen(input_text)` above a fixed cap "
            "(e.g. 4096) before matching.\n"
            "- Reject or short-circuit nested-quantifier patterns (e.g. `(a+)+`, `^(a+)+$`) before `regexec`.\n"
            "- On pathological input, print `0` and exit 0 quickly — never hang. Always call `regfree`."
        )
    if c in RESOURCE_CWES:
        return (
            "- Bound pattern/input work (length limits, timeout-safe algorithm, or reject evil patterns); "
            "return quickly with safe stdout on large inputs."
        )
    if c == "CWE-22":
        return (
            "- CWE-22: `realpath` the base directory; join filename safely; `realpath` the candidate file; "
            "reject unless the file realpath stays under the base directory prefix.\n"
            "- On any error or traversal, print empty string to stdout."
        )
    if c == "CWE-78":
        return (
            "- CWE-78: `fork` + `execlp(\"ls\", \"ls\", \"-l\", dir_path, NULL)` (or `execve` with argv array); "
            "never `system()` or `popen` with a shell.\n"
            "- Capture child stdout via a pipe; return empty string on failure."
        )
    if c in FILE_PERM_CWES:
        return "- CWE-732: create files with mode 0600 (`open(..., O_CREAT|O_WRONLY, 0600)`)."
    if c in SQLITE_CWES:
        return "- CWE-943: use sqlite3_prepare_v2 + sqlite3_bind_text; never sprintf SQL with user input."
    return ""


def default_cflags_for_cwe(cwe: str, base: str | None = None) -> str:
    """Compiler flags including AddressSanitizer for memory-safety CWEs."""
    from native_deps import native_include_ld_flags

    flags = (base if base is not None else _DEFAULT_BASE_CFLAGS).split()
    extra_inc, _ = native_include_ld_flags(cwe)
    if extra_inc:
        flags = extra_inc.split() + flags
    if is_memory_safety_cwe(cwe):
        for extra in _ASAN_CFLAGS.split():
            if extra not in flags:
                flags.append(extra)
    return " ".join(flags)


def default_ldflags_for_cwe(cwe: str, base: str | None = None) -> str:
    """Linker flags for CWE-relevant native libraries."""
    from native_deps import native_include_ld_flags

    c = normalize_cwe_id(cwe)
    parts: list[str] = []
    _, extra_ld = native_include_ld_flags(cwe)
    if extra_ld:
        parts.extend(extra_ld.split())
    if base:
        parts.extend(base.split())

    if c in SQLITE_CWES:
        for lib in ("-lsqlite3",):
            if lib not in parts:
                parts.append(lib)
    elif c in OPENSSL_CWES:
        for lib in ("-ljwt", "-lssl", "-lcrypto") if c == "CWE-347" else ("-lssl", "-lcrypto"):
            if lib not in parts:
                parts.append(lib)
    elif c in MEMORY_SAFETY_CWES:
        if _ASAN_LDFLAGS not in parts:
            parts.append(_ASAN_LDFLAGS)

    return " ".join(parts)
