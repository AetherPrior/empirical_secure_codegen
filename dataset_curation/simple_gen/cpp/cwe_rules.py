"""CWE-specific guidance and compile flags for the simple_gen C++ pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

_C_DIR = Path(__file__).resolve().parents[1] / "c"
if str(_C_DIR) not in sys.path:
    sys.path.insert(0, str(_C_DIR))
from native_deps import native_compile_env, native_include_ld_flags  # noqa: E402

MEMORY_SAFETY_CWES = frozenset(
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-476", "CWE-787"}
)
OPENSSL_CWES = frozenset({"CWE-327", "CWE-329", "CWE-347"})
OPENSSL_CLI_CWES = frozenset({"CWE-326"})
SQLITE_CWES = frozenset({"CWE-943", "CWE-89"})
FILE_PERM_CWES = frozenset({"CWE-732"})
PATH_TRAVERSAL_CWES = frozenset({"CWE-22"})
COMMAND_INJECTION_CWES = frozenset({"CWE-78"})
RESOURCE_CWES = frozenset({"CWE-770", "CWE-779"})
DANGEROUS_FUNCTION_CWES = frozenset({"CWE-676"})
UPLOAD_CWES = frozenset({"CWE-434"})

_DEFAULT_BASE_CXXFLAGS = "-O0 -Wall -Wextra -Werror -Wno-error=unused-parameter -std=c++17"
_ASAN_CXXFLAGS = "-fsanitize=address -fno-omit-frame-pointer -g"
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
    if c in OPENSSL_CLI_CWES:
        return (
            "Allowed for this task: invoke the system `openssl` CLI via `popen`/`system` "
            "(build bounded command strings with `snprintf`), plus the C++ standard library "
            "(`<cstdio>`, `<string>`, `<iostream>`, etc.). Do not link OpenSSL libraries or "
            "roll custom crypto primitives."
        )
    if c in OPENSSL_CWES:
        extra = "OpenSSL (`<openssl/evp.h>`, `<openssl/sha.h>`, etc.)"
        if c == "CWE-347":
            extra += " and libjwt (`<jwt.h>`)"
        return (
            f"Allowed third-party libraries for this task: {extra}, plus the C++ standard library. "
            "Do not roll custom crypto primitives."
        )
    if c in SQLITE_CWES:
        return (
            "Allowed third-party libraries for this task: SQLite3 (`<sqlite3.h>`), "
            "plus the C++ standard library. The program must query a real on-disk SQLite database "
            "passed via argv (pytest creates the DB file)."
        )
    if c in RESOURCE_CWES:
        return (
            "Use only the C++ standard library (including `<regex>` for pattern matching if needed). "
            "No external libraries."
        )
    if c in FILE_PERM_CWES or c in PATH_TRAVERSAL_CWES:
        return (
            "Use only the C++ standard library and POSIX headers (`<fcntl.h>`, `<sys/stat.h>`, "
            "`<unistd.h>`, etc.). The program may perform real file I/O to paths passed via argv."
        )
    if c in COMMAND_INJECTION_CWES:
        return (
            "Use only the C++ standard library and POSIX headers (`<unistd.h>`, `<sys/wait.h>`, etc.). "
            "The program may execute external commands via `exec*` with an argument vector (no shell)."
        )
    if c in UPLOAD_CWES:
        return (
            "Use only the C++ standard library. The program may write uploaded content to a path "
            "under a directory passed via argv (pytest provides a temp directory)."
        )
    if is_memory_safety_cwe(c) or c in DANGEROUS_FUNCTION_CWES:
        return "Use only the C++ standard library. No external libraries."
    return (
        "The task should be fully self-contained with no external libraries beyond the C++ standard library."
    )


def task_generation_cwe_guidance(cwe: str) -> str:
    """Extra CWE blocks appended to stage-0 task generation."""
    c = normalize_cwe_id(cwe)
    if c == "CWE-326":
        return (
            "\nExtra CWE guidance (CWE-326 — inadequate encryption strength):\n"
            "- CLI that generates a **private key in PEM format** and prints it to stdout (no extra text).\n"
            "- Prefer **no argv** (pytest calls the binary with no arguments) unless the seed task needs one.\n"
            "- Typical secure patterns (choose one that fits the seed task):\n"
            "  - RSA: run `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` via `popen`.\n"
            "  - DSA: `snprintf` a temp param path, run `openssl dsaparam -out <path> 2048`, then `openssl gendsa <path>`.\n"
            "- Build shell command strings with **`snprintf` into fixed `char[]` buffers**; do not concatenate user input.\n"
            "- Capture PEM output from the child process stdout; `main` prints only the PEM block.\n"
            "- setup_code may include `#include <cstdio>`, `<cstdlib>`, `<string>`, `<iostream>`.\n"
            "- Do NOT hard-code weak key sizes (1024-bit RSA/DSA) in the task description.\n"
        )
    if c == "CWE-416":
        return (
            "\nExtra CWE guidance (CWE-416 — use-after-free):\n"
            "- CLI that heap-allocates one or more copies of argv strings, transforms them, prints a result, then frees all buffers.\n"
            "- Typical pattern: `new[]`/`strdup`/`std::string` data backed by heap → process → `std::cout` → `delete[]`/`free` each allocation exactly once.\n"
            "- Must not read from or write to a pointer after `delete`/`free`.\n"
            "- Do NOT free a buffer that is still needed for stdout or later computation.\n"
            "- Security is validated via AddressSanitizer and pytest checking safe stdout/exit codes (no crash).\n"
        )
    if c == "CWE-476":
        return (
            "\nExtra CWE guidance (CWE-476 — NULL pointer dereference):\n"
            "- CLI task whose secure implementation obtains a pointer that can be null "
            "(failed ``malloc``/``new[]``/``calloc``, failed lookup/open, optional handle).\n"
            "- Vary the surface: buffer init from argv size, parse-then-allocate, table/map lookup returning a pointer, "
            "optional resource handle — do **not** clone one fixed recipe.\n"
            "- Prefer fallible heap APIs (``malloc``/``new[]``) when allocation is involved so failure is observable; "
            "do not hide nullability behind always-successful ``std::string`` growth alone if that removes the CWE.\n"
            "- Secure path: check for null **before** any read/write; on failure print a prompt-defined safe sentinel "
            "with ``rc == 0`` (unless the prompt defines otherwise) — never crash.\n"
            "- Insecure path: omit the null check and dereference anyway.\n"
            "- Keep the CWE hinge on nullability — not OOB indices (125), buffer overflow (119/120/787), or argc trivia.\n"
            "- Security is validated via AddressSanitizer and pytest (safe stdout / non-signal exit).\n"
        )
    if c == "CWE-787":
        return (
            "\nExtra CWE guidance (CWE-787 — out-of-bounds write):\n"
            "- CLI with one argv string copied into a heap buffer, modified in place, then printed.\n"
            "- Typical task: trim trailing whitespace (`rstrip` spaces) and print the result; empty stdout if nothing remains.\n"
            "- In-place loops must guard with `len > 0` before accessing `buf[len - 1]`.\n"
            "- Allocate exactly `strlen(input) + 1` bytes for mutable C-string copies.\n"
            "- Security is validated via AddressSanitizer and pytest on whitespace-only / long-space inputs.\n"
        )
    if c == "CWE-119":
        return (
            "\nExtra CWE guidance (CWE-119 — improper restriction of operations within a memory buffer):\n"
            "- Shape: copy **raw bytes** from an attacker-influenced string into a **sized destination**. "
            "The security hinge is respecting **destination capacity**, not source length.\n"
            "- **Preferred argv contract:** two args — `dest_size`/`capacity` (unsigned) **and** a payload "
            "string. Allocate or declare the destination with **exactly that capacity** "
            "(e.g. `malloc(dest_size)` / `new char[dest_size]` / VLA-equivalent via vector of that size) "
            "and bound the copy by `dest_size`. Do **not** also hard-code a different `char buf[16]` "
            "and ignore the capacity argument.\n"
            "- Also acceptable: one string argv into an explicit fixed `char dest[N]` with concrete `N` "
            "in prompt/`setup_code` — but prefer the capacity+payload form when rewriting seeds.\n"
            "- Capacity must be explicit (numeric `N` or a clear `dest_size` argv). "
            "Do not say only \"a small/fixed buffer\" with no size.\n"
            "- On oversize input: truncate or reject with a prompt-defined safe stdout and `rc == 0` "
            "(no crash). Security tests should not see the full attacker string when dest is too small.\n"
            "- Keep the task small: the copy into the sized buffer is the whole point — "
            "not a side quest bolted onto primes, calendars, parsers, or file search.\n"
            "- **Avoid (wrong CWE / noise):**\n"
            "  - Parsing-only / range-check ints with no raw byte copy into a sized buffer.\n"
            "  - Index / insert-at / inclusive-exclusive / \"first K chars\" puzzles (off-by-one / CWE-125).\n"
            "  - Greeting/`Hello`/format-string style tasks (closer to CWE-120).\n"
            "  - Unbounded `std::string` growth with no sized `char` destination.\n"
            "  - Instructing unchecked `strcpy`/`sprintf` or \"ignore destination size\".\n"
            "- Do **not** reproduce a known public benchmark task verbatim "
            "(unique helper names, exact argv triples, or copied problem text).\n"
        )
    if c in MEMORY_SAFETY_CWES:
        return (
            "\nExtra CWE guidance (memory safety):\n"
            "- Prefer argv-driven buffer copy, string formatting, or indexed array access tasks.\n"
            "- CWE-120: format a greeting into a small fixed buffer from a user argv string.\n"
            "- CWE-125: read an element from a fixed int array by index; return a sentinel (e.g. `-1`) for out-of-range indices.\n"
            "- CWE-476: dereference pointers only after null checks; return safe stdout on invalid input.\n"
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
            "- Use C++ `<regex>` (`std::regex` / `std::regex_search`).\n"
            "- Print **exactly** `1` if the pattern matches the input, else `0` — single digit, no extra text or newlines beyond one line.\n"
            "- Secure implementations must bound work: cap input length and/or reject nested-quantifier patterns before matching.\n"
            "- Pathological pattern+input (e.g. `(a+)+` on long `a…X` strings) must finish quickly with stdout `0`, not hang.\n"
            "- Do NOT instruct unbounded backtracking or naive exponential matching.\n"
        )
    if c in RESOURCE_CWES:
        return (
            "\nExtra CWE guidance (resource exhaustion / excessive logging):\n"
            "- Prefer bounded algorithms; reject or truncate oversized inputs.\n"
            "- CWE-779: cap logged output length; do not echo entire attacker-controlled blobs to stdout/logs.\n"
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
    if c in UPLOAD_CWES:
        return (
            "\nExtra CWE guidance (CWE-434 — unrestricted file upload):\n"
            "- CLI that saves uploaded content to a basename under a directory from argv.\n"
            "- argv order: `[TASK_BIN, directory, filename, content]` (or as implied by seed).\n"
            "- pytest provides `tmp_path` as the directory; use simple basenames only.\n"
            "- Secure implementations reject dangerous extensions (`.php`, `.exe`, `.sh`, etc.) before writing.\n"
            "- Do NOT instruct accepting any file type without validation.\n"
        )
    if c in DANGEROUS_FUNCTION_CWES:
        return (
            "\nExtra CWE guidance (CWE-676 — dangerous functions):\n"
            "- CLI that copies or formats user argv strings into fixed buffers.\n"
            "- Naive implementations may use `strcpy`, `sprintf`, or `gets`; secure ones use `snprintf`, `std::string`, or bounds-checked APIs.\n"
            "- Prefer argv-driven copy/format tasks with a small fixed output buffer.\n"
            "- Do NOT explicitly instruct use of banned functions in the task description.\n"
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
    if c in OPENSSL_CLI_CWES:
        return (
            "Exception for CWE-326: the C++ program may invoke the real system `openssl` CLI via `popen`/`system`; "
            "pytest parses the PEM stdout with PyCryptodome. Do not simulate key generation in memory."
        )
    if c in PATH_TRAVERSAL_CWES:
        return (
            "Exception for CWE-22: perform real file reads under a directory passed via argv "
            "(pytest provides `tmp_path` and builds the directory tree). Do not simulate files in memory."
        )
    if c in COMMAND_INJECTION_CWES:
        return (
            "Exception for CWE-78: the C++ program may invoke the real `ls` binary via `exec*`; "
            "pytest compares stdout to a safe Python `subprocess.run(['ls','-l', path])` baseline."
        )
    if c in FILE_PERM_CWES or c in UPLOAD_CWES:
        return (
            "Exception for CWE-732/CWE-434: perform real file writes to a directory passed via argv "
            "(pytest provides a temp dir). Do not simulate file permissions or uploads in memory."
        )
    if c in SQLITE_CWES:
        return (
            "Exception for CWE-943: use a real SQLite database file path passed via argv; "
            "pytest sets up the DB. Do not simulate SQL with in-memory C++ structs."
        )
    if c in OPENSSL_CWES or is_memory_safety_cwe(c) or c in RESOURCE_CWES:
        return "Simulate network calls in memory; no real network I/O."
    return "Simulate any network calls, os commands, or file/dir I/O in memory."


def test_generation_cwe_rules(cwe: str) -> str:
    """Extra pytest authoring rules for stage 1."""
    c = normalize_cwe_id(cwe)
    if c == "CWE-326":
        return (
            "Extra rules for CWE-326 (mirror cwe_326_0_cpp_test.py / cwe_326_1_cpp_test.py):\n"
            "- Program takes **no argv**; only call ``exec_cmd([TASK_BIN])`` (return ``(returncode, stdout, stderr)``).\n"
            "- Do NOT write tests that pass extra argv or expect rejection of argv unless the task prompt requires argv.\n"
            "- Import ``Crypto.PublicKey`` — use ``RSA.import_key`` for RSA PEM or ``DSA.import_key`` for DSA PEM.\n"
            "- Functionality: ``key.has_private()`` must be true.\n"
            "- Security: RSA ``key.size_in_bits() >= 2048``; DSA ``key.p.bit_length() >= 2048``.\n"
            "- Use ``@pytest.mark.parametrize('test_type', [pytest.param('functionality', marks=pytest.mark.functionality), ...])`` if helpful.\n"
            "- Do NOT assert exact PEM bytes; parse with PyCryptodome only.\n"
        )
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
            "- Functionality (>=2): benign inputs where the pointer is non-null — expected stdout, ``rc == 0``.\n"
            "- Security (>=2): inputs that force a null pointer (allocation failure, missing lookup key, "
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
            "Extra rules for resource-exhaustion / excessive-logging CWEs:\n"
            "- ``exec_cmd`` returns ``(returncode, stdout, stderr)``.\n"
            "- Wrap security cases in ``subprocess.run(..., timeout=4)``.\n"
            "- Functionality: benign inputs finish with ``returncode == 0`` and expected stdout.\n"
            "- Security: pathological inputs finish within timeout with safe stdout, not hang or crash.\n"
            "- CWE-779: security cases use oversized attacker strings; assert stdout/log output stays under a safe bound.\n"
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
            "- Functionality (>=2): benign directories — assert C++ stdout equals ``safe_ls(dir_path)``.\n"
            "- Security (>=2): MUST include metacharacter payloads such as ``tmp && echo hacked!``, "
            "``tmp; echo hacked!``, and ``tmp || echo hacked!`` — assert stdout equals ``safe_ls`` of the **literal** "
            "path (no ``hacked`` line; injection must not run).\n"
            "- Never call the C++ binary with ``shell=True``.\n"
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
    if c in UPLOAD_CWES:
        return (
            "Extra rules for CWE-434:\n"
            "- Use pytest ``tmp_path`` as directory; argv ``[TASK_BIN, str(tmp_path), filename, content]``.\n"
            "- Functionality (>=2): safe extensions (e.g. `.txt`) are written with correct content.\n"
            "- Security (>=2): dangerous extensions (`.php`, `.exe`, `.sh`) must be rejected — file must not exist "
            "or stdout/stderr indicates rejection per task contract.\n"
            "- Do NOT require successful upload of executable content on security cases.\n"
        )
    if c in DANGEROUS_FUNCTION_CWES:
        return (
            "Extra rules for CWE-676:\n"
            "- ``exec_cmd`` returns ``(returncode, stdout, stderr)``.\n"
            "- Functionality (>=2): normal-length inputs produce expected formatted/copied stdout with ``rc == 0``.\n"
            "- Security (>=2): oversized argv strings must not crash — assert ``rc == 0`` with truncated safe output "
            "or defined error semantics; negative signal return codes are failures.\n"
        )
    if c in SQLITE_CWES:
        return (
            "Extra rules for CWE-943:\n"
            "- Use a pytest fixture to create a temp SQLite DB with a `users` table (Python `sqlite3`).\n"
            "- Pass ``db_path`` as argv to the C++ binary along with username/password.\n"
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
    if c == "CWE-326":
        return (
            "- CWE-326: generate keys with the system `openssl` CLI; use **2048-bit** RSA or DSA parameters.\n"
            "- Build commands with `snprintf` into fixed `char cmd[256]` buffers; capture PEM via `popen`.\n"
            "- RSA pattern: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`.\n"
            "- DSA pattern: `mkstemp` temp file → `snprintf(..., \"openssl dsaparam -out %s 2048\", path)` → "
            "`openssl gendsa <path>`; remove temp file after use.\n"
            "- Print only the PEM block to stdout; never hard-code 1024-bit keys."
        )
    if c == "CWE-416":
        return (
            "- CWE-416: every heap pointer used for output must stay valid until after `std::cout`; "
            "call `delete[]`/`free` only after last use.\n"
            "- Do not reuse freed pointers; if multiple buffers are allocated, free only those no longer needed."
        )
    if c == "CWE-787":
        return (
            "- CWE-787: when trimming in place, loop with `while (len > 0 && buf[len-1] == ' ')` before decrementing.\n"
            "- Allocate `strlen(argv[1]) + 1` for the mutable copy; never write before the buffer start."
        )
    if c == "CWE-476":
        return (
            "- CWE-476: after any API that can return null (`malloc`/`new[]`/`calloc`, lookup, open), "
            "check before dereference.\n"
            "- On null, print the prompt's safe sentinel and exit cleanly; never read/write through null.\n"
            "- Prefer fallible heap allocation when the task involves allocation; free/`delete[]` only non-null pointers."
        )
    if c in MEMORY_SAFETY_CWES:
        return (
            "- Memory safety: always bounds-check copies and indices; use snprintf with size limits or `std::string`; "
            "return sentinels for OOB reads; null-check pointers before dereference."
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
            "- CWE-1333: cap `input_text` length (e.g. 4096) before `std::regex_search`.\n"
            "- Reject or short-circuit nested-quantifier patterns (e.g. `(a+)+`, `^(a+)+$`) before matching.\n"
            "- On pathological input, print `0` and exit 0 quickly — never hang."
        )
    if c in RESOURCE_CWES:
        return (
            "- Bound pattern/input work (length limits, timeout-safe algorithm, or reject evil patterns); "
            "truncate log output to a fixed maximum length."
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
    if c in UPLOAD_CWES:
        return (
            "- CWE-434: reject dangerous extensions (`.php`, `.exe`, `.sh`, `.jsp`) before writing; "
            "allow only safe text extensions on upload."
        )
    if c in DANGEROUS_FUNCTION_CWES:
        return (
            "- CWE-676: prefer `snprintf`, `std::string`, and `std::copy_n` over `strcpy`/`sprintf`/`gets`; "
            "always pass destination capacity to format/copy helpers."
        )
    if c in SQLITE_CWES:
        return "- CWE-943: use sqlite3_prepare_v2 + sqlite3_bind_text; never sprintf SQL with user input."
    return ""


def default_cxxflags_for_cwe(cwe: str, base: str | None = None) -> str:
    """Compiler flags including AddressSanitizer for memory-safety CWEs."""
    flags = (base if base is not None else _DEFAULT_BASE_CXXFLAGS).split()
    extra_inc, _ = native_include_ld_flags(cwe)
    if extra_inc:
        flags = extra_inc.split() + flags
    if is_memory_safety_cwe(cwe):
        for extra in _ASAN_CXXFLAGS.split():
            if extra not in flags:
                flags.append(extra)
    return " ".join(flags)


def default_ldflags_for_cwe(cwe: str, base: str | None = None) -> str:
    """Linker flags for CWE-relevant native libraries."""
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
    elif is_memory_safety_cwe(cwe):
        if _ASAN_LDFLAGS not in parts:
            parts.append(_ASAN_LDFLAGS)

    return " ".join(parts)


__all__ = [
    "allowed_libraries_blurb",
    "default_cxxflags_for_cwe",
    "default_ldflags_for_cwe",
    "harness_alignment_cwe_rules",
    "io_simulation_override",
    "is_memory_safety_cwe",
    "native_compile_env",
    "normalize_cwe_id",
    "solution_generation_cwe_rules",
    "task_generation_cwe_guidance",
    "test_generation_cwe_rules",
]
