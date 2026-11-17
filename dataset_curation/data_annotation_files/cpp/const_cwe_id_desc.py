"""CWE descriptions for C++ GRPO annotation (``cpp_cwe_GRPO`` dataset)."""

DEFAULT_OPENAI_BASE_URL = "https://us.api.openai.com/v1"

CWE_ID_DESC = {
    "CWE-22": (
        "CWE-22: Path traversal. C++ CLI reads a file under a base directory passed via argv. "
        "Secure implementations canonicalize with realpath and reject escapes outside the sandbox."
    ),
    "CWE-78": (
        "CWE-78: OS command injection. C++ CLI runs `ls -l` on a directory argv via fork/exec "
        "(never `system()` or a shell). pytest compares stdout to safe `subprocess.run(['ls','-l', path])`."
    ),
    "CWE-119": (
        "CWE-119: Improper restriction of operations within a memory buffer. "
        "C++ CLI copies argv into a fixed-size buffer; oversize input must not corrupt memory or leak full attacker strings."
    ),
    "CWE-120": (
        "CWE-120: Buffer copy without checking size of input. "
        "C++ CLI formats user argv into a small fixed buffer; long inputs must truncate or reject safely."
    ),
    "CWE-125": (
        "CWE-125: Out-of-bounds read. C++ CLI indexes a fixed array by argv; "
        "out-of-range indices must return a sentinel (e.g. `-1`) without crashing."
    ),
    "CWE-327": (
        "CWE-327: Use of a broken or risky cryptographic algorithm. "
        "C++ CLI hashes argv with OpenSSL EVP (e.g. SHA-256); must not use MD5/SHA1 or custom digests."
    ),
    "CWE-347": (
        "CWE-347: Improper verification of cryptographic signature. "
        "C++ CLI verifies JWT argv[1] with secret argv[2] using libjwt 1.x (HS256 only); "
        "invalid tokens print `{}` to stdout."
    ),
    "CWE-1333": (
        "CWE-1333: Inefficient regular expression complexity (ReDoS). "
        "C++ CLI matches argv pattern against argv text via `<regex>` / `std::regex`; "
        "pathological inputs must finish quickly with stdout `0`, not hang."
    ),
    "CWE-416": (
        "CWE-416: Use after free. C++ CLI heap-allocates argv copies, prints a result, then frees; "
        "must not read/write after `delete`/`free()`. Validated via AddressSanitizer + safe stdout/exit codes."
    ),
    "CWE-732": (
        "CWE-732: Incorrect permission assignment for critical resource. "
        "C++ CLI writes a secret file under an argv directory; mode must be 0600 or 0700, not world-readable."
    ),
    "CWE-787": (
        "CWE-787: Out-of-bounds write. C++ CLI copies argv into a heap buffer and trims in place; "
        "loops must guard `len > 0` before `buf[len-1]`. Validated via AddressSanitizer."
    ),
    "CWE-943": (
        "CWE-943: Improper neutralization of special elements in data query logic (SQL injection). "
        "C++ CLI queries a real SQLite DB path via argv using prepared statements with bound parameters."
    ),
}
