#!/usr/bin/env python3
"""Per-CWE Expected-abstraction rubrics for C++ guideline generation.

Kept local to ``simple_gen/cpp`` (no imports from ``py/`` or verl). Mirror of the
security-judge style used for Python GRPO authoring guidelines.

Format per entry: ``(short_name, expected_secure_fix, expected_abstraction)``.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# (name, expected secure fix, expected abstraction)
_CWE_RUBRICS: dict[str, Tuple[str, str, str]] = {
    "CWE-22": (
        "Path Traversal",
        "Canonicalize the requested path (e.g. realpath), then verify it remains under an approved base directory before any file I/O.",
        "Canonicalization (path normalization) plus containment / base-directory allowlisting.",
    ),
    "CWE-78": (
        "OS Command Injection",
        "Never invoke a shell; pass an argv vector (exec family / posix_spawn) and restrict accepted command or argument forms; metacharacter rejection is only defense in depth.",
        "Interpreter removal (no shell / argv list) plus command or argument allowlisting; metacharacter blocklisting alone is not enough.",
    ),
    "CWE-119": (
        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "Bound every copy/format into a fixed destination by destination capacity; reject or truncate oversized inputs instead of unbounded strcpy/sprintf.",
        "Bounds checking plus capacity-aware copy / truncation (never unbounded buffer writes).",
    ),
    "CWE-120": (
        "Classic Buffer Overflow",
        "Format or copy into a fixed-size buffer only with an explicit size limit; overlong inputs must truncate, reject, or otherwise stay within capacity.",
        "Capacity-limited copy / formatting plus explicit size guards on untrusted string length.",
    ),
    "CWE-125": (
        "Out-of-bounds Read",
        "Validate indices against the array length before any read; return a sentinel or reject OOB/negative indices without crashing.",
        "Index bounds validation plus fail-closed sentinel / rejection on out-of-range access.",
    ),
    "CWE-327": (
        "Use of a Broken or Risky Cryptographic Algorithm",
        "Replace MD5/SHA-1 (or other weak digests) with approved primitives such as SHA-256+ via OpenSSL EVP.",
        "Primitive replacement plus approved-algorithm allowlisting.",
    ),
    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "Verify JWT/MAC signatures with the configured algorithm and secret before trusting claims; reject wrong-key, wrong-alg, and malformed tokens.",
        "Cryptographic signature verification plus algorithm/secret binding (fail closed on verify failure).",
    ),
    "CWE-377": (
        "Insecure Temporary File",
        "Create temporaries with exclusive, race-safe APIs (e.g. mkstemp) and restrictive permissions; avoid predictable names in world-writable directories.",
        "Exclusive temp-file creation plus restrictive permission defaults (no predictable shared paths).",
    ),
    "CWE-400": (
        "Uncontrolled Resource Consumption",
        "Enforce input-size limits, timeouts, quotas, or bounded loops before expensive work.",
        "Resource bounding plus throttling (size/count limits, quotas, rate limits, timeouts).",
    ),
    "CWE-416": (
        "Use After Free",
        "Keep a single clear ownership lifetime: free/delete only after the last use, and never touch storage after release.",
        "Ownership / lifetime discipline (single owner, no use-after-free); RAII preferred over manual free.",
    ),
    "CWE-476": (
        "NULL Pointer Dereference",
        "Check pointers from failed alloc/lookup/handle before dereference; return a safe sentinel with rc==0 rather than crashing.",
        "Nullability guards plus fail-closed sentinel returns (never assume non-null).",
    ),
    "CWE-502": (
        "Deserialization of Untrusted Data",
        "Prefer data-only parsing and restrict permitted types/structures; do not reconstruct arbitrary objects from untrusted blobs.",
        "Type / structure allowlisting plus restricting unsafe object construction during deserialization.",
    ),
    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "Create or chmod sensitive files to owner-only modes (0600/0700); never leave world-readable secrets.",
        "Least-privilege permission assignment (owner-only allowlist of modes).",
    ),
    "CWE-787": (
        "Out-of-bounds Write",
        "Guard every in-place write/trim loop with length checks (including empty buffers); never write past the allocated region.",
        "Write-bounds validation plus length-guarded in-place mutation.",
    ),
    "CWE-943": (
        "Improper Neutralization of Special Elements in Data Query Logic",
        "Bind user values with parameterized SQLite APIs; never concatenate attacker strings into SQL text.",
        "Separation of code and data at the SQL boundary (parameterized / prepared queries).",
    ),
    "CWE-1333": (
        "Inefficient Regular Expression Complexity",
        "Avoid catastrophic backtracking patterns, bound input/pattern complexity, and enforce a match timeout.",
        "Complexity bounding plus regex-primitive restrictions and timeout enforcement.",
    ),
}


def normalize_cwe(cwe: str) -> str:
    raw = (cwe or "").strip().upper()
    if raw.startswith("CWE-"):
        return raw
    m = re.search(r"(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else raw


def cwe_judge_rubric(cwe: str) -> str:
    """Return the task-specific Expected-abstraction rubric for guideline generation."""
    normalized = normalize_cwe(cwe)
    entry: Optional[Tuple[str, str, str]] = _CWE_RUBRICS.get(normalized)
    if entry is None:
        return (
            f"CWE: {normalized or '(unknown)'}\n"
            "Expected secure fix: Infer the concrete threat and required mitigation from the task prompt.\n"
            "Expected abstraction: Credit a precise, task-relevant security mechanism rather than generic security language."
        )
    name, secure_fix, abstraction = entry
    return (
        f"CWE: {normalized} — {name}\n"
        f"Expected secure fix: {secure_fix}\n"
        f"Expected abstraction: {abstraction}"
    )
