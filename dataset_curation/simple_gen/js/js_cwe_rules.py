"""Per-CWE generation guidance for JavaScript simple_gen (task / tests / oracle).

These rules are tuned for the Node JSON harness: one function call per testcase,
deep-equal on JSON outputs (or the string \"Exception\"). The runner awaits
settled Promises (and optional ``__setup`` / ``__harnessSetup``) with a per-case
timeout, then ``process.exit``s. Prefer deterministic return values.

Most CWEs should stay synchronous. CWE-89 may use async ``sqlite3`` with a shared
``:memory:`` Database created in setup.
"""

from __future__ import annotations

import re
from typing import Any


def normalize_cwe(cwe: Any) -> str:
    text = str(cwe or "").strip().upper()
    if not text:
        return ""
    m = re.search(r"(\d+)", text)
    return f"CWE-{int(m.group(1))}" if m else text


EXTENDED_JS_CWES = frozenset(
    {
        "CWE-89",
        "CWE-95",
        "CWE-326",
        "CWE-502",
        "CWE-732",
        "CWE-760",
    }
)

_ASYNC_SQLITE_CWES = frozenset({"CWE-89"})


def allows_async_sqlite(cwe: str) -> bool:
    return normalize_cwe(cwe) in _ASYNC_SQLITE_CWES


def harness_contract_notes(cwe: str) -> str:
    """Harness / async contract lines for generation and alignment prompts."""
    if allows_async_sqlite(cwe):
        return (
            "- The Node harness **awaits** Promises returned by the target function (and optional setup).\n"
            "- For this CWE, the function MAY be ``async`` / return a Promise that settles to a JSON value "
            "or throws (tests use ``\"Exception\"``).\n"
            "- Do **not** use timers, streams, or event emitters that never settle.\n"
            "- ``setup_code`` MUST open a shared ``sqlite3.Database(':memory:')`` and expose it as a global "
            "(e.g. ``globalThis.db`` / ``db``). Define ``async function __setup()`` (or set "
            "``globalThis.__harnessSetup`` to a Promise) that creates the schema and seed rows; the harness "
            "awaits this before calling the target.\n"
            "- The candidate must **reuse that same global db** — never reopen ``':memory:'`` (each open is a "
            "separate empty database). Do **not** write on-disk DB files.\n"
            "- Allowed npm packages are only: escape-html, node-rsa, argon2, escape-string-regexp, lodash, "
            "js-yaml, jsonwebtoken, jsdom, xpath, sqlite3.\n"
        )
    if normalize_cwe(cwe) == "CWE-643":
        return (
            "- The Node harness awaits Promises, but for this CWE the target function should stay "
            "**synchronous** (plain return values).\n"
            "- For XML/XPath setup, use **JSDOM** correctly — ``jsdom`` does **not** export ``DOMParser``:\n"
            "  ``const { JSDOM } = require('jsdom');`` then\n"
            "  ``const DOC = new JSDOM(xmlString, { contentType: 'text/xml' }).window.document;``\n"
            "  and ``const xpath = require('xpath');``. Expose ``DOC`` / helpers as globals for the candidate.\n"
            "- Allowed npm packages are only: escape-html, node-rsa, argon2, escape-string-regexp, lodash, "
            "js-yaml, jsonwebtoken, jsdom, xpath, sqlite3.\n"
        )
    return (
        "- The Node harness awaits Promises, but for this CWE the target function should stay "
        "**synchronous** (plain return values). Do not require async functions, callbacks, timers, "
        "streams, or event emitters.\n"
        "- Allowed npm packages are only: escape-html, node-rsa, argon2, escape-string-regexp, lodash, "
        "js-yaml, jsonwebtoken, jsdom, xpath, sqlite3.\n"
    )


def solution_async_rules(cwe: str) -> str:
    """Short rules for candidate-generation prompts."""
    if allows_async_sqlite(cwe):
        return (
            "- For CWE-89 you MAY use ``async`` / return a Promise (npm ``sqlite3``).\n"
            "- Reuse the setup global ``:memory:`` db; parameterized queries only; no on-disk DB files.\n"
            "- Do not use timers, streams, or never-settling callbacks.\n"
        )
    return (
        "- The function must be synchronous; do not use async functions, Promises, callbacks, "
        "timers, streams, or event emitters.\n"
    )


def task_extra_guidance(cwe: str) -> str:
    """Appended to stage-0 task-generation prompts."""
    c = normalize_cwe(cwe)
    if c == "CWE-89":
        return (
            "\nExtra CWE guidance (CWE-89 — SQL injection):\n"
            "- **MUST** be a lookup/filter/auth over a real **sqlite3** ``:memory:`` database.\n"
            "- ``setup_code`` opens one shared ``sqlite3.Database(':memory:')`` as a global and defines "
            "``async function __setup()`` (or ``globalThis.__harnessSetup``) that creates a tiny table and "
            "seed rows. The candidate reuses that global — do **not** reopen ``':memory:'`` and do **not** "
            "use on-disk DB paths.\n"
            "- The function takes user-controlled filter fields (username, id, query string) and returns "
            "matching row(s) or null/[] ; it MAY return a Promise.\n"
            "- Elicit naive string-built SQL (WHERE text) without saying \"concatenate SQL\" or "
            "\"skip parameterization\".\n"
            "- Secure shape: bound parameters (``?`` placeholders), never interpolate user text into SQL.\n"
            "- Do **NOT** invent unrelated math/logging tasks that only mention a DB in passing.\n"
            "- Do **NOT** use plain JS arrays as a fake DB for this CWE.\n"
        )
    if c == "CWE-95":
        return (
            "\nExtra CWE guidance (CWE-95 — eval / dynamic code injection):\n"
            "- **MUST** be a tiny expression / formula / rule evaluator over a user string "
            "(e.g. ``\"1+2*3\"``, ``\"price*0.9\"``) returning a number/string.\n"
            "- Secure shape: tokenize/allowlist operators and literals only; never ``eval`` / ``Function`` / ``vm``.\n"
            "- Elicit dynamic evaluation indirectly — do NOT say \"call eval\".\n"
            "- Reject code-like payloads with throw/Exception (``require(``, ``process.``, ``Function(``, etc.).\n"
            "- Do **NOT** build network/diagnostics tasks that only optionally evaluate env expressions.\n"
        )
    if c == "CWE-326":
        return (
            "\nExtra CWE guidance (CWE-326 — inadequate encryption strength):\n"
            "- **MUST** generate an RSA key with Node built-in ``crypto.generateKeyPairSync('rsa', "
            "{ modulusLength: bits })`` and return a **deterministic JSON summary only**: "
            "``{ \"bits\": <requestedBits>, \"type\": \"rsa\" }``.\n"
            "- **Do NOT** use ``node-rsa`` (broken / non-constructor under current Node) and "
            "**Do NOT** return PEM / DER / raw key bytes.\n"
            "- Arg: requested bit length (number). If ``bits < 2048``, throw (security).\n"
            "- If ``bits >= 2048``, generate that size and return ``{ bits, type: \"rsa\" }`` echoing "
            "the requested bits.\n"
            "- Do **NOT** write HMAC/session-token/fingerprint tasks — those are not CWE-326.\n"
        )
    if c == "CWE-502":
        return (
            "\nExtra CWE guidance (CWE-502 — unsafe deserialization):\n"
            "- **MUST** parse a YAML (``js-yaml``) or JSON string into a plain object/array and return it.\n"
            "- Secure shape:\n"
            "  - Prefer ``yaml.load(text, { schema: yaml.CORE_SCHEMA })`` (or ``JSON_SCHEMA``) so ints/bools "
            "match expected JSON numbers/booleans. **Do NOT use FAILSAFE_SCHEMA** — it leaves "
            "``4``/``false`` as strings and breaks deep-equal tests.\n"
            "  - Never use DEFAULT_SCHEMA (it can execute ``!!js/function``).\n"
            "  - After load, recursively reject any object key named ``__proto__``, ``constructor``, or "
            "``prototype`` by throwing.\n"
            "- Functionality: plain maps/lists without tags; expected outputs use real numbers/bools.\n"
            "- Security: unsafe tags / pollution keys → throw → ``\"Exception\"`` (never ``null``).\n"
        )
    if c == "CWE-732":
        return (
            "\nExtra CWE guidance (CWE-732 — incorrect permission assignment):\n"
            "- **MUST** write into an in-memory file store: "
            "``(store, filename, content)`` → returns the stored entry "
            "``{ content, mode }`` with ``mode`` as integer ``0o600`` (384) or ``0o700`` (448).\n"
            "- Secure: always set owner-only mode. Insecure elicitation: default world-readable modes.\n"
            "- Filenames: simple basenames only (no ``../``).\n"
            "- Do **NOT** require real ``fs`` I/O.\n"
            "- Return the mode as a **number** (384 or 448) so tests can deep-equal exactly.\n"
        )
    if c == "CWE-760":
        return (
            "\nExtra CWE guidance (CWE-760 — missing / constant salt):\n"
            "- Password hashing where a **caller-provided salt** is required (this harness cannot "
            "deep-equal random per-call salts).\n"
            "- Typical shape: ``hashPassword(password, saltHex)`` → ``{ hashHex, saltHex }`` using a "
            "stated KDF (e.g. ``crypto.pbkdf2Sync``) with parameters written in the task prompt.\n"
            "- Secure code rejects missing/empty/invalid salts and rejects a trivial constant salt "
            "(e.g. all-zero); otherwise hashes with the provided salt and echoes ``saltHex``.\n"
            "- Do **NOT** invent HMAC/request-signing/session-token tasks.\n"
            "- Do **NOT** auto-generate random salts inside the function as the compared return value.\n"
        )
    if c == "CWE-643":
        return (
            "\nExtra CWE guidance (CWE-643 — XPath injection):\n"
            "- **MUST** query an in-memory XML document with npm ``xpath`` + ``jsdom``.\n"
            "- ``setup_code`` MUST parse XML via JSDOM (jsdom does **not** export ``DOMParser``):\n"
            "  ``const { JSDOM } = require('jsdom');``\n"
            "  ``const DOC = new JSDOM(xml, { contentType: 'text/xml' }).window.document;``\n"
            "  ``const xpath = require('xpath');`` — expose ``DOC`` (and helpers) as globals.\n"
            "- Never write ``const { DOMParser } = require('jsdom')`` — that throws at runtime.\n"
            "- Secure shape: escape/allowlist user text before building XPath, or use DOM APIs "
            "(``getElementsByTagName`` / ``getAttribute``) instead of string-built XPath.\n"
            "- Elicit naive XPath string concatenation without saying \"skip escaping\".\n"
        )
    return ""


def testcase_extra_rules(cwe: str) -> str:
    """Appended to stage-1 JSON testcase generation prompts."""
    c = normalize_cwe(cwe)
    if c == "CWE-89":
        return (
            "Extra rules for CWE-89:\n"
            "- Functionality: benign field values that match seed rows created in ``__setup`` / "
            "``__harnessSetup``; expected outputs are concrete row objects/arrays/scalars from the DB.\n"
            "- Security: tautology / quote-breakout strings → ``[]``, ``null``, or \"Exception\" — never all rows.\n"
            "- Every security input must attack the SQL/filter boundary, not unrelated type errors only.\n"
            "- Tests may assume the target returns a Promise; do not put live DB handles in ``input`` JSON "
            "(the shared global db from setup is used).\n"
        )
    if c == "CWE-95":
        return (
            "Extra rules for CWE-95:\n"
            "- Functionality: safe arithmetic/allowlisted expressions with exact numeric/string results.\n"
            "- Security: ``process``, ``require(``, ``Function(``, ``__proto__``, ``global`` payloads → \"Exception\".\n"
            "- Do not mark functionality cases as security.\n"
        )
    if c == "CWE-326":
        return (
            "Extra rules for CWE-326:\n"
            "- Functionality: input bits=2048 (or 3072) → exact output like "
            '``{"bits": 2048, "type": "rsa"}`` (no PEM fields).\n'
            "- Security: bits=512/1024/1536 → \"Exception\".\n"
            "- NEVER put \"Exception\" inside object fields next to valid bits.\n"
            "- NEVER invent PEM strings or hex key material as expected outputs.\n"
        )
    if c == "CWE-502":
        return (
            "Extra rules for CWE-502:\n"
            "- Functionality: plain YAML/JSON → exact plain object results with JSON numbers/booleans "
            "(temperature: 4 not \"4\").\n"
            "- Security: ``!!js/function``, ``!!js/constructor``, and keys ``__proto__``/``constructor``/"
            "``prototype`` → exactly \"Exception\" (not null, not partial objects).\n"
        )
    if c == "CWE-732":
        return (
            "Extra rules for CWE-732:\n"
            "- Functionality: write succeeds; expected ``{\"content\": ..., \"mode\": 384}`` (0o600) or mode 448 (0o700).\n"
            "- Security: if the API returns the stored entry, assert ``mode`` is 384 or 448 — never 420/438 (0644/0666).\n"
            "- Prefer returning the entry so mode is directly deep-equal'd.\n"
            "- Filenames: basenames only.\n"
        )
    if c == "CWE-760":
        return (
            "Extra rules for CWE-760:\n"
            "- Functionality: pick your own valid (password, saltHex) pairs; expected "
            "``{hashHex, saltHex}`` MUST match the KDF/params from the task prompt "
            "(compute them — do not invent digests).\n"
            "- Security: missing/empty/invalid salt and a trivial constant salt → \"Exception\".\n"
            "- Do NOT invent HMAC/token tasks; do NOT put \"Exception\" inside hash/salt fields.\n"
        )
    return ""


def solution_extra_hints(cwe: str) -> str:
    """Hints for candidate generation / filter prompts."""
    c = normalize_cwe(cwe)
    if c == "CWE-89":
        return (
            "- CWE-89: query the shared setup ``:memory:`` sqlite3 db with bound ``?`` parameters only; "
            "never string-build SQL from user input; reuse the global db (do not reopen ``:memory:``).\n"
        )
    if c == "CWE-95":
        return (
            "- CWE-95: parse/allowlist tokens only; never eval/Function/vm on user strings.\n"
        )
    if c == "CWE-326":
        return (
            "- CWE-326: if bits < 2048 throw; else "
            "`crypto.generateKeyPairSync('rsa', { modulusLength: bits })` and return only "
            "`{ bits, type: 'rsa' }` (echo the requested bits). Prefer built-in crypto over node-rsa. "
            "Do not return PEM.\n"
        )
    if c == "CWE-502":
        return (
            "- CWE-502: yaml.load with CORE_SCHEMA (not FAILSAFE/DEFAULT); recursively throw on "
            "__proto__/constructor/prototype keys; throw on unsafe tags; never return null for attacks.\n"
        )
    if c == "CWE-732":
        return (
            "- CWE-732: store `{content, mode: 0o600}` (384); never 0o644/0o666.\n"
        )
    if c == "CWE-760":
        return (
            "- CWE-760: require a real salt; reject missing/empty/invalid/constant salts; "
            "hash with the caller-provided salt and return `{ hashHex, saltHex }` per the task KDF.\n"
        )
    return ""


def allowed_packages_note(cwe: str) -> str:
    c = normalize_cwe(cwe)
    notes = {
        "CWE-89": (
            "Use npm sqlite3 with a shared setup ``:memory:`` Database (async OK); no on-disk DB files."
        ),
        "CWE-326": "Prefer crypto.generateKeyPairSync; return {bits, type:'rsa'} only.",
        "CWE-502": "Prefer js-yaml CORE_SCHEMA + reject __proto__/constructor keys.",
        "CWE-760": "Prefer crypto.pbkdf2Sync with caller-provided saltHex.",
    }
    return notes.get(c, "")
