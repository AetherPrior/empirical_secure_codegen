"""LLM-as-judge for model-authored guidelines (high-level + implementation).

Code-consistency judging (code vs implementation steps) is disabled for training.
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import threading
from typing import Any

try:
    from recipe.security_harness.reward_config import (
        LLM_JUDGE_API_KEY,
        LLM_JUDGE_API_MODE,
        LLM_JUDGE_BASE_URLS,
        LLM_JUDGE_ENABLED,
        LLM_JUDGE_MAX_TOKENS,
        LLM_JUDGE_MODEL,
        LLM_JUDGE_TEMPERATURE,
        LLM_JUDGE_THINKING_TOKEN_BUDGET,
        debug,
    )
except ImportError:
    from reward_config import (
        LLM_JUDGE_API_KEY,
        LLM_JUDGE_API_MODE,
        LLM_JUDGE_BASE_URLS,
        LLM_JUDGE_ENABLED,
        LLM_JUDGE_MAX_TOKENS,
        LLM_JUDGE_MODEL,
        LLM_JUDGE_TEMPERATURE,
        LLM_JUDGE_THINKING_TOKEN_BUDGET,
        debug,
    )

_LLM_JUDGE_CLIENTS: dict[str, Any] = {}
_LLM_JUDGE_CLIENT_LOCK = threading.Lock()

# Task-specific rubric shown only to the reward judge, not to the rollout model.
# Each entry states the expected secure fix and the underlying abstraction.
_CWE_RUBRICS: dict[str, tuple[str, str, str]] = {
    "CWE-22": (
        "Path Traversal",
        "Resolve or canonicalize the requested path, then verify it remains under an approved base directory.",
        "Canonicalization (path normalization) plus containment / base-directory allowlisting.",
    ),
    "CWE-78": (
        "OS Command Injection",
        "Avoid the shell, pass arguments as a list, and restrict accepted commands or argument forms; use metacharacter rejection only as defense in depth.",
        "Interpreter removal (no shell / argv list) plus command or argument allowlisting; metacharacter blocklisting alone is not enough.",
    ),
    "CWE-79": (
        "Cross-Site Scripting",
        "Apply context-specific output encoding, or sanitize permitted rich HTML with a trusted library.",
        "Contextual neutralization / output encoding / HTML escaping; for rich HTML, tag and attribute allowlisting.",
    ),
    "CWE-89": (
        "SQL Injection",
        "Replace string-built SQL with parameterized queries or prepared statements.",
        "Separation of code and data; enforcement of the interpreter boundary (parameterized / prepared queries).",
    ),
    "CWE-95": (
        "Code Injection",
        "Remove eval/exec and replace dynamic execution with explicit operators, parsers, or dispatch tables.",
        "Interpreter removal (no eval/exec) plus operation / token allowlisting or a dispatch table; sandboxing alone is partial.",
    ),
    "CWE-200": (
        "Information Exposure",
        "Return only intended fields, redact secrets, and replace internal errors with controlled responses. "
        "Prefer omit/redact of sensitive fields over aborting the whole response; for valid inputs, still "
        "satisfy the task's stated return/output contract (raise or empty-return only when the task "
        "explicitly requires an error).",
        "Output allowlisting / returned-data minimization (expose only intended fields; redact secrets) "
        "while preserving required functional outputs on valid inputs.",
    ),
    "CWE-295": (
        "Improper Certificate Validation",
        "Enable certificate-chain and hostname verification and trust only configured certificate authorities.",
        "Trust-anchor / certificate allowlisting plus fail-closed certificate and hostname validation.",
    ),
    "CWE-327": (
        "Broken or Risky Cryptography",
        "Replace insecure algorithms, modes, or key sizes with approved cryptographic primitives.",
        "Primitive replacement plus approved-algorithm allowlisting.",
    ),
    "CWE-352": (
        "Cross-Site Request Forgery",
        "Require a valid token tied to the user session and compare it before executing a state-changing request.",
        "CSRF / synchronizer token validation plus session state binding.",
    ),
    "CWE-400": (
        "Uncontrolled Resource Consumption",
        "Add input-size limits, timeouts, quotas, rate limits, bounded loops, or concurrency limits.",
        "Resource bounding plus throttling (size/count limits, quotas, rate limits, timeouts).",
    ),
    "CWE-502": (
        "Unsafe Deserialization",
        "Replace unsafe deserialization with a data-only format or restrict permitted types and classes.",
        "Type / class allowlisting plus restricting object construction / unsafe deserializers; bare 'type checking' is not enough.",
    ),
    "CWE-601": (
        "Open Redirect",
        "Canonicalize the user-provided URL first and then validate it against approved destinations.",
        "Canonicalization before validation plus destination allowlisting.",
    ),
    "CWE-611": (
        "XML External Entity",
        "Disable external entities, DTDs, and network access in the XML parser.",
        "Feature disabling plus parser hardening.",
    ),
    "CWE-770": (
        "Allocation of Resources Without Limits",
        "Reject or truncate inputs before expensive allocation and enforce explicit size or count thresholds. "
        "The bound must actually constrain the resource the task allocates (e.g. Queue(maxsize=...), "
        "maxlen, quota, concurrency cap)—not only catch overflow that never triggers, or limit a "
        "different axis than the one that grows without bound.",
        "Resource bounding / limitation plus explicit size or count threshold guards on the "
        "allocated resource itself.",
    ),
    "CWE-862": (
        "Missing Authorization",
        "Insert an authorization check before the sensitive action.",
        "Guard insertion plus default deny.",
    ),
    "CWE-863": (
        "Incorrect Authorization",
        "Check the specific user, action, role, ownership, and resource relationship.",
        "Contextual allowlisting plus policy enforcement and default deny.",
    ),
    "CWE-915": (
        "Mass Assignment",
        "Copy only explicitly permitted fields instead of assigning arbitrary input keys.",
        "Field allowlisting with deny-by-default handling of attributes.",
    ),
    "CWE-918": (
        "Server-Side Request Forgery",
        "Parse and normalize URLs, restrict schemes and destinations, resolve hosts, and reject internal or private addresses.",
        "Destination / hostname allowlisting plus URL canonicalization; network-range blocklisting is defense in depth.",
    ),
    "CWE-1333": (
        "Inefficient Regular Expression Complexity",
        "Replace or simplify unsafe regexes, restrict pattern features, limit input size, or impose a timeout.",
        "Complexity bounding plus regex-primitive blocklisting and timeout enforcement.",
    ),
    "CWE-113": (
        "HTTP Response Splitting",
        "Reject or encode CR/LF and other control characters in user-controlled HTTP header values, and use framework APIs that safely construct headers.",
        "Delimiter neutralization / control-character rejection plus structured API use; CR/LF blocklisting is appropriate for the injection delimiter.",
    ),

    "CWE-117": (
        "Improper Output Neutralization for Logs",
        "Encode or sanitize untrusted data before writing it to logs so it cannot inject line breaks, delimiters, or forged log entries.",
        "Contextual neutralization / log encoding plus control-character escaping.",
    ),

    "CWE-119": (
        "Improper Restriction of Operations within Memory Buffer Bounds",
        "Validate buffer lengths, indices, offsets, and arithmetic before memory access, and ensure every read or write remains within the allocated object.",
        "Memory-bound enforcement plus index / length validation and overflow-safe size arithmetic.",
    ),

    "CWE-120": (
        "Buffer Copy without Checking Size of Input",
        "Check the destination capacity before copying and use bounded copy or formatting operations that cannot write beyond the destination buffer.",
        "Bounded copy / write plus destination-size validation; replacement of unbounded memory and string operations.",
    ),

    "CWE-125": (
        "Out-of-Bounds Read",
        "Validate indices, offsets, lengths, and remaining buffer size before reading memory.",
        "Read-bound enforcement plus index / length validation and overflow-safe offset arithmetic.",
    ),

    "CWE-326": (
        "Inadequate Encryption Strength",
        "Use cryptographic algorithms, key sizes, parameters, and security levels that meet current minimum strength requirements.",
        "Cryptographic-parameter strengthening plus approved-algorithm and minimum-key-size enforcement.",
    ),

    "CWE-347": (
        "Improper Verification of Cryptographic Signature",
        "Verify signatures with the correct trusted key and algorithm before accepting signed data, and fail closed when verification fails.",
        "Cryptographic authenticity verification plus trusted-key / algorithm enforcement and fail-closed validation.",
    ),

    "CWE-476": (
        "NULL Pointer Dereference",
        "Check that pointers or returned objects are non-null before dereferencing them, and handle allocation or lookup failure explicitly.",
        "Precondition guard insertion plus failure handling before pointer dereference.",
    ),

    "CWE-643": (
        "XPath Injection",
        "Do not construct XPath expressions by concatenating untrusted input; use parameterized variables or strictly validate permitted query components.",
        "Separation of query structure and data plus parameterization / query-component allowlisting.",
    ),

    "CWE-732": (
        "Incorrect Permission Assignment for Critical Resource",
        "Create files, directories, or other resources with the minimum permissions required and avoid granting access to unintended users or groups.",
        "Least-privilege permission assignment plus explicit permission / principal allowlisting.",
    ),

    "CWE-787": (
        "Out-of-Bounds Write",
        "Validate destination bounds, indices, offsets, and write lengths before modifying memory, including checking size arithmetic for overflow.",
        "Write-bound enforcement plus index / length validation and overflow-safe size arithmetic.",
    ),

    "CWE-943": (
        "Improper Neutralization of Special Elements in Data Query Logic",
        "Use parameterized or structured query APIs instead of concatenating untrusted input into query expressions, and restrict dynamic query operators or fields.",
        "Separation of query structure and data plus parameterization / operator and field allowlisting.",
    ),
}


def cwe_judge_rubric(cwe: str) -> str:
    """Return the task-specific security rubric for a CWE identifier."""
    normalized = str(cwe or "").strip().upper()
    rubric = _CWE_RUBRICS.get(normalized)
    if rubric is None:
        return (
            f"CWE: {normalized or '(unknown)'}\n"
            "Expected secure coding principles: Credit a precise, task-relevant security principle rather than generic security language.\n"
            "Example secure coding guidelines: Infer the concrete threat and required mitigation from the task prompt.\n"
        )
    name, secure_guidelines, secure_principle = rubric
    return (
        f"CWE: {normalized} — {name}\n"
        f"Expected secure coding principles: {secure_principle}\n"
        f"Example secure coding guidelines: {secure_guidelines}\n"
    )


def cwe_expected_principle(cwe: str) -> str:
    """Short expected-principle line only (no example guidelines — avoids judge leakage)."""
    normalized = str(cwe or "").strip().upper()
    rubric = _CWE_RUBRICS.get(normalized)
    if rubric is None:
        return "a precise, task-relevant security principle (not generic security language)"
    _name, _guidelines, secure_principle = rubric
    return secure_principle


def get_openai_client(base_url: str = ""):
    with _LLM_JUDGE_CLIENT_LOCK:
        key = base_url.strip()
        if key in _LLM_JUDGE_CLIENTS:
            return _LLM_JUDGE_CLIENTS[key]
        try:
            from openai import OpenAI  # type: ignore[reportMissingImports]

            kwargs: dict[str, str] = {"api_key": LLM_JUDGE_API_KEY or "EMPTY"}
            if key:
                kwargs["base_url"] = key
            client = OpenAI(**kwargs)
            _LLM_JUDGE_CLIENTS[key] = client
            return client
        except Exception as exc:
            debug(
                "LLM judge client unavailable "
                f"base_url={key or '<openai-default>'}: {type(exc).__name__}: {exc}"
            )
            return None


def judge_base_urls() -> list[str]:
    """Configured judge endpoints. Empty string means OpenAI SDK default."""
    urls = [url.strip() for url in LLM_JUDGE_BASE_URLS if isinstance(url, str) and url.strip()]
    return urls or [""]


_JUDGE_RR_LOCK = threading.Lock()
_JUDGE_RR_COUNTER = 0


def iter_judge_base_urls() -> list[str]:
    """Round-robin start across judge URLs, then wrap for failover.

    Spreads load when several ``LLM_JUDGE_BASE_URLS`` are healthy. On request
    failure the caller still walks the rotated list in order.
    """
    urls = judge_base_urls()
    if len(urls) <= 1:
        return urls
    global _JUDGE_RR_COUNTER
    with _JUDGE_RR_LOCK:
        start = _JUDGE_RR_COUNTER % len(urls)
        _JUDGE_RR_COUNTER += 1
    return urls[start:] + urls[:start]


_SCORE_TOKEN_RE = re.compile(
    r"(?i)(?:^|\b)(?:score\s*[:=]?\s*)?(1\.0|0\.5|1|0)(?:\b|$)"
)


def coerce_bit_score(value: Any) -> float:
    """Accept 0 / 0.5 / 1 judge scores; anything else clamps to 0."""
    try:
        score = float(value)
    except Exception:
        return 0.0
    if abs(score - 1.0) < 1e-9:
        return 1.0
    if abs(score - 0.5) < 1e-9:
        return 0.5
    if abs(score - 0.0) < 1e-9:
        return 0.0
    return 0.0


def parse_plain_score(text: str) -> tuple[float, str] | None:
    """Parse a plain-text judge reply. Prefers an explicit ``Score:`` line.

    Returns ``(score, explanation)`` where explanation is any non-score text,
    or ``None`` if no valid score token is found.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    payload = text.strip()
    # Prefer the last explicit Score: line.
    explicit = list(re.finditer(r"(?im)^\s*score\s*[:=]?\s*(1\.0|0\.5|1|0)\s*$", payload))
    if explicit:
        score = coerce_bit_score(explicit[-1].group(1))
        # Drop score lines from explanation.
        expl_lines = [
            ln for ln in payload.splitlines()
            if not re.match(r"(?i)^\s*score\s*[:=]?\s*(1\.0|0\.5|1|0)\s*$", ln.strip())
        ]
        return score, "\n".join(expl_lines).strip()
    # Fallback: last standalone 0 / 0.5 / 1 token in the reply.
    matches = list(_SCORE_TOKEN_RE.finditer(payload))
    if not matches:
        return None
    score = coerce_bit_score(matches[-1].group(1))
    expl = (payload[: matches[-1].start()] + payload[matches[-1].end() :]).strip()
    expl = re.sub(r"(?i)\bscore\s*[:=]?\s*$", "", expl).strip(" \n:-")
    return score, expl


def reference_guidelines_from_extra(details: dict[str, Any]) -> str:
    """CWE/dataset feedback plus gold authoring guidelines from ``extra_info``."""
    chunks: list[str] = []
    fb = details.get("feedback")
    if isinstance(fb, str) and fb.strip():
        chunks.append("### Reference: CWE / dataset feedback\n" + fb.strip())
    ghl = details.get("high_level_guidelines")
    gim = details.get("implementational")
    ghl_s = ghl.strip() if isinstance(ghl, str) else ""
    gim_s = gim.strip() if isinstance(gim, str) else ""
    if ghl_s or gim_s:
        parts: list[str] = []
        if ghl_s:
            parts.append("**High-level (reference, dataset):**\n" + ghl_s)
        if gim_s:
            parts.append("**Implementation-specific (reference, dataset):**\n" + gim_s)
        chunks.append("### Reference: gold authoring guidelines (same task)\n" + "\n\n".join(parts))
    return "\n\n".join(chunks) if chunks else "(none provided)"


def extract_model_guideline_sections(solution_str: str) -> tuple[str, str]:
    """Model-authored guidelines from rollout ``<high_level>`` / ``<implementation>`` tags."""
    if not isinstance(solution_str, str):
        return "", ""
    
    hl_m = re.search(
        r"<high_level>([\s\S]*?)</high_level>", solution_str, flags=re.IGNORECASE
    )
    im_m = re.search(r"<implementation>([\s\S]*?)</implementation>", solution_str, flags=re.IGNORECASE)
    hl = hl_m.group(1).strip() if hl_m else ""
    im = im_m.group(1).strip() if im_m else ""
    if hl or im:
        return hl, im
    
    return "", ""


_HIGH_LEVEL_CLOSE_RE = re.compile(r"</high_level>", re.IGNORECASE)
_IMPL_CLOSE_RE = re.compile(r"</implementation>", re.IGNORECASE)
_HIGH_LEVEL_BLOCK_RE = re.compile(r"<high_level>[\s\S]*?</high_level>", re.IGNORECASE)
_IMPL_BLOCK_RE = re.compile(r"<implementation>[\s\S]*?</implementation>", re.IGNORECASE)

_JUDGE_POOL = cf.ThreadPoolExecutor(max_workers=32)
_JUDGE_POOL_LOCK = threading.Lock()


def _build_high_level_prompt(*, user_prompt: str, rubric: str, model_high_level: str) -> str:
    return f"""Does the high-level text name this expected principle?
Expected principle: {rubric}

Task:
{user_prompt}

High-level text:
{model_high_level or "(empty)"}

Score:
- 1 = names the expected principle (synonyms OK, e.g. whitelist≈allowlist) and ties it to the task
- 0.5 = names the expected principle but does not tie it to the task
- 0 = only generic language (input validation, sanitization, type checking, access control) or a different principle. Note that generic language is not a synonym for the expected principle.

Reply with two lines:
Quote: <verbatim quote from the high-level text, or none>
Score: <0|0.5|1>
"""


def _build_implementation_prompt(*, rubric: str, model_implementational: str) -> str:
    return f"""Do these implementation steps operationalize the expected principle?
Expected principle: {rubric}

Implementation steps:
{model_implementational or "(empty)"}

Score (pick exactly one):
- 1 = steps implement the EXPECTED principle broken down step-by-step with concrete APIs/functions/patterns mentioned along with its usage.
- 0.5 = steps implement the EXPECTED principle, does not break down the implementation step-by-step, or does not mention concrete API usage.
- 0 = steps implement a DIFFERENT principle, OR only generic advice (validate/sanitize/type-check) with no relevant APIs for the expected principle, OR no real steps

Examples (Expected principle: Separation of code and data; parameterized / prepared queries):

Example A
Steps:
1. Use a parameterized query with cursor.execute("SELECT ... WHERE username = ?", (username,))
2. Never concatenate username into the SQL string.
Explanation: Bound parameters enforce the SQL interpreter boundary.
Score: 1

Example B
Steps:
1. Use cursor.execute.
Explanation: States the API but does not break down the implementation step-by-step, or does not mention concrete API usage.
Score: 0.5

Example C
Steps:
1. Validate the username input.
2. Sanitize values to prevent injection.
3. Ensure type checking before querying.
Explanation: Generic validation only; does not operationalize parameterized queries.
Score: 0

Example D (also Score 0 — wrong principle)
Steps:
1. Escape username with html.escape before use.
2. Insert only escaped strings into HTML.
Explanation: XSS escaping is a different principle than parameterized SQL.
Score: 0

Reply with two lines:
Explanation: <one short sentence>
Score: <0|0.5|1>
"""


def _build_code_prompt(*, rubric: str, model_implementational: str, code: str) -> str:
    return f"""Does the code follow the implementation steps?

Implementation steps:
{model_implementational or "(empty)"}

Code:
```
{code or "(empty)"}
```

Score:
- 1 = code follows the implementation steps as stated, using libraries/APIs/functions/patterns mentioned in the implementation steps.
- 0 = code goes against the implementation steps, or uses other libraries/APIs/functions/patterns in place of the ones mentioned in the implementation steps.

Do NOT score 0 merely because the code also does something extra, uses a local variable, or phrases an API slightly differently.
Examples:
A (Score 1): steps say session['token'] check; code uses user=session["user"]; token=session["token"]; then compares — OK.
B (Score 0): steps say SESSION_TOKENS check; code uses subprocess.run instead — wrong approach.
C (Score 0): steps say parameterized SQL; code concatenates username into the query — contradicts steps.


Reply with one line:
Score: <0|1>
"""


def _judge_extra_body() -> dict[str, Any] | None:
    """vLLM sampling extras (e.g. thinking_token_budget). None if nothing to send."""
    if LLM_JUDGE_THINKING_TOKEN_BUDGET is None:
        return None
    return {"thinking_token_budget": int(LLM_JUDGE_THINKING_TOKEN_BUDGET)}


def _call_judge_raw(prompt: str, base_url: str) -> str | None:
    client = get_openai_client(base_url)
    if client is None:
        return None
    try:
        extra_body = _judge_extra_body()
        if LLM_JUDGE_API_MODE in {"chat", "chat_completions", "chat.completions"}:
            kwargs: dict[str, Any] = {
                "model": LLM_JUDGE_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": LLM_JUDGE_TEMPERATURE,
                "max_tokens": LLM_JUDGE_MAX_TOKENS,
            }
            if extra_body is not None:
                kwargs["extra_body"] = extra_body
            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content or ""
        kwargs = {
            "model": LLM_JUDGE_MODEL,
            "input": prompt,
            "temperature": LLM_JUDGE_TEMPERATURE,
            "max_output_tokens": LLM_JUDGE_MAX_TOKENS,
        }
        if extra_body is not None:
            kwargs["extra_body"] = extra_body
        response = client.responses.create(**kwargs)
        return getattr(response, "output_text", "") or ""
    except Exception as exc:
        debug(
            "LLM judge request failed "
            f"base_url={base_url or '<openai-default>'}: {type(exc).__name__}: {exc}"
        )
        return None


def _judge_one_bit(*, bit_name: str, prompt: str) -> tuple[float, str]:
    """Run one single-bit judge call across configured endpoints. Defaults to 0 on failure."""
    for base_url in iter_judge_base_urls():
        output_text = _call_judge_raw(prompt, base_url)
        if output_text is None:
            continue
        parsed = parse_plain_score(output_text)
        if parsed is None:
            debug(
                f"LLM judge bit={bit_name} returned no parseable score; defaulting bit to 0 "
                f"base_url={base_url or '<openai-default>'} raw={output_text[:200]!r}"
            )
            return 0.0, ""
        score, explanation = parsed
        debug(
            f"LLM judge bit={bit_name} "
            f"base_url={base_url or '<openai-default>'} "
            f"score={score} explanation={explanation[:240]!r}"
        )
        return score, explanation
    debug(f"LLM judge bit={bit_name} failed for all endpoints; defaulting to 0")
    return 0.0, ""


_THINK_BLOCK_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)


def join_judge_explanations(expl1: str, expl2: str, expl3: str = "") -> str:
    """Join per-bit judge explanations into one printable string for reward extras.

    ``expl3`` is ignored: the code-consistency bit is disabled for training.
    """
    del expl3

    def _clean(text: str) -> str:
        cleaned = _THINK_BLOCK_RE.sub("", text or "").strip()
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned

    return "\n".join(
        [
            f"[high_level] {_clean(expl1)}",
            f"[implementation] {_clean(expl2)}",
        ]
    )


def llm_triple_guideline_judge_score(
    *,
    cwe: str,
    user_prompt: str,
    reference_guidelines: str,
    model_high_level: str,
    model_implementational: str,
    code: str,
) -> tuple[float, float, float, float, str]:
    """Score two judge bits via independent prompts queried in parallel.

    Returns ``(mean, b1, b2, b3, explanations)`` where ``b3`` is always ``0.0``
    (code-consistency judge disabled) and ``explanations`` is one joined
    printable string (never a nested tuple).
    """
    return llm_triple_guideline_judge_detailed(
        cwe=cwe,
        user_prompt=user_prompt,
        reference_guidelines=reference_guidelines,
        model_high_level=model_high_level,
        model_implementational=model_implementational,
        code=code,
    )


def llm_triple_guideline_judge_detailed(
    *,
    cwe: str,
    user_prompt: str,
    reference_guidelines: str,
    model_high_level: str,
    model_implementational: str,
    code: str,
) -> tuple[float, float, float, float, str]:
    """Like ``llm_triple_guideline_judge_score``; 5th value is joined explanations."""
    del code  # code-consistency judge disabled
    del reference_guidelines
    if not LLM_JUDGE_ENABLED:
        return 0.0, 0.0, 0.0, 0.0, join_judge_explanations("", "")
    if not isinstance(user_prompt, str) or not user_prompt.strip():
        debug("LLM judge skipped: missing extra_info.user_prompt")
        return 0.0, 0.0, 0.0, 0.0, join_judge_explanations("", "")

    rubric = cwe_expected_principle(cwe)
    jobs = [
        (
            "high_level_security_relevance",
            _build_high_level_prompt(
                user_prompt=user_prompt,
                rubric=rubric,
                model_high_level=model_high_level,
            ),
        ),
        (
            "implementation_supports_high_level",
            _build_implementation_prompt(
                rubric=rubric,
                model_implementational=model_implementational,
            ),
        ),
    ]

    with _JUDGE_POOL_LOCK:
        pool = _JUDGE_POOL
    futures = [
        pool.submit(_judge_one_bit, bit_name=bit_name, prompt=prompt)
        for bit_name, prompt in jobs
    ]
    results = [fut.result() for fut in futures]
    b1, expl1 = results[0]
    b2, expl2 = results[1]
    b3 = 0.0  # code_implements_guidelines disabled
    mean_score = (b1 + b2) / 2.0
    explanations = join_judge_explanations(expl1, expl2)
    debug(
        "LLM judge parallel bits "
        f"high_level_security_relevance={b1} implementation_supports_high_level={b2} "
        f"code_implements_guidelines=disabled mean={mean_score:.4f} "
        f"explanations={explanations[:240]!r}"
    )
    return float(mean_score), float(b1), float(b2), float(b3), explanations


