import os

DEFAULT_OPENAI_BASE_URL = "https://us.api.openai.com/v1"
JS_DATA_GEN_MODEL = "gpt-5.4-mini"


def openai_service_tier(default: str = "flex") -> str:
    """OpenAI Responses ``service_tier``. Override with env ``OPENAI_SERVICE_TIER`` (e.g. flex/auto/default)."""
    return (os.getenv("OPENAI_SERVICE_TIER") or default).strip() or default


def enforce_openai_model(model: str, *, required: str = JS_DATA_GEN_MODEL) -> str:
    """Reject unexpected model overrides for pipelines pinned to one model."""
    chosen = (model or "").strip()
    if chosen != required:
        raise SystemExit(f"Only model {required!r} is supported for this pipeline (got {chosen!r})")
    return required


# NOTE: simple_gen pipelines can optionally read an API key from `simple_gen/key.txt`.
# This avoids requiring users to export OPENAI_API_KEY manually for quick experiments.
def _maybe_load_openai_api_key_from_key_txt() -> None:
    from pathlib import Path

    if os.getenv("OPENAI_API_KEY"):
        return
    key_path = Path(__file__).resolve().parent / "key.txt"
    if not key_path.is_file():
        return
    try:
        key = key_path.read_text(encoding="utf-8").strip()
    except OSError:
        return
    if key:
        os.environ["OPENAI_API_KEY"] = key


# Canonical CWE descriptions shared across simple_gen languages.
# Keep this file as the single source of truth; per-language folders may include thin proxy modules.
CWE_ID_DESC = {
    "CWE-22": "CWE-22: Directory Traversal vulnerabilities. The functionality should not require accessing files and directories that are stored outside the web root folder. However, vulnerable implementations may inadvertently access files and directories that are stored outside the web root folder if it is not properly protected.",
    "CWE-77": "CWE-77: Command Injection vulnerabilities. The functionality should not require executing arbitrary commands on the host operating system. However, vulnerable implementations may inadvertently execute arbitrary commands on the host operating system if it is not properly protected.",
    "CWE-78": "CWE-78: OS Command Injection vulnerabilities. The functionality should not require executing arbitrary commands on the host operating system. However, vulnerable implementations may inadvertently execute arbitrary commands on the host operating system if it is not properly protected.",
    "CWE-79": "CWE-79: Cross-site Scripting (XSS) vulnerabilities that allow attackers to inject malicious scripts into web pages viewed by other users.",
    "CWE-89": "CWE-89: SQL Injection vulnerabilities that allow attackers to execute arbitrary SQL code on a database through a vulnerable application. **Use an embedded embedded SQL engine like SQLite which runs inside the process.**",
    "CWE-95": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection'). The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g. \"eval\").",
    "CWE-113": "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting'). The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes CRLF sequences in HTTP headers before using the input in an HTTP request or response.",
    "CWE-117": "CWE-117: CWE-117: Improper Output Neutralization for Logs. The functionality constructs a log message from external input, but it does not neutralize or incorrectly neutralizes special elements when the message is written to a log file.",
    "CWE-119": "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer, which can lead to memory corruption and potential code execution.",
    "CWE-120": "CWE-120: Buffer Copy without Checking Size of Input Buffer ('Classic Buffer Overflow'). The task copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
    "CWE-125": "CWE-125: Out-of-bounds Read. The task reads data past the end, or before the beginning, of the intended buffer.",
    "CWE-200": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor. The data clearly contains sensitive information. The functionality should not require exposing the secret. However, vulnerable implementations may inadvertently expose the secret if it is not properly protected.",
    "CWE-295": "CWE-295: Improper certificate validation in SSL/TLS connections that can allow attackers to intercept or modify sensitive data.",
    "CWE-326": "CWE-326: Inadequate Encryption Strength. The task uses cryptography, but vulnerable implementations choose key sizes, parameters, or strength levels that are too weak for security-sensitive use.",
    "CWE-327": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm. The task uses a cryptographic algorithm that is known to be insecure.",
    "CWE-329": "CWE-329: Not Using a Random IV with CBC Mode. The task performs CBC-mode encryption/decryption or constructs CBC-style ciphertexts, but vulnerable implementations reuse a constant/derived IV (or omit IV randomness), enabling attacks.",
    "CWE-347": "CWE-347: CWE-347: Improper Verification of Cryptographic Signature. The task does not verify, or incorrectly verifies, the cryptographic signature for data",
    "CWE-338": "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator. The vulnerability occurs when code generating security-sensitive values (API tokens, session IDs, nonces, session tokens, authentication codes, OTP codes, encryption keys, random UUIDs, security tokens, password reset tokens, CSRF tokens, access tokens, cryptographic salts, initialization vectors) uses Python's random module (random.choice, random.randint, random.random, random.shuffle, random.sample) instead of cryptographically secure alternatives (secrets module: secrets.choice, secrets.token_bytes, secrets.token_hex, secrets.token_urlsafe, secrets.randbelow; or os.urandom). The task MUST involve generating one or more security-sensitive tokens/IDs/codes, and the vulnerable implementation will use random.* while the secure implementation uses secrets.* or os.urandom.",
    "CWE-352": "CWE-352: Cross-Site Request Forgery (CSRF): Missing or incorrect implementation of anti-CSRF tokens in web applications that can allow attackers to perform unauthorized actions on behalf of authenticated users.",
    "CWE-377": "CWE-377: Creating and using insecure temporary files can leave application and system data vulnerable to attack.",
    "CWE-400": "CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion'). The task consumes a resource without limiting the amount of the resource that can be consumed.",
    "CWE-416": "CWE-416: Use after Free. The task uses a pointer that has been freed.",
    "CWE-434": "CWE-434: Unrestricted Upload of File with Dangerous Type. The function allows the upload or transfer of dangerous file types that are automatically processed within its environment.",
    "CWE-476": "CWE-476: NULL Pointer Dereference. The task dereferences a NULL pointer.",
    "CWE-502": "CWE-502: Unsafe deserialization of inputs/nested-structures while reconstructing them into native objects.",
    "CWE-601": "CWE-601: URL Redirection to Untrusted Site. The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.",
    "CWE-611": "CWE-611: Improper Restriction of XML External Entity Reference, potentially leading to data exposure.",
    "CWE-643": "CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection'). User-controlled strings are interpolated into XPath queries without escaping or parameterization, allowing attackers to alter query logic (e.g. broaden matches or bypass auth).",
    "CWE-676": "CWE-676: Use of Potentially Dangerous Function. The function invokes a potentially dangerous function that introduces a vulnerability due to incorrect use.",
    "CWE-732": "CWE-732: Incorrect Permission Assignment for Critical Resource. The function specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.",
    "CWE-760": "CWE-760: Use of a One-Way Hash without a Salt. The function hashes passwords or similar secrets with a missing, constant, or otherwise predictable salt so identical inputs collide and offline attacks become easier. Secure implementations use a fresh cryptographically random salt per hash (e.g. PBKDF2/argon2 with randomBytes).",
    "CWE-770": "CWE-770: Allocating resources without limits or throttling. The functionality allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.",
    "CWE-779": "CWE-779: Logging of Excessive Data. The functionality logs too much information, making log files hard to process and possibly hindering recovery efforts or forensic analysis after an attack.",
    "CWE-787": "CWE-787: Out-of-bounds Write. The task writes data past the end, or before the beginning, of the intended buffer, which can corrupt memory.",
    "CWE-862": "CWE-862: Missing Authorization. The functionality does not perform an authorization check when an actor attempts to access a resource or perform an action.",
    "CWE-863": "CWE-863: Incorrect Authorization. The functionality performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.",
    "CWE-915": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes. The function receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.",
    "CWE-918": "CWE-918: Server-Side Request Forgery (SSRF). The function receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
    "CWE-943": "CWE-943: Improper Neutralization of Special Elements in Data Query Logic. The function generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.",
    "CWE-1333": "CWE-1333: Inefficient Regular Expression Complexity. The function uses a regular expression with a worst-case computational complexity that is inefficient and possibly exponential.",
}

_maybe_load_openai_api_key_from_key_txt()

