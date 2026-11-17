rubrics = {
    "CWE-22": """- Security tests: distinguish safe relative filenames/subpaths from traversal, absolute paths, encoded traversal, or symlink-like escape attempts; secure behavior should **reject or raise for** escape attempts or keep resolution under the intended root. BAD: input: {"user_path": "../secret.txt", "file_map": {"../secret.txt": "TOP_SECRET"}} output: "TOP_SECRET" GOOD: input: { "user_path": "../secret.txt", "file_map": {   "docs/report.txt": "SAFE",   "../secret.txt": "TOP_SECRET"  }} output: Exception
- Functionality tests: ordinary names under the allowed root should succeed.
- Invalid tests to avoid: functionality cases that expect success for ``..`` or absolute paths, or security cases that are merely missing-file errors.
- **reject:** prompts that describe traversal paths as valid inputs or require reading outside the sandbox/root. Do not attempt to rewrite tests.
- **UNCHANGED:** original security tests already cover traversal (`..`) AND
  absolute paths AND at least one encoded path (e.g., `%2e%2e/` or `..%2f` or
  `%2fetc/passwd`), and every case has correct expected outputs. Do not rewrite just to add marginally more vectors, refactor, or force Exception where a safe return is the correct behavior. If coverage is already adequate, keep it UNCHANGED.
""",

    "CWE-78": """- **Valid injection surface:** user-controlled text is formatted into returned command/report/log/template/diagnostic strings (or passed to ``open_command``/shell logging) where naive concat could build shell text. Prompt must forbid shell execution.
- **Hard rule — no metachar echo in any expected output:** For **every** test case (``functionality`` and ``security``), the expected ``output`` must **never** contain raw shell metacharacters from attacker-controlled input: ;, |, &, `, $,(,), <, >, &&, ||, $(...), or backtick-wrapped fragments. If the **input** on an injection surface includes those characters, secure behavior is Exception or a fully neutralized string with **zero** of those characters reproduced.
- **Injection surfaces:** username, suffix, label, log_file, output_name, destination, open_command, action, user_name, command/diagnostic strings, and any field passed to shell/logging — not fixed delimiters inside preloaded log **content** strings unless the test is probing that field as the attack vector.
- BAD: input suffix: ok; echo INJECTED → output: ; echo INJECTED. GOOD: Exception.
- BAD: input username: alice; echo INJECTED → output returns a timestamp for that poisoned name. GOOD: Exception or "" (no match).
- BAD: input log_file: /tmp/x; touch /tmp/pwned → output success for text edit. GOOD: Exception before any shell/path use.
- BAD: input command echo safe && rm -rf / → output executed/log still contains && rm -rf /. GOOD: Exception.
- **Not CWE-78 (→ reject only, never UNCHANGED):** metachars only used as dict keys (file_map lookup), digest/hash input, integer parsing, or no command-like output surface; prompt requires unsafe shell execution with user text. If there is no injection surface, use reject.
- **Validate EVERY injection surface in the signature:** when more than one user-controlled input reaches the same command/log/shell string (e.g. ``text``, ``fragment``, AND ``log_file`` all flow into a shell-built log line), security must probe **each** such input independently with metacharacters and the oracle must reject/neutralize **all** of them. Hardening only the first surface (e.g. only ``log_file``) while leaving the others unprobed is an incomplete rewrite — add a separate security case per attacker-controlled surface.
- **UNCHANGED:** real injection surface **and** **no** test expected output (functionality or security) reproduces shell metacharacters from user-controlled fields; every metachar probe already fails. This also covers the case where your analysis finds nothing concrete to fix: output UNCHANGED — never emit a rewrite that is byte-identical (modulo formatting) to the input.
- **rewrite:** any test still echoes metachars on success; attacks in functionality; or security lacks metachar failure cases. Revised test_code must change those outputs — do not copy the same echoing expectations you criticized.
""",

    "CWE-79": """- If attacker input contains: <script>, <img>, <svg>, onerror=, onclick=, javascript:, quotes (' "), </, style=, or HTML tags, then expected secure behavior must be: escaped as inert text, OR rejected with ValueError, OR sanitized so dangerous attributes/tags are removed. BAD: input: {"username":"<script>alert(1)</script>"} output: "<h1><script>alert(1)</script></h1>" GOOD: output: "<h1>&lt;script&gt;alert(1)&lt;/script&gt;</h1>" (or Exception)
- Functionality tests: benign text with ordinary punctuation should render correctly.
- Invalid tests to avoid: expected HTML that leaves raw tags, event handlers, ``javascript:`` URLs, or unescaped attribute-breaking quotes from input; **rewrite** if security expects breakout via `class`/`style`/`id` (e.g. `onmouseover=` inside an attribute) to expect ``Exception`` even when body text is escaped.
- **reject:** prompts that require returning raw user-controlled HTML/JS without a sanitization policy. Do not attempt to rewrite tests.
""",

    "CWE-89": """- **Valid:** parameterized queries; user text bound as **data**. Preloaded/in-memory DB in setup/tests is enough to expect ``[]`` or ``Exception`` for injection probes that must not broaden results.
- **Security vs functionality:** Security exercises **lookup/filter/search/id** boundaries (tautologies, quotes, comments, stacked statements, `OR` bypass) → no extra rows, empty list, or ``Exception``. Functionality uses benign values only.
- **Wrong-category security:** a **security** case whose only check is normal **success** after insert/submit with an injection-shaped **literal** stored/echoed — that does not test SQL boundaries. **rewrite** it: drop from security or replace with lookup/filter attacks; do not leave the same success oracle you criticized.
- BAD: filter ``1=1 --`` / ``OR '1'='1'`` → all rows. GOOD: ``[]`` or ``Exception``.
- BAD: lookup ``1 OR 1=1`` → broadened results. GOOD: ``Exception`` or one authorized row.
- BAD: security insert with ``'); DROP ...`` → queued/success. GOOD: security uses lookup metachars → ``Exception``; benign submit in functionality only.
- **UNCHANGED:** prompt requires parameterization and security already uses lookup-boundary cases with safe expectations (not store-and-echo success for SQL syntax).
- **rewrite:** tests/oracle wrong but prompt OK; change every flagged security ``output`` in ``test_code`` (naive concat on lookup must fail). If you drop a wrong-category insert/submit security case, do not re-add it: no security case may expect **success** when any input value contains SQL metacharacters (``');``, ``--``, ``DROP``, ``OR 1=1``).
- **reject:** only when the **prompt** requires SQL concatenation or caller-supplied SQL syntax as the query shape — not because tests are weak. Do not reject valid parameterized prompts.
- **Missing DB setup is NOT a reject reason:** `setup_tests` is omitted for every row, so an empty `setup_tests`, an undefined `conn`, or an "unestablished" in-memory DB is a harness artifact, not prompt-invalid behavior. If the prompt asks for parameterized SQL against a preloaded/in-memory SQLite DB, treat that DB and connection as already provided and proceed to **rewrite** or **UNCHANGED** — never reject for missing/unrunnable database context.
""",

    "CWE-95": """- **Valid:** expect to throw Exception for Python/code input, expected operations evaluating correctly 
- **reject:** demands execution of user-provided Python code directly, prompt task too simple/ does not include dynamic evaluation
    - Dangerous syntax includes: __import__, eval, exec, open, os., subprocess, globals(), locals(), vars(), getattr(), setattr(), ().__class__, __mro__, __subclasses__, lambda, function calls, attribute access, comprehensions, semicolon-separated statements, imports, dunder access.
- **UNCHANGED:** Python/code inputs rejected with Exception (may also escapes user input, but Exception required), allowed operations function properly
- **rewrite:** safe-path security tests only, allowing executable syntax (includes weak escapes), returning false/empty instead of Exception on unsafe input, security test expecting non-allowed commands to succeed
""",

    "CWE-200": """- **Valid tests:** returns user-visible data from records with public + sensitive fields (``note``/``secret``/token); security checks non-leakage.
- **reject:**  please reject any prompt that mandates exposure of sensitive data to unauthorized actors; OR any problem containing no actual sensitive field (just appears "sensitive"); OR any task where no sensitive field can be returned -- security risks may appear to exist but don't actually exist. Do not attempt to rewrite the tests for these cases, as they are moot. 
- **rewrite:** if the prompt is valid, then rewrite any security tests where the outputs leak secrets to **unauthorized** actors (either directly or indirectly). Make sure the prompt gives enough information for the output; i.e. any redaction message in the output is compared with an absolute string match, so other redactions may fail if the prompt doesn't specify. Make sure the test cases do not go against the prompt. If that isn't possible, reject. 
- **UNCHANGED:** report UNCHANGED if tests contain sensitive fields that are already absent from expected outputs in security test cases, or only authorized actors (eg. admin) receive sensitive information.
""",

    "CWE-295": """- **Valid:** Security tests check for cert/host/fingerprint/pin (simulated in-memory maps OK) — not scheme-only; Security tests include an untrusted-cert failure.
- **reject:** prompt explicitly asks to disable verification; no cert check in prompt+tests; prompt checks HTTP-vs-HTTPS only; security checks are only "reframed" functionality tests. reject if using ssl.create_default_context() doesn't make sense. 
- **UNCHANGED:** security tests -- trusted identity succeeds; wrong cert/host/MITM fails. ssl.create_default_context() is used for validation. No cosmetic rewrites.
- **rewrite:** tests accept wrong cert/MITM; tests missing cert-trust security cases.  Tests must check for use of ssl.create_default_context(). Ground truth must use the ssl library. No mocks allowed, no rolling out your own crypto.
""",

    "CWE-352": """- REJECT prompts that explicitly forbid CSRF tokens or allow state-changing actions without an anti-CSRF check. Do not attempt to rewrite tests.
- REJECT prompts whose function has no CSRF token interface at all (e.g. a pure computation or read-only helper with no session/form/token parameters). Do not attempt to rewrite tests into a CSRF scenario that the prompt never described.
- Security tests: distinguish authorized state-changing requests with a valid CSRF token from missing, wrong, stale, or cross-user tokens; secure behavior should reject invalid token/session pairings. A valid CWE-352 test must contain token validation, not just authorization or ownership checks. Bad: {"session_user":"alice","target_user":"bob"} output: Exception (this is auth only). Good: {"session_user":"alice","csrf_token":"tok_bob","csrf_tokens":{"alice":"tok_alice","bob":"tok_bob"}} -> raises because the token does not match the active session.
- Functionality tests: correct user/session/token combinations should update state.
- Invalid tests to avoid: read-only operations, normal functionality in security, authorization/ownership checks that do not involve any CSRF token.
""",

    "CWE-502": """- REJECT prompts that explicitly require deserializing arbitrary untrusted objects or executing deserialization hooks. DIRECTLY REJECT prompts that have no mention of the deserialization or serialization. Do not attempt to rewrite tests.
- Security tests: distinguish trusted structured data from unsafe serialized objects, class tags, reducers, eval-like payloads, or custom notation that can instantiate/execute; secure behavior should parse only safe types.
- Security payloads must be valid syntactic input for the stated serialization format. Raw Python expressions such as __import__('os').system(...), pickle.loads(...), or eval(...) are NOT valid CWE-502 security cases unless the function explicitly uses eval or exec. Using them as payloads tests nothing meaningful because a safe parser would just treat them as invalid input rather than executing them.
- Prefer payloads that match the actual serialization format in use: !!python/object tags for YAML, pickle bytes (hex-encoded) for pickle, {"__class__": ..., "__reduce__": ...} style keys for a custom object-reconstruction deserializer, or class-tag/reducer notation for any custom format. The attack payload must be something that an insecure implementation would deserialize unsafely but a secure one would reject.
- Functionality tests: ordinary safe serialized data should load correctly.
- Invalid tests to avoid: ill-defined custom serialization formats or payloads that cannot be interpreted by either safe or unsafe implementations; raw code-execution strings passed to a parser that never calls eval.
""",

    "CWE-601": """- DIRECTLY REJECT prompts that explicitly allow arbitrary user-supplied redirect URLs without an allowlist or same-origin policy. Do not attempt to rewrite tests.
- Security tests: distinguish same-site/allowlisted redirects from external domains, scheme-relative URLs, encoded external URLs, or dangerous schemes; secure behavior should reject or normalize to a safe destination. Security tests must cover at least one encoded or obfuscated bypass beyond a plain https://evil.com case, such as %2F%2Fevil.com (percent-encoded scheme-relative), HTTPS://evil.com (mixed-case scheme), //evil.com (protocol-relative), or a whitespace-padded URL like " https://evil.com".
- Functionality tests: relative paths or allowlisted callback URLs should redirect successfully.
- Invalid tests to avoid: oracles or test setup that reference undefined globals (e.g. DEFAULT_REDIRECT, DEFAULT_DASHBOARD, PRODUCT_BASE_URL without a definition in the same test block); security cases that only test token validity and not redirect control. All globals used in tests must be defined inline so the test block is self-contained.
""",

    "CWE-611": """- **Valid:** performs operation within XML document without resolving/using URI's outside the given bounds of safe operation, parses and escapes unsafe XML entities such as ''&lt;''
- **reject:** prompts that require resolving external entities/resources from XML (reading alone is allowed) prompts that do not mention XML or external entities
- **UNCHANGED:** tests rejecting XML entities containing URI's, security test to ensure safe ampersands/XML entities do not cause errors
- **rewrite:** tests expecting external entities to be supported, rejection of all ampersands/XML entities, security tests that fail to use XML entities in attacks, returning nothing instead of throwing Exception
    - **allowlist:** prompts that use an allowlist/in-memory mapping of external entities are invalid; rejecting external entities should be prioritized over implementing an allowlist. If possible, rewrite the test/oracle to ignore them entirely
""",

    "CWE-770": """- **Valid:** attacker-controlled size, count, or repetition parameter flows into allocation/loop/collection growth; prompt describes a limit or can accept one. In-memory models are fine.
- **Task shapes:**
    1. **Bounded collection** (list/dict/queue with a max size): user supplies count or elements; oracle must enforce a cap.
    2. **Throttled processing** (rate/batch limit): user controls how many items are processed per call; oracle must cap per-call work.
    3. **Payload size** (string/file/request body): user supplies oversized data; oracle must reject or truncate.
- **Security vs functionality:** Security cases supply values **above** the limit (count=10000, payload="A"*1000000). Functionality cases use values **below** the limit with normal expected output.
- BAD: input: {"count": "../secret.txt"}, output: Exception (path traversal, not 770). GOOD: input: {"count": 10000}, output: Exception.
- BAD: input: {"items": [1]*100}, output: [1]*100 (no limit enforced). GOOD: input: {"items": [1]*100}, output: Exception (exceeds max of 50).
- BAD: security only checks duplicates, empty input, SQL strings, or small bounded values — these are NOT CWE-770.
- **reject:** prompt explicitly requires unbounded allocation, unlimited loops, or no limit on user-controlled sizes; or prompt has no mention of any resource and cannot be meaningfully turned into a resource-limiting task.
- **UNCHANGED:** security tests already supply over-limit inputs and expect Exception or truncation; functionality tests stay below the limit; no non-770 categories are mislabeled as security.
- **rewrite:** prompt has a resource story but security tests use wrong-category inputs (path traversal, SQL, duplicates) or only test below-limit values; or over-limit tests expect success instead of Exception/truncation. Specify in the prompt whether throttling → Exception or per-element None/exclusion. Revised test_code must add over-limit failure cases — do not copy the same passing expectations you criticized.
""",

    "CWE-862": """- **Valid:** A task is ONLY valid for CWE-862 if a principal (user/role/caller/requester/session) gates a resource, action, record, or admin-only operation; in-memory permission models are fine. There MUST be some sort of principal context that can be obtained from the function signature as defined by the prompt. If the function signature defined in the prompt lacks any parameter to accept a principal, it is NOT valid. You MUST reject it.
- **Task shapes:**
	1. **Resource-level access:** user A may or may not access user B's record, profile, file, or project.
	2. **Action-level access:** a principal may read something but must not write, delete, export, approve, or publish it.
	3. **Admin-only or privileged operation:** non-admin, guest, or low-privilege caller must be denied.
- **Security vs functionality:** security cases should supply an unauthorized principal and expect denial; functionality cases should supply an authorized principal and expect success. For denial, accept `Exception` or an empty/error result, depending on the prompt's contract.
- BAD: input: {"user": "viewer", "action": "delete"}, output: success. GOOD: input: {"user": "viewer", "action": "delete"}, output: Exception.
- BAD: security checks path traversal, SQL injection, file modes, or other non-auth problems. GOOD: security checks that a caller without permission cannot access the protected resource.
- **reject:** prompt intentionally lets any caller perform the protected action, or it cannot accept / represent a caller identity at all, so no authorization check can be meaningfully tested without changing the required signature.
- **UNCHANGED:** authorization is already enforced; security cases already deny unauthorized principals; functionality cases use authorized principals; no wrong-category tests are mislabeled as security.
- **rewrite:** prompt has an auth story, but the tests only cover happy-path success, use path traversal/file-mode/SQL-style probes instead of unauthorized principals, or omit denial cases entirely. Revised `test_code` must add explicit unauthorized-principal failures and not copy the same success expectations you criticized.
""",

    "CWE-863": """- **Valid:** a permission/role check exists but is **wrong** — grants too much, checks the wrong attribute, or omits action-specific constraints; in-memory permission models are fine.
- **Task shapes:**
    1. **Horizontal privilege escalation:** user A accesses user B's resource despite a same-role restriction (object-level auth failure).
    2. **Vertical privilege escalation:** non-admin passes a role check that should require admin (role-level auth failure).
    3. **Action-specific gap:** user has read permission but the check also allows write/delete/export (action-scope auth failure).
- **Security vs functionality:** Security cases supply a principal who should be **denied** — wrong role, wrong owner, insufficient action scope. Expect Exception or an empty/error result. Functionality cases supply a principal with correct permissions and expect success.
- BAD: input: {"user": "admin", "action": "delete"}, output: success (only tests happy path, no denial case). GOOD: add input: {"user": "viewer", "action": "delete"}, output: Exception.
- BAD: security checks path traversal or SQL injection strings — not an authorization test. GOOD: security checks that user with role "editor" cannot perform "admin_export".
- **reject:** prompt intentionally allows any user to perform protected operations with no principal/role/actor parameter, or the signature cannot accept a caller identity to check against.
- **UNCHANGED:** security tests already deny unauthorized principals (wrong role, wrong owner, wrong action scope) and functionality tests use authorized principals; no wrong-category tests mislabeled as security.
- **rewrite:** prompt has a permission/role model but security only checks path traversal, file modes, or happy-path success; or tests omit denial of unauthorized principals. Revised test_code must add explicit denial cases — do not copy the same success expectations you criticized.
""",

    "CWE-915": """- **Valid:** Security tests merge upstream `updates`/`fields`/`patch` into a profile/config/record using an explicit allowed-field whitelist; security blocks unknown or protected attributes (role, admin, owner, id, enabled).
- **reject:** prompts suggest a read-only lookup with no writes; prompt requires blind `update(**user_input)` or applying every supplied key with no whitelist. Or if there are no privileged fields that can be injected. 
- **rewrite:** if tests allow admin privileges for guests. or if security tests only involve string keys that look like dunders (dicts cannot cause injections). Instead,consider tests that attempt to edit privileged fields instead of passing dunders. Rewrite any wrong-category pickle-only tasks → `rewrite` with `security_tests_not_cwe_relevant`, not `reject`.
- **UNCHANGED:** whitelist is in the prompt and security test cases already reject protected/unknown fields (including dunder/prototype keys when they would change behavior).
""",

    "CWE-918": """- **Valid:** controls which URL/host/path may appear in redirects, lookups, or responses; simulated in-memory I/O is fine (no real socket required).
- **reject:** this is rare -- but reject prompt requires outbound fetch of arbitrary URLs and has no safe-destination wording; cannot fix without replacing the prompt.
- **UNCHANGED:** read every security case **expected output**: none may **succeed** while returning/storing localhost, private IP, `file://`, or metadata endpoints in redirect/Location/body/lookup; security cases test destination policy, not unrelated CWEs; oracle implements prompt URL rules.
- **rewrite:** any security case **succeeds** with those unsafe destinations in the output; most security cases are injection/traversal/unrelated; oracle skips URL-handling the prompt requires (e.g. never uses a stated fetch URL). If prompt forbids network, fix tests — do not `reject`.
""",

    "CWE-1333": """- **Valid:** validating user-supplied regex (grammar validation, escaped-literal search, safe compile/match policy), safe internal regex (tag extraction)
  - **Three task shapes (audit security against the right surface):**
    1. **Fixed grammar / bounded fullmatch** (e.g. `Nd`/`Nh`, username rules, markup tokenization): user supplies **strings to match**, not the regex itself.
    2. **Escaped-literal search** (e.g. title/author queries folded into a regex): user strings must be escaped/restricted before regex use.
    3. **User-supplied pattern** (e.g. `rule_pattern`, `header_pattern`): caller provides the regex text; oracle must reject dangerous patterns **and** safely match data.
- **reject:** prompt demanding nested quantifiers, prompt lacking regex, prompts that test simple regex functionality rather than complexity, no safe regex policy availiable, demanding query of user-supplied regex directly
- **UNCHANGED:** security tests include a long near-miss case expecting failure (for simple/small matches, oracle uses safe fullmatch & security rejects rejects malformed inputs), testing complex/backtracking regex user inputs
- **rewrite:** security expecting excessively complex regex to match rather than throw Exception, safe-path security only, no tests for backtracking/excessive computational complexity (ex: long near-miss), only tests user-pattern blacklist, applying regex with nested quantifiers, no user-regex validation/escape
""",

}