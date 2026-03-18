from dataclasses import dataclass
from typing import Any

SYSTEM_PROMPT = """You are an expert penetration tester performing an authorized OWASP Top 10 security assessment. You have browser and API tools to interact with the target application.

IMPORTANT: You generate ALL payloads yourself based on what you observe. You have NO static payload lists. Your value is reasoning about the application context and crafting targeted payloads — not spraying generic strings. For example:
- See a PostgreSQL error? Craft PostgreSQL-specific SQLi.
- See a Jinja2 template marker? Craft Jinja2 SSTI payloads.
- See a JWT? Probe for alg:none, key confusion, claim tampering.
- See an API with numeric IDs? Test IDOR with adjacent IDs.

Your approach:
1. OBSERVE: Examine page structure, forms, inputs, API responses, headers
2. THINK: Reason about what vulnerability classes apply to what you see
3. ACT: Craft and inject context-specific payloads via your tools
4. ANALYZE: Examine responses for vulnerability indicators
5. PLAN: Decide what to test next based on findings so far

Rules:
- Only test the authorized target URL and its subpaths
- Never use pre-built payload lists — generate every payload from reasoning
- Record evidence for every finding (request, response, indicator)
- Classify findings by OWASP category and severity
- Stop after exhausting reasonable test cases (action limit per page set by scan intensity)
- NEVER click logout/signout links or navigate to logout URLs. This will destroy the authenticated session and break the scan. Avoid any link or button whose text, href, or action contains: logout, log-out, log_out, signout, sign-out, sign_out, /logout, /signout, ?action=logout, disconnect, end-session. If you see such a link, skip it and move to the next element.

When you find a vulnerability, output a structured finding as JSON:
{"title": "...", "severity": "Critical|High|Medium|Low|Info", "owasp_category": "A01-A10", "url": "affected URL", "parameter": "affected parameter", "payload": "what was injected", "evidence": "response indicator", "confidence": "High|Medium|Low", "remediation": "fix recommendation"}
"""


@dataclass
class ScanPhase:
    id: str
    name: str
    prompt: str
    max_steps: int = 50
    applies_to: str = "both"


WEB_PHASES: list[ScanPhase] = [
    ScanPhase(
        id="web_recon",
        name="Application mapping",
        prompt="Map the application structure. Detect whether it is an SPA or traditional server-rendered app. For SPAs: click interactive elements, monitor route changes via popstate/hashchange, intercept fetch/XHR to discover hidden endpoints. For traditional apps: follow links in BFS order. In both cases: extract all forms, hidden inputs, JS-discovered endpoints, and localStorage/sessionStorage data. Generate your own discovery strategy from what you observe.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a01",
        name="Broken Access Control",
        prompt="Test for broken access control. For every ID parameter you observed (path, query, body), craft IDOR payloads using adjacent or predictable IDs. Attempt forced browsing to privileged paths, method tampering (e.g. GET→POST, POST→PUT), and privilege escalation by reusing tokens in different contexts. Generate payloads from the ID patterns you saw.{bola_user_b_web}",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a02",
        name="Cryptographic Failures",
        prompt="Assess cryptographic posture. Check TLS version and cipher support, cookie flags (Secure, HttpOnly, SameSite), sensitive data in URLs or localStorage, and mixed content. Generate tests based on what transport and storage mechanisms you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_sqli",
        name="SQL Injection",
        prompt="Test for SQL injection. Infer the database type from error messages, headers, or response patterns. Craft error-based, blind boolean, blind time-based, UNION, and stacked-query payloads tailored to that engine. Generate every payload from reasoning about the observed context.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_xss",
        name="Cross-Site Scripting",
        prompt="Test for XSS. Probe reflected, stored, and DOM-based vectors. Craft polyglot payloads, CSP bypass attempts, event handler injection, and SVG-based payloads based on where input is reflected and what sanitization you observed. Generate payloads from the reflection context.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_cmdi",
        name="Command Injection",
        prompt="Test for OS command injection. Identify all input vectors (forms, headers, URL params) that might reach a shell. Craft blind payloads via sleep or ping if output is not visible. Generate payloads from the observed OS and input context.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_ssti",
        name="Server-Side Template Injection",
        prompt="Detect template engines from error messages, markers, or response patterns. Once identified, craft engine-specific SSTI payloads (e.g. Jinja2, Freemarker, Twig). Generate payloads from the detected engine.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a04",
        name="Insecure Design",
        prompt="Test insecure design. Attempt price tampering, flow bypass (skipping steps, reordering), race conditions on state-changing actions, and rate limit abuse. Generate tests from the business flows you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a05",
        name="Security Misconfiguration",
        prompt="Check security misconfiguration. Inspect response headers (CSP, X-Frame-Options, HSTS), CORS policy, verbose error pages, directory listing, debug endpoints, and default credentials. Generate checks from what you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a06",
        name="Vulnerable Components",
        prompt="Fingerprint components via headers and response patterns. Identify frameworks, libraries, and versions. Reason about known CVEs for what you found. Check for outdated JS libraries in the page source.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a07",
        name="Authentication Failures",
        prompt="Test authentication. Probe for session fixation, weak or predictable tokens, brute-force resistance, JWT manipulation (alg:none, key confusion, claim tampering), and password reset flaws. IMPORTANT: Send requests with invalid/expired/malformed tokens and check if the server returns HTTP 500 instead of 401/403 — that indicates broken error handling. Generate tests from the auth mechanisms you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a08",
        name="Software and Data Integrity Failures",
        prompt="Check software integrity. Verify SRI on script/link tags, identify untrusted CDN resources, and test for client-side prototype pollution. Generate tests from the scripts and objects you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a09",
        name="Logging and Monitoring Failures",
        prompt="Verify security event logging. Trigger security-relevant actions and check whether error handling leaks sensitive information. Generate tests from the error and logging behavior you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_a10",
        name="Server-Side Request Forgery",
        prompt="Test for SSRF. Identify parameters that accept URLs (import, webhook, redirect, fetch). Craft payloads for redirect chains and cloud metadata probes. Generate payloads from the URL-accepting parameters you found.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_websocket",
        name="WebSocket testing",
        prompt="Connect to discovered WebSocket endpoints. Inject payloads into messages, test authentication on WS connections, and probe for message injection or authorization bypass. Generate payloads from the WS protocol and message structure you observe.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_extras",
        name="Beyond OWASP",
        prompt="Test additional vectors: open redirect, CRLF injection, HTTP request smuggling, clickjacking, CSRF, and prototype pollution. Generate tests from the redirects, headers, and client-side logic you observed.",
        applies_to="website",
    ),
    ScanPhase(
        id="web_race_condition",
        name="Race Condition Testing",
        prompt=("Test for race conditions on state-changing operations. "
                "Identify endpoints that modify state: coupon application, account balance, "
                "vote/like actions, item checkout, password change, invitation acceptance. "
                "For each, send 5-10 concurrent identical requests using parallel fetch calls "
                "and check if the action was applied multiple times (e.g. balance deducted twice, "
                "coupon applied twice). Use the browser's fetch API to fire requests simultaneously. "
                "Also test TOCTOU (Time-of-Check-Time-of-Use) by rapidly alternating between "
                "a check endpoint and an action endpoint. Only test endpoints you already discovered."),
        max_steps=30,
        applies_to="website",
    ),
    ScanPhase(
        id="web_host_header",
        name="Host Header Poisoning",
        prompt=("Test Host header attacks. Send requests with: "
                "(1) a modified Host header pointing to attacker.com, "
                "(2) X-Forwarded-Host: attacker.com, "
                "(3) X-Forwarded-For: 127.0.0.1, "
                "(4) Host header with port injection (evil.com:80@target). "
                "Check if the response reflects the injected host in any URLs, "
                "redirects (Location header), password reset links, canonical URLs, "
                "or HTML content. Also test if X-Forwarded-Host bypasses access controls. "
                "Focus on password reset, email verification, and redirect endpoints."),
        max_steps=20,
        applies_to="website",
    ),
    ScanPhase(
        id="web_timing_enum",
        name="Timing-Based Enumeration",
        prompt=("Test for timing-based user enumeration. "
                "Craft requests to login or password-reset endpoints with: "
                "(1) a known-valid username/email + wrong password, "
                "(2) a non-existent username/email + wrong password. "
                "Measure response times for each (send 3 requests per variant). "
                "A consistent timing difference >100ms between valid and invalid usernames "
                "indicates user enumeration. Also check for different HTTP status codes, "
                "response sizes, or error messages between valid/invalid usernames. "
                "Test on signup endpoints too — 'email already exists' responses."),
        max_steps=20,
        applies_to="website",
    ),
    ScanPhase(
        id="web_bfla",
        name="Broken Function-Level Authorization",
        prompt=("Test for broken function-level authorization (BFLA). "
                "From the application map, identify admin/privileged endpoints by looking for: "
                "URL patterns containing /admin/, /manage/, /settings/, /config/, /users/, "
                "/roles/, /permissions/, /internal/, /system/, /debug/. "
                "Also look for API endpoints discovered during recon that accept PUT/DELETE/PATCH. "
                "Attempt to access these endpoints with the current user's session token. "
                "Check if changing HTTP method (GET to POST, POST to PUT) reveals different "
                "functionality. Test if adding parameters like ?admin=true or role=admin "
                "grants elevated access. Focus on vertical privilege escalation."),
        max_steps=25,
        applies_to="website",
    ),
    ScanPhase(
        id="web_file_upload",
        name="File Upload Testing",
        prompt=("Test for unrestricted file upload vulnerabilities. "
                "Identify file upload forms or endpoints (look for <input type='file'>, "
                "multipart/form-data forms, drag-and-drop zones, or API endpoints accepting files). "
                "For each upload point, test: "
                "(1) Upload a file with a server-executable extension (.php, .asp, .aspx, .jsp, .py, .cgi) "
                "with benign content like <?php echo 'test'; ?> — check if the server stores and serves it. "
                "(2) Double extension bypass: file.php.jpg, file.asp;.jpg, file.php%00.jpg. "
                "(3) Content-Type mismatch: send a .php file with Content-Type: image/jpeg. "
                "(4) SVG with embedded JavaScript: <svg><script>alert(1)</script></svg>. "
                "(5) Oversized file (>50MB if possible) to test upload limits. "
                "(6) Null byte in filename: file.php\\x00.jpg. "
                "After upload, attempt to access the uploaded file URL directly. "
                "If the file executes (PHP, JSP), this is Critical RCE."),
        max_steps=30,
        applies_to="website",
    ),
    ScanPhase(
        id="web_password_reset",
        name="Password Reset Flow Testing",
        prompt=("Test the password reset/forgot password flow for security weaknesses. "
                "Locate the password reset functionality (look for 'Forgot Password', "
                "'Reset Password' links). Test: "
                "(1) Account enumeration: submit a valid email vs non-existent email and compare "
                "response messages, HTTP status codes, and response sizes. Different responses reveal "
                "which accounts exist. "
                "(2) If you receive a reset token/link, check token length and entropy. "
                "Short or predictable tokens can be brute-forced. "
                "(3) Submit the same reset request twice — does it invalidate the first token? "
                "(4) Check if the reset page accepts the password change without the old password. "
                "(5) Test Host header injection on the reset endpoint: set Host: attacker.com and check "
                "if the reset link in any response contains attacker.com. "
                "IMPORTANT: Only test with the scan's own email address. Do not test with other emails."),
        max_steps=25,
        applies_to="website",
    ),
    ScanPhase(
        id="web_session_mgmt",
        name="Session Management Testing",
        prompt=("Test session management security. "
                "(1) Check if the session cookie changes after login (session fixation). "
                "Record the session cookie/token BEFORE login, compare AFTER login — they must differ. "
                "(2) Check session cookie properties: is it HttpOnly? Secure? SameSite? "
                "(3) Test concurrent sessions: make a second authenticated request from a different "
                "context and check if the original session is still valid. "
                "(4) Check if session token appears in URLs (query strings or path). "
                "(5) Test if accessing a 'change password' or 'change email' endpoint invalidates "
                "existing sessions or requires re-authentication. "
                "(6) Check session token length and entropy — short tokens are brute-forceable. "
                "IMPORTANT: Do NOT click logout or signout. Only inspect cookies and compare values."),
        max_steps=20,
        applies_to="website",
    ),
]

API_PHASES: list[ScanPhase] = [
    ScanPhase(
        id="api_recon",
        name="Endpoint discovery",
        prompt="Map all API endpoints from imports. Discover undocumented endpoints via path wordlists and OPTIONS probing. Generate discovery strategies from the base paths and patterns you observe.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_auth",
        name="Authentication testing",
        prompt="Test authentication on discovered endpoints. Check for missing auth on protected endpoints, broken token validation, token reuse across contexts, and JWT manipulation. IMPORTANT: Send requests with invalid/expired/malformed bearer tokens and check if the server returns HTTP 500 instead of 401/403 — that indicates broken error handling in token validation. Generate tests from the auth scheme you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_authz",
        name="Authorization / BOLA",
        prompt="Test authorization. For every object ID in path, query, or body, craft IDOR payloads. Test horizontal and vertical privilege escalation. Generate payloads from the ID patterns you observed.{bola_user_b_api}",
        applies_to="api",
    ),
    ScanPhase(
        id="api_injection",
        name="Endpoint injection testing",
        prompt="Test injection on discovered endpoints. Probe SQLi, NoSQLi, LDAP injection, XSS in responses, and XXE in XML endpoints. Infer backend from response structure and errors, then craft targeted payloads.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_mass_assign",
        name="Mass assignment",
        prompt="Send extra fields in POST/PUT requests. Check whether unintended fields are persisted. Generate field names from the schema, similar endpoints, or common patterns you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_rate_limit",
        name="Rate limiting",
        prompt="Rapid-fire requests to the same endpoint. Check for 429 responses and resource exhaustion. Generate test patterns from the endpoint semantics you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_ssrf",
        name="SSRF testing",
        prompt="Identify URL-accepting parameters (webhooks, file import, redirect). Craft cloud metadata and internal service probes. Generate payloads from the URL parameters you found.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_graphql",
        name="GraphQL testing",
        prompt="If GraphQL is present: test introspection, query batching, deep nesting, and alias brute-force. Generate payloads from the schema and operations you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_data_exposure",
        name="Excessive data exposure",
        prompt="Compare response fields to what the UI displays. Look for PII, secrets, or internal IDs. Generate checks from the response structure you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_business_logic",
        name="Business logic",
        prompt="Test flow bypass, parameter tampering, race conditions, and idempotency violations. Generate tests from the business flows and state transitions you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_race_condition",
        name="API Race Conditions",
        prompt=("Test API endpoints for race conditions. "
                "For every state-changing endpoint (POST, PUT, PATCH, DELETE) you discovered, "
                "send 5-10 concurrent identical requests and check if the operation was applied "
                "multiple times. Focus on: payment/transfer endpoints, resource creation, "
                "quota/limit decrements, approval/activation flows. "
                "Also test if the API supports idempotency keys — if so, verify they are enforced."),
        max_steps=25,
        applies_to="api",
    ),
    ScanPhase(
        id="api_bfla",
        name="API Function-Level Authorization",
        prompt=("Test for broken function-level authorization in the API. "
                "Identify admin/management endpoints from recon (paths with /admin/, /manage/, "
                "/internal/, /users/{id}/role, /settings/). "
                "Attempt to call them with the normal user's token. "
                "Try method switching (GET→DELETE, GET→PUT) on discovered endpoints. "
                "Check if adding admin-like query params (?role=admin, ?is_admin=1) bypasses auth. "
                "Test if documentation endpoints (/swagger, /openapi, /graphql) are accessible."),
        max_steps=20,
        applies_to="api",
    ),
    ScanPhase(
        id="api_host_header",
        name="API Host Header Injection",
        prompt=("Test API endpoints for host header injection. "
                "Send requests with modified Host, X-Forwarded-Host, and X-Forwarded-For headers. "
                "Check if responses contain reflected host values in URLs, HATEOAS links, "
                "or redirect headers. Test if X-Forwarded-For: 127.0.0.1 bypasses IP allowlists "
                "on restricted endpoints. Also check for different behavior with "
                "X-Original-URL and X-Rewrite-URL headers (path override attacks)."),
        max_steps=20,
        applies_to="api",
    ),
    ScanPhase(
        id="api_content_type",
        name="Content-Type Confusion",
        prompt=("Test API endpoints for content-type confusion attacks. "
                "For each POST/PUT/PATCH endpoint discovered: "
                "(1) Send the same JSON body but with Content-Type: application/xml — check if "
                "the server parses it differently or returns errors revealing the XML parser. "
                "(2) Send JSON body as application/x-www-form-urlencoded — some frameworks "
                "auto-parse both, which may bypass JSON schema validation. "
                "(3) Send multipart/form-data with the same fields — test if file upload is enabled. "
                "(4) Send text/plain — some CORS configurations allow this without preflight. "
                "(5) Remove Content-Type entirely — check how the server handles ambiguity. "
                "Compare all responses to the baseline. Different parsing = different validation = bypass."),
        max_steps=20,
        applies_to="api",
    ),
    ScanPhase(
        id="api_method_override",
        name="HTTP Method Override",
        prompt=("Test API endpoints for HTTP method override attacks. "
                "For each endpoint, check if method override headers are honored: "
                "(1) Send GET request with X-HTTP-Method-Override: DELETE — does it delete the resource? "
                "(2) Send POST with X-HTTP-Method: PUT — does it update instead of create? "
                "(3) Send GET with X-Method-Override: POST — does it execute the POST action? "
                "(4) Send POST with _method=DELETE in the body (Rails/Laravel convention). "
                "(5) Send GET with query parameter ?_method=PUT. "
                "If any of these change server behavior, it means method-based access control "
                "(e.g. 'only allow GET on this endpoint') can be bypassed. "
                "Focus on endpoints that restrict certain HTTP methods."),
        max_steps=20,
        applies_to="api",
    ),
]


ATTACK_CHAIN_PHASE = ScanPhase(
    id="attack_chain_analysis",
    name="Attack Chain Analysis",
    prompt=(
        "You have completed all individual scan phases. Now analyze your findings "
        "for EXPLOITABLE ATTACK CHAINS — combinations of 2-3 vulnerabilities that "
        "together create a higher-severity impact than any single finding alone.\n\n"
        "Your findings so far:\n{findings_summary}\n\n"
        "For each potential chain:\n"
        "1. Identify which findings combine and explain the attack path\n"
        "2. ATTEMPT to execute the chain using your tools (don't just theorize)\n"
        "3. If successful, report as a single finding with severity based on "
        "the COMBINED impact (often Critical even if individual findings are Low/Medium)\n"
        "4. Include step-by-step evidence showing each link in the chain\n\n"
        "Chain patterns to evaluate against YOUR findings:\n"
        "- Open Redirect + OAuth/SSO → redirect token to attacker, account takeover\n"
        "- CORS misconfig + sensitive API → cross-origin authenticated data theft\n"
        "- XSS + non-HttpOnly cookie → steal session via document.cookie\n"
        "- XSS + CSRF-vulnerable form → inject auto-submit (password/email change)\n"
        "- SSRF + cloud metadata → fetch 169.254.169.254 for AWS/Azure credentials\n"
        "- IDOR + no rate limit → mass enumeration of all user records\n"
        "- JWT weakness (alg:none or weak key) + role claim → forge admin token\n"
        "- Host header injection + password reset → poisoned reset link\n"
        "- File upload + path traversal → place webshell in executable directory\n"
        "- Content-type confusion + WAF → bypass input validation via alternate parser\n"
        "- Timing enumeration + no rate limit → confirmed users + brute force\n"
        "- Missing SameSite + CORS → cross-site authenticated request\n"
        "- Session fixation + XSS → fix session then hijack via XSS\n"
        "- API version downgrade + missing auth on old version → bypass new auth\n\n"
        "RULES:\n"
        "- Only report chains you can PROVE with evidence from actual requests\n"
        "- Do NOT report theoretical chains you cannot attempt\n"
        "- Each chain finding must reference the individual findings it combines\n"
        "- Set severity based on the worst possible outcome of the full chain\n"
        "- If no chains are exploitable, say so — don't force findings"
    ),
    max_steps=40,
    applies_to="both",
)


_FOCUS_PHASE_MAP: dict[str, set[str]] = {
    "xss":          {"web_a03_xss", "api_injection"},
    "sqli":         {"web_a03_sqli", "api_injection"},
    "sql injection": {"web_a03_sqli", "api_injection"},
    "cmdi":         {"web_a03_cmdi", "api_injection"},
    "command injection": {"web_a03_cmdi", "api_injection"},
    "ssti":         {"web_a03_ssti", "api_injection"},
    "ssrf":         {"web_a10", "api_ssrf"},
    "idor":         {"web_a01", "api_authz"},
    "bola":         {"web_a01", "api_authz"},
    "auth":         {"web_a07", "api_auth"},
    "authentication": {"web_a07", "api_auth"},
    "access control": {"web_a01", "api_authz", "web_bfla", "api_bfla"},
    "csrf":         {"web_extras"},
    "upload":       {"web_extras"},
    "misconfig":    {"web_a05"},
    "crypto":       {"web_a02"},
    "graphql":      {"api_graphql"},
    "rate limit":   {"api_rate_limit"},
    "mass assignment": {"api_mass_assign"},
    "business logic": {"web_extras", "api_business_logic", "web_race_condition", "api_race_condition"},
    "data exposure": {"api_data_exposure"},
    "race condition": {"web_race_condition", "api_race_condition"},
    "host header":  {"web_host_header", "api_host_header"},
    "timing":       {"web_timing_enum"},
    "enumeration":  {"web_timing_enum"},
    "bfla":         {"web_bfla", "api_bfla"},
    "authorization": {"web_a01", "api_authz", "web_bfla", "api_bfla"},
    "file upload":  {"web_file_upload"},
    "upload":       {"web_file_upload", "web_extras"},
    "password reset": {"web_password_reset"},
    "session":      {"web_session_mgmt"},
    "session management": {"web_session_mgmt"},
    "content type": {"api_content_type"},
    "method override": {"api_method_override"},
    "chain": {"attack_chain_analysis"},
    "attack chain": {"attack_chain_analysis"},
}

_RECON_PHASE_IDS = {"web_recon", "api_recon"}


def _resolve_focus_phases(focus_areas: list[str]) -> set[str] | None:
    """Map user-friendly focus area names to the set of phase IDs to keep.

    Returns None if focus_areas is empty (= run everything).
    Always includes recon phases so the LLM has context.
    """
    if not focus_areas:
        return None
    matched: set[str] = set()
    for area in focus_areas:
        key = area.strip().lower()
        if key in _FOCUS_PHASE_MAP:
            matched |= _FOCUS_PHASE_MAP[key]
        else:
            for map_key, phase_ids in _FOCUS_PHASE_MAP.items():
                if key in map_key or map_key in key:
                    matched |= phase_ids
    if not matched:
        return None
    matched |= _RECON_PHASE_IDS
    return matched


def get_phases(scan_mode: str, app_info: dict | None = None,
               scan_scope: str = "directory",
               focus_areas: list[str] | None = None) -> list[ScanPhase]:
    phases: list[ScanPhase] = []
    app_info = app_info or {}
    has_websockets = app_info.get("has_websockets", True)

    skip_recon = scan_scope == "url_only"
    allowed_ids = _resolve_focus_phases(focus_areas or [])

    if scan_mode in ("website", "both"):
        for p in WEB_PHASES:
            if skip_recon and p.id == "web_recon":
                continue
            if p.id == "web_websocket" and not has_websockets:
                continue
            if allowed_ids is not None and p.id not in allowed_ids:
                continue
            phases.append(p)

    if scan_mode in ("api", "both"):
        for p in API_PHASES:
            if skip_recon and p.id == "api_recon":
                continue
            if allowed_ids is not None and p.id not in allowed_ids:
                continue
            phases.append(p)

    if phases and (allowed_ids is None or "attack_chain_analysis" in allowed_ids):
        phases.append(ATTACK_CHAIN_PHASE)

    return phases


def build_system_prompt(
    target: Any,
    endpoint_registry: Any,
    app_info: dict | None = None,
    extra_domains: list[str] | None = None,
) -> str:
    parts: list[str] = [SYSTEM_PROMPT]
    url = getattr(target, "url", "")
    scan_mode = getattr(target, "scan_mode", "both")

    from urllib.parse import urlparse

    from scanners.ai_agent.agent import _build_allowed_domains, _extract_base_domain
    target_host = (urlparse(url).hostname or "").lower()
    extra_set = set(d.strip().lower() for d in extra_domains if d.strip()) if extra_domains else None
    allowed = _build_allowed_domains(url, extra_set)
    scope_str = ", ".join(f"*.{d}" for d in sorted(allowed))

    scan_scope = getattr(target, "scan_scope", "directory")
    focus_urls = getattr(target, "focus_urls", None) or []

    parts.append(f"\n\nTarget: {url}")
    parts.append(f"Scan mode: {scan_mode}")
    parts.append(f"SCOPE: Only scan URLs under these domains: {scope_str}. Do NOT request any third-party domains (CDNs, analytics, trackers, etc). Any out-of-scope URL will be automatically blocked.")

    if scan_scope == "url_only":
        parts.append(
            "\n\n*** URL-ONLY SCOPE ***\n"
            "CRITICAL RESTRICTION: You must ONLY test the exact URL(s) listed below. "
            "Do NOT crawl, do NOT follow links, do NOT discover other pages or endpoints. "
            "Focus all your testing effort on these specific URL(s) only:\n"
        )
        targets = focus_urls if focus_urls else [url]
        for u in targets:
            parts.append(f"  - {u}")
        parts.append(
            "\nSkip any reconnaissance/crawling phase. Go directly to security testing "
            "on the URL(s) above. Test all applicable vulnerability classes on these "
            "specific URL(s)."
        )
    elif scan_scope == "directory":
        parsed_path = urlparse(url).path.rstrip("/")
        parts.append(
            f"\n\nDIRECTORY SCOPE: Limit scanning to {url} and its sub-paths "
            f"(anything under {parsed_path}/). Do NOT crawl outside this directory. "
            "Keep reconnaissance lightweight — only discover pages under this path prefix."
        )
        if focus_urls:
            parts.append("Additionally, prioritize these specific URLs:")
            for u in focus_urls:
                parts.append(f"  - {u}")
    else:
        if focus_urls:
            parts.append("\nPrioritize testing these specific URLs first:")
            for u in focus_urls:
                parts.append(f"  - {u}")
            parts.append("Then continue with full-site crawl and testing.")

    if scan_mode in ("api", "both") and endpoint_registry is not None:
        get_all = getattr(endpoint_registry, "get_all", None)
        eps = get_all() if callable(get_all) else []
        if eps:
            parts.append(f"\nImported/discovered API endpoints: {len(eps)}")
            for ep in eps[:20]:
                method = getattr(ep, "method", "?")
                path = getattr(ep, "path", "?")
                parts.append(f"  - {method} {path}")
            if len(eps) > 20:
                parts.append(f"  ... and {len(eps) - 20} more")

    focus_areas = getattr(target, "focus_areas", None) or []
    if focus_areas:
        areas_str = ", ".join(focus_areas)
        parts.append(
            f"\n\n*** FOCUS AREA RESTRICTION ***\n"
            f"You must ONLY test for: {areas_str}.\n"
            f"Do NOT test for any other vulnerability class. Skip all unrelated checks.\n"
            f"Focus 100% of your effort on {areas_str} and directly related relevance checks "
            f"(e.g., for XSS: input reflection, output encoding, DOM manipulation, CSP bypass; "
            f"for SQLi: error-based, blind, time-based, union-based).\n"
            f"If a page or endpoint is not relevant to {areas_str}, skip it immediately."
        )

    exclude_urls = getattr(target, "exclude_urls", None) or []
    if exclude_urls:
        parts.append(
            "\n\n*** EXCLUDED URLs / PATHS ***\n"
            "The user has explicitly excluded the following URLs/paths from scanning. "
            "You MUST NOT navigate to, crawl, test, or send any requests to these. "
            "Skip them entirely — any attempt will be automatically blocked:\n"
        )
        for u in exclude_urls:
            parts.append(f"  - {u}")
        parts.append(
            "\nIf you encounter links pointing to excluded URLs, ignore them. "
            "Do not include excluded URLs in any test payloads or redirect targets."
        )

    scan_intensity = getattr(target, "scan_intensity", "deep")
    if scan_intensity == "light":
        parts.append(
            "\n\n*** SCAN INTENSITY: LIGHT ***\n"
            "This is a quick reconnaissance-level scan. Be fast and efficient:\n"
            "- Per input/parameter: test 3-5 payloads maximum per vulnerability class\n"
            "- Use only the most common/effective payloads (top canonical examples)\n"
            "- Skip edge cases, encoding variations, and WAF bypass techniques\n"
            "- Max 15 actions per page/endpoint. Move on quickly if no obvious indicator\n"
            "- Prioritize breadth over depth — check more pages with fewer payloads each\n"
            "- Skip low-severity checks (info-level headers, verbose errors, etc.)"
        )
    elif scan_intensity == "standard":
        parts.append(
            "\n\n*** SCAN INTENSITY: STANDARD ***\n"
            "Balanced scan for reasonable coverage:\n"
            "- Per input/parameter: test 8-15 payloads per vulnerability class\n"
            "- Include common encoding variations (URL-encode, HTML entities, double-encode)\n"
            "- Try basic WAF bypass for each class (case variation, comment insertion)\n"
            "- Max 30 actions per page/endpoint\n"
            "- Test both reflected and stored variants where applicable\n"
            "- Include standard header checks (CORS, CSP, X-Frame-Options, etc.)"
        )
    else:
        parts.append(
            "\n\n*** SCAN INTENSITY: DEEP ***\n"
            "Maximum coverage — be thorough and exhaustive:\n"
            "- Per input/parameter: test 20-40+ payloads per vulnerability class\n"
            "- Include ALL encoding variations: URL, double-URL, HTML entities, Unicode, hex, octal\n"
            "- Extensive WAF/filter bypass: case mixing, null bytes, comment injection, nested tags, "
            "polyglot payloads, alternative syntax, protocol-relative URLs\n"
            "- Max 50+ actions per page/endpoint — exhaust all reasonable test cases\n"
            "- Test reflected, stored, DOM-based, and blind variants\n"
            "- Check secondary injection points: headers (Referer, User-Agent, X-Forwarded-For), "
            "cookies, JSON values, multipart boundaries, file upload names\n"
            "- Attempt chained attacks (e.g., open redirect → XSS, SSRF → internal port scan)\n"
            "- Test for race conditions, parameter pollution, HTTP smuggling where relevant\n"
            "- Generate context-aware payloads that match the technology stack observed"
        )

    app_info = app_info or {}
    if app_info.get("is_spa"):
        framework = app_info.get("framework", "unknown")
        parts.append(f"\nSPA detected: {framework}. Use interaction-based discovery: click elements, monitor route changes, intercept fetch/XHR.")

    return "".join(parts)
