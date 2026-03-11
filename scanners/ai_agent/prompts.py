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
- Stop after exhausting reasonable test cases (max 50 actions per page)

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
        prompt="Test for broken access control. For every ID parameter you observed (path, query, body), craft IDOR payloads using adjacent or predictable IDs. Attempt forced browsing to privileged paths, method tampering (e.g. GET→POST, POST→PUT), and privilege escalation by reusing tokens in different contexts. Generate payloads from the ID patterns you saw.",
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
        prompt="Test authentication. Probe for session fixation, weak or predictable tokens, brute-force resistance, JWT manipulation (alg:none, key confusion, claim tampering), and password reset flaws. Generate tests from the auth mechanisms you observed.",
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
]

API_PHASES: list[ScanPhase] = [
    ScanPhase(
        id="api_recon",
        name="API endpoint mapping",
        prompt="Map all API endpoints from imports. Discover undocumented endpoints via path wordlists and OPTIONS probing. Generate discovery strategies from the base paths and patterns you observe.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_auth",
        name="API authentication testing",
        prompt="Test authentication. Check for missing auth on protected endpoints, broken token validation, token reuse across contexts, and JWT manipulation. Generate tests from the auth scheme you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_authz",
        name="API authorization / BOLA",
        prompt="Test authorization. For every object ID in path, query, or body, craft IDOR payloads. Test horizontal and vertical privilege escalation. Generate payloads from the ID patterns you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_injection",
        name="API injection",
        prompt="Test injection. Probe SQLi, NoSQLi, LDAP injection, XSS in API responses, and XXE in XML endpoints. Infer backend from response structure and errors, then craft targeted payloads.",
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
        name="SSRF via API",
        prompt="Identify URL-accepting parameters (webhooks, file import, redirect). Craft cloud metadata and internal service probes. Generate payloads from the URL parameters you found.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_graphql",
        name="GraphQL-specific",
        prompt="If GraphQL is present: test introspection, query batching, deep nesting, and alias brute-force. Generate payloads from the schema and operations you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_data_exposure",
        name="Excessive data exposure",
        prompt="Compare API response fields to what the UI displays. Look for PII, secrets, or internal IDs. Generate checks from the response structure you observed.",
        applies_to="api",
    ),
    ScanPhase(
        id="api_business_logic",
        name="Business logic",
        prompt="Test flow bypass, parameter tampering, race conditions, and idempotency violations. Generate tests from the business flows and state transitions you observed.",
        applies_to="api",
    ),
]


def get_phases(scan_mode: str, app_info: dict | None = None) -> list[ScanPhase]:
    phases: list[ScanPhase] = []
    app_info = app_info or {}
    has_websockets = app_info.get("has_websockets", True)

    if scan_mode in ("website", "both"):
        for p in WEB_PHASES:
            if p.id == "web_websocket" and not has_websockets:
                continue
            phases.append(p)

    if scan_mode in ("api", "both"):
        phases.extend(API_PHASES)

    return phases


def build_system_prompt(
    target: Any,
    endpoint_registry: Any,
    app_info: dict | None = None,
) -> str:
    parts: list[str] = [SYSTEM_PROMPT]
    url = getattr(target, "url", "")
    scan_mode = getattr(target, "scan_mode", "both")

    parts.append(f"\n\nTarget: {url}")
    parts.append(f"Scan mode: {scan_mode}")

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

    app_info = app_info or {}
    if app_info.get("is_spa"):
        framework = app_info.get("framework", "unknown")
        parts.append(f"\nSPA detected: {framework}. Use interaction-based discovery: click elements, monitor route changes, intercept fetch/XHR.")

    return "".join(parts)
