# Website Scanning

[← Back to README](../README.md)

For websites (traditional or SPA), the scanner uses **real browser automation** (Playwright + Chromium) instead of raw HTTP requests.

## How It Works

1. **Authentication** — Auto-detects auth type (form, SSO/OIDC, OAuth) and logs in
2. **Passive Reconnaissance** — Deterministic checks at $0 (source maps, headers, secrets, telemetry)
3. **Active Scanning** — LLM agent drives the browser through 15 OWASP phases
4. **Runtime Verification** — Replays attack payloads to confirm/disprove findings
5. **Triage** — Evidence-based classification of all findings

## SPA Handling

The scanner handles Single Page Applications (React, Angular, Vue) with:

- **Network idle detection** — Waits for all XHR/fetch requests to complete
- **DOM stability polling** — Hashes page content repeatedly until it stops changing
- **Route interception** — Monitors client-side navigation and captures dynamically loaded resources
- **Request interception from page load** — Captures all `.js` requests from the very start, including from iframes

## 25 Website Scan Phases

| # | Phase | What the Agent Does | Example |
|---|-------|---------------------|---------|
| 1 | **Application Mapping** | Opens Chromium, follows links, extracts forms/inputs/storage. For SPAs: clicks elements, intercepts fetch/XHR | `navigate()` → `get_links()` → `get_forms()` → `get_local_storage()` |
| 2 | **Broken Access Control (A01)** | IDOR on path/query IDs, forced browsing to admin paths, HTTP method tampering | Change `/users/42/profile` to `/users/43/profile` |
| 3 | **Cryptographic Failures (A02)** | TLS/cipher checks, cookie flags (Secure/HttpOnly/SameSite), sensitive data in URLs or localStorage | `get_cookies()` → session without `Secure` flag |
| 4 | **SQL Injection (A03)** | Infers DB engine from errors, crafts engine-specific payloads: error-based, blind boolean, time-based, UNION | `fuzz_parameter(url, "id", ["1' OR 1=1--", "1' AND SLEEP(5)--"])` |
| 5 | **Cross-Site Scripting (A03)** | Reflected, stored, DOM-based XSS. Polyglots, CSP bypass, event handlers, SVG payloads | `inject_payload("search", "<svg/onload=alert(1)>")` |
| 6 | **Command Injection (A03)** | Identifies shell-reachable inputs. Blind payloads with sleep/ping if no output | `fuzz_parameter(url, "filename", ["; sleep 5", "\| cat /etc/passwd"])` |
| 7 | **Template Injection (A03)** | Detects template engine from errors, crafts SSTI payloads | Sends `{{7*7}}` → response has `49` → confirmed Jinja2 SSTI |
| 8 | **Insecure Design (A04)** | Business logic: price tampering, flow bypass, race conditions, rate limit abuse | Submit order with `price: 0.01` or skip payment step |
| 9 | **Security Misconfig (A05)** | Response headers, CORS policy, verbose errors, directory listings, debug endpoints, default creds | `api_request("OPTIONS", url, headers={"Origin": "https://evil.com"})` |
| 10 | **Vulnerable Components (A06)** | Fingerprint JS libraries from scripts/headers, check for known CVEs via NVD + OSV.dev | Find `jquery-3.3.1.min.js` → lookup CVE-2020-11022 |
| 11 | **Auth Failures (A07)** | Session fixation, weak tokens, brute-force resistance, JWT manipulation (alg:none, claim tampering) | `test_token_security(token)` → try alg:none bypass |
| 12 | **Integrity Failures (A08)** | SRI on external scripts, untrusted CDN resources, prototype pollution via `__proto__` | `<script src="cdn.example.com/lib.js">` without `integrity=` |
| 13 | **Logging Failures (A09)** | Trigger security events, check for sensitive data leakage in error responses | Invalid input → response contains `java.sql.SQLException` |
| 14 | **SSRF (A10)** | URL-accepting params (webhooks, file import, redirects), cloud metadata probes | `fuzz_parameter(url, "callback", ["http://169.254.169.254/..."])` |
| 15 | **WebSocket + Beyond OWASP** | WS auth testing, message injection. Plus: open redirect, CRLF, request smuggling, clickjacking, CSRF | `ws_connect("wss://app.com/ws")` → `ws_inject(...)` |

## Domain Scoping

The scanner restricts activity to the target domain and its subdomains:

- Third-party domains are excluded and listed in the UI
- Additional domains can be explicitly included via the "Additional Domains" field
- Affiliated domain groups can be configured so scanning one domain auto-includes related ones

## Session Protection

6-layer logout protection prevents the LLM from accidentally destroying the session:

1. **URL pattern matching** - Hardcoded list of logout URL patterns blocks navigation before it happens
2. **Click selector blocking** - CSS selectors targeting logout elements are intercepted and blocked
3. **Href inspection** - Before any click, the element's href is checked for logout keywords
4. **Post-click recovery** - If a click navigates to a logout URL via JS redirect, the scanner navigates back
5. **LLM prompt instructions** - System prompt explicitly forbids clicking logout/signout links
6. **Link filtering** - Logout links are filtered out so the LLM never sees them as options
