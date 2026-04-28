# Security Checks Reference

[← Back to README](../README.md)

Complete reference of every security check the scanner performs. Organized by scan phase and check type.

## Summary

| Category | Count | LLM Cost | FP Risk |
|----------|-------|----------|---------|
| Passive Reconnaissance | 26 checks | $0 (deterministic) | Zero/Very Low |
| Active Web Phases | 25 phases | LLM-driven | Low (context-aware) |
| Active API Phases | 15 phases | LLM-driven | Low (context-aware) |
| Attack Chain Analysis | 1 phase (12 chain patterns) | LLM-driven | Low (must prove with evidence) |
| **Total** | **67 check categories** | | |

> Passive checks run on the seed host **and** every passively-discovered in-scope HTTPS sub-domain (from page DOM, `robots.txt`, `sitemap.xml`, and live browser network traffic). After every active phase, any newly observed sub-domain gets a passive re-audit for TLS and security headers (Stage A host-delta, capped at 10 new hosts per phase). See [Web Scanning](web-scanning.md#sibling-sub-domain-coverage) for the full flow.

---

## Phase 1: Passive Reconnaissance (Deterministic, $0)

These checks run before any LLM calls. They analyze the page, HTTP responses, cookies, and JavaScript files using pattern matching and direct inspection. Every finding is a verifiable fact.

### Information Disclosure

| # | Check | CWE | Severity | What It Detects |
|---|-------|-----|----------|-----------------|
| 1 | JavaScript Source Maps | CWE-540 | Medium | `.js.map` files accessible in production — exposes original unminified source code, developer comments, internal paths |
| 2 | Hardcoded Secrets in JS | CWE-798 | High | API keys, passwords, AWS keys, JWT tokens, database connection strings embedded in client-side JavaScript |
| 3 | Internal URLs/IPs in JS | CWE-200 | Low | Private IPs (10.x, 192.168.x), localhost references, staging/dev/QA URLs leaked in JavaScript |
| 4 | Sensitive Files | CWE-538 | Critical–Low | `.git/HEAD`, `.env`, `.git/config`, `wp-config.php.bak`, `.DS_Store`, `web.config`, `crossdomain.xml` |
| 5 | HTML Comments with Secrets | CWE-615 | Medium–Low | Passwords, API keys, TODO/FIXME notes, debug credentials in HTML comments |
| 6 | Server Version Disclosure | CWE-200 | Low | `Server`, `X-Powered-By`, `X-AspNet-Version` headers revealing technology stack |
| 7 | Error Page Info Disclosure | CWE-209 | Low | 404/500 pages revealing stack traces (Python/Java/PHP/.NET), internal paths, DB configuration |
| 8 | Sensitive Data in URL Params | CWE-598 | Medium | Passwords, tokens, SSN, credit card numbers in query strings (logged by proxies, servers, browser history) |

### Client-Side Security

| # | Check | CWE | Severity | What It Detects |
|---|-------|-----|----------|-----------------|
| 9 | Dangerous DOM Sinks | CWE-79/95 | Medium | `innerHTML`, `outerHTML`, `document.write`, `eval()`, `new Function()`, `v-html`, `dangerouslySetInnerHTML`, `bypassSecurityTrust`, `$sce.trustAsHtml` |
| 10 | Subresource Integrity (SRI) | CWE-353 | Low | External scripts/stylesheets loaded without `integrity=` attribute — CDN compromise leads to code injection |
| 11 | Mixed Content | CWE-319 | Medium–Low | HTTP resources (scripts, styles, iframes) loaded on HTTPS pages — MitM can inject malicious code |
| 12 | Password Autocomplete | CWE-522 | Low | `<input type="password">` without `autocomplete="off"` — browser caches credentials on disk |
| 13 | Form Actions to External Domains | CWE-200 | High–Medium | Forms submitting data to third-party domains, especially forms with password or sensitive fields |
| 13a | **Vulnerable JavaScript Library** (hybrid) | CWE-1104 / CWE-937 | Critical–Medium | Two-stage hybrid fingerprinting of client-side libraries (49-library regex catalog: jQuery, AngularJS, Angular, React, Vue, Bootstrap, Lodash, Moment, Handlebars, Next.js, etc.). **Stage 1** — explicit catalog match against URL patterns, `<script src>` / `<link href>` in DOM, and file content via version-extracting regexes. **Stage 2** — when the catalog misses, four heuristic extractors (`_HEURISTIC_CDN_PATH`, `_HEURISTIC_FILENAME`, `_HEURISTIC_BANNER`, `_HEURISTIC_PKG_META`) recover `(name, version)` from CDN paths, SemVer-bearing filenames, JS file banners, and inline `package.json` metadata. **Stage 3** — every URL the scanner encounters across auth flows, SPA crawl, and the network-request listener is unioned into a single `JSUrlRegistry` (`scanners/ai_agent/js_registry.py`) so library audits are no longer scoped only to the seed page. Each detected `(library, version)` is enriched with live CVE/CVSS data from **NVD + OSV.dev** (severity derived from CVSS, capped by confidence in version extraction). |

### Transport & Header Security

| # | Check | CWE | Severity | What It Detects |
|---|-------|-----|----------|-----------------|
| 14 | Missing Security Headers | CWE-693 | Low | HSTS, CSP, X-Frame-Options, X-Content-Type-Options — all absent headers reported together |
| 15 | CSP Policy Weakness Analysis | CWE-693 | Medium–Low | `unsafe-inline`, `unsafe-eval`, wildcard `*`, `data:` URIs, missing `frame-ancestors`, `base-uri`, `form-action`, `object-src` |
| 16 | CORS Misconfiguration | CWE-942 | High–Medium | Wildcard origin with credentials, reflected arbitrary origin, null origin allowed |
| 17 | Referrer-Policy Missing/Weak | CWE-200 | Low | Missing header or `unsafe-url`/`no-referrer-when-downgrade` leaks full URL to third parties |
| 18 | Permissions-Policy Missing | CWE-16 | Low | No restriction on camera, microphone, geolocation, payment API browser features |
| 19 | HTTP→HTTPS Redirect | CWE-319 | Medium–Low | HTTP serves content without redirecting to HTTPS, or uses non-301 redirect |
| 20 | HSTS Preload Readiness | CWE-319 | Low | HSTS present but `max-age` too short, missing `includeSubDomains` |
| 21 | Clickjacking Protection | CWE-1021 | Medium | Both X-Frame-Options and CSP `frame-ancestors` missing on HTML pages — page is frameable |
| 22 | Cache-Control on Auth Pages | CWE-525 | Medium–Low | Authenticated pages missing `Cache-Control: no-store` — sensitive content cached by browsers/proxies |
| 22a | **TLS Protocol/Cipher Audit** | CWE-326 / CWE-327 | High–Medium | Deprecated protocols (TLS 1.0, TLS 1.1) accepted; weak cipher suites enumerated via `sslyze` (primary, bypasses OpenSSL 3.x legacy-provider gap) with raw-socket fallback: 3DES/Sweet32 (CVE-2016-2183), RC4, EXPORT, NULL, anonymous DH/ECDH. Runs per host (seed + every in-scope HTTPS sub-domain discovered during the scan). Pins `maximum_version=TLSv1_2` when probing weak ciphers to eliminate TLS 1.3 false positives |

### Session & Token Security

| # | Check | CWE | Severity | What It Detects |
|---|-------|-----|----------|-----------------|
| 23 | Cookie Security Audit | CWE-614 | Medium–Low | Per-cookie check: missing `Secure` flag, missing `HttpOnly`, weak `SameSite` — session cookies flagged higher |
| 24 | JWT Token Analysis | CWE-347 | High–Medium | `alg:none` (no signature), symmetric HMAC with potential weak secret, missing `exp`/`iss`/`aud`/`jti` claims, PII in token payload |
| 25 | API Version Downgrade | CWE-693 | Medium | Old API versions (e.g. `/v1/`) still accessible when `/v2/` exists — older versions often lack security controls |

### Telemetry & Token Leakage (12 sub-checks)

| # | Check | CWE | Severity | What It Detects |
|---|-------|-----|----------|-----------------|
| 26 | CSRF/Session Tokens in Telemetry | CWE-532 | High | Token values (CSRF, session, auth) found in POST bodies to logging/telemetry endpoints |
| 27 | JWT Tokens in Telemetry | CWE-532 | High | JWT tokens forwarded to logging endpoints |
| 28 | Sensitive Headers in Telemetry | CWE-532 | Medium | Authorization, Cookie, X-CSRF-Token header names/values referenced in telemetry payloads |
| 29 | Sensitive JSON Keys in Telemetry | CWE-532 | High | `sessionHash`, `authToken`, `apiKey`, etc. with credential-like values in telemetry JSON |
| 30 | Tokens in Telemetry URL Query | CWE-598 | High | Token values appearing in query strings of telemetry GET/POST URLs |
| 31 | Tokens Sent to Third-Party Domains | CWE-359 | Critical–High | Session/auth tokens in POST bodies sent to third-party analytics/error-reporting domains |
| 32 | JWT Sent to Third-Party Domains | CWE-359 | High | JWT tokens in POST bodies to external domains |
| 33 | Serialized Headers in Telemetry | CWE-532 | Medium | Full HTTP request headers object serialized in telemetry JSON payloads |
| 34 | Console Methods Overridden | CWE-532 | Low | `console.log`/`error` monkey-patched (not native) — may forward logged data to remote service |
| 35 | Logging Endpoint Response Leakage | CWE-532 | High | GET to logging endpoint returns previously logged data containing security tokens |
| 36 | Telemetry Endpoint Discovery | CWE-532 | Info | Logging endpoints detected via performance entries — manual review recommended |

---

## Phase 2: Active Web Scanning (LLM-Driven, 25 Phases)

The LLM agent drives a real Chromium browser through each phase, crafting context-aware payloads from what it observes. No hardcoded payload lists.

### OWASP Top 10 Coverage

| # | Phase | OWASP | What the Agent Tests |
|---|-------|-------|---------------------|
| 1 | **Application Mapping** | — | Crawl pages, follow links, extract forms/inputs/storage, discover SPA routes via client-side navigation |
| 2 | **Broken Access Control** | A01 | IDOR on path/query/body IDs, forced browsing to admin paths, HTTP method tampering (GET→POST→PUT). **Two-User BOLA mode**: when User B credentials are supplied, authenticates as both users, collects User A's resource IDs, replays as User B to prove authorization bypass (BOLA) or privilege escalation (BFLA). |
| 3 | **Cryptographic Failures** | A02 | TLS/cipher checks, cookie flags (Secure/HttpOnly/SameSite), sensitive data in URLs or localStorage |
| 4 | **SQL Injection** | A03 | Infer DB engine from errors, craft engine-specific payloads: error-based, blind boolean, time-based, UNION, stacked |
| 5 | **Cross-Site Scripting** | A03 | Reflected, stored, DOM-based XSS. Polyglots, CSP bypass, event handlers, SVG payloads |
| 6 | **Command Injection** | A03 | Identify shell-reachable inputs. Blind payloads with sleep/ping if no output |
| 7 | **Template Injection (SSTI)** | A03 | Detect template engine from errors/markers, craft engine-specific payloads (Jinja2, Freemarker, Twig) |
| 8 | **Insecure Design** | A04 | Price tampering, flow bypass (skip steps, reorder), rate limit abuse |
| 9 | **Security Misconfiguration** | A05 | CSP, X-Frame-Options, HSTS, CORS, verbose errors, directory listing, debug endpoints, default credentials |
| 10 | **Vulnerable Components** | A06 | Fingerprint frameworks/libraries/versions from headers and page source, reason about known CVEs |
| 11 | **Authentication Failures** | A07 | Session fixation, weak tokens, brute-force resistance, JWT manipulation, HTTP 500 vs 401/403 error handling |
| 12 | **Integrity Failures** | A08 | SRI on script/link tags, untrusted CDN resources, client-side prototype pollution |
| 13 | **Logging Failures** | A09 | Trigger security events, check if error handling leaks sensitive information |
| 14 | **SSRF** | A10 | Identify URL-accepting parameters (import, webhook, redirect), probe redirect chains and cloud metadata |
| 15 | **WebSocket Testing** | — | Connect to WS endpoints, inject payloads, test auth on WS, probe message injection |
| 16 | **Beyond OWASP** | — | Open redirect, CRLF injection, HTTP request smuggling, clickjacking, CSRF, prototype pollution |

### Context-Aware Phases

| # | Phase | What the Agent Tests | Why Context-Aware |
|---|-------|---------------------|-------------------|
| 17 | **Race Condition Testing** | Send 5-10 concurrent identical requests on state-changing operations (checkout, balance, votes). Test TOCTOU patterns | Only tests endpoints observed during recon |
| 18 | **Host Header Poisoning** | Modified Host, X-Forwarded-Host, X-Forwarded-For headers. Check reflection in URLs, password reset links, redirects | Focuses on reset/redirect endpoints |
| 19 | **Timing-Based Enumeration** | Compare response times for valid vs invalid usernames on login/reset endpoints. Also checks error message/status differences | Measures actual timing, not guessing |
| 20 | **Broken Function-Level Auth** | Access admin/privileged endpoints (/admin/, /manage/, /settings/) with normal user session. Method switching (GET→DELETE) | Uses app map from recon phase |
| 21 | **File Upload Testing** | Server-executable extensions (.php, .asp, .jsp), double extensions, Content-Type mismatch, SVG with JS, null bytes, oversized files | Only runs if upload forms found |
| 22 | **Password Reset Flow** | Account enumeration (different responses for valid/invalid emails), token predictability/reuse, Host header injection on reset endpoint | Only runs if reset form found |
| 23 | **Session Management** | Session fixation (cookie before/after login), concurrent sessions, token in URLs, session entropy, re-auth on sensitive actions | Tests observed session mechanism |

---

## Phase 3: Active API Scanning (LLM-Driven, 15 Phases)

For APIs imported via Postman or OpenAPI, the scanner also runs deterministic baseline execution + hybrid body fuzzing before the LLM phases.

### OWASP API Security Top 10 Coverage

| # | Phase | What the Agent Tests |
|---|-------|---------------------|
| 1 | **Endpoint Discovery** | Probe for undocumented endpoints using path patterns, OPTIONS, common admin/debug paths |
| 2 | **Authentication Testing** | Remove auth headers, test JWT manipulation (alg:none, claim tampering), token expiry/reuse |
| 3 | **Authorization / BOLA** | IDOR payloads on every object ID in path, query, body — horizontal and vertical escalation. **Two-User BOLA mode**: same as web — User A recon → User B replay to definitively confirm BOLA/BFLA. |
| 4 | **Injection Testing** | SQLi, NoSQLi, LDAP injection, XSS in JSON responses, XXE in XML endpoints |
| 5 | **Mass Assignment** | Extra fields in POST/PUT, read resource back to check persistence |
| 6 | **Rate Limiting** | Rapid-fire requests to login/transaction endpoints, check for 429 responses |
| 7 | **SSRF** | URL-accepting parameters probed for cloud metadata and internal services |
| 8 | **GraphQL** | Introspection, query batching, deep nesting (DoS), alias brute-force |
| 9 | **Excessive Data Exposure** | Compare API response fields to UI — flag hidden PII, debug data, internal IDs |
| 10 | **Business Logic** | Flow bypass, negative amounts, parameter tampering, idempotency violations |

### Context-Aware API Phases

| # | Phase | What the Agent Tests | Why Context-Aware |
|---|-------|---------------------|-------------------|
| 11 | **Race Conditions** | Concurrent identical requests on POST/PUT/PATCH/DELETE. Idempotency key enforcement | Only tests state-changing endpoints |
| 12 | **Function-Level Auth** | Access admin/management endpoints with normal user token, method switching, admin query params | Uses discovered endpoint list |
| 13 | **Host Header Injection** | X-Forwarded-Host reflection in HATEOAS links, X-Forwarded-For IP bypass, X-Original-URL path override | Tests actual API response content |
| 14 | **Content-Type Confusion** | Send JSON as XML, form-data as JSON, multipart with same fields, remove Content-Type entirely | Compares responses to baseline |
| 15 | **HTTP Method Override** | X-HTTP-Method-Override: DELETE on GET, _method=PUT in body, X-Method-Override header | Tests if method-based ACL is bypassable |

---

## Phase 4: Attack Chain Analysis (Final LLM Phase)

Runs **after all other phases complete**. Receives a summary of every finding discovered so far and attempts to combine them into multi-step attack chains with higher severity.

| Chain Pattern | Individual Findings | Combined Impact |
|--------------|-------------------|-----------------|
| **OAuth Token Theft** | Open redirect + OAuth login flow | Critical — account takeover |
| **Cross-Origin Data Theft** | CORS misconfig + missing SameSite + sensitive API | Critical — steal user data from attacker website |
| **Session Hijack via XSS** | XSS + non-HttpOnly session cookie | Critical — steal session via `document.cookie` |
| **Forced Actions via XSS** | XSS + CSRF-vulnerable form (password/email change) | Critical — attacker changes user's password |
| **Cloud Credential Theft** | SSRF + cloud metadata (169.254.169.254) | Critical — AWS/Azure key extraction |
| **Mass Data Dump** | IDOR + no rate limiting | Critical — enumerate all user records |
| **Admin Token Forgery** | JWT alg:none + role claim in token | Critical — forge admin JWT |
| **Poisoned Reset Link** | Host header injection + password reset endpoint | High — redirect reset link to attacker |
| **Webshell RCE** | File upload + path traversal | Critical — execute code on server |
| **WAF Bypass → Injection** | Content-type confusion + injection vulnerability | High — bypass validation via alternate parser |
| **Brute Force** | Timing enumeration (valid users) + no rate limit | High — confirmed users + password spray |
| **Auth Bypass via Old API** | API version downgrade + missing auth on old version | High — access without authentication |

The LLM **attempts to execute** each applicable chain using the `chain_exploit` tool, not just theorize. Only proven chains with evidence are reported.

**Multi-step chaining tools:**
- `get_findings_so_far` — lets the LLM query all findings discovered across prior phases
- `chain_exploit` — declares an ordered sequence of steps (each using existing tools) and executes them end-to-end, collecting evidence at each step
- Cross-phase context injection ensures every phase after the first sees a summary of prior discoveries

---

## Phase 5: Post-Scan Pipeline ($0 LLM Cost)

| Step | What It Does |
|------|-------------|
| **Runtime Verification** | Replays exact attack payloads against live target — verdicts: CONFIRMED / DISPROVED / INCONCLUSIVE. Exploit chains are replayed end-to-end with step outputs carried forward |
| **Triage Engine** | 3-layer evidence-based classification: passive recon (auto-TP) → evidence rules → confidence scoring |
| **CVE Enrichment** | Live lookup against NVD + OSV.dev for detected library versions |
| **CVSS Adjustment** | Context-aware scoring: runtime-verified findings scored higher, false positives set to 0.0 |
| **Report Generation** | PDF with three-stage evidence trail, curl commands for reproduction, remediation steps |

---

## CWE Coverage Summary

| CWE | Description | Check Type |
|-----|-------------|------------|
| CWE-16 | Configuration | Passive (Permissions-Policy, X-Content-Type-Options) |
| CWE-22 | Path Traversal | Active (Web/API injection) |
| CWE-78 | OS Command Injection | Active (Web/API injection) |
| CWE-79 | Cross-Site Scripting | Passive (DOM sinks) + Active (reflected/stored/DOM) |
| CWE-89 | SQL Injection | Active (Web/API injection) |
| CWE-95 | Code Injection | Passive (eval, new Function) |
| CWE-200 | Information Disclosure | Passive (internal URLs, version headers, referrer-policy) |
| CWE-203 | Observable Discrepancy | Active (timing-based enumeration) |
| CWE-209 | Error Info Disclosure | Passive (error pages) |
| CWE-285 | Improper Authorization | Active (BFLA) |
| CWE-287 | Improper Authentication | Active (auth bypass) |
| CWE-307 | Brute Force | Active (rate limiting) |
| CWE-319 | Cleartext Transmission | Passive (HSTS, mixed content, HTTPS redirect) |
| CWE-347 | Improper Verification | Passive (JWT analysis) |
| CWE-352 | CSRF | Active (Beyond OWASP) |
| CWE-353 | Missing Integrity Check | Passive (SRI) |
| CWE-359 | Privacy Violation | Passive (tokens to third parties) |
| CWE-362 | Race Condition | Active (concurrent request testing) |
| CWE-384 | Session Fixation | Active (session management) |
| CWE-391 | Error Handling | Active (500 vs 401/403) |
| CWE-434 | Unrestricted Upload | Active (file upload testing) |
| CWE-436 | Interpretation Conflict | Active (content-type confusion) |
| CWE-502 | Deserialization | Active (injection) |
| CWE-522 | Insufficiently Protected Credentials | Passive (password autocomplete) |
| CWE-525 | Browser Cache Weakness | Passive (Cache-Control) |
| CWE-530 | Exposure via Backup | Passive (sensitive files) |
| CWE-532 | Log Injection | Passive (telemetry token leakage) |
| CWE-538 | File/Dir Info Exposure | Passive (.git, .DS_Store) |
| CWE-540 | Source Code Exposure | Passive (source maps) |
| CWE-598 | GET Request Query String | Passive (sensitive URL params) |
| CWE-601 | Open Redirect | Active (Beyond OWASP) |
| CWE-611 | XXE | Active (injection) |
| CWE-614 | Sensitive Cookie Without Secure | Passive (cookie audit) |
| CWE-615 | Comment Info Exposure | Passive (HTML comments) |
| CWE-639 | Authorization Bypass Through ID | Active (IDOR/BOLA single-user + two-user) |
| CWE-285 | Improper Authorization (BFLA) | Active (two-user BFLA) |
| CWE-640 | Weak Password Recovery | Active (password reset flow) |
| CWE-644 | Improper Neutralization of HTTP Headers | Active (host header poisoning) |
| CWE-650 | Trusting HTTP Methods | Active (method override) |
| CWE-693 | Protection Mechanism Failure | Passive (CSP weakness, missing headers) |
| CWE-798 | Hardcoded Credentials | Passive (secrets in JS) |
| CWE-918 | SSRF | Active (Web/API) |
| CWE-942 | Overly Permissive CORS | Passive (CORS check) |
| CWE-326 | Inadequate Encryption Strength | Passive (TLS weak ciphers: 3DES/Sweet32, RC4, EXPORT) |
| CWE-327 | Broken/Risky Cryptographic Algorithm | Passive (deprecated TLS 1.0/1.1, anonymous DH/ECDH, NULL ciphers) |
| CWE-937 | Using Components with Known Vulnerabilities | Passive (vulnerable JS library detection + NVD/OSV.dev CVE lookup) |
| CWE-1021 | Improper Restriction of Frames | Passive (clickjacking) |
| CWE-1104 | Unmaintained Third-Party Component | Passive (vulnerable JS library detection) |
| CWE-1321 | Prototype Pollution | Active (Beyond OWASP) |

---

## OWASP Coverage Matrix

| OWASP Category | Passive Checks | Active Web Phases | Active API Phases |
|---------------|----------------|-------------------|-------------------|
| **A01** Broken Access Control | — | Broken Access Control, BFLA | Authorization/BOLA, BFLA, Method Override |
| **A02** Cryptographic Failures | Cookie audit, HSTS, HTTPS redirect, mixed content, **TLS protocol/cipher audit (per host)** | Cryptographic Failures | — |
| **A03** Injection | DOM sinks, source maps | SQLi, XSS, CMDi, SSTI | Injection Testing |
| **A04** Insecure Design | — | Insecure Design, Race Conditions, File Upload | Race Conditions, Business Logic |
| **A05** Security Misconfiguration | CSP weakness, headers, CORS, clickjacking, error pages, Permissions-Policy | Security Misconfiguration, Host Header | Host Header, Content-Type Confusion |
| **A06** Vulnerable Components | **Vulnerable JS library detection + NVD/OSV.dev CVE enrichment** | Vulnerable Components | — |
| **A07** Auth Failures | JWT analysis, password autocomplete | Auth Failures, Timing Enum, Password Reset, Session Mgmt | Authentication Testing |
| **A08** Integrity Failures | SRI missing | Integrity Failures | Mass Assignment |
| **A09** Logging Failures | Telemetry token leakage (12 checks) | Logging Failures | — |
| **A10** SSRF | — | SSRF | SSRF |

### OWASP API Security Top 10

| OWASP API | Passive Checks | Active API Phases |
|-----------|----------------|-------------------|
| **API1** Broken Object Level Auth | — | Authorization/BOLA (single-user guess + two-user confirmed) |
| **API2** Broken Authentication | JWT analysis, cookie audit | Authentication Testing |
| **API3** Broken Object Property Level Auth | — | Mass Assignment, Data Exposure |
| **API4** Unrestricted Resource Consumption | — | Rate Limiting |
| **API5** Broken Function Level Auth | — | BFLA, Method Override |
| **API6** Unrestricted Access to Sensitive Business Flows | — | Race Conditions, Business Logic |
| **API7** SSRF | — | SSRF |
| **API8** Security Misconfiguration | Headers, CORS, CSP | Host Header, Content-Type Confusion |
| **API9** Improper Inventory Management | API version downgrade | Endpoint Discovery |
| **API10** Unsafe Consumption of APIs | Tokens to third parties, form actions | — |
