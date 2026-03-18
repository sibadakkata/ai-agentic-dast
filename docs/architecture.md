# Architecture

[← Back to README](../README.md)

## System Overview

The scanner is built around a **single LLM agent** that drives a real browser and HTTP client through security tests autonomously. No hardcoded attack playbooks — the LLM reasons about what it sees and crafts payloads accordingly.

```
┌─────────────────────────────────────────────────────────────────┐
│                        WEB UI / REST API                        │
│                     (FastAPI + Single-page HTML)                 │
├─────────────────────────────────────────────────────────────────┤
│                        SCAN ORCHESTRATOR                        │
│                          (agent.py)                              │
│                                                                 │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│   │   Auth    │  │ Passive  │  │   LLM    │  │   Runtime    │  │
│   │  Module   │  │  Recon   │  │  Agent   │  │  Verifier    │  │
│   │(auth.py)  │  │(passive_ │  │  Loop    │  │              │  │
│   │          │  │ recon.py) │  │          │  │              │  │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│        │              │             │                │          │
│   ┌────▼──────────────▼─────────────▼────────────────▼───────┐ │
│   │                    TOOL LAYER (28 tools)                  │ │
│   │  Browser: navigate, click, fill, screenshot               │ │
│   │  Injection: inject_payload, fuzz_parameter                │ │
│   │  Observation: get_page_source, get_cookies, get_network   │ │
│   │  SPA: wait_for_spa_route, intercept_requests, execute_js  │ │
│   │  WebSocket: ws_connect, ws_send, ws_inject                │ │
│   │  API: api_request, api_request_raw, replay_with_mod       │ │
│   │  Auth Testing: test_auth_bypass, test_token_security      │ │
│   └────┬───────────────────────────────┬─────────────────────┘ │
│        │                               │                       │
│   ┌────▼─────────┐            ┌────────▼─────────┐            │
│   │  Playwright   │            │     HTTPX         │            │
│   │  (Chromium)   │            │  (API requests)   │            │
│   └──────────────┘            └──────────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                    POST-SCAN PIPELINE                            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│   │  Triage   │  │   CVE    │  │  Report  │  │    Excel     │  │
│   │  Engine   │  │  Lookup  │  │   (PDF)  │  │   Export     │  │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                     INFRASTRUCTURE                               │
│   AWS Bedrock (Claude/Mistral) · LiteLLM · SQLite · Docker     │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Loop

The core scanning logic follows an **Observe-Think-Act-Analyze-Plan** cycle:

```
                    ┌──────────────────┐
                    │   Phase Prompt   │
                    │ (e.g. "Test for  │
                    │  SQL Injection") │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
              ┌────▶│    OBSERVE       │
              │     │ Read context:    │
              │     │ - HTTP responses │
              │     │ - Page source    │
              │     │ - Network logs   │
              │     │ - Prior findings │
              │     └────────┬─────────┘
              │              │
              │     ┌────────▼─────────┐
              │     │     THINK        │
              │     │ LLM reasons:     │
              │     │ - Attack surface │
              │     │ - Tech stack     │
              │     │ - Vuln plausible?│
              │     └────────┬─────────┘
              │              │
              │     ┌────────▼─────────┐
              │     │      ACT         │
              │     │ LLM calls tools: │
              │     │ navigate()       │
              │     │ inject_payload() │
              │     │ fuzz_parameter() │
              │     │ api_request()    │
              │     └────────┬─────────┘
              │              │
              │     ┌────────▼─────────┐
              │     │    ANALYZE       │
              │     │ Interpret result: │
              │     │ - Status codes   │
              │     │ - Reflection?    │
              │     │ - Timing delta?  │
              │     │ - Error strings? │
              │     └────────┬─────────┘
              │              │
              │     ┌────────▼─────────┐
              │     │     PLAN         │──── Phase complete?
              │     │ Next action:     │     └─▶ Move to next phase
              │     │ - Go deeper?     │
              │     │ - Try new param? │
              │     │ - Done?          │
              └─────└──────────────────┘
                   (up to 25 steps per phase)
```

## Scan Phases

### Website Phases (22)

| # | Phase | OWASP | Context-Aware |
|---|-------|-------|---------------|
| 1 | Application Mapping | — | |
| 2 | Broken Access Control | A01 | |
| 3 | Cryptographic Failures | A02 | |
| 4 | SQL Injection | A03 | |
| 5 | Cross-Site Scripting | A03 | |
| 6 | Command Injection | A03 | |
| 7 | Template Injection (SSTI) | A03 | |
| 8 | Insecure Design / Business Logic | A04 | |
| 9 | Security Misconfiguration | A05 | |
| 10 | Vulnerable Components | A06 | |
| 11 | Authentication Failures | A07 | |
| 12 | Integrity Failures | A08 | |
| 13 | Logging Failures | A09 | |
| 14 | SSRF | A10 | |
| 15 | WebSocket Testing | — | |
| 16 | Beyond OWASP (CRLF, CSRF, etc.) | — | |
| 17 | Race Condition Testing | A04 | ✓ Concurrent requests on state-changing ops |
| 18 | Host Header Poisoning | A05 | ✓ Tests reflection in reset links/redirects |
| 19 | Timing-Based Enumeration | A07 | ✓ Response time analysis for user enumeration |
| 20 | Broken Function-Level Auth | A01 | ✓ Admin endpoint access with normal user |
| 21 | File Upload Testing | A04 | ✓ Extension bypass, content-type mismatch, polyglot |
| 22 | Password Reset Flow | A07 | ✓ Token predictability, account enumeration |
| 23 | Session Management | A07 | ✓ Fixation, rotation, concurrent sessions |

### API Phases (15)

| # | Phase | Focus | Context-Aware |
|---|-------|-------|---------------|
| 1 | Endpoint Discovery | Hidden/undocumented endpoints | |
| 2 | Authentication Testing | Token validation, JWT manipulation | |
| 3 | Authorization / BOLA | IDOR, horizontal/vertical escalation | |
| 4 | Injection Testing | SQLi, NoSQLi, XSS in JSON, XXE | |
| 5 | Mass Assignment | Extra fields, role escalation | |
| 6 | Rate Limiting | Brute-force resistance | |
| 7 | SSRF | URL-accepting parameters, metadata probes | |
| 8 | GraphQL | Introspection, batching, deep nesting | |
| 9 | Excessive Data Exposure | PII leakage, debug data | |
| 10 | Business Logic | Flow bypass, race conditions, price tampering | |
| 11 | Race Conditions | Concurrent requests on state-changing endpoints | ✓ |
| 12 | Function-Level Auth | Admin/management endpoint access | ✓ |
| 13 | Host Header Injection | X-Forwarded-Host, path override | ✓ |
| 14 | Content-Type Confusion | JSON↔XML↔form-data parser attacks | ✓ |
| 15 | HTTP Method Override | X-HTTP-Method-Override bypass | ✓ |

## Tool System (28 Tools)

| Category | Tools | Purpose |
|----------|-------|---------|
| **Browser** | `navigate`, `click`, `fill`, `submit_form`, `screenshot` | Navigate pages, interact with elements |
| **Injection** | `inject_payload` | Inject payloads into page DOM |
| **Observation** | `get_page_source`, `get_cookies`, `get_network_log`, `get_forms`, `get_links`, `get_local_storage` | Read page content, cookies, XHR, storage |
| **SPA** | `wait_for_spa_route`, `intercept_requests`, `execute_js` | Handle React/Angular/Vue, intercept fetch/XHR |
| **WebSocket** | `ws_connect`, `ws_send`, `ws_receive`, `ws_inject`, `ws_close` | Full WebSocket lifecycle testing |
| **API** | `api_request`, `api_request_raw`, `fuzz_parameter`, `replay_with_modification` | HTTP requests, fuzzing, response comparison |
| **Discovery** | `get_api_endpoints` | List imported/discovered API endpoints |
| **Auth Testing** | `test_auth_bypass`, `test_method_override`, `test_token_security` | Auth bypass, method override, JWT manipulation |

## Authentication Module

The auth module (`auth.py`) handles:

- **Auto-detection**: Identifies auth type (form, SSO/OIDC, OAuth, API key, bearer)
- **Multi-step OIDC**: Sequential form interactions (email → continue → password → submit)
- **Session management**: Captures cookies/tokens, monitors expiry, auto-refreshes
- **Self-healing**: If the browser gets redirected to login mid-scan, auth re-triggers automatically
- **Fallback selectors**: LLM-suggested selectors with generic defaults as fallback

## Passive Reconnaissance

Before any LLM calls, 24 deterministic check categories run at $0 cost:

**Information Disclosure**
- Exposed JavaScript source maps (`.js.map` files accessible in production)
- Hardcoded secrets/tokens in client-side JavaScript
- Internal URLs/IPs leaked in source code
- Sensitive files (`.git/`, `.env`, `wp-config.php`)
- HTML comments containing sensitive information
- Error page information disclosure (stack traces, internal paths)
- Email addresses exposed in source code
- Sensitive data in URL query parameters

**Client-Side Security**
- Dangerous DOM sinks (`innerHTML`, `eval`, `document.write`)
- Subresource Integrity (SRI) missing on external scripts
- Mixed content (HTTP resources on HTTPS pages)
- Password fields without autocomplete="off"
- Form actions targeting external domains

**Transport & Header Security**
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- CSP policy weakness analysis (`unsafe-inline`, `unsafe-eval`, wildcards)
- CORS misconfiguration (reflected origin, wildcard + credentials)
- Referrer-Policy missing or weak
- Permissions-Policy missing
- HTTP→HTTPS redirect validation
- HSTS preload readiness (max-age, includeSubDomains)
- Clickjacking (both X-Frame-Options and frame-ancestors missing)
- Cache-Control on authenticated pages

**Session & Token Security**
- Cookie security audit (Secure, HttpOnly, SameSite flags)
- JWT token analysis (weak algorithms, missing claims, PII)
- Security tokens in telemetry/logging payloads (12 sub-checks)
- API version downgrade (old versions still accessible)

## LLM Integration

- **Primary**: AWS Bedrock (Claude Haiku/Sonnet, Mistral/Ministral)
- **Router**: `litellm` handles model routing — `bedrock/` models go direct, others via optional LiteLLM proxy
- **Cost tracking**: Per-scan token counting with real-time cost display
- **Error recovery**: Auto-retry on rate limits, context trimming on overflow, message repair on malformed sequences
- **Context management**: Phase history pruning, response truncation, tool-call pair validation

## Data Persistence

- **SQLite** database for scan metadata, status, and configuration
- **JSON files** for detailed scan results (findings, test logs, phases)
- **PDF/Excel** generated reports stored on disk
- **Docker volumes** ensure data survives container restarts
