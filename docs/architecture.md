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

> Full phase prompt details: [System Prompt Guide](system-prompt-guide.md)

### Website Phases (25)

| # | Phase ID | Name | OWASP | Context-Aware |
|---|----------|------|-------|---------------|
| 1 | `web_recon` | Application Mapping | — | |
| 2 | `web_a01` | Broken Access Control | A01 | |
| 3 | `web_a02` | Cryptographic Failures | A02 | |
| 4 | `web_a03_sqli` | SQL Injection | A03 | ✓ DB-specific payloads (SQLite/MySQL/PG/MSSQL) |
| 5 | `web_a03_xss` | Cross-Site Scripting | A03 | ✓ Context-aware (HTML/attr/JS/DOM) |
| 6 | `web_a03_cmdi` | Command Injection | A03 | ✓ Unix/Windows, header injection |
| 7 | `web_a03_ssti` | Template Injection (SSTI) | A03 | ✓ Engine-specific (Jinja2/Pebble/EJS/Mako) |
| 8 | `web_a03_path_traversal` | Path Traversal / LFI | A03 | ✓ Encoded, double-encoded, null byte, wrappers |
| 9 | `web_a03_xxe` | XML External Entity | A03 | ✓ Blind XXE, parameter entities, SVG upload |
| 10 | `web_a04` | Insecure Design | A04 | ✓ Price tampering, step skipping, coupon abuse |
| 11 | `web_a05` | Security Misconfiguration | A05 | |
| 12 | `web_a06` | Vulnerable Components | A06 | |
| 13 | `web_a07` | Authentication Failures | A07 | |
| 14 | `web_a08` | Integrity Failures | A08 | |
| 15 | `web_a09` | Logging Failures | A09 | |
| 16 | `web_a10` | SSRF | A10 | |
| 17 | `web_websocket` | WebSocket Testing | — | |
| 18 | `web_extras` | Beyond OWASP (CRLF, CSRF) | — | |
| 19 | `web_race_condition` | Race Condition Testing | A04 | ✓ Parallel fetch via execute_js |
| 20 | `web_host_header` | Host Header Poisoning | A05 | ✓ Reflection in reset links/redirects |
| 21 | `web_timing_enum` | Timing-Based Enumeration | A07 | ✓ Response time analysis for user enum |
| 22 | `web_bfla` | Broken Function-Level Auth | A01 | ✓ Admin endpoint access with normal user |
| 23 | `web_file_upload` | File Upload Testing | A04 | ✓ Extension bypass, polyglot |
| 24 | `web_password_reset` | Password Reset Flow | A07 | ✓ Token predictability |
| 25 | `web_session_mgmt` | Session Management | A07 | ✓ Fixation, rotation, concurrent sessions |

### API Phases (15)

| # | Phase ID | Name | Focus | Context-Aware |
|---|----------|------|-------|---------------|
| 1 | `api_recon` | Endpoint Discovery | Hidden/undocumented endpoints | |
| 2 | `api_auth` | Authentication Testing | Token validation, JWT manipulation | |
| 3 | `api_authz` | Authorization / BOLA | IDOR, horizontal/vertical escalation | |
| 4 | `api_injection` | Injection Testing | SQLi, NoSQLi, XSS, CMDi, XXE in JSON | ✓ |
| 5 | `api_mass_assign` | Mass Assignment | Extra fields, role escalation | |
| 6 | `api_rate_limit` | Rate Limiting | Brute-force resistance | |
| 7 | `api_ssrf` | SSRF | URL-accepting params, metadata probes | |
| 8 | `api_graphql` | GraphQL | Introspection, batching, deep nesting | |
| 9 | `api_data_exposure` | Data Exposure | PII leakage, debug data | |
| 10 | `api_business_logic` | Business Logic | Flow bypass, race conditions, price tampering | |
| 11 | `api_race_condition` | Race Conditions | Concurrent state-changing requests | ✓ |
| 12 | `api_bfla` | Function-Level Auth | Admin/management endpoint access | ✓ |
| 13 | `api_host_header` | Host Header Injection | X-Forwarded-Host, path override | ✓ |
| 14 | `api_content_type` | Content-Type Confusion & HTTP Smuggling | JSON↔XML↔form parser + CL.TE/TE.CL | ✓ |
| 15 | `api_method_override` | HTTP Method Override | X-HTTP-Method-Override bypass | ✓ |

### Attack Chain Phase (1)

`attack_chain_analysis` — runs after all phases, combines findings into exploit chains (e.g. XSS + non-HttpOnly cookie → session hijack).

### Reliability Mechanisms

| Mechanism | File | Purpose |
|-----------|------|---------|
| **Evidence Buffer** | `agent.py` | Preserves compact test records that survive context trimming |
| **Phase Retry** | `agent.py` `_RETRY_PHASES` | Re-attempts critical phases if 0 findings found (12 phases) |
| **Min Security Calls** | `agent.py` `_MIN_SECURITY_CALLS` | Forces LLM to make enough tool calls before concluding (22 phases) |
| **Finding Grounding** | `agent.py` `extract_findings` | Rejects findings without payload/evidence from actual tool output |
| **Vuln Signal Extraction** | `tools.py` | Auto-detects SQL/XSS/CMDi/SSTI patterns and flags them prominently |

> Deep dive on these mechanisms: [Scanner Internals](scanner-internals.md)

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
