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

### Website Phases (15)

| # | Phase | OWASP |
|---|-------|-------|
| 1 | Application Mapping | — |
| 2 | Broken Access Control | A01 |
| 3 | Cryptographic Failures | A02 |
| 4 | SQL Injection | A03 |
| 5 | Cross-Site Scripting | A03 |
| 6 | Command Injection | A03 |
| 7 | Template Injection (SSTI) | A03 |
| 8 | Insecure Design / Business Logic | A04 |
| 9 | Security Misconfiguration | A05 |
| 10 | Vulnerable Components | A06 |
| 11 | Authentication Failures | A07 |
| 12 | Integrity Failures | A08 |
| 13 | Logging Failures | A09 |
| 14 | SSRF | A10 |
| 15 | WebSocket + Beyond OWASP | — |

### API Phases (10)

| # | Phase | Focus |
|---|-------|-------|
| 1 | Endpoint Discovery | Hidden/undocumented endpoints |
| 2 | Authentication Testing | Token validation, JWT manipulation |
| 3 | Authorization / BOLA | IDOR, horizontal/vertical escalation |
| 4 | Injection Testing | SQLi, NoSQLi, XSS in JSON, XXE |
| 5 | Mass Assignment | Extra fields, role escalation |
| 6 | Rate Limiting | Brute-force resistance |
| 7 | SSRF | URL-accepting parameters, metadata probes |
| 8 | GraphQL | Introspection, batching, deep nesting |
| 9 | Excessive Data Exposure | PII leakage, debug data |
| 10 | Business Logic | Flow bypass, race conditions, price tampering |

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

Before any LLM calls, deterministic checks run at $0 cost:

- Exposed JavaScript source maps (`.js.map` files accessible in production)
- Dangerous DOM sinks (`innerHTML`, `eval`, `document.write`)
- Hardcoded secrets/tokens in client-side JavaScript
- Internal URLs/IPs leaked in source code
- Sensitive files (`.git/`, `.env`, `wp-config.php`)
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- HTML comments containing sensitive information
- Security tokens in telemetry/logging payloads (including custom CSRF headers)
- JWT tokens sent to third-party domains

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
