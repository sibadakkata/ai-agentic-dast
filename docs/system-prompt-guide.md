# System Prompt & Phase Architecture

[← Back to README](../README.md)

How the LLM is instructed to scan, what phases run, and how to tune scan behavior.

## Overview

The scanner's intelligence comes from **two layers of prompts** sent to the LLM:

1. **System Prompt** (`SYSTEM_PROMPT` in `prompts.py`) — permanent context describing the LLM's role, all available tools, attack methodology, and finding format rules
2. **Phase Prompts** (one per scan phase) — step-by-step instructions for a specific vulnerability class (e.g. SQL Injection, XSS)

The LLM sees the system prompt once at the start, then receives phase prompts one at a time as the scan progresses.

```
┌────────────────────────────────────────────────────┐
│  SYSTEM PROMPT (always present)                     │
│  - Role: OWASP Top 10+ penetration tester          │
│  - Tool Reference (28 tools, categorized)           │
│  - Attack Methodology (Observe → Act → Analyze)    │
│  - Finding Format (JSON schema with rules)          │
│  - Rules (scope, evidence, no logout, etc.)         │
├────────────────────────────────────────────────────┤
│  PHASE 1 PROMPT: "Application Mapping"              │
│    → LLM acts (5-25 steps) → findings extracted    │
├────────────────────────────────────────────────────┤
│  PHASE 2 PROMPT: "SQL Injection"                    │
│    → LLM acts (5-25 steps) → findings extracted    │
├────────────────────────────────────────────────────┤
│  ...continues for all phases...                     │
└────────────────────────────────────────────────────┘
```

---

## System Prompt Structure

The `SYSTEM_PROMPT` in `scanners/ai_agent/prompts.py` has these sections:

### 1. Role Definition

Tells the LLM it is an autonomous OWASP Top 10+ penetration tester that must use tools to verify every claim.

### 2. Tool Reference

All 28 tools organized by category, with parameter signatures and usage guidance:

| Category | Tools |
|----------|-------|
| **BROWSER** | `navigate`, `click`, `fill`, `submit_form`, `screenshot` |
| **DISCOVERY** | `get_page_source`, `get_forms`, `get_links`, `get_cookies`, `get_local_storage`, `get_network_log`, `get_api_endpoints` |
| **HTTP** | `api_request`, `api_request_raw`, `fuzz_parameter`, `replay_with_modification`, `inject_payload` |
| **SPA** | `wait_for_spa_route`, `intercept_requests`, `execute_js` |
| **AUTH & AUTHZ** | `test_auth_bypass`, `test_method_override`, `test_token_security` |
| **WEBSOCKET** | `ws_connect`, `ws_send`, `ws_receive`, `ws_inject`, `ws_close` |

Each tool listing includes parameter names, types, and a brief description of what the tool returns. This is critical because the LLM can only use tools it knows about.

### 3. Adaptive Payload Generation Methodology

Instructs the LLM how to generate payloads based on observed context rather than using hardcoded lists:

```
OBSERVE context → REASON about tech stack → CRAFT targeted payloads
```

Includes technology-specific examples:
- **PostgreSQL error** → use `::int` casts, `pg_sleep()`
- **Express/Node.js** → try `require()`, template injection in EJS
- **Jinja2 templates** → `{{ config.items() }}`, `{{ ''.__class__.__mro__ }}`
- **JWT tokens** → alg:none, key confusion, claim tampering
- **IDOR patterns** → sequential IDs, UUID enumeration

### 4. Attack Loop

The LLM's reasoning cycle per step:

```
OBSERVE → REASON → ACT → ANALYZE → ADAPT → ESCALATE
```

Key rules in the loop:
- **`baseline_value`**: Always prepend a real value when fuzzing (e.g. `test'` not just `'`) because `LIKE '%input%'` clauses need it
- **500 errors = dig deeper**: Internal server errors are signals, not failures
- **Different responses = investigate**: Status code or body length changes indicate potential vulnerabilities
- **Parallel testing**: Use `execute_js` with `Promise.all + fetch` for race conditions

### 5. Finding Format

Strict JSON schema the LLM must follow when reporting findings:

```json
{
  "title": "SQL Injection in /api/search",
  "severity": "Critical",
  "owasp_category": "A03:2021",
  "url": "http://target.com/api/search",
  "parameter": "q",
  "payload": "test' OR 1=1--",
  "evidence": "Response contains SQLITE_ERROR: near \"OR\": syntax error",
  "confidence": "high",
  "remediation": "Use parameterized queries"
}
```

Rules enforced:
- **`payload`** is mandatory — no payload = finding rejected
- **`evidence`** is mandatory — must reference actual tool output
- Hallucinated findings (no tool-call backing) are automatically rejected by `extract_findings()`

### 6. Scope & Safety Rules

- Only test URLs within `allowed_domains`
- Never click logout links or submit logout forms
- Always check every input, not just the first one
- Treat HTTP 500 as a signal to investigate further

---

## Phase Definitions

Each phase is a `ScanPhase` dataclass with:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique identifier (e.g. `web_a03_sqli`) |
| `name` | `str` | Display name (e.g. "SQL Injection") |
| `prompt` | `str` | Full phase instructions sent to the LLM |
| `max_steps` | `int` | Maximum LLM turns for this phase (default: 50) |
| `applies_to` | `str` | `"website"`, `"api"`, or `"both"` |

### Web Phases (25)

| # | Phase ID | Name | OWASP |
|---|----------|------|-------|
| 1 | `web_recon` | Application Mapping | — |
| 2 | `web_a01` | Broken Access Control | A01 |
| 3 | `web_a02` | Cryptographic Failures | A02 |
| 4 | `web_a03_sqli` | SQL Injection | A03 |
| 5 | `web_a03_xss` | Cross-Site Scripting | A03 |
| 6 | `web_a03_cmdi` | Command Injection | A03 |
| 7 | `web_a03_ssti` | Server-Side Template Injection | A03 |
| 8 | `web_a03_path_traversal` | Path Traversal / LFI | A03 |
| 9 | `web_a03_xxe` | XML External Entity Injection | A03 |
| 10 | `web_a04` | Insecure Design | A04 |
| 11 | `web_a05` | Security Misconfiguration | A05 |
| 12 | `web_a06` | Vulnerable Components | A06 |
| 13 | `web_a07` | Authentication Failures | A07 |
| 14 | `web_a08` | Software & Data Integrity Failures | A08 |
| 15 | `web_a09` | Logging & Monitoring Failures | A09 |
| 16 | `web_a10` | Server-Side Request Forgery | A10 |
| 17 | `web_websocket` | WebSocket Testing | — |
| 18 | `web_extras` | Beyond OWASP (CRLF, CSRF, etc.) | — |
| 19 | `web_race_condition` | Race Condition Testing | A04 |
| 20 | `web_host_header` | Host Header Poisoning | A05 |
| 21 | `web_timing_enum` | Timing-Based Enumeration | A07 |
| 22 | `web_bfla` | Broken Function-Level Auth | A01 |
| 23 | `web_file_upload` | File Upload Testing | A04 |
| 24 | `web_password_reset` | Password Reset Flow | A07 |
| 25 | `web_session_mgmt` | Session Management Testing | A07 |

### API Phases (15)

| # | Phase ID | Name |
|---|----------|------|
| 1 | `api_recon` | Endpoint Discovery |
| 2 | `api_auth` | Authentication Testing |
| 3 | `api_authz` | Authorization / BOLA |
| 4 | `api_injection` | Endpoint Injection (SQLi, NoSQLi, XSS, CMDi, XXE) |
| 5 | `api_mass_assign` | Mass Assignment |
| 6 | `api_rate_limit` | Rate Limiting |
| 7 | `api_ssrf` | SSRF Testing |
| 8 | `api_graphql` | GraphQL Testing |
| 9 | `api_data_exposure` | Excessive Data Exposure |
| 10 | `api_business_logic` | Business Logic |
| 11 | `api_race_condition` | API Race Conditions |
| 12 | `api_bfla` | API Function-Level Auth |
| 13 | `api_host_header` | API Host Header Injection |
| 14 | `api_content_type` | Content-Type Confusion & HTTP Smuggling |
| 15 | `api_method_override` | HTTP Method Override |

### Attack Chain Phase (1)

`attack_chain_analysis` runs after all other phases. It receives a `{findings_summary}` of all prior findings and looks for exploitable chains:

- Open Redirect + OAuth token theft
- XSS + non-HttpOnly session cookie
- SSRF + internal API access
- IDOR + data exfiltration

---

## Phase Selection Logic

`get_phases()` in `prompts.py` determines which phases run based on:

| Parameter | Effect |
|-----------|--------|
| `scan_mode` | `website` → web phases only; `api` → API phases only; `both` → all |
| `scan_scope` | `url_only` skips recon phases |
| `focus_areas` | Restricts to specific phases (see Focus Phase Map below) |
| `has_websockets` | If `False`, skips `web_websocket` |

### Focus Phase Map (`_FOCUS_PHASE_MAP`)

When a user specifies focus areas (e.g. "sqli, xss"), the scanner maps them to specific phases:

| User Input | Phases Selected |
|------------|----------------|
| `xss` | `web_a03_xss`, `api_injection` |
| `sqli`, `sql injection` | `web_a03_sqli`, `api_injection` |
| `nosql` | `web_a03_sqli`, `api_injection` |
| `cmdi`, `command injection` | `web_a03_cmdi`, `api_injection` |
| `ssti` | `web_a03_ssti`, `api_injection` |
| `path traversal`, `lfi` | `web_a03_path_traversal`, `api_injection` |
| `xxe`, `xml` | `web_a03_xxe`, `api_injection`, `api_content_type` |
| `ssrf` | `web_a10`, `api_ssrf` |
| `idor`, `bola` | `web_a01`, `api_authz` |
| `auth` | `web_a07`, `api_auth` |
| `race condition` | `web_race_condition`, `api_race_condition` |
| `business logic` | `web_a04`, `web_extras`, `api_business_logic`, `web_race_condition` |
| `graphql` | `api_graphql` |
| `file upload` | `web_file_upload`, `web_extras` |
| `smuggling` | `api_content_type` |
| `chain`, `attack chain` | `attack_chain_analysis` |

Recon phases are always included regardless of focus.

---

## How Phase Prompts Are Written

Each phase prompt follows a consistent structure:

```
1. OBJECTIVE — What this phase tests for
2. METHODOLOGY — Step-by-step approach:
   a. Identify inputs/endpoints to test
   b. Specific payloads to try (categorized by technique)
   c. What to look for in responses
   d. Escalation steps if initial tests succeed
3. CRITICAL RULES — Phase-specific requirements
```

### Example: SQL Injection Phase Prompt Structure

```
Objective: Test all input points for SQL injection vulnerabilities

Step 1: Identify injectable parameters (forms, search, API endpoints)
Step 2: Test categories:
  - Error-based: ' " ; ) --
  - Boolean blind: ' OR 1=1-- vs ' OR 1=2--
  - Union: ' UNION SELECT NULL--
  - Time-based: '; WAITFOR DELAY '0:0:5'--
  - Auth bypass: admin'-- in login forms
  - DB-specific: SQLite, MySQL, PostgreSQL, MSSQL variants
  - NoSQL: {"$gt":""}, {"$ne":""} for MongoDB
  - WAF bypass: encoded, case-mixed, comment-injected payloads
Step 3: Use baseline_value (e.g. "test" + payload) for LIKE clauses
Step 4: On 500 errors — dig deeper, try more payloads
Step 5: On different response lengths — investigate blind injection
```

---

## Optimizing the System Prompt

### When to Modify

- **Detection gap**: Scanner misses a known vulnerability class → add payloads/techniques to the relevant phase
- **False positives**: Scanner reports non-issues → tighten evidence requirements in FINDING FORMAT
- **New tool added**: Update the TOOL REFERENCE section so the LLM knows the tool exists
- **New technology**: Add technology-specific payload examples to ADAPTIVE PAYLOAD GENERATION

### Best Practices

1. **Be prescriptive, not vague** — "Try `' OR 1=1--`" is better than "Try SQL injection payloads"
2. **Include response indicators** — Tell the LLM what success looks like: "If response contains `SQLITE_ERROR`, this confirms SQL injection"
3. **Use baseline_value** — Always instruct the LLM to prepend a real value when fuzzing search/filter inputs
4. **Category-specific payloads** — Group payloads by technique (error-based, blind, union, time-based)
5. **Escalation paths** — After detecting a vuln, instruct the LLM to escalate (e.g. extract data, bypass WAF)
6. **Keep context budget** — Phase prompts are injected into the LLM context window. Keep them concise but actionable.

### Testing Prompt Changes

1. Modify the phase prompt in `prompts.py`
2. Run a focused scan: set `focus_areas` to just the relevant phase
3. Compare findings before/after against a known-vulnerable target (e.g. Juice Shop, DVAPI)
4. Check the test log for tool call counts — ensure the LLM is actually executing the new instructions

---

## File Reference

| File | What to Edit | When |
|------|-------------|------|
| `scanners/ai_agent/prompts.py` | `SYSTEM_PROMPT` | Adding tools, changing methodology, updating rules |
| `scanners/ai_agent/prompts.py` | `WEB_PHASES` / `API_PHASES` | Adding/modifying scan phases |
| `scanners/ai_agent/prompts.py` | `_FOCUS_PHASE_MAP` | Adding new focus area keywords |
| `scanners/ai_agent/prompts.py` | `get_phases()` | Changing phase selection logic |
| `scanners/ai_agent/agent.py` | `_RETRY_PHASES` | Adding phases that should retry on 0 findings |
| `scanners/ai_agent/agent.py` | `_MIN_SECURITY_CALLS` | Setting minimum tool calls per phase |
