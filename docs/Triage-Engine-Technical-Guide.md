# AI Agentic DAST Scanner — Triage Engine Technical Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Security Engineering Team  
**Classification:** Internal — Team Reference

---

## 1. Executive Summary

The Triage Engine is the core intelligence layer of the AI Agentic DAST Scanner. It sits between the AI agent's raw findings and the final security report, acting as an automated senior penetration tester that validates, classifies, and enriches every finding before it reaches a human reviewer.

**The problem it solves:** AI-powered scanners are powerful at discovering potential vulnerabilities, but they produce false positives, inconsistent severity ratings, and findings that lack the evidence rigor expected in a professional penetration test report. The Triage Engine eliminates scanner noise, corrects severity ratings using real evidence, and ensures only actionable findings reach the final report.

**Key design principles:**
- **Zero LLM calls** — Fully deterministic, reproducible, auditable
- **Target-agnostic** — Works identically for websites, APIs, and SPAs
- **Evidence-based** — Every verdict is backed by HTTP response data or runtime proof
- **Layered approach** — Multiple verification stages with clear fallback logic

---

## 2. Architecture Overview

The Triage Engine processes findings through a multi-layered pipeline. Each layer has increasing specificity, and earlier layers take priority.

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent Raw Finding                      │
│  (title, severity, URL, parameter, payload, evidence)       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 0: Runtime Verification (Payload Replay)             │
│  Real HTTP requests against live target                     │
│  Verdicts: CONFIRMED / DISPROVED / INCONCLUSIVE             │
│  ┌───────────────────────────────────────────┐              │
│  │ Smart Inconclusive Resolver (6 rules)     │              │
│  │ Auto-resolves ~70% of inconclusive cases  │              │
│  └───────────────────────────────────────────┘              │
└──────────────────────────┬──────────────────────────────────┘
                           │ (if no runtime result or inconclusive)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: Evidence-Based Pattern Classification             │
│  1A: Not-a-Finding (positive security observations)         │
│  1B: Auto False Positive (provably wrong findings)          │
│  1C: Injection checks (SQLi, XSS, SSRF, XXE, etc.)         │
│  1D: Security header & config checks                        │
│  1E: Application-specific patterns (30+ categories)         │
│  1F: Broad catch-all for remaining known categories         │
└──────────────────────────┬──────────────────────────────────┘
                           │ (if no pattern matched)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2: Confidence-Based Fallback                         │
│  Score from -10 to +10 based on HTTP evidence signals       │
│  High confidence → True Positive                            │
│  Ambiguous → Manual Review (narrow band: 0 to +1 only)      │
│  Negative confidence → False Positive                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  POST-PROCESSING: Context-Aware CVSS Adjustment             │
│  Adjusts base CVSS score based on observed evidence         │
│  Generates human-readable CVSS rationale                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               Final Triaged Finding                         │
│  verdict, final_severity, CWE, CVSS, rationale,            │
│  reason, steps, dev_action, curl command                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Layer 0: Runtime Verification (Payload Replay)

### 3.1 Purpose

Runtime Verification is the most authoritative layer. Instead of relying on the AI agent's interpretation, it **replays the actual attack payload against the live target** and observes the real HTTP response. This provides deterministic proof of exploitability.

### 3.2 How It Works

1. The Runtime Verifier receives a finding with its URL, parameter, and payload
2. It dispatches to a vulnerability-specific verifier function based on the finding title
3. The verifier sends crafted HTTP requests to the live target
4. It analyzes real responses for exploitation indicators
5. Returns one of three verdicts: **CONFIRMED**, **DISPROVED**, or **INCONCLUSIVE**

### 3.3 Supported Verifiers (17 Total)

| # | Verifier | Technique | Confirms When |
|---|----------|-----------|---------------|
| 1 | **SQL Injection** | Boolean differential (1=1 vs 1=2), error-based, time-based (SLEEP) | SQL error strings in response, significant length difference between true/false queries, or measurable time delay |
| 2 | **XSS** | Inject unique canary string, check reflection | Canary reflected unencoded in response HTML |
| 3 | **SSRF** | Request cloud metadata IP (169.254.169.254) | Internal/cloud metadata content in response |
| 4 | **XXE** | Send XML with external entity referencing /etc/passwd | File contents (root:x:0) in response |
| 5 | **Path Traversal** | Request ../../etc/passwd | System file content in response |
| 6 | **Command Injection** | Time-based differential (sleep N, measure delta) | Response delayed by injected sleep value |
| 7 | **Open Redirect** | Inject external URL, check Location header | 3xx redirect to attacker-controlled domain |
| 8 | **CSRF** | Replay request without CSRF token | Server accepts state change without token (HTTP 200) |
| 9 | **IDOR** | Compare response for original vs tampered object ID | Different data returned for manipulated ID |
| 10 | **Rate Limiting** | Send rapid sequential requests | No 429 (Too Many Requests) response after 10+ attempts |
| 11 | **Missing Headers** | Fetch URL, inspect response headers | Expected security header (HSTS, CSP, etc.) absent |
| 12 | **Cookie Attributes** | Fetch URL, inspect Set-Cookie attributes | Missing HttpOnly, Secure, or SameSite flags |
| 13 | **CORS** | Send OPTIONS/GET with Origin header, check ACAO | Permissive Access-Control-Allow-Origin (e.g., wildcard *) |
| 14 | **Information Disclosure** | Check response headers and body | Server version, X-Powered-By, or debug info exposed |
| 15 | **TLS/Transport Security** | Inspect HTTPS enforcement and TLS headers | Missing HSTS, weak TLS configuration, or HTTP available |
| 16 | **Sensitive Data** | Scan response body for credential patterns | API keys, passwords, tokens, or secrets found in response |
| 17 | **JWT Validation** | Send requests with alg=none and expired tokens | Server accepts invalid JWTs (should return 401/403), or returns 5xx (broken error handling) |

### 3.4 Dispatch Logic

Findings are routed to verifiers by matching keywords in the finding title:

```
Finding title contains "sql injection" → _verify_sqli()
Finding title contains "xss"           → _verify_xss()
Finding title contains "cors"          → _verify_cors()
...and so on for all 17 verifiers
```

The dispatch table is ordered by specificity. More specific matches (e.g., "sql injection") come before broader ones (e.g., "header"). If no keywords match, the finding is marked `UNVERIFIED` and proceeds to Layer 1.

### 3.5 Smart Inconclusive Resolver

When runtime verification returns `INCONCLUSIVE`, the engine doesn't immediately push the finding to manual review. Instead, it applies 6 intelligent rules that combine partial runtime signals with HTTP evidence:

| Rule | Condition | Decision |
|------|-----------|----------|
| **1** | Config/header finding (not injection) | **True Positive (Low)** — Config findings are verifiable by inspection |
| **2** | Injection claim + all responses 4xx/5xx + no positive evidence | **False Positive** — Server rejected all attack payloads |
| **3** | Strong negative runtime signals (≥2 of: rejected, blocked, sanitized, etc.) + low confidence | **False Positive** — Server defenses effective |
| **4** | Partial positive runtime signals (≥1 of: accepted, reflected, 200, etc.) + confidence ≥1 | **True Positive (Low)** — Some evidence supports the finding |
| **5** | Confidence ≤ -2 + zero positive indicators | **False Positive** — Insufficient evidence |
| **6** | Confidence ≥ 1 + not injection type | **True Positive (Low)** — Positive signals for non-injection finding |

This resolver eliminates approximately 70% of findings that would otherwise require manual review.

---

## 4. Layer 1: Evidence-Based Pattern Classification

When runtime verification is unavailable or falls through (unmatched finding type, or INCONCLUSIVE that couldn't be auto-resolved), the engine applies deterministic pattern rules based on the finding's title, evidence, payload, and HTTP response data.

### 4.1 Layer 1A: Not-a-Finding (Positive Observations)

Findings with titles indicating successful security controls are immediately classified as informational:

**Keywords:** "properly configured", "not vulnerable", "secure cookie config", "robust input", etc.

**Result:** `NOT_A_FINDING` / `Info` severity

### 4.2 Layer 1B: Auto False Positive

These are findings that are **provably wrong for any target**:

| Pattern | Reason | Example |
|---------|--------|---------|
| Zero evidence | No payload, no test data, no scanner evidence | Finding with empty evidence field |
| All redirects + injection claim | Scanner wasn't authenticated; injection requires access | SQLi finding where all responses were 302 |
| HPKP finding | Deprecated by all browsers since 2018 | "Missing HPKP header" |
| SameSite=Lax flagged | Lax is the OWASP recommendation and browser default | "Weak SameSite cookie attribute" |
| performance.timing | Standard browser API present on every website | "JavaScript API exposure" |
| Dynamic script creation | Standard JS (document.createElement) | "Dynamic script source" |

### 4.3 Layer 1C: Injection Checks

For each injection type, the engine examines HTTP response bodies and evidence for specific exploitation indicators:

**SQL Injection:**
- Searches for SQL error strings (mysql, postgresql, syntax error, etc.)
- Checks for data extraction keywords (union select, table_name, column_name)
- If found → `TRUE_POSITIVE` / `High`
- If not found (just HTTP 500) → `FALSE_POSITIVE` / Reclassified as improper error handling (CWE-391)

**XSS:**
- Searches for reflection keywords (`<script`, `onerror=`, `alert(`, etc.)
- If reflected → `TRUE_POSITIVE` / `Medium` (requires user interaction)
- If not reflected → `FALSE_POSITIVE`

**SSRF:**
- Searches for internal/cloud metadata in response
- If found → `TRUE_POSITIVE` / `High`
- If not found → `FALSE_POSITIVE`

**XXE, Path Traversal, Command Injection, Deserialization:** Similar approach — search for specific exploitation markers in response data.

### 4.4 Layer 1D: Security Headers & Configuration

Specific rules for common security header findings:

| Finding Type | Verdict | Severity | CWE | Reasoning |
|-------------|---------|----------|-----|-----------|
| Missing HSTS | True Positive | Low | CWE-319 | Requires active MITM to exploit |
| Missing CSP | True Positive | Low | CWE-693 | Defense-in-depth for XSS |
| Missing SRI | True Positive | Low | CWE-353 | Requires CDN compromise |
| Missing X-Frame-Options | True Positive | Low | CWE-1021 | Clickjacking requires user interaction |
| Missing X-Content-Type-Options | True Positive | Low | CWE-16 | MIME sniffing prevention |
| Insecure Cookie (session) | True Positive | Medium | CWE-614 | Session cookie without Secure/HttpOnly |
| Insecure Cookie (non-session) | True Positive | Low | CWE-614 | Lower risk for non-session cookies |

### 4.5 Layer 1E: Application-Specific Patterns (30+ Categories)

Detailed rules for specific vulnerability classes:

| Category | Key Decision Logic | Possible Verdicts |
|----------|-------------------|-------------------|
| **Rate Limiting** | HTTP 429 present? All 200s for 5+ requests? | FP if 429 seen, TP Medium if bypassed |
| **CSRF** | Token in evidence? Request accepted without token? | FP if token found, TP Medium if no token + 200 |
| **IDOR** | All 401/403? Data from another user in response? | FP if denied, TP Medium if data leak |
| **CORS** | Wildcard ACAO + credentials? | TP Low to High depending on config |
| **Open Redirect** | External domain in Location header? | TP Medium if confirmed, FP if no redirect |
| **Session Fixation** | Session ID regenerated after auth? | TP Medium if not regenerated |
| **OAuth/OIDC** | Token leaked? Missing state/PKCE? | TP High if token leaked, TP Low if config |
| **Prototype Pollution** | Payload executed in Object.prototype? | TP Medium if confirmed |
| **Template Injection** | Template expression evaluated? | TP High if executed |
| **Third-Party Libraries** | CVEs found via NVD/OSV.dev lookup? | Severity based on highest CVSS from CVE data |

### 4.6 Layer 1F: Broad Catch-All Categories

For findings that don't match specific patterns above, 8 broad categories catch remaining known types:

1. **Authentication/session weakness** — CWE-287
2. **HTTP method/verb tampering** — CWE-749
3. **Header injection / CRLF** — CWE-113
4. **File upload issues** — CWE-434
5. **Directory listing / path disclosure** — CWE-548
6. **Insecure communication / mixed content** — CWE-319
7. **Server-side includes / backup files** — CWE-538
8. **Generic vulnerability/weakness/issue** — Confidence-based

---

## 5. Layer 2: Confidence-Based Fallback

For truly unknown finding types that match no patterns, the engine falls back to a confidence score calculated from HTTP evidence signals.

### 5.1 Confidence Scoring (-10 to +10)

**Negative Signals (decrease confidence):**

| Signal | Score Impact | Rationale |
|--------|-------------|-----------|
| No test data at all | -3 | Cannot verify without test results |
| All responses are redirects (301/302) | -4 | Scanner wasn't authenticated |
| All responses are 403 | -3 | Access denied to endpoint |
| All responses are 404 | -3 | Endpoint doesn't exist |
| Zero evidence (no payload, no tests) | -5 | Nothing to validate |
| HTTP 500 without specific errors | -1 | Generic crash, not specific vuln |
| All 401/403 (≥2 requests) | -3 | Strong access denial |

**Positive Signals (increase confidence):**

| Signal | Score Impact | Rationale |
|--------|-------------|-----------|
| Payload reflected in response body | +3 | Input reaches output |
| SQL error keywords in response | +4 | Database error exposed |
| XSS reflection keywords in response | +3 | Script tags reflected |
| SSRF internal content in response | +4 | Internal data leaked |
| XXE/file content in response | +5 | File system access |
| Path traversal file content | +5 | Directory traversal works |
| Command injection OS output | +5 | OS commands executed |
| Deserialization markers | +4 | Object deserialization active |
| Time-based differential confirmed | +3 | Measurable delay from injection |
| HTTP 200 with content | +1 | Server processed request |
| Title contains "missing"/"absent" | +1 | Config finding (usually real) |

### 5.2 Decision Bands

| Confidence Range | Verdict | Severity |
|-----------------|---------|----------|
| **+5 to +10** | True Positive | Medium |
| **+2 to +4** | True Positive | Low |
| **0 to +1** (config finding) | True Positive | Low |
| **0 to +1** (all responses failed) | False Positive | Not Exploitable |
| **0 to +1** (other) | **Manual Review** | TBD |
| **-1 to -2** (config finding) | True Positive | Low |
| **-1 to -2** (other) | False Positive | Not Exploitable |
| **-3 to -10** | False Positive | Not Exploitable |

The Manual Review band is intentionally narrow (only confidence 0 to +1 for non-config, non-error findings). This minimizes the human workload while preserving review for genuinely ambiguous cases.

---

## 6. Post-Processing: Context-Aware CVSS Adjustment

After classification, the engine adjusts the base CVSS score based on what was actually observed during testing.

### 6.1 Adjustment Rules

| Rule | Condition | Adjustment | Rationale |
|------|-----------|------------|-----------|
| Pattern-only (no runtime proof) | High-sev finding not runtime-verified | -1.0 | Lower confidence without replay proof |
| PII in response | Sensitive keywords (email, password, token) in body | +0.5 | Data sensitivity increases impact |
| All error responses | Every response was 4xx/5xx | -1.5 | Attack partially blocked |
| Data extraction confirmed | union select, information_schema, root:x:0 in evidence | +0.5 | Active data exfiltration |
| XSS in JSON API | XSS reflected in application/json response | -2.0 | JSON not rendered as HTML by browser |
| CORS * with credentials | Wildcard origin + credentials allowed | Set to ≥6.5 | Fully exploitable cross-origin access |
| Brute force succeeded | Login success keywords in evidence | +2.0 | Account compromise confirmed |
| False Positive | Verdict is FP | Set to 0.0 | Not exploitable |
| Manual Review | Verdict is Manual Review | No adjustment | Score is preliminary |

### 6.2 CVSS Rationale

Every finding receives a human-readable `cvss_rationale` string explaining the score:

```
Base: 6.1 from CWE-79 | -2.0 XSS in JSON response (not rendered as HTML by browser) | Final: 4.1 (Medium)
```

```
Base: 9.8 from CWE-89 | +0.5 Data extraction confirmed in response | Final: 10.0 (Critical)
```

This rationale is displayed in the UI (as a tooltip on the CVSS score) and included in the PDF report.

### 6.3 Manual CVSS Override

Human reviewers can manually override the CVSS score for any finding via the UI. Overrides are:
- Persisted to disk (`{scan_id}_cvss_overrides.json`)
- Displayed with a `*` indicator in the UI
- Preserved across container restarts

---

## 7. CWE & CVSS Database

The engine maintains a built-in database of 25 CWE profiles for generic vulnerability categories (not tied to specific CVEs):

| Profile Key | CWE | Base CVSS | Category |
|-------------|-----|-----------|----------|
| sqli_confirmed | CWE-89 | 9.8 | SQL Injection |
| rce_confirmed | CWE-78 | 9.8 | Command Injection / RCE |
| deserialization | CWE-502 | 8.1 | Insecure Deserialization |
| auth_bypass | CWE-287 | 7.5 | Authentication Bypass |
| ssrf_confirmed | CWE-918 | 7.5 | Server-Side Request Forgery |
| xxe_confirmed | CWE-611 | 7.5 | XML External Entity |
| path_traversal_confirmed | CWE-22 | 7.5 | Path Traversal |
| idor_confirmed | CWE-639 | 6.5 | Insecure Direct Object Reference |
| xss_confirmed | CWE-79 | 6.1 | Cross-Site Scripting |
| missing_sri | CWE-353 | 6.1 | Subresource Integrity |
| auth_error_500 | CWE-755 | 5.3 | Error Handling (Auth) |
| rate_limit | CWE-307 | 5.3 | Rate Limiting |
| session_mgmt | CWE-384 | 5.3 | Session Management |
| prototype_pollution | CWE-1321 | 5.3 | Prototype Pollution |
| missing_csp | CWE-693 | 4.7 | Content Security Policy |
| open_redirect | CWE-601 | 4.7 | Open Redirect |
| third_party | CWE-829 | 4.7 | Third-Party Components |
| missing_hsts | CWE-319 | 4.3 | HTTP Strict Transport Security |
| csrf | CWE-352 | 4.3 | Cross-Site Request Forgery |
| missing_xframe | CWE-1021 | 4.3 | Clickjacking |
| info_disclosure | CWE-200 | 3.7 | Information Disclosure |
| error_info | CWE-209 | 3.7 | Error Information Leakage |
| error_handling | CWE-391 | 3.7 | Improper Error Handling |
| input_validation | CWE-20 | 3.7 | Input Validation |
| cors | CWE-942 | 3.7 | CORS Misconfiguration |
| logging | CWE-778 | 3.7 | Insufficient Logging |
| debug_staging | CWE-489 | 3.7 | Debug/Active Code |
| missing_xcto | CWE-16 | 3.1 | X-Content-Type-Options |

For **third-party library findings**, the engine dynamically queries NVD and OSV.dev APIs to fetch real CVE data and CVSS scores.

---

## 8. Severity Policy

The engine enforces a consistent severity scale across all targets:

| Severity | Criteria | CVSS Range |
|----------|----------|------------|
| **Critical** | Confirmed RCE, data exfiltration, or account takeover WITH proof | 9.0 – 10.0 |
| **High** | Confirmed active exploit with demonstrated real impact | 7.0 – 8.9 |
| **Medium** | Known CVE with documented exploit path (not exploited here), or confirmed vuln requiring user interaction | 4.0 – 6.9 |
| **Low** | Config weakness, defense-in-depth, theoretical, reconnaissance aid | 0.1 – 3.9 |
| **Info** | Best practice observation, no security impact | 0.0 |
| **Not Exploitable** | False positive — proven not exploitable by evidence | N/A (CVSS 0.0) |
| **TBD** | Manual review required — insufficient evidence to decide | Preliminary score |

---

## 9. Output Fields

Each triaged finding contains:

| Field | Description |
|-------|-------------|
| `title` | Original finding title from AI agent |
| `scanner_severity` | AI agent's original severity (displayed as "AI Sev") |
| `final_severity` | Triage engine's determined severity (displayed as "Triage Sev") |
| `verdict` | `TRUE_POSITIVE`, `FALSE_POSITIVE`, `NOT_A_FINDING`, `MANUAL_REVIEW` |
| `reason` | Human-readable explanation of the classification decision |
| `confidence` | Confidence score (-10 to +10) |
| `cwe` | CWE identifier (e.g., CWE-89) |
| `cvss` | CVSS score (0.0 – 10.0), context-adjusted |
| `cvss_vector` | CVSS v3.1 vector string |
| `cvss_rationale` | Human-readable explanation of CVSS score |
| `cve` | CVE identifier (for library findings with known CVEs) |
| `exploit_evidence` | Specific exploitation proof |
| `steps` | Reproduction steps |
| `dev_action` | Recommended remediation action for developers |
| `curl` | Ready-to-use curl command to reproduce the test |
| `verification_method` | Runtime verifier method used (e.g., sqli_boolean_differential) |
| `verification_evidence` | Runtime verifier output |

---

## 10. End-to-End Example

### Example: AI reports "SQL Injection" on `/api/users?id=1`

**Step 1 — Runtime Verifier:**
```
1. Send: GET /api/users?id=testvalue        → Baseline (200, 1420 chars)
2. Send: GET /api/users?id=testvalue'       → Check for SQL errors
3. Send: GET /api/users?id=testvalue' OR '1'='1  → Boolean TRUE
4. Send: GET /api/users?id=testvalue' OR '1'='2  → Boolean FALSE
5. Compare: TRUE response (3200 chars) vs FALSE (1420 chars)
   Δ = 1780 chars → CONFIRMED (boolean_differential)
```

**Step 2 — Triage Engine (Layer 0):**
```
Runtime verdict: CONFIRMED
→ final_severity = "Critical" (boolean differential = data extraction risk)
→ CWE-89, CVSS 9.8
→ verdict = TRUE_POSITIVE
→ reason = "[RUNTIME VERIFIED] Boolean differential: true=3200, false=1420, Δ=1780"
```

**Step 3 — CVSS Adjustment:**
```
Base: 9.8 from CWE-89
+0.5 Data extraction confirmed in response
Final: 10.0 (Critical)
```

### Example: AI reports "XSS" but response is JSON API

**Step 1 — Runtime Verifier:**
```
1. Inject canary "xvrf7k3q9z" into parameter
2. Response: 200, Content-Type: application/json
3. Canary found in JSON body → CONFIRMED
```

**Step 2 — Triage Engine:**
```
Runtime verdict: CONFIRMED
→ final_severity = "Medium", CWE-79, CVSS 6.1
```

**Step 3 — CVSS Adjustment:**
```
Base: 6.1 from CWE-79
-2.0 XSS in JSON response (not rendered as HTML by browser)
Final: 4.1 (Medium)
Rationale: "Base: 6.1 from CWE-79 | -2.0 XSS in JSON response | Final: 4.1 (Medium)"
```

### Example: AI reports "SQL Injection" but only gets HTTP 500

**Step 1 — Runtime Verifier:**
```
1. Boolean differential: both TRUE and FALSE return same error page
2. No SQL error strings in response
3. Time-based: no measurable delay
→ DISPROVED
```

**Step 2 — Triage Engine (Layer 0):**
```
Runtime verdict: DISPROVED
→ verdict = FALSE_POSITIVE
→ final_severity = "Not Exploitable"
→ reason = "[RUNTIME DISPROVED] No boolean differential, no SQL errors, no time delay"
```

---

## 11. How to Read the UI

The findings table in the scanner UI shows:

| Column | Meaning |
|--------|---------|
| **AI Sev** | What the AI agent originally reported (its best guess) |
| **Triage Sev** | What the triage engine determined after evidence analysis |
| **Verdict** | Classification: True Positive, False Positive, Manual Review |
| **Verified** | How it was verified: "Replay Confirmed" (runtime), "Pattern" (evidence rules), "Needs Human Review" |
| **CWE** | Weakness category identifier |
| **CVSS** | Context-adjusted risk score (hover for rationale, click pencil to override) |
| **Reason** | Full explanation of the classification decision |

**Common severity changes you'll see:**
- AI says "High" → Triage says "Not Exploitable" — AI detected a pattern but runtime disproved it
- AI says "High" → Triage says "Low" — Real finding but lower impact than AI estimated
- AI says "Medium" → Triage says "High" — Evidence shows more severe impact than AI reported

---

## 12. Maintenance & Tuning

### Adding a New Verifier

1. Create an `async def _verify_new_type(client, finding)` function in `runtime_verifier.py`
2. Add dispatch entry to `VULN_DISPATCH` list
3. Add corresponding CWE profile to `CWE_PROFILES` in `triage_engine.py`
4. Add runtime severity mapping in `_runtime_severity()`
5. Add remediation text in `_runtime_dev_action()`
6. Add CWE routing in `_runtime_cwe()`

### Adding a New Pattern Rule

1. Add the rule in the appropriate Layer 1 section of `_classify_inner()` in `triage_engine.py`
2. Always set both `verdict` and `final_severity`
3. Include a human-readable `reason` explaining the classification
4. Include a `dev_action` with specific remediation guidance
5. Apply CWE/CVSS via `_cwe_apply()` where applicable

### Tuning Confidence Bands

Edit the confidence thresholds in Layer 2 of `_classify_inner()`. The current bands are:
- `≥5` → TP Medium
- `≥2` → TP Low
- `0-1` → Manual Review (non-config only)
- `-1 to -2` → FP
- `≤-3` → FP

Narrowing the Manual Review band reduces human workload; widening it increases safety.

---

## 13. Files Reference

| File | Purpose |
|------|---------|
| `scripts/triage_engine.py` | Core classification logic (Layers 0-2, CVSS adjustment) |
| `scripts/runtime_verifier.py` | Payload replay and HTTP verification (17 verifiers) |
| `scripts/cve_lookup.py` | NVD/OSV.dev API integration for CVE enrichment |
| `scripts/report_generator.py` | PDF report generation with triage results |
| `web/app.py` | API endpoints serving triaged findings |
| `web/static/index.html` | Frontend displaying AI Sev vs Triage Sev |

---

*This document should be updated whenever the triage engine logic is modified. Keep it in sync with the codebase.*
