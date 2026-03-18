# Triage Engine

[← Back to README](../README.md)

The triage engine classifies every scanner finding **offline** — no LLM calls, $0 cost. It answers: *"Is this finding real (True Positive), noise (False Positive), or does it need human review?"*

## Overview

```
Finding from AI Agent / Passive Recon
         │
         ▼
┌─────────────────────────────────────────────┐
│  LAYER 0: Passive Recon / Runtime Verified  │
│  Deterministic facts → immediate verdict    │
├─────────────────────────────────────────────┤
│  LAYER 1: Evidence-Based Rules              │
│  Pattern-match title + HTTP evidence        │
├─────────────────────────────────────────────┤
│  LAYER 2: Confidence Scoring (-10 to +10)   │
│  Score from HTTP signals → verdict          │
├─────────────────────────────────────────────┤
│  Output: Verdict + Severity + CWE/CVSS      │
│          + Remediation + Evidence            │
└─────────────────────────────────────────────┘
```

## Layer 0: Passive Recon & Runtime Verification

### Passive Recon Findings

Findings from the passive reconnaissance phase are **deterministic facts** (a file exists, a header is missing, a token is leaked). These are auto-classified as TRUE_POSITIVE with confidence 8/10.

### Runtime Verified Findings

If the runtime verifier replayed the attack payload against the live target:

| Runtime Result | Triage Verdict | Logic |
|---------------|----------------|-------|
| **CONFIRMED** | TRUE_POSITIVE | Payload worked on replay — real vulnerability |
| **DISPROVED** | FALSE_POSITIVE | Payload rejected on replay — server blocks it |
| **INCONCLUSIVE** | Smart Resolver (see below) | Partial signals — auto-resolve or fall through |

### Smart Inconclusive Resolver

When runtime verification is inconclusive, 6 rules try to auto-resolve instead of pushing everything to manual review:

| Rule | Condition | Result |
|------|-----------|--------|
| 1 | Config/header finding (not injection) | TRUE_POSITIVE (Low) — config findings are verifiable by inspection |
| 2 | Injection claim + all responses 4xx/5xx + no positive indicators | FALSE_POSITIVE — server rejected attack payloads |
| 3 | Runtime evidence has 2+ rejection signals ("blocked", "sanitized", "filtered") + low confidence | FALSE_POSITIVE — strong rejection evidence |
| 4 | Runtime evidence has positive signals + moderate confidence | TRUE_POSITIVE (Low) — partial exploitation evidence |
| 5 | Confidence ≤ -2 + zero positive indicators | FALSE_POSITIVE — insufficient evidence |
| 6 | Confidence ≥ 1 + non-injection finding | TRUE_POSITIVE (Low) — likely valid low-severity finding |

## Layer 1: Evidence-Based Rules

For each vulnerability type, the engine looks for **concrete proof** in HTTP responses:

### Injection Findings

| Finding Type | TRUE_POSITIVE if... | FALSE_POSITIVE if... |
|-------------|---------------------|---------------------|
| **SQL Injection** | SQL error strings in response (`mysql`, `syntax error`, `ORA-`, `SQLSTATE`) | HTTP 500 but NO SQL keywords — just bad error handling (reclassified as CWE-391) |
| **XSS** | Payload reflected unencoded (`<script`, `onerror=`, `alert(`) | Payload NOT reflected or HTML-encoded — input sanitized |
| **SSRF** | Internal/metadata content returned (`169.254.169.254`, `/etc/passwd`) | Only redirects/errors — server didn't fetch the URL |
| **XXE** | File content in response (`root:x:0`, `win.ini`, `[extensions]`) | No entity expansion — XML parser rejects external entities |
| **Path Traversal** | OS file content in response | No file content — path sanitized |
| **Command Injection** | OS output in response (`uid=`, `drwxr`, `volume serial`) | No OS output — generic crash (reclassified as error handling) |
| **Deserialization** | Java/Python markers (`java.lang`, `pickle`, `__reduce__`) | No execution markers — server rejected serialized input |
| **Template Injection** | Expression evaluated (e.g., `7*7=49`) | Expression not executed — stored as text |

### Access Control & Auth

| Finding Type | TRUE_POSITIVE if... | FALSE_POSITIVE if... |
|-------------|---------------------|---------------------|
| **IDOR** | HTTP 200 with PII data from different user | All 401/403 — authorization checks work |
| **Access Control** | HTTP 200 where 401/403 expected | All requests denied |
| **CSRF** | Request accepted without token (HTTP 200) | CSRF token detected in evidence |
| **Rate Limiting** | HTTP 429 returned = FP (works); all 200 with no 429 = TP | |
| **Open Redirect** | 3xx redirect to external domain confirmed | Payload rejected or same-domain redirect |

### Configuration & Headers

Config/header findings are generally TRUE_POSITIVE (Low) — they're verifiable facts:

- Missing HSTS → Low (CWE-319, CVSS 4.3)
- Missing CSP → Low (CWE-693, CVSS 4.7)
- Missing X-Frame-Options → Low (CWE-1021, CVSS 4.3)
- Missing SRI → Low (CWE-353, CVSS 6.1)
- Cookie flags → Low/Medium depending on whether it's a session cookie

### Auto-FP Rules

Some findings are **always false positives** regardless of target:

| Pattern | Reason |
|---------|--------|
| HPKP / Public Key Pinning | Deprecated by all browsers since 2018 |
| SameSite=Lax flagged as weak | Lax is the browser default and OWASP recommendation |
| `performance.timing` API | Standard browser API on every website |
| Dynamic script creation | Standard JS pattern (`createElement('script')`) |
| All responses are redirects + injection claim | Scanner wasn't authenticated |
| Zero evidence (no payload, no tests, no data) | Cannot validate with no data |

### Outdated Libraries

Library findings use **live CVE lookup** (no hardcoded CVE lists):

1. Extract library name + version from finding
2. Query **NVD** (National Vulnerability Database) and **OSV.dev** for known CVEs
3. Apply highest CVSS from real CVEs
4. If CVEs found → TRUE_POSITIVE (Medium, capped — not exploited in this scan)
5. If no CVEs → TRUE_POSITIVE (Low, maintenance recommendation)

## Layer 2: Confidence Scoring

For findings that don't match specific Layer 1 patterns, a confidence score is computed from HTTP signals:

### Negative Signals (Reduce Confidence)

| Signal | Score | Meaning |
|--------|-------|---------|
| No test data at all | -3 | Nothing to evaluate |
| All responses are redirects (301/302/307) | -4 | Scanner wasn't authenticated |
| All responses are 403 | -3 | Access denied everywhere |
| All responses are 404 | -3 | Endpoints don't exist |
| Zero evidence + no payload + no tests | -5 | Completely empty finding |
| HTTP 500 without specific error keywords | -1 | Generic crash, not specific vuln |
| All 401/403 with ≥2 requests | -3 | Access denied consistently |

### Positive Signals (Increase Confidence)

| Signal | Score | Meaning |
|--------|-------|---------|
| Payload reflected in response body | +3 | Server echoes input |
| SQL error keywords in response | +4 | Database error exposed |
| XSS reflection keywords | +3 | Script tags/handlers reflected |
| SSRF internal content | +4 | Metadata/internal data returned |
| XXE file content | +5 | External entity processed |
| Path traversal file content | +5 | OS file read confirmed |
| Command injection OS output | +5 | Command executed |
| Deserialization markers | +4 | Object processing detected |
| Time-based + confirmed differential | +3 | Measurable delay |
| HTTP 200 (not redirect) | +1 | Server processed request |
| "Missing"/"absent" in title | +1 | Config finding pattern |

### Score → Verdict Mapping

| Score Range | Verdict | Notes |
|------------|---------|-------|
| ≥ 5 | TRUE_POSITIVE (Medium) | Strong evidence |
| 2–4 | TRUE_POSITIVE (Low) | Moderate evidence |
| 0–1 (config finding) | TRUE_POSITIVE (Low) | Config findings valid even with weak signals |
| 0–1 (injection + all errors) | FALSE_POSITIVE | Server rejected all payloads |
| 0–1 (ambiguous) | MANUAL_REVIEW | Insufficient evidence either way |
| -1 to -2 (config) | TRUE_POSITIVE (Low) | Config findings still valid |
| -1 to -2 (other) | FALSE_POSITIVE | Negative signals outweigh |
| ≤ -3 | FALSE_POSITIVE | Strong negative — scanner noise |

## CVSS Adjustment

After classification, the base CVSS score is adjusted based on actual evidence:

| Condition | Adjustment | Rationale |
|-----------|------------|-----------|
| FALSE_POSITIVE verdict | Set to 0.0 | Not exploitable |
| Not runtime-verified + high-sev | -1.0 | Pattern match only, not confirmed |
| PII/sensitive data in response | +0.5 | Higher impact |
| All responses were errors | -1.5 | Attack partially blocked |
| XSS in JSON API response | -2.0 | Not rendered as HTML by browser |
| Brute force succeeded (account access) | +2.0 | Confirmed account compromise |
| Data extraction confirmed | +0.5 | Real data leak |
| CORS wildcard + credentials | Set to ≥6.5 | Exploitable CORS |

Every finding includes a `cvss_rationale` field explaining the final score calculation.

## Severity Policy

Consistent regardless of what the LLM originally reported:

| Severity | Criteria |
|----------|----------|
| **Critical** | Confirmed RCE, data exfiltration, or account takeover WITH proof |
| **High** | Confirmed exploit with demonstrated real impact |
| **Medium** | Known CVE with exploit path, or confirmed issue needing multi-account verification |
| **Low** | Config weakness, defense-in-depth, theoretical risk |
| **Info** | Best practice, false positive, scanner noise |

## CWE/CVSS Mapping

| Finding Type | CWE | Base CVSS |
|-------------|-----|-----------|
| SQL Injection (confirmed) | CWE-89 | 9.8 |
| RCE / Command Injection | CWE-78 | 9.8 |
| Insecure Deserialization | CWE-502 | 8.1 |
| SSRF (confirmed) | CWE-918 | 7.5 |
| Path Traversal (confirmed) | CWE-22 | 7.5 |
| Auth Bypass | CWE-287 | 7.5 |
| IDOR | CWE-639 | 6.5 |
| XSS (confirmed) | CWE-79 | 6.1 |
| Missing SRI | CWE-353 | 6.1 |
| Rate Limiting | CWE-307 | 5.3 |
| Prototype Pollution | CWE-1321 | 5.3 |
| Session Management | CWE-384 | 5.3 |
| Missing CSP | CWE-693 | 4.7 |
| Open Redirect | CWE-601 | 4.7 |
| CSRF | CWE-352 | 4.3 |
| Missing HSTS | CWE-319 | 4.3 |
| Missing X-Frame-Options | CWE-1021 | 4.3 |
| Info Disclosure | CWE-200 | 3.7 |
| Error Handling | CWE-391 | 3.7 |
| CORS | CWE-942 | 3.7 |
| Missing X-Content-Type-Options | CWE-16 | 3.1 |

## Examples

### SQL Injection — CONFIRMED

```
AI Agent reports: "SQL Injection in /api/search"
  Payload: ' OR 1=1--
  Evidence: "mysql syntax error near '' at line 1"

Triage:
  Layer 0: Runtime replay → same SQL error → CONFIRMED
  Layer 1: SQL_ERROR_KEYWORDS found in response body
  Verdict: TRUE_POSITIVE | Critical | CWE-89 | CVSS 9.8
  Dev Action: "Use parameterized queries."
```

### XSS — FALSE POSITIVE

```
AI Agent reports: "Reflected XSS in /api/profile"
  Payload: <script>alert(1)</script>
  Response: &lt;script&gt;alert(1)&lt;/script&gt;

Triage:
  Layer 0: Runtime replay → HTML-encoded output → DISPROVED
  Verdict: FALSE_POSITIVE | Info
  Reason: "Output is HTML-encoded. Not executable."
```

### Scanner Noise — AUTO FALSE POSITIVE

```
AI Agent reports: "Broken Access Control in /admin"
  All test responses: [302, 302, 302]

Triage:
  Layer 1: All responses are redirects → scanner not authenticated
  Verdict: FALSE_POSITIVE | Info
  Reason: "All 3 responses were 302 redirects."
```

### Missing Header — TRUE POSITIVE (Low)

```
AI Agent reports: "Missing HSTS header"
  Evidence: "Strict-Transport-Security not present"

Triage:
  Layer 1: Title matches "hsts" + "missing"
  Verdict: TRUE_POSITIVE | Low | CWE-319 | CVSS 4.3
  Dev Action: "Add HSTS header with max-age=31536000"
```
