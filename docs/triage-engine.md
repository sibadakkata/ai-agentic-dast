# Triage Engine

[← Back to README](../README.md)

The triage engine classifies every scanner finding **offline** — no LLM calls, $0 cost. It answers: *"Is this finding real (True Positive), noise (False Positive), or does it need human review?"*

## Overview

```
Finding from AI Agent / Passive Recon
         │
         ▼
┌─────────────────────────────────────────────┐
│  LAYER 0A: Passive Recon / Runtime Verified │
│  Deterministic facts → immediate verdict    │
├─────────────────────────────────────────────┤
│  LAYER 0B: SPA Catch-All Detector           │
│  Detects SPAs returning index.html for      │
│  sensitive file paths → FALSE_POSITIVE      │
├─────────────────────────────────────────────┤
│  LAYER 0C: Hardcoded Secret Validation      │
│  Shannon entropy + framework constant       │
│  filter → rejects fake secrets              │
├─────────────────────────────────────────────┤
│  LAYER 1: Evidence-Based Rules              │
│  Pattern-match title + HTTP evidence        │
├─────────────────────────────────────────────┤
│  LAYER 2: Confidence Scoring (-10 to +10)   │
│  Score from HTTP signals → verdict          │
├─────────────────────────────────────────────┤
│  POST-CLASSIFICATION:                       │
│  • Exploitation tier (validated/informal.)  │
│  • Triage narrative (AI steps vs engine)    │
│  • Deduplication by (host + CWE + param)    │
├─────────────────────────────────────────────┤
│  Output: Verdict + Severity + CWE/CVSS      │
│          + Tier + Narrative + Remediation    │
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

## Layer 0B: SPA Catch-All Detection

Single-Page Applications (React, Angular, Vue) typically return their main `index.html` shell with HTTP 200 for **any** URL path — including sensitive file paths like `/.git/HEAD` or `/.env`. The AI sees "200 OK" and reports "Sensitive File Accessible," but the response is just the SPA shell.

**Detection logic:**
1. Finding claims a sensitive file is accessible (title or URL matches known patterns)
2. HTTP response is 200
3. Response body contains SPA markers (`<!doctype html>`, `<div id="root">`, `ng-version`, etc.)
4. Response body does **NOT** contain real file content signatures (`ref: refs/heads/`, `DB_PASSWORD=`, `<?php`, etc.)

**Also marks FALSE_POSITIVE when:** Sensitive file path returns 404/403/410 (file is blocked, not exposed).

## Layer 0C: Hardcoded Secret Validation

The AI's passive recon may detect patterns that look like secrets in JavaScript but are actually framework constants or low-entropy values.

**Shannon entropy check:**
- Real secrets (API keys, tokens) have high entropy (>4.0 bits/char)
- Framework constants have low entropy (e.g., `$$ROW_INTERNAL` = 3.2 bits)

**Framework constant database (38 patterns):**
`$$ROW_INTERNAL`, `__react_devtools`, `ng-version`, `__VUE__`, `__NEXT_DATA__`, `_DATADOG_SYNTHETICS`, `changeme`, `password`, `example`, `test_key`, `sample_key`, etc.

**Result:** Finding is marked FALSE_POSITIVE with explanation of the entropy score and constant match.

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
| Unrestricted File Upload | CWE-434 | 9.8 |
| JWT alg:none | CWE-347 | 9.1 |
| Insecure Deserialization | CWE-502 | 8.1 |
| SSRF (confirmed) | CWE-918 | 7.5 |
| Path Traversal (confirmed) | CWE-22 | 7.5 |
| Auth Bypass | CWE-287 | 7.5 |
| CORS (wildcard + credentials) | CWE-942 | 7.5 |
| Broken Function-Level Auth | CWE-285 | 7.5 |
| Race Condition | CWE-362 | 6.5 |
| HTTP Method Override | CWE-650 | 6.5 |
| Token Leakage | CWE-532 | 6.5 |
| Password Reset Weakness | CWE-640 | 6.5 |
| IDOR | CWE-639 | 6.5 |
| XSS (confirmed) | CWE-79 | 6.1 |
| Missing SRI | CWE-353 | 6.1 |
| Mixed Content (active) | CWE-319 | 5.3 |
| Sensitive Data in URL | CWE-598 | 5.3 |
| Rate Limiting | CWE-307 | 5.3 |
| Prototype Pollution | CWE-1321 | 5.3 |
| Session Management / Fixation | CWE-384 | 5.3 |
| Host Header Injection | CWE-644 | 5.3 |
| Timing-Based Enumeration | CWE-203 | 5.3 |
| Content-Type Confusion | CWE-436 | 5.3 |
| API Version Downgrade | CWE-693 | 5.3 |
| JWT Weakness | CWE-347 | 5.3 |
| CSP Weakness | CWE-693 | 4.7 |
| Open Redirect | CWE-601 | 4.7 |
| CSRF | CWE-352 | 4.3 |
| Missing HSTS | CWE-319 | 4.3 |
| Clickjacking | CWE-1021 | 4.3 |
| Missing Cache-Control | CWE-525 | 4.3 |
| Insecure Cookie | CWE-614 | 4.3 |
| Error Page Info Disclosure | CWE-209 | 3.7 |
| Info Disclosure | CWE-200 | 3.7 |
| Error Handling | CWE-391 | 3.7 |
| CORS | CWE-942 | 3.7 |
| Referrer-Policy Weak/Missing | CWE-200 | 3.1 |
| Missing X-Content-Type-Options | CWE-16 | 3.1 |
| HSTS Incomplete | CWE-319 | 2.1 |
| Permissions-Policy Missing | CWE-16 | 2.1 |
| Password Autocomplete | CWE-522 | 2.1 |

## Exploitation Tiers

After classification, every finding is assigned an **exploitation tier** indicating whether exploitation was actually proven:

| Tier | Meaning | Assigned When |
|------|---------|---------------|
| **validated** | Exploitation proven | Runtime confirmed, payload reflected in body, SQL error strings returned, timing differential confirmed, SSRF internal data returned |
| **informational** | Detected but not proven | Pattern match, missing header, config check, no active exploitation attempt succeeded |
| **n/a** | Not applicable | FALSE_POSITIVE or NOT_A_FINDING verdicts |

This is inspired by XBOW's "proof over probability" methodology — separating findings that would hold up in a bug bounty submission (validated) from those that are observations requiring manual verification (informational).

## Deduplication

After triage, findings are deduplicated by a key of `(target_host, CWE, parameter)`. If no CWE is present, the key falls back to `(target_host, normalized_title, parameter)`.

When duplicates are found, only the **highest severity** instance is kept. This reduces noise from:
- Multiple scan phases testing the same endpoint
- Passive recon + active scanning finding the same issue
- Retry prompts re-discovering existing findings

Typical reduction: **40-60%** fewer findings with zero information loss.

## Triage Narrative

Every finding includes a structured `triage_narrative` object with two sections:

### "What the AI Scanner Tested" (`ai_tested`)
Step-by-step list of what the AI agent did:
1. Which endpoint was targeted
2. What payload was injected (or pattern passively detected)
3. How many HTTP requests were sent
4. Whether runtime verification was attempted
5. What severity the AI originally assigned

### "How Triage Engine Validated" (`triage_validated`)
Step-by-step list of how the engine independently verified:
1. HTTP response codes checked
2. Response bodies analyzed (with byte sizes)
3. Specific validation logic applied (reflection check, SPA detection, entropy analysis, etc.)
4. CWE mapping and CVSS scoring
5. Whether severity was adjusted (and from/to)
6. Final verdict + exploitation tier
7. Detailed reasoning

This separation makes it clear to end users exactly what happened during the scan vs what the triage engine concluded during post-processing.

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
  Tier: informational
  Dev Action: "Add HSTS header with max-age=31536000"
```

### SPA Catch-All — FALSE POSITIVE

```
AI Agent reports: "Sensitive File Accessible: .git/HEAD"
  URL: https://myapp.com/.git/HEAD
  Evidence: "HTTP 200 returned for /.git/HEAD"

Triage:
  Layer 0B: SPA catch-all detected
    - HTTP 200, Content-Type: text/html
    - Body contains: <!doctype html>, <div id="root">
    - Body does NOT contain: ref: refs/heads/, [core], [remote
  Verdict: FALSE_POSITIVE
  Reason: "SPA catch-all: server returns the app shell (index.html)
           for any URL path. HTTP 200 does not mean the file is
           accessible — the response body is HTML, not file content."
```

### Fake Secret — FALSE POSITIVE (Entropy Filter)

```
AI Agent reports: "Hardcoded Master/Service Secret in JavaScript"
  URL: https://support.ccleaner.com/EclairNG.js
  Evidence: INTERNAL_KEY:"$$ROW_INTERNAL"

Triage:
  Layer 0C: Hardcoded secret validation
    - Value: $$ROW_INTERNAL
    - Shannon entropy: 3.2 bits (threshold: 4.0)
    - Match: known framework constant (Salesforce/EclairNG)
  Verdict: FALSE_POSITIVE
  Reason: "Flagged value '$$ROW_INTERNAL' is a framework constant
           or low-entropy string (Shannon entropy: 3.2), not a real
           secret. Real API keys have high entropy (>4.0) and are
           20+ random chars."
```

### Triage Narrative Example

```json
{
  "triage_narrative": {
    "ai_tested": [
      "Targeted endpoint: https://example.com/search?q=test",
      "Injected payload: <script>alert(1)</script>",
      "Sent 1 HTTP request(s) and captured response(s)",
      "AI classified as: High"
    ],
    "triage_validated": [
      "Checked HTTP response codes: [200]",
      "Analyzed 1 response body (38 bytes)",
      "Confirmed: injected payload reflected in response body",
      "Mapped to: CWE-79",
      "CVSS scored: 6.1",
      "Severity adjusted: High -> Medium",
      "Verdict: TRUE POSITIVE",
      "Exploitation tier: validated",
      "Reasoning: XSS payload reflected in response body."
    ]
  }
}
```
