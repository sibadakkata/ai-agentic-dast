"""Universal Triage Engine - works for ANY target (website, API, SPA).

Three-layer classification:
  Layer 1: Evidence-based auto-classification (deterministic rules)
  Layer 2: Confidence scoring from HTTP evidence patterns
  Layer 3: NEEDS_VERIFICATION for unknowns -> human queue

No target-specific logic. No LLM calls. No hardcoded URLs.
CVE data from NVD/OSV (via cve_lookup.py).
CWE mappings for generic weakness categories.
"""

import json
import re
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cve_lookup import enrich_library_finding, extract_libraries

# ══════════════════════════════════════════════════════════════════════
# SEVERITY POLICY (same for every target):
#   Critical = confirmed RCE, data exfil, or account takeover WITH proof
#   High     = confirmed active exploit with demonstrated real impact
#   Medium   = known CVE with documented exploit path (not exploited here)
#   Low      = config weakness, defense-in-depth, theoretical, recon aid
#   Info     = best practice, no security impact
# ══════════════════════════════════════════════════════════════════════

SEV_FROM_CVSS = lambda s: (
    "Critical" if s >= 9.0 else
    "High" if s >= 7.0 else
    "Medium" if s >= 4.0 else
    "Low" if s > 0 else "Info"
)

# CWE database for generic weakness types (no CVE, just category)
CWE_PROFILES = {
    "missing_hsts":     {"cwe": "CWE-319", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "missing_csp":      {"cwe": "CWE-693", "cvss": 4.7, "vec": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"},
    "missing_xframe":   {"cwe": "CWE-1021","cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "missing_xcto":     {"cwe": "CWE-16",  "cvss": 3.1, "vec": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "missing_sri":      {"cwe": "CWE-353", "cvss": 6.1, "vec": "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"},
    "rate_limit":       {"cwe": "CWE-307", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "csrf":             {"cwe": "CWE-352", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "info_disclosure":  {"cwe": "CWE-200", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "error_info":       {"cwe": "CWE-209", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "error_handling":   {"cwe": "CWE-391", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "input_validation": {"cwe": "CWE-20",  "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"},
    "open_redirect":    {"cwe": "CWE-601", "cvss": 4.7, "vec": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"},
    "session_mgmt":     {"cwe": "CWE-384", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "cors":             {"cwe": "CWE-942", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "logging":          {"cwe": "CWE-778", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "debug_staging":    {"cwe": "CWE-489", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "third_party":      {"cwe": "CWE-829", "cvss": 4.7, "vec": "AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "prototype_pollution": {"cwe": "CWE-1321", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "auth_bypass":      {"cwe": "CWE-287", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "sqli_confirmed":   {"cwe": "CWE-89",  "cvss": 9.8, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "xss_confirmed":    {"cwe": "CWE-79",  "cvss": 6.1, "vec": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "ssrf_confirmed":   {"cwe": "CWE-918", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "xxe_confirmed":    {"cwe": "CWE-611", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rce_confirmed":    {"cwe": "CWE-78",  "cvss": 9.8, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "path_traversal_confirmed": {"cwe": "CWE-22", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "idor_confirmed":   {"cwe": "CWE-639", "cvss": 6.5, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "deserialization":  {"cwe": "CWE-502", "cvss": 8.1, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
}


def _cwe_apply(r, profile_key):
    p = CWE_PROFILES.get(profile_key, {})
    r["cwe"] = p.get("cwe", "")
    r["cvss"] = p.get("cvss", 0.0)
    r["cvss_vector"] = p.get("vec", "")


def _runtime_severity(title: str, method: str, details: dict) -> str:
    """Assign severity for a runtime-CONFIRMED finding."""
    t = title.lower()
    if any(k in t for k in ["rce", "command injection", "remote code", "shell injection"]):
        return "Critical"
    if any(k in t for k in ["sql injection", "sqli"]):
        if "error_based" in method or "boolean" in method or "time_based" in method:
            return "Critical"
        return "High"
    if any(k in t for k in ["ssrf", "xxe", "path traversal", "directory traversal", "file inclusion"]):
        return "High"
    if any(k in t for k in ["xss", "cross-site scripting"]):
        return "Medium"
    if any(k in t for k in ["idor", "insecure direct object"]):
        return "High"
    if any(k in t for k in ["open redirect"]):
        return "Medium"
    if any(k in t for k in ["csrf"]):
        return "Medium"
    if any(k in t for k in ["rate limit", "brute force"]):
        return "Medium"
    if any(k in t for k in ["cookie", "header", "hsts", "csp"]):
        return "Low"
    return "Medium"


def _runtime_dev_action(title: str) -> str:
    """Return remediation for a runtime-confirmed finding."""
    t = title.lower()
    if "sql" in t:
        return "URGENT: Use parameterized queries. Never concatenate user input into SQL."
    if "xss" in t:
        return "HTML-encode all output. Implement Content-Security-Policy."
    if "ssrf" in t:
        return "Block outbound requests to RFC1918 and metadata IPs. Whitelist allowed URLs."
    if "xxe" in t:
        return "Disable external entities in XML parser. Prefer JSON."
    if "path traversal" in t or "file inclusion" in t:
        return "Validate and canonicalize file paths. Use allowlists."
    if "command" in t or "rce" in t:
        return "CRITICAL: Never pass user input to OS commands. Use safe APIs."
    if "redirect" in t:
        return "Whitelist allowed redirect destinations."
    if "csrf" in t:
        return "Add CSRF tokens to all state-changing endpoints."
    if "idor" in t:
        return "Implement object-level authorization on every data access."
    if "rate limit" in t:
        return "Implement rate limiting: 429 after repeated failed attempts."
    return "Fix the confirmed vulnerability."


def _runtime_cwe(r: dict, title: str):
    """Apply CWE/CVSS for runtime-confirmed findings."""
    t = title.lower()
    mapping = {
        "sql": "sqli_confirmed", "xss": "xss_confirmed", "ssrf": "ssrf_confirmed",
        "xxe": "xxe_confirmed", "path traversal": "path_traversal_confirmed",
        "directory traversal": "path_traversal_confirmed",
        "command injection": "rce_confirmed", "remote code": "rce_confirmed",
        "idor": "idor_confirmed", "csrf": "csrf", "rate limit": "rate_limit",
        "brute force": "rate_limit", "hsts": "missing_hsts", "csp": "missing_csp",
        "cookie": "session_mgmt", "open redirect": "open_redirect",
    }
    for keyword, profile in mapping.items():
        if keyword in t:
            _cwe_apply(r, profile)
            return


# ══════════════════════════════════════════════════════════════════════
# HELPER: extract evidence signals from finding + test logs
# ══════════════════════════════════════════════════════════════════════

def find_tests(finding, test_log, limit=5):
    url = (finding.get("url", "") or "").split("?")[0]
    param = finding.get("parameter", "") or ""
    matched = []
    for t in test_log:
        req = t.get("request", {})
        t_url = req.get("url", "") or req.get("endpoint", "")
        score = 0
        if url and url in t_url:
            score += 3
        if param and param.lower() in json.dumps(req, default=str).lower():
            score += 2
        if score > 0:
            matched.append((score, t))
    matched.sort(key=lambda x: -x[0])
    return [m[1] for m in matched[:limit]]


def get_statuses(tests):
    statuses = []
    for t in tests:
        resp = t.get("response_summary", {})
        if not isinstance(resp, dict):
            continue
        s = resp.get("status")
        if s:
            statuses.append(s)
        for r in resp.get("results", []):
            if isinstance(r, dict) and r.get("status"):
                statuses.append(r["status"])
    return statuses


def get_response_bodies(tests):
    bodies = []
    for t in tests:
        resp = t.get("response_summary", {})
        if not isinstance(resp, dict):
            continue
        body = resp.get("body_snippet", "") or resp.get("body", "") or ""
        if isinstance(body, dict):
            body = json.dumps(body, default=str)
        bodies.append(str(body).lower())
    return bodies


def _build_curl(t):
    req = t.get("request", {})
    m = req.get("method", "GET")
    u = req.get("url", "") or req.get("endpoint", "")
    if not u:
        return ""
    parts = [f"curl -X {m}"]
    for k, v in list(req.get("headers", {}).items())[:4]:
        parts.append(f"  -H '{k}: {str(v)[:60]}'")
    body = req.get("body", "")
    if body:
        b = json.dumps(body, default=str) if isinstance(body, (dict, list)) else str(body)
        parts.append(f"  -d '{b[:250]}'")
    parts.append(f"  '{u[:200]}'")
    return " \\\n".join(parts)


# ══════════════════════════════════════════════════════════════════════
# LAYER 2: Confidence scoring
# ══════════════════════════════════════════════════════════════════════

SQL_ERROR_KEYWORDS = [
    "syntax error", "mysql", "postgresql", "oracle", "sql server", "sqlite",
    "unclosed quotation", "you have an error in your sql", "odbc", "jdbc",
    "ora-", "pg_query", "microsoft ole db", "warning: mysql", "mariadb",
    "sqlstate", "pdo_", "pg_exec", "unterminated string",
]

XSS_REFLECTION_KEYWORDS = [
    "<script", "onerror=", "onload=", "javascript:", "alert(", "prompt(",
    "confirm(", "<img", "<svg", "onfocus=",
]

SSRF_SUCCESS_KEYWORDS = [
    "ami-id", "instance-id", "iam", "security-credentials", "user-data",
    "metadata", "169.254.169.254", "localhost", "127.0.0.1",
    "internal", "root:", "/etc/passwd", "compute.internal",
]

XXE_SUCCESS_KEYWORDS = [
    "root:x:0", "/etc/passwd", "win.ini", "[extensions]",
    "<!entity", "file:///", "expect://",
]

PATH_TRAVERSAL_KEYWORDS = [
    "root:x:0", "[boot loader]", "[extensions]", "win.ini",
    "/etc/shadow", "web.config", "<?xml",
]

COMMAND_INJECTION_KEYWORDS = [
    "uid=", "gid=", "root:x:", "total ", "drwxr", "-rw-r",
    "volume serial", "directory of", "windows\\system32",
]

DESERIALIZATION_KEYWORDS = [
    "java.lang", "runtimeexception", "classnotfound",
    "objectinputstream", "readobject", "ysoserial",
    "pickle", "marshal", "__reduce__",
]


def _compute_confidence(finding, tests, statuses, bodies, evidence):
    """Score finding confidence from -10 to +10 based on HTTP evidence."""
    score = 0
    title = (finding.get("title", "") or "").lower()
    payload = str(finding.get("payload", "") or "").lower()

    # ── Negative signals (reduces confidence) ──
    if not statuses:
        score -= 3  # no test data at all

    all_redirects = all(s in (301, 302, 303, 307, 308) for s in statuses) if statuses else False
    if all_redirects:
        score -= 4  # scanner wasn't authenticated

    all_403 = all(s == 403 for s in statuses) if statuses else False
    if all_403:
        score -= 3  # access denied

    all_404 = all(s == 404 for s in statuses) if statuses else False
    if all_404:
        score -= 3  # endpoint not found

    ev = str(finding.get("evidence", "") or "")
    if not ev and not payload and not tests:
        score -= 5  # zero evidence

    # ── Positive signals (increases confidence) ──

    # Payload reflected in response body
    if payload and any(payload[:30] in b for b in bodies):
        score += 3

    # SQL errors in response
    if any(kw in b for b in bodies for kw in SQL_ERROR_KEYWORDS):
        score += 4

    # XSS reflected
    if any(kw in b for b in bodies for kw in XSS_REFLECTION_KEYWORDS):
        score += 3

    # SSRF: internal content in response
    if any(kw in b for b in bodies for kw in SSRF_SUCCESS_KEYWORDS):
        score += 4

    # XXE: file content in response
    if any(kw in b for b in bodies for kw in XXE_SUCCESS_KEYWORDS):
        score += 5

    # Path traversal: file content
    if any(kw in b for b in bodies for kw in PATH_TRAVERSAL_KEYWORDS):
        score += 5

    # Command injection: OS output
    if any(kw in b for b in bodies for kw in COMMAND_INJECTION_KEYWORDS):
        score += 5

    # Deserialization markers
    if any(kw in b for b in bodies for kw in DESERIALIZATION_KEYWORDS):
        score += 4

    # Time-based: response took significantly longer (check evidence text)
    if any(kw in evidence.lower() for kw in ["time-based", "sleep(", "delay", "5000ms", "10 second"]):
        if any(kw in evidence.lower() for kw in ["confirmed", "differential", "measurable"]):
            score += 3

    # HTTP 200 with large response (potential data leak)
    if any(s == 200 for s in statuses) and not all_redirects:
        score += 1

    # HTTP 500 without specific error = weak signal
    if any(s == 500 for s in statuses):
        has_specific_error = any(
            any(kw in b for kw in SQL_ERROR_KEYWORDS + COMMAND_INJECTION_KEYWORDS)
            for b in bodies
        )
        if not has_specific_error:
            score -= 1  # generic crash, not specific vuln

    # All 401/403 = access denied, strong negative for injection claims
    all_denied = all(s in (401, 403) for s in statuses) if statuses else False
    if all_denied and len(statuses) >= 2:
        score -= 3

    # Title contains "missing" / "absent" = config finding, slight positive
    if any(k in title for k in ["missing", "absent", "no ", "lack"]):
        score += 1

    return max(-10, min(10, score))


# ══════════════════════════════════════════════════════════════════════
# LAYER 1 + 2 + 3: Main classify function
# ══════════════════════════════════════════════════════════════════════

def classify(finding, test_log):
    """Universal triage: classify any scanner finding from any target.
    Returns dict with verdict, severity, CVE/CWE, evidence, steps, etc."""

    title = (finding.get("title", "") or "").lower()
    ev_raw = finding.get("evidence", "") or ""
    evidence = str(ev_raw).lower() if not isinstance(ev_raw, dict) else json.dumps(ev_raw).lower()
    severity = finding.get("severity", "Info")
    url = finding.get("url", "") or ""
    payload = str(finding.get("payload", "") or "")

    tests = find_tests(finding, test_log)
    statuses = get_statuses(tests)
    bodies = get_response_bodies(tests)
    all_redirects = all(s in (301, 302, 303, 307, 308) for s in statuses) if statuses else False
    confidence = _compute_confidence(finding, tests, statuses, bodies, evidence)

    r = {
        "title": finding.get("title", ""),
        "scanner_severity": severity,
        "owasp": finding.get("owasp_category", "") or "",
        "url": url,
        "parameter": finding.get("parameter", "") or "",
        "payload": payload[:200],
        "scanner_evidence": str(ev_raw)[:500],
        "verdict": "NEEDS_VERIFICATION",
        "final_severity": "Low",
        "cve": "", "cwe": "", "cvss": 0.0, "cvss_vector": "",
        "exploit_evidence": "",
        "steps": "",
        "dev_action": "",
        "reason": "",
        "confidence": confidence,
        "curl": _build_curl(tests[0]) if tests else "",
        "response_status": list(set(statuses))[:6],
        "verification_method": finding.get("verification_method", "none"),
        "verification_evidence": finding.get("verification_evidence", ""),
    }

    # ==================================================================
    # LAYER 0: RUNTIME VERIFICATION — real payload replay results
    # If the runtime verifier already tested this finding, use its verdict.
    # This takes priority over all pattern matching below.
    # ==================================================================

    rv_verdict = finding.get("verdict")
    rv_verified = finding.get("verified", False)

    if rv_verified and rv_verdict in ("CONFIRMED", "DISPROVED", "INCONCLUSIVE"):
        rv_method = finding.get("verification_method", "")
        rv_evidence = finding.get("verification_evidence", "")
        rv_details = finding.get("verification_details", {})

        if rv_verdict == "CONFIRMED":
            sev = _runtime_severity(title, rv_method, rv_details)
            r.update(
                verdict="TRUE_POSITIVE",
                final_severity=sev,
                reason=f"[RUNTIME VERIFIED] {rv_evidence}",
                exploit_evidence=rv_evidence,
                steps=f"Verification method: {rv_method}\n"
                      f"Details: {json.dumps(rv_details, default=str)[:300]}",
                dev_action=_runtime_dev_action(title),
            )
            _runtime_cwe(r, title)
            return r

        if rv_verdict == "DISPROVED":
            r.update(
                verdict="FALSE_POSITIVE",
                final_severity="-",
                reason=f"[RUNTIME DISPROVED] {rv_evidence}",
                dev_action="No action — runtime verification confirmed this is not exploitable.",
            )
            return r

        # INCONCLUSIVE — fall through to pattern matching below
        # but boost/reduce confidence based on what the verifier found
        r["reason"] = f"[RUNTIME INCONCLUSIVE] {rv_evidence} — using pattern analysis as fallback."

    # ==================================================================
    # LAYER 1A: NOT A FINDING - positive observations
    # ==================================================================
    positive_kw = [
        "not found", "properly configured", "properly restricted",
        "properly implemented", "properly secured", "no vulnerabilit",
        "good:", "not vulnerable", "no issues", "robust input",
        "secure cookie config", "https enforcement properly",
        "session management strength",
    ]
    if any(k in title for k in positive_kw):
        r.update(verdict="NOT_A_FINDING", final_severity="Info",
                 reason="Positive security observation.",
                 dev_action="No action required.")
        return r

    # ==================================================================
    # LAYER 1B: AUTO FALSE POSITIVE - provably wrong for ANY target
    # ==================================================================

    # Zero evidence
    if not ev_raw and not payload and not tests:
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 reason="Zero evidence: no payload, no test data, no scanner evidence. "
                        "Cannot validate a finding with no supporting data.",
                 dev_action="No action - no evidence.")
        return r

    # All responses are redirects = scanner wasn't authenticated
    # BUT: for config/header findings the redirect doesn't invalidate the finding
    if statuses and all_redirects:
        is_injection = any(k in title for k in [
            "sql", "xss", "ssrf", "xxe", "injection", "traversal",
            "command", "deserialization", "rce", "idor",
        ])
        if is_injection:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason=f"All {len(statuses)} responses were {list(set(statuses))} redirects. "
                            "Scanner was not authenticated. Injection findings require "
                            "authenticated access to the actual endpoint to be valid.",
                     dev_action="No action. Re-test with authenticated session if concerned.")
            return r

    # HPKP (deprecated by all browsers in 2018)
    if "hpkp" in title or "public key pin" in title:
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 reason="HTTP Public Key Pinning (HPKP) was deprecated by Chrome in 2018 "
                        "and removed from all browsers. Not a valid finding.",
                 dev_action="No action. HPKP is deprecated.")
        return r

    # SameSite=Lax flagged as weak (it's the OWASP recommendation)
    if "samesite" in title and "lax" in title:
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 reason="SameSite=Lax is the browser DEFAULT and OWASP-recommended setting. "
                        "Strict breaks legitimate cross-site navigation.",
                 dev_action="No action. SameSite=Lax is correct.")
        return r

    # performance.timing API flagged (standard browser API, not a vuln)
    if "performance" in title and ("timing" in title or "api" in title):
        if "navigation" in title or "resource" in title or "performance.timing" in evidence:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason="performance.timing is a standard browser API on every website. "
                            "Not a vulnerability.",
                     dev_action="No action.")
            return r

    # Dynamic script creation (standard JS, not a vuln without XSS)
    if "dynamic script" in title and ("creation" in title or "source" in title):
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 reason="document.createElement('script') is standard JavaScript used by "
                        "every SPA and analytics library. Not a vulnerability without XSS.",
                 dev_action="No action.")
        return r

    # ==================================================================
    # LAYER 1C: INJECTION CHECKS - evidence-based for ANY target
    # ==================================================================

    # SQL Injection
    if "sql" in title and "injection" in title:
        has_sql_error = any(kw in evidence for kw in SQL_ERROR_KEYWORDS)
        has_sql_body = any(kw in b for b in bodies for kw in SQL_ERROR_KEYWORDS)
        has_data_extract = any(kw in evidence for kw in ["union select", "1=1", "table_name", "column_name"])

        if has_sql_error or has_sql_body or has_data_extract:
            _cwe_apply(r, "sqli_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cve=f"N/A ({r['cwe']}: SQL Injection)",
                     reason="SQL error strings or data extraction confirmed in response. "
                            "This is a real SQL injection.",
                     steps=f"1. Send payload to {url}\n"
                           f"2. Response contains SQL error: "
                           f"{[kw for kw in SQL_ERROR_KEYWORDS if kw in evidence][:3]}\n"
                           "3. CONFIRMED - database is directly exposed to injection",
                     dev_action="Use parameterized queries. Never concatenate user input into SQL.")
            return r
        else:
            _cwe_apply(r, "error_handling")
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cve=f"N/A ({r['cwe']}: Improper Error Handling)",
                     reason="HTTP 500 on special characters but NO SQL error strings, "
                            "no data extraction, no boolean/time-based differential. "
                            "This is improper error handling (CWE-391), not SQL injection.",
                     steps=f"1. Payload sent to {url}\n"
                           "2. Response: HTTP 500 with generic error\n"
                           "3. NO SQL keywords in response body\n"
                           "4. CONCLUSION: error handling bug, not SQLi",
                     dev_action="Return HTTP 400 for malformed input. Add input validation.")
            return r

    # XSS (Cross-Site Scripting)
    if "xss" in title or "cross-site scripting" in title or "cross site scripting" in title:
        reflected = any(kw in b for b in bodies for kw in XSS_REFLECTION_KEYWORDS)
        reflected_ev = any(kw in evidence for kw in XSS_REFLECTION_KEYWORDS)

        if reflected or reflected_ev:
            _cwe_apply(r, "xss_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cve=f"N/A ({r['cwe']}: XSS)",
                     reason="XSS payload reflected in response body. "
                            "Medium because exploitation requires user interaction.",
                     steps=f"1. Inject payload into {url}\n"
                           "2. Payload reflected in response HTML\n"
                           "3. Browser would execute injected script\n"
                           "4. CONFIRMED - input not sanitized on output",
                     dev_action="HTML-encode all output. Implement CSP.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-79",
                     reason="XSS claimed but payload NOT reflected in response body. "
                            "Input appears to be sanitized or rejected.",
                     dev_action="No action - input is sanitized.")
            return r

    # SSRF (Server-Side Request Forgery)
    if "ssrf" in title or "server-side request" in title:
        has_internal = any(kw in b for b in bodies for kw in SSRF_SUCCESS_KEYWORDS)
        has_internal_ev = any(kw in evidence for kw in SSRF_SUCCESS_KEYWORDS)

        if (has_internal or has_internal_ev) and not all_redirects:
            _cwe_apply(r, "ssrf_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cve=f"N/A ({r['cwe']}: SSRF)",
                     reason="Internal/metadata content found in response. "
                            "Server fetched an internal resource.",
                     steps=f"1. Send SSRF payload to {url}\n"
                           "2. Response contains internal content\n"
                           "3. CONFIRMED - server fetches attacker-controlled URLs",
                     dev_action="Whitelist allowed outbound URLs. Block RFC1918 and metadata IPs.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-918",
                     reason="SSRF payloads returned redirects or generic responses. "
                            "No internal/metadata content in response body. "
                            "Server did not fetch the attacker URL.",
                     dev_action="No action - server correctly rejected SSRF attempts.")
            return r

    # XXE (XML External Entity)
    if "xxe" in title or "xml external" in title or "xml entity" in title:
        has_file = any(kw in b for b in bodies for kw in XXE_SUCCESS_KEYWORDS)
        has_file_ev = any(kw in evidence for kw in XXE_SUCCESS_KEYWORDS)

        if has_file or has_file_ev:
            _cwe_apply(r, "xxe_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cve=f"N/A ({r['cwe']}: XXE)",
                     reason="External entity processed - file content or network access confirmed.",
                     steps=f"1. Send XXE payload to {url}\n"
                           "2. Response contains file content (e.g., /etc/passwd)\n"
                           "3. CONFIRMED - XML parser processes external entities",
                     dev_action="Disable external entities in XML parser. Use JSON instead of XML.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-611",
                     reason="XXE payload sent but no file content or entity expansion in response.",
                     dev_action="No action - XML parser appears to reject external entities.")
            return r

    # Path Traversal
    if any(k in title for k in ["path traversal", "directory traversal",
                                 "local file inclusion", "local file read", "file inclusion"]):
        has_file = any(kw in b for b in bodies for kw in PATH_TRAVERSAL_KEYWORDS)
        has_file_ev = any(kw in evidence for kw in PATH_TRAVERSAL_KEYWORDS)

        if has_file or has_file_ev:
            _cwe_apply(r, "path_traversal_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cve=f"N/A ({r['cwe']}: Path Traversal)",
                     reason="File content from outside web root found in response.",
                     steps=f"1. Send traversal payload (../../etc/passwd) to {url}\n"
                           "2. Response contains OS file content\n"
                           "3. CONFIRMED - application reads arbitrary files",
                     dev_action="Validate and canonicalize file paths. Use allowlists.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-22",
                     reason="Path traversal payload sent but no file content in response. "
                            "Server appears to reject or sanitize path input.",
                     dev_action="No action - path sanitization appears effective.")
            return r

    # Command Injection / RCE
    # Note: "rce" removed as standalone - matches "subresource", "enforcement", "force"
    if any(k in title for k in ["command injection", "remote code execution", "os command",
                                 "code execution", "shell injection", "command execution"]):
        has_output = any(kw in b for b in bodies for kw in COMMAND_INJECTION_KEYWORDS)
        has_output_ev = any(kw in evidence for kw in COMMAND_INJECTION_KEYWORDS)

        if has_output or has_output_ev:
            _cwe_apply(r, "rce_confirmed")
            r.update(verdict="TRUE_POSITIVE", final_severity="Critical",
                     cve=f"N/A ({r['cwe']}: Command Injection)",
                     reason="OS command output found in response. Server executed injected command.",
                     steps=f"1. Send command injection payload to {url}\n"
                           "2. Response contains OS output (uid, dir listing, etc.)\n"
                           "3. CRITICAL - arbitrary command execution confirmed",
                     dev_action="NEVER pass user input to OS commands. Use safe APIs.")
            return r
        else:
            _cwe_apply(r, "error_handling")
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason="Command injection payload sent but no OS output in response. "
                            "Server crashed or returned generic error.",
                     dev_action="Improve error handling for unexpected input.")
            return r

    # Deserialization
    if "deserialization" in title or "deserializ" in title:
        has_markers = any(kw in b for b in bodies for kw in DESERIALIZATION_KEYWORDS)
        has_markers_ev = any(kw in evidence for kw in DESERIALIZATION_KEYWORDS)

        if has_markers or has_markers_ev:
            _cwe_apply(r, "deserialization")
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cve=f"N/A ({r['cwe']}: Insecure Deserialization)",
                     reason="Deserialization markers found in response.",
                     dev_action="Do not deserialize untrusted data. Use allowlists for classes.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-502",
                     reason="Deserialization payload sent but zero execution markers "
                            "(no Java stack traces, no pickle errors, no class loading). "
                            "Server did not process the payload.",
                     dev_action="No action - server rejects serialized input.")
            return r

    # IDOR (Insecure Direct Object Reference)
    if "idor" in title or "insecure direct object" in title or "broken object" in title:
        _cwe_apply(r, "idor_confirmed")
        all_denied = all(s in (401, 403) for s in statuses) if statuses else False
        has_data_leak = any(s == 200 for s in statuses) and any(
            kw in b for b in bodies for kw in ["email", "name", "address", "phone", "ssn", "account"]
        )
        if all_denied:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason=f"All {len(statuses)} requests returned 401/403. "
                            "Server enforces authorization correctly.",
                     dev_action="No action - authorization checks are effective.")
            return r
        if has_data_leak:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="Accessed other user's data (PII keywords in 200 response). "
                            "Confirm with two distinct accounts for High severity.",
                     steps=f"1. Request returned 200 with PII-like content at {url}\n"
                           "2. Check if this data belongs to a different user\n"
                           "3. If confirmed → upgrade to High",
                     dev_action="Implement object-level authorization checks.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="IDOR pattern detected. Single-session test cannot fully confirm. "
                        "Classified as Low TP (defense-in-depth). Upgrade to High if "
                        "manual two-account test confirms unauthorized access.",
                 steps="1. Login as User A, note resource IDs\n"
                       "2. Login as User B, try to access User A's resources\n"
                       "3. If successful → confirmed IDOR (upgrade to High)",
                 dev_action="Implement authorization checks on every data access.")
        return r

    # Template Injection (SSTI)
    if "template" in title and "injection" in title:
        executed = any(kw in evidence for kw in ["49", "7*7", "executed", "rendered", "${"])
        if executed:
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     cwe="CWE-1336", cvss=8.1,
                     cve="N/A (CWE-1336: Server-Side Template Injection)",
                     reason="Template expression was evaluated (e.g., 7*7=49). "
                            "Can lead to RCE depending on template engine.",
                     dev_action="Never pass user input into template expressions. Use sandboxed templates.")
            return r
        else:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason="Template injection payload sent but not executed. "
                            "Input stored as text, not evaluated.",
                     dev_action="No action - template engine does not evaluate user input.")
            return r

    # ==================================================================
    # LAYER 1D: CONFIGURATION / HEADER CHECKS - universal
    # ==================================================================

    # Missing security headers (generic)
    if any(k in title for k in ["missing header", "missing security header",
                                 "missing critical security", "security header"]):
        _cwe_apply(r, "missing_hsts")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cve=f"N/A ({r['cwe']}: Missing Security Headers)",
                 reason="Security headers absent. Defense-in-depth measure. "
                        "No exploit demonstrated - these prevent future attacks.",
                 steps=f"1. curl -s -I {url or '<target>'}\n"
                       "2. Check for: Strict-Transport-Security, X-Frame-Options,\n"
                       "   Content-Security-Policy, X-Content-Type-Options\n"
                       "3. NOTE: Missing headers = config improvement, not active exploit",
                 dev_action="Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options to all responses.")
        return r

    if "hsts" in title and ("missing" in title or "no " in title):
        _cwe_apply(r, "missing_hsts")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="HSTS absent. Requires active MITM to exploit. No exploit demonstrated.",
                 dev_action="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
        return r

    if "csp" in title and ("missing" in title or "no " in title or "lack" in title or "absence" in title):
        _cwe_apply(r, "missing_csp")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="CSP absent. Defense-in-depth for XSS mitigation. Not exploitable alone.",
                 dev_action="Implement Content-Security-Policy header.")
        return r

    if "sri" in title or "subresource integrity" in title or ("integrity" in title and "missing" in title):
        _cwe_apply(r, "missing_sri")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="No SRI on external scripts. Requires CDN compromise to exploit. Theoretical.",
                 dev_action="Add integrity= hash to all external <script> and <link> tags.")
        return r

    if "clickjack" in title or ("x-frame" in title and "missing" in title):
        _cwe_apply(r, "missing_xframe")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="X-Frame-Options absent. Clickjacking requires user interaction. "
                        "SameSite cookies mitigate most attacks.",
                 dev_action="Add X-Frame-Options: DENY and CSP: frame-ancestors 'none'.")
        return r

    # Outdated libraries - DYNAMIC via OSV + NVD
    if any(k in title for k in ["outdated", "version", "library", "librari",
                                 "react", "jquery", "bootstrap", "angular", "vue",
                                 "lodash", "moment", "express"]):
        libs = extract_libraries(finding)
        if libs:
            all_cves = []
            all_summaries = []
            max_cvss = 0.0

            for lib_name, lib_ver in libs:
                enriched = enrich_library_finding(lib_name, lib_ver)
                if enriched["has_cves"]:
                    for c in enriched["cves"]:
                        all_cves.append(c)
                        if c["cvss"] and c["cvss"] > max_cvss:
                            max_cvss = c["cvss"]
                    all_summaries.append(enriched["summary"])
                else:
                    all_summaries.append(f"{lib_name}@{lib_ver}: 0 CVEs (OSV.dev)")

            if all_cves:
                top = sorted(all_cves, key=lambda x: x.get("cvss", 0), reverse=True)
                cve_str = "; ".join(f"{c['cve']} (CVSS {c['cvss']:.1f})" for c in top[:5])
                cwes = list(set(cw for c in top[:3] for cw in c.get("cwes", [])))
                final_sev = "Medium" if max_cvss >= 4.0 else "Low"

                lib_list = ", ".join(f"{n}@{v}" for n, v in libs)
                steps = [f"1. Detected: {lib_list}"]
                for i, c in enumerate(top[:4], 2):
                    steps.append(f"{i}. {c['cve']}: CVSS {c['cvss']:.1f} - {c.get('description', '')[:70]}")
                steps.append(f"{len(top[:4])+2}. Source: NVD + OSV.dev (authoritative)")
                steps.append(f"{len(top[:4])+3}. NOT exploited in this scan -> capped at Medium max")

                r.update(verdict="TRUE_POSITIVE", final_severity=final_sev,
                         cve=cve_str, cwe=", ".join(cwes[:3]) or "CWE-1104",
                         cvss=max_cvss, cvss_vector=top[0].get("vector", ""),
                         reason=f"{len(all_cves)} CVEs from NVD/OSV. " + "; ".join(all_summaries[:2]),
                         steps="\n".join(steps),
                         dev_action=f"Upgrade {lib_list} to latest stable versions.")
                return r
            else:
                r.update(verdict="TRUE_POSITIVE", final_severity="Low", cwe="CWE-1104",
                         reason="Libraries detected but 0 CVEs per OSV.dev. "
                                "May be EOL but not actively vulnerable. " + "; ".join(all_summaries),
                         dev_action=f"Consider upgrading for maintenance.")
                return r

    # Rate limiting
    if "rate limit" in title or "brute force" in title:
        has_429 = 429 in statuses
        all_ok = all(s in (200, 302) for s in statuses) if statuses else False
        _cwe_apply(r, "rate_limit")
        if has_429:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason=f"Server returned HTTP 429 (Too Many Requests). "
                            "Rate limiting is implemented.",
                     dev_action="No action - rate limiting is active.")
            return r
        if statuses and all_ok and not has_429 and len(statuses) >= 5:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason=f"{len(statuses)} requests accepted without HTTP 429 or CAPTCHA. "
                            "No actual brute-force success demonstrated. Medium until proven at scale.",
                     steps=f"1. Sent {len(statuses)} rapid requests -> all accepted\n"
                           f"2. Status codes: {list(set(statuses))}\n"
                           "3. Zero 429, zero CAPTCHA, zero lockout\n"
                           "4. NOTE: no actual account compromised -> Medium, not High",
                     dev_action="Add rate limiting: 5 failed attempts -> 429 + CAPTCHA.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason=f"Rate limiting not observed in {len(statuses)} test(s). "
                        "Insufficient volume to confirm absence, but no 429 seen. "
                        "Classified as Low TP (defense-in-depth recommendation).",
                 dev_action="Implement rate limiting: 429 after repeated failed attempts.")
        return r

    # CSRF
    if "csrf" in title:
        _cwe_apply(r, "csrf")
        has_token_evidence = any(kw in evidence for kw in [
            "csrf_token", "csrftoken", "_token", "xsrf", "authenticity_token",
            "x-csrf", "__requestverificationtoken", "antiforgery",
        ])
        no_token_evidence = any(kw in evidence for kw in [
            "no csrf", "missing csrf", "no token", "missing token",
            "without token", "token absent", "not found",
        ])
        accepted_without_token = any(s == 200 for s in statuses) and no_token_evidence

        if has_token_evidence and not no_token_evidence:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     reason="CSRF token detected in evidence. Server implements CSRF protection. "
                            "Modern SameSite=Lax cookies provide additional defense.",
                     dev_action="No action - CSRF protection is implemented.")
            return r
        if accepted_without_token:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="State-changing request accepted without CSRF token (HTTP 200). "
                            "Medium because exploitation requires victim to visit attacker page.",
                     steps="1. Intercept the POST/PUT/DELETE request\n"
                           "2. Remove any CSRF token\n"
                           "3. Server accepted the request -> confirmed\n"
                           "4. SameSite cookies may partially mitigate in modern browsers",
                     dev_action="Add CSRF tokens to all state-changing endpoints.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="CSRF token not detected in forms/requests. Classified as Low TP "
                        "(defense-in-depth). SameSite=Lax default in modern browsers partially mitigates.",
                 dev_action="Validate CSRF tokens server-side on all state-changing endpoints.")
        return r

    # Information disclosure
    if any(k in title for k in ["information disclosure", "server stack", "verbose error",
                                 "framework", "server information", "infrastructure",
                                 "error format", "version disclosure"]):
        _cwe_apply(r, "info_disclosure")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Server/framework version or internal details exposed. "
                        "Aids reconnaissance but not directly exploitable.",
                 dev_action="Remove version headers. Return generic error pages.")
        return r

    # Status/debug pages
    if "status" in title and ("accessible" in title or "debug" in title or "public" in title):
        _cwe_apply(r, "info_disclosure")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Debug/status page publicly accessible. Information exposure only.",
                 dev_action="Restrict to authenticated admin users or internal network.")
        return r

    # CORS
    if "cors" in title:
        _cwe_apply(r, "cors")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="CORS misconfiguration or absence. Default (no CORS headers) is actually safe. "
                        "Only a problem if Access-Control-Allow-Origin: * with credentials.",
                 dev_action="Configure CORS explicitly if cross-origin access needed.")
        return r

    # Open redirect
    if "redirect" in title and "open" in title:
        _cwe_apply(r, "open_redirect")
        redirected_external = any(
            kw in evidence for kw in ["evil.com", "attacker.com", "external", "different domain"]
        )
        location_header = any(
            kw in b for b in bodies for kw in ["location:", "location=", "redirect_uri"]
        )
        has_3xx = any(s in (301, 302, 303, 307, 308) for s in statuses)

        if redirected_external or (location_header and has_3xx):
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="Server redirects to attacker-controlled domain confirmed. "
                            "Medium because exploitation requires user interaction (phishing).",
                     steps=f"1. Send redirect payload to {url}\n"
                           "2. Response: 3xx with Location pointing to external domain\n"
                           "3. CONFIRMED - server blindly redirects to user-supplied URL",
                     dev_action="Whitelist allowed redirect destinations. Reject external URLs.")
            return r
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 reason="Open redirect payload sent but no evidence of external redirect. "
                        "Server either rejected the payload, redirected to same domain, "
                        "or returned an error.",
                 dev_action="No action - redirect appears to be properly restricted.")
        return r

    # Session management
    if any(k in title for k in ["session fixation", "session token", "token regeneration", "weak token"]):
        _cwe_apply(r, "session_mgmt")
        fixation_confirmed = any(kw in evidence for kw in [
            "same session", "not regenerated", "unchanged", "fixated", "reused after login",
        ])
        if fixation_confirmed:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="Session ID not regenerated after authentication. "
                            "Attacker can fixate a known session ID before victim logs in.",
                     dev_action="Regenerate session ID on every authentication event.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Session management weakness reported. Classified as Low TP "
                        "(defense-in-depth). No active exploitation demonstrated.",
                 dev_action="Regenerate session ID on authentication. Use secure session settings.")
        return r

    # OAuth/OIDC
    if any(k in title for k in ["oidc", "oauth", "pkce", "state parameter",
                                 "nonce", "authorization code", "redirect_uri",
                                 "client_id", "token endpoint"]):
        _cwe_apply(r, "auth_bypass")
        token_leaked = any(kw in evidence for kw in [
            "access_token", "id_token", "authorization_code", "leaked", "exposed",
        ])
        bypass_confirmed = any(kw in evidence for kw in [
            "bypass", "no state", "missing pkce", "no nonce", "accepted without",
        ])
        if token_leaked:
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     reason="OAuth token or authorization code exposed in evidence. "
                            "Can lead to account takeover.",
                     dev_action="Enforce PKCE. Never expose tokens in URLs or logs.")
            return r
        if bypass_confirmed:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="OAuth/OIDC misconfiguration confirmed (missing state/PKCE/nonce). "
                            "Enables CSRF on auth flow or token interception.",
                     dev_action="Enforce PKCE, validate state parameter, whitelist redirect_uri.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="OAuth/OIDC configuration weakness reported. Classified as Low TP "
                        "(hardening recommendation). No exploitation demonstrated.",
                 dev_action="Enforce PKCE, validate state, whitelist redirect_uri.")
        return r

    # Prototype pollution
    if "prototype" in title and "pollution" in title:
        _cwe_apply(r, "prototype_pollution")
        pollution_confirmed = any(kw in evidence for kw in [
            "polluted", "__proto__", "constructor.prototype", "executed", "true",
        ])
        if pollution_confirmed:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     reason="Prototype pollution confirmed - attacker can modify Object.prototype. "
                            "Impact depends on how polluted properties are consumed downstream.",
                     dev_action="Use Object.create(null), freeze prototypes, or validate merge inputs.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Prototype pollution pattern detected in client-side JavaScript. "
                        "Classified as Low TP. Impact depends on downstream property consumption.",
                 dev_action="Use Object.create(null) for config objects. Freeze prototypes in critical paths.")
        return r

    # Staging/debug references
    if any(k in title for k in ["staging", "debug", "development"]) and \
       any(k in title for k in ["reference", "code", "artifact", "build", "environment"]):
        _cwe_apply(r, "debug_staging")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Staging/debug references found in code. Low in non-prod, "
                        "Medium if this is production.",
                 dev_action="Remove staging references before production deployment.")
        return r

    # Third-party scripts
    if any(k in title for k in ["third-party", "tag management", "external script"]):
        _cwe_apply(r, "third_party")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="External scripts loaded. Theoretical supply-chain risk. "
                        "Mitigate with SRI and CSP.",
                 dev_action="Add SRI to external scripts. Implement CSP script-src whitelist.")
        return r

    # Logging absence
    if "logging" in title and any(k in title for k in ["missing", "no ", "absence", "insufficient"]):
        _cwe_apply(r, "logging")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="No security event logging detected. Hard to verify externally.",
                 dev_action="Implement security event logging to SIEM.")
        return r

    # Input validation
    if "input validation" in title or "insufficient" in title:
        _cwe_apply(r, "input_validation")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Server accepts invalid input but no exploit path demonstrated.",
                 dev_action="Add server-side input validation.")
        return r

    # Improper error handling (500 on bad input)
    if "error" in title and ("handling" in title or "improper" in title):
        _cwe_apply(r, "error_handling")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="HTTP 500 on malformed input. Unhandled exception, not injection.",
                 dev_action="Return HTTP 400 for invalid input. Catch exceptions.")
        return r

    # Cookie-related (generic)
    if "cookie" in title and any(k in title for k in ["httponly", "secure", "flag", "attribute",
                                                       "missing", "insecure", "no "]):
        is_session_cookie = any(kw in evidence for kw in [
            "session", "sid", "jwt", "auth", "token", "login", "connect.sid",
            "phpsessid", "jsessionid", "asp.net_sessionid",
        ])
        if is_session_cookie:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-614", cvss=4.3,
                     reason="Session/authentication cookie missing security attributes. "
                            "Medium because attackers could intercept or access the session cookie.",
                     dev_action="Set Secure, HttpOnly, SameSite=Lax on all session cookies.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-614", cvss=3.7,
                 reason="Cookie missing security attributes (Secure/HttpOnly/SameSite). "
                        "Low TP — defense-in-depth hardening recommendation.",
                 dev_action="Set Secure, HttpOnly, SameSite on all cookies.")
        return r

    # Password in URL (generic - could be real or scanner-fabricated)
    if "password" in title and ("url" in title or "query" in title):
        scanner_fabricated = any(kw in evidence for kw in [
            "method=post", "form method=\"post\"", "post request",
        ]) or any(kw in payload for kw in ["password=test", "password=mysecret", "password="])
        app_uses_get = any(kw in evidence for kw in [
            "method=get", "method=\"get\"", "get request with password",
        ])

        if app_uses_get:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-598", cvss=4.3,
                     reason="Application sends password via GET. Password visible in "
                            "browser history, server logs, and referrer headers.",
                     dev_action="Change login form to method=POST. Never send credentials via GET.")
            return r
        r.update(verdict="FALSE_POSITIVE", final_severity="-",
                 cwe="CWE-598", cvss=0.0,
                 reason="Scanner fabricated a GET request with password in URL. "
                        "Real login forms universally use POST. The application does not "
                        "send passwords via GET — the scanner created this test artificially.",
                 dev_action="No action. Login form already uses POST method.")
        return r

    # Access control
    if "access control" in title or "authorization" in title or "privilege" in title:
        all_denied = all(s in (401, 403) for s in statuses) if statuses else False
        unauthorized_access = any(s == 200 for s in statuses) and not all_denied
        if all_denied:
            r.update(verdict="FALSE_POSITIVE", final_severity="-",
                     cwe="CWE-285", cvss=0.0,
                     reason=f"All {len(statuses)} requests returned 401/403. "
                            "Server enforces access control correctly.",
                     dev_action="No action - access control is effective.")
            return r
        if unauthorized_access:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-285", cvss=5.3,
                     reason="Request returned HTTP 200 where 401/403 was expected. "
                            "Potential unauthorized access. Medium until confirmed with "
                            "multi-account testing.",
                     steps=f"1. Accessed {url} and received 200\n"
                           "2. Expected 401/403 for unauthorized user\n"
                           "3. Confirm with two separate user accounts for High",
                     dev_action="Implement proper authorization checks on all endpoints.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-285", cvss=3.7,
                 reason="Access control weakness reported. Classified as Low TP "
                        "(defense-in-depth). No exploitation demonstrated in single-session scan.",
                 dev_action="Implement proper authorization checks on all endpoints.")
        return r

    # ==================================================================
    # LAYER 1E: CATCH-ALL PATTERNS for common finding types
    # ==================================================================

    # TLS/SSL/Certificate issues
    if any(k in title for k in ["tls", "ssl", "certificate", "cipher", "protocol",
                                 "https", "http/2", "weak crypto", "encryption"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-326", cvss=3.7,
                 reason="TLS/SSL/cipher configuration weakness. Defense-in-depth hardening.",
                 dev_action="Enforce TLS 1.2+, disable weak ciphers, use strong certificates.")
        return r

    # Cache control issues
    if any(k in title for k in ["cache control", "cache-control", "caching", "no-store",
                                 "sensitive data cached", "browser cache"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-525", cvss=3.1,
                 reason="Cache-control headers missing or misconfigured for sensitive pages. "
                        "Sensitive data may be cached by browser or proxy.",
                 dev_action="Set Cache-Control: no-store on all sensitive pages.")
        return r

    # Content type / MIME issues
    if any(k in title for k in ["content-type", "mime", "x-content-type", "sniffing"]):
        _cwe_apply(r, "missing_xcto")
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason="Content-Type or MIME sniffing issue. Defense-in-depth.",
                 dev_action="Set X-Content-Type-Options: nosniff on all responses.")
        return r

    # Referrer policy
    if "referrer" in title and ("policy" in title or "leak" in title or "missing" in title):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-200", cvss=3.1,
                 reason="Referrer-Policy header missing or weak. URLs with sensitive "
                        "parameters may leak to third-party sites via Referer header.",
                 dev_action="Set Referrer-Policy: strict-origin-when-cross-origin.")
        return r

    # Feature/Permissions policy
    if any(k in title for k in ["feature policy", "permissions policy", "feature-policy",
                                 "permissions-policy"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-16", cvss=3.1,
                 reason="Permissions-Policy header absent. Browser features (camera, mic, "
                        "geolocation) not explicitly restricted.",
                 dev_action="Set Permissions-Policy header to restrict unnecessary browser features.")
        return r

    # Generic "missing" or "absent" pattern (likely a header/config finding)
    if any(k in title for k in ["missing", "absent", "lack of", "no "]) and \
       not any(k in title for k in ["injection", "xss", "sqli", "rce", "ssrf"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-16", cvss=3.1,
                 reason="Missing security control or configuration. Classified as Low TP "
                        "(defense-in-depth hardening recommendation).",
                 dev_action="Implement the suggested security control.")
        return r

    # Sensitive data exposure (in headers, comments, source code)
    if any(k in title for k in ["sensitive data", "data exposure", "data leak",
                                 "credential", "api key", "secret", "token exposure",
                                 "source code", "comment", "html comment"]):
        has_real_data = any(kw in evidence for kw in [
            "password", "secret", "api_key", "apikey", "bearer", "private_key",
            "aws_access", "database", "connection_string",
        ])
        if has_real_data:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-200", cvss=5.3,
                     reason="Sensitive data (credentials, API keys, secrets) found in "
                            "response or source code.",
                     dev_action="Remove all secrets from client-side code. Use environment variables.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-200", cvss=3.7,
                 reason="Potential sensitive data exposure detected. No confirmed secrets in evidence.",
                 dev_action="Review and remove unnecessary information from responses.")
        return r

    # ==================================================================
    # LAYER 2: Confidence-based fallback for UNKNOWN finding types
    # ==================================================================

    if confidence >= 5:
        r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                 reason=f"High confidence ({confidence}/10) based on HTTP evidence. "
                        "Payload reflected or specific error content found in response.",
                 dev_action="Investigate and fix the underlying issue.")
        return r

    if confidence >= 3:
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason=f"Moderate confidence ({confidence}/10). Some evidence present "
                        "supporting the finding. Classified as Low TP.",
                 dev_action="Investigate. May warrant Burp Suite confirmation for upgrade.")
        return r

    if confidence >= 0:
        is_config_finding = any(k in title for k in [
            "header", "config", "setting", "policy", "cookie", "cache",
            "transport", "tls", "ssl", "certificate", "encryption",
            "hardening", "best practice", "recommendation",
        ])
        if is_config_finding:
            r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                     reason=f"Configuration/hardening finding (confidence {confidence}/10). "
                            "Classified as Low TP — defense-in-depth recommendation.",
                     dev_action="Apply the suggested hardening measure.")
            return r
        r.update(verdict="MANUAL_REVIEW", final_severity="TBD",
                 reason=f"Insufficient evidence to decide (confidence {confidence}/10). "
                        "No strong positive or negative signals. Requires manual verification "
                        "with Burp Suite or authenticated re-scan.",
                 dev_action="Manual review required. Re-test with authenticated session or Burp Suite.")
        return r

    if confidence >= -3:
        r.update(verdict="MANUAL_REVIEW", final_severity="TBD",
                 reason=f"Weak signals (confidence {confidence}/10). Negative signals slightly "
                        "outweigh positive but not enough to confidently dismiss. "
                        "Needs manual verification.",
                 dev_action="Manual review recommended. Likely noise but cannot confirm without re-test.")
        return r

    # Very low confidence — clearly FP
    r.update(verdict="FALSE_POSITIVE", final_severity="-",
             reason=f"Very low confidence ({confidence}/10). Strong negative signals: "
                    "all redirects, all 403/404, or zero evidence. Scanner noise.",
             dev_action="No action.")
    return r
