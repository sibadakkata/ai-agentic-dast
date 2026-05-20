"""Universal Triage Engine - works for ANY target (website, API, SPA).

Three-layer classification:
  Layer 1: Evidence-based auto-classification (deterministic rules)
  Layer 2: Confidence scoring from HTTP evidence patterns
  Layer 3: NEEDS_VERIFICATION for unknowns -> human queue

Exploitation tiers (post-classification):
  VALIDATED     = Proven exploitable (runtime confirmed, reflection in body, etc.)
  INFORMATIONAL = Detected/suspected but exploitation not proven

No target-specific logic. No LLM calls. No hardcoded URLs.
CVE data from NVD/OSV (via cve_lookup.py).
CWE mappings for generic weakness categories.
"""

import json
import math
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

def _coerce_cvss(s) -> float:
    """Coerce a CVSS value (str/int/float/None) to float. Returns 0.0 if invalid.

    Passive-recon findings store cvss as strings (e.g. "5.9"); triage callers
    may pass raw hints, so normalize defensively here.
    """
    if s is None or s == "":
        return 0.0
    if isinstance(s, (int, float)):
        return float(s)
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return 0.0

SEV_FROM_CVSS = lambda s: (
    lambda v: (
        "Critical" if v >= 9.0 else
        "High" if v >= 7.0 else
        "Medium" if v >= 4.0 else
        "Low" if v > 0 else "Info"
    )
)(_coerce_cvss(s))

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
    "auth_error_500":   {"cwe": "CWE-755", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"},
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
    "bola_confirmed":   {"cwe": "CWE-639", "cvss": 8.6, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "bfla_confirmed":   {"cwe": "CWE-285", "cvss": 8.1, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
    "deserialization":  {"cwe": "CWE-502", "cvss": 8.1, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "insecure_cookie":  {"cwe": "CWE-614", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "jwt_weakness":     {"cwe": "CWE-347", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "jwt_alg_none":     {"cwe": "CWE-347", "cvss": 9.1, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "cors_misconfiguration": {"cwe": "CWE-942", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "missing_cache_control": {"cwe": "CWE-525", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "external_form":    {"cwe": "CWE-200", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "api_version_downgrade": {"cwe": "CWE-693", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "race_condition":   {"cwe": "CWE-362", "cvss": 6.5, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"},
    "host_header_injection": {"cwe": "CWE-644", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "timing_enumeration": {"cwe": "CWE-203", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "bfla":             {"cwe": "CWE-285", "cvss": 7.5, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "token_leakage":    {"cwe": "CWE-532", "cvss": 6.5, "vec": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "csp_weakness":     {"cwe": "CWE-693", "cvss": 4.7, "vec": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"},
    "referrer_policy":  {"cwe": "CWE-200", "cvss": 3.1, "vec": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "permissions_policy": {"cwe": "CWE-16", "cvss": 2.1, "vec": "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "mixed_content":    {"cwe": "CWE-319", "cvss": 5.3, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "password_autocomplete": {"cwe": "CWE-522", "cvss": 2.1, "vec": "AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "sensitive_url_params": {"cwe": "CWE-598", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "https_redirect":   {"cwe": "CWE-319", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "hsts_preload":     {"cwe": "CWE-319", "cvss": 2.1, "vec": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "error_disclosure": {"cwe": "CWE-209", "cvss": 3.7, "vec": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "clickjacking":     {"cwe": "CWE-1021", "cvss": 4.3, "vec": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "file_upload":      {"cwe": "CWE-434", "cvss": 9.8, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "password_reset":   {"cwe": "CWE-640", "cvss": 6.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "session_fixation": {"cwe": "CWE-384", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "content_type_confusion": {"cwe": "CWE-436", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "method_override":  {"cwe": "CWE-650", "cvss": 6.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"},
    "attack_chain":     {"cwe": "CWE-20",  "cvss": 8.1, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    # LLM application security (OWASP Top 10 for LLM Applications 2025)
    "llm_prompt_injection":    {"cwe": "CWE-77",  "cvss": 8.1, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "llm_info_disclosure":     {"cwe": "CWE-200", "cvss": 7.5, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "llm_output_handling":     {"cwe": "CWE-79",  "cvss": 6.1, "vec": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "llm_excessive_agency":    {"cwe": "CWE-269", "cvss": 8.8, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "llm_prompt_leakage":      {"cwe": "CWE-200", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "llm_unbounded_consumption": {"cwe": "CWE-400", "cvss": 5.3, "vec": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
}


# ══════════════════════════════════════════════════════════════════════
# SECRET VALIDATION: entropy + framework constant detection
# ══════════════════════════════════════════════════════════════════════

FRAMEWORK_CONSTANTS = frozenset([
    "$$row_internal", "$$row_number", "$$row_id",
    "__react_devtools", "__react_fiber", "__react_internal",
    "__vue__", "__vue_app__", "__nuxt__",
    "ng-version", "ng-app", "ng-controller",
    "__next_data__", "__next_loaded_pages__",
    "__webpack_require__", "__webpack_modules__",
    "process.env.node_env", "process.env.public_url",
    "__sentry_dsn__", "__sentry_release__",
    "eclairng", "aura_token", "aura_context",
])

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely a real secret."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_fake_secret(value: str) -> bool:
    """Return True if value looks like a framework constant, not a real secret."""
    v_lower = value.lower().strip().strip("\"'`")
    if v_lower in FRAMEWORK_CONSTANTS:
        return True
    if any(v_lower.startswith(p) for p in ("$$", "__", "ng-", "react-")):
        if _shannon_entropy(v_lower) < 3.0:
            return True
    if len(v_lower) < 8 and _shannon_entropy(v_lower) < 3.5:
        return True
    readable_words = ["internal", "external", "default", "public", "private",
                      "master", "service", "config", "test", "demo", "example",
                      "placeholder", "changeme", "password", "secret", "token"]
    if any(w in v_lower for w in readable_words) and _shannon_entropy(v_lower) < 3.5:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════
# GARAK LLM — CWE + tier helpers
# ══════════════════════════════════════════════════════════════════════

_OWASP_CWE: dict[str, str] = {
    "LLM01": "CWE-74",   # Prompt Injection
    "LLM02": "CWE-200",  # Insecure Output Handling
    "LLM05": "CWE-807",  # Supply Chain
    "LLM06": "CWE-200",  # Sensitive Information Disclosure
    "LLM09": "CWE-693",  # Overreliance
}

_HIGH_IMPACT_PROBES = {
    "grandma.Slurs", "grandma.Substances", "grandma.Win10", "grandma.Win11",
    "dan.DanInTheWild", "lmrc.Profanity", "lmrc.SlurUsage", "lmrc.Sexualised",
    "lmrc.SexualContent", "lmrc.QuackMedicine", "lmrc.Bullying",
    "promptinject.HijackKillHumansMini", "promptinject.HijackHateHumansMini",
}


def _assign_exploitation_tier_garak(result, probe):
    """Assign exploitation tier for Garak findings.
    Garak probes that trigger a failure ARE the exploit — the model
    actually produced the harmful output."""
    if probe in _HIGH_IMPACT_PROBES:
        result["exploitation_tier"] = "validated"
    else:
        result["exploitation_tier"] = "validated"


# ══════════════════════════════════════════════════════════════════════
# EXPLOITATION TIER: classify proof level after triage verdict
# ══════════════════════════════════════════════════════════════════════

def _assign_exploitation_tier(result, finding):
    """Add exploitation_tier field: 'validated' or 'informational'.

    VALIDATED = exploitation proven (runtime confirmed, payload reflected,
                specific error content, timing differential confirmed)
    INFORMATIONAL = detected but not proven exploitable (pattern match,
                    config check, missing header, no active exploitation)
    """
    if result.get("verdict") in ("FALSE_POSITIVE", "NOT_A_FINDING"):
        result["exploitation_tier"] = "n/a"
        return

    tier = "informational"  # default

    reason = (result.get("reason") or "").lower()
    verification = (result.get("verification_method") or "").lower()

    if "[runtime verified]" in reason or "runtime_confirmed" in verification:
        tier = "validated"
    elif "reflected" in reason and "payload" in reason:
        tier = "validated"
    elif any(kw in reason for kw in ["confirmed", "proven", "demonstrated"]):
        if "deterministic" in verification or result.get("confidence", 0) >= 6:
            tier = "validated"
    elif result.get("verification_method") == "passive_deterministic":
        vuln_type = (finding.get("title") or "").lower()
        if any(k in vuln_type for k in ["subdomain takeover", "dangling", ".git/", ".env",
                                         "rce", "sqli", "command injection"]):
            tier = "validated"
    elif any(kw in reason for kw in ["sql error", "root:x:", "uid=", "gid=",
                                      "ami-id", "instance-id", "file:///",
                                      "xss confirmed"]):
        tier = "validated"

    result["exploitation_tier"] = tier


# ══════════════════════════════════════════════════════════════════════
# DEDUPLICATION: merge findings by (host + CWE + parameter)
# ══════════════════════════════════════════════════════════════════════

def deduplicate(findings):
    """Remove duplicate findings, keeping the highest-severity instance.

    Dedup key: (target_host, cwe, parameter). If no CWE, falls back to
    (target_host, title_normalized).
    """
    SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4,
                "Not Exploitable": 5, "TBD": 6}

    seen = {}
    for f in findings:
        url = f.get("url", "") or ""
        host = url.split("//")[-1].split("/")[0].split(":")[0].lower() if "//" in url else ""
        cwe = f.get("cwe", "") or ""
        param = (f.get("parameter", "") or "").lower().strip()
        title_norm = re.sub(r"[^a-z0-9]", "", (f.get("title", "") or "").lower())[:40]

        if cwe:
            key = (host, cwe, param)
        else:
            key = (host, title_norm, param)

        sev = f.get("final_severity", "Low")
        rank = SEV_RANK.get(sev, 4)

        if key not in seen or rank < SEV_RANK.get(seen[key].get("final_severity", "Low"), 4):
            seen[key] = f

    return list(seen.values())


def _passive_recon_action(title: str) -> str:
    """Remediation for passive recon findings."""
    t = title.lower()
    if "source map" in t:
        return "Remove source maps from production. Configure build tools to exclude .map files from deployment."
    if "dom sink" in t or "innerhtml" in t or "eval" in t or "trustashtml" in t:
        return "Audit the identified DOM sink for user-controlled input. Use safe alternatives (textContent, sanitize libraries)."
    if "hardcoded" in t and ("key" in t or "secret" in t or "password" in t or "token" in t):
        return "URGENT: Remove hardcoded secrets from client-side code. Rotate compromised credentials. Use server-side env vars."
    if "internal" in t and ("ip" in t or "url" in t or "localhost" in t):
        return "Remove internal URLs/IPs from client-side JavaScript before deployment."
    if "git" in t and ("expos" in t or "accessible" in t):
        return "CRITICAL: Block .git/ directory access immediately. Use web server rules (nginx: location ~ /\\.git { deny all; })."
    if ".env" in t or "environment file" in t:
        return "CRITICAL: Block .env file access. Move secrets to a vault. Rotate all exposed credentials."
    if "security header" in t or "missing" in t:
        return "Add recommended security headers to all responses."
    if "version disclosure" in t or "server version" in t:
        return "Remove version information from response headers (Server, X-Powered-By)."
    if "html comment" in t:
        return "Remove sensitive information from HTML comments before deployment."
    if "insecure cookie" in t or "cookie" in t and ("secure" in t or "httponly" in t or "samesite" in t):
        return "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all session cookies."
    if "jwt" in t and ("alg" in t or "weakness" in t or "none" in t):
        return "Use strong asymmetric algorithms (RS256/ES256) for JWT signing. Enforce exp, iss, aud, jti claims. Never allow alg=none."
    if "cors" in t:
        return "Configure CORS to allow only trusted origins. Never reflect arbitrary Origin. Avoid Access-Control-Allow-Origin: * with credentials."
    if "cache-control" in t or "cache" in t and "no-store" in t:
        return "Set Cache-Control: no-store on all authenticated pages to prevent caching of sensitive data."
    if "sri" in t or "subresource integrity" in t:
        return "Add integrity= attributes to all external script and stylesheet tags. Use SRI hash generation tools."
    if "form" in t and "external" in t:
        return "Verify external form targets are trusted. Avoid submitting sensitive data to third-party domains."
    if "api version" in t or "deprecated api" in t:
        return "Decommission deprecated API versions. Redirect old version requests to current version. Apply same security controls to all active versions."
    if "race condition" in t:
        return "Implement idempotency keys, database-level locking, or optimistic concurrency control on state-changing operations."
    if "host header" in t:
        return "Validate and whitelist the Host header server-side. Do not use Host header values to generate URLs, redirects, or links."
    if "timing" in t and "enum" in t:
        return "Normalize response times for authentication endpoints regardless of username validity. Use constant-time comparison for credentials."
    if "function-level" in t or "bfla" in t:
        return "Enforce role-based access control at the API/function level. Deny by default and explicitly grant access per role."
    if "token" in t and ("leak" in t or "log" in t or "telemetry" in t):
        return "Remove security tokens from telemetry/logging payloads. Redact sensitive values before logging. Review all POST bodies to logging endpoints."
    if "csp" in t and "weakness" in t:
        return "Tighten CSP policy: remove 'unsafe-inline' and 'unsafe-eval', use nonces or hashes instead. Add frame-ancestors, base-uri, form-action directives."
    if "referrer" in t and "policy" in t:
        return "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive pages). Prevents URL leakage to third parties."
    if "permissions" in t and "policy" in t:
        return "Add Permissions-Policy header to restrict unused browser features: camera=(), microphone=(), geolocation=(), payment=()."
    if "mixed content" in t:
        return "Load all resources over HTTPS. Update hardcoded http:// URLs to https:// or use protocol-relative URLs. Set CSP upgrade-insecure-requests."
    if "autocomplete" in t and "password" in t:
        return "Add autocomplete='off' or autocomplete='new-password' to password input fields to prevent browser credential caching."
    if "sensitive" in t and "url" in t and "param" in t:
        return "Never pass passwords, tokens, or PII in URL query strings. Use POST body or HTTP headers. Query strings are logged everywhere."
    if "https redirect" in t or ("http" in t and "redirect" in t and "https" in t):
        return "Configure HTTP to redirect to HTTPS with a 301 (permanent) redirect. Enable HSTS to prevent future HTTP access."
    if "hsts" in t and ("preload" in t or "incomplete" in t):
        return "Set HSTS with max-age=31536000, includeSubDomains. Submit to hstspreload.org for browser preload list inclusion."
    if "error page" in t and ("disclos" in t or "stack" in t or "information" in t):
        return "Configure custom error pages that do not reveal stack traces, internal paths, or framework details. Return generic error messages."
    if "clickjacking" in t or "frameable" in t:
        return "Set X-Frame-Options: DENY and CSP frame-ancestors 'self' to prevent the page from being embedded in iframes."
    if "file upload" in t or "unrestricted upload" in t:
        return "CRITICAL: Validate uploaded file types server-side using magic bytes (not just extension/Content-Type). Store uploads outside webroot. Disable execution in upload directories."
    if "password reset" in t:
        return "Use cryptographically random, single-use, time-limited reset tokens. Return identical responses for valid/invalid emails. Invalidate old tokens on new request."
    if "session fixation" in t or ("session" in t and "management" in t):
        return "Regenerate session ID after login and privilege changes. Set Secure, HttpOnly, SameSite flags. Implement session timeout and concurrent session limits."
    if "content" in t and "type" in t and "confusion" in t:
        return "Validate Content-Type header server-side and reject unexpected types. Use explicit JSON/XML parsers, not automatic content negotiation."
    if "method override" in t:
        return "Disable HTTP method override headers (X-HTTP-Method-Override, X-Method-Override). If needed, restrict to specific trusted endpoints only."
    if "attack chain" in t or "chain" in t and ("exploit" in t or "combin" in t):
        return "This is a multi-step attack chain combining multiple findings. Fix ALL individual vulnerabilities in the chain — patching any single link breaks the full chain."
    return "Review and remediate the identified issue."


def _cwe_apply(r, profile_key):
    p = CWE_PROFILES.get(profile_key, {})
    r["cwe"] = p.get("cwe", "")
    r["cvss"] = p.get("cvss", 0.0)
    r["cvss_vector"] = p.get("vec", "")


def _cwe_from_hint(r, finding):
    """Apply CWE/CVSS from a cwe_hint if available."""
    hint = finding.get("cwe_hint", "")
    if not hint:
        return
    r["cwe"] = hint
    for key, profile in CWE_PROFILES.items():
        if profile.get("cwe") == hint:
            r["cvss"] = profile.get("cvss", 0.0)
            r["cvss_vector"] = profile.get("vec", "")
            return
    r["cvss"] = r.get("cvss") or 5.0


def _adjust_cvss(r, finding, statuses, bodies, evidence, title):
    """Context-aware CVSS adjustment based on actual evidence.

    Adjusts the base CVSS score up or down based on what was actually observed,
    and builds a human-readable rationale explaining the score.
    """
    base = r.get("cvss", 0.0)
    if base == 0.0:
        r["cvss_rationale"] = "No CVSS assigned (informational or no CWE mapped)."
        return

    adjustments = []
    verdict = r.get("verdict", "")

    if verdict == "FALSE_POSITIVE":
        r["cvss"] = 0.0
        r["cvss_rationale"] = "CVSS set to 0.0 — finding is not exploitable (false positive)."
        return

    if verdict == "MANUAL_REVIEW":
        r["cvss_rationale"] = (
            f"Base CVSS {base:.1f} from {r.get('cwe', 'CWE profile')}. "
            "Score is preliminary — requires manual verification to confirm."
        )
        return

    # --- Context adjustments for TRUE_POSITIVE findings ---

    # 1. Runtime verified vs pattern-only
    rv_method = r.get("verification_method", "none")
    if rv_method != "none" and "RUNTIME" in (r.get("reason", "") or ""):
        adjustments.append("+0.0 Runtime verification confirmed exploitability")
    elif "pattern" in rv_method or rv_method == "none":
        if base >= 7.0:
            base -= 1.0
            adjustments.append("-1.0 Not runtime-verified (pattern match only, high-sev finding)")

    # 2. Data sensitivity signals in response
    pii_keywords = ["email", "password", "ssn", "credit card", "phone",
                     "address", "name", "account", "balance", "token"]
    has_pii = any(kw in b for b in bodies for kw in pii_keywords)
    if has_pii and base < 9.0:
        base += 0.5
        adjustments.append("+0.5 PII/sensitive data observed in response")

    # 3. All responses are error codes (attack partially blocked)
    if statuses and all(s >= 400 for s in statuses):
        if base >= 5.0:
            base -= 1.5
            adjustments.append(f"-1.5 All {len(statuses)} responses were errors ({list(set(statuses))})")

    # 4. Mixed success/error (partial exploitation)
    if statuses and any(s < 400 for s in statuses) and any(s >= 400 for s in statuses):
        adjustments.append("+0.0 Mixed responses — partial exploitation observed")

    # 5. Injection confirmed with data extraction
    data_extract_kw = ["table_name", "column_name", "union select",
                        "information_schema", "root:x:0", "uid="]
    if any(kw in evidence for kw in data_extract_kw):
        if base < 9.5:
            base += 0.5
            adjustments.append("+0.5 Data extraction or system info confirmed in response")

    # 6. XSS in JSON API vs HTML (JSON XSS much lower risk)
    if any(k in title for k in ["xss", "cross-site"]):
        json_response = any("application/json" in b for b in bodies)
        if json_response:
            base -= 2.0
            adjustments.append("-2.0 XSS in JSON response (not rendered as HTML by browser)")

    # 7. Config/header findings — already Low, no adjustment needed
    config_kw = ["header", "hsts", "csp", "cookie", "referrer", "permissions",
                 "x-frame", "x-content-type", "cache", "tls", "ssl"]
    if any(k in title for k in config_kw):
        adjustments.append("+0.0 Configuration/hardening finding (standard base score)")

    # 8. CORS with credentials vs without
    if "cors" in title:
        vd = finding.get("verification_details") or {}
        acao = str(vd.get("acao", "")) if isinstance(vd, dict) else ""
        acac = str(vd.get("acac", "")) if isinstance(vd, dict) else ""
        if acao == "*" and acac == "true":
            base = max(base, 6.5)
            adjustments.append(f"Set to {base:.1f} — CORS * with credentials is exploitable")
        elif acao == "*":
            adjustments.append("+0.0 CORS wildcard without credentials (lower risk)")

    # 9. Rate limit with actual account compromise evidence
    if "rate limit" in title or "brute force" in title:
        if any(kw in evidence for kw in ["success", "logged in", "welcome", "dashboard"]):
            base += 2.0
            adjustments.append("+2.0 Brute force succeeded — account access confirmed")

    # Clamp to valid range
    base = max(0.0, min(10.0, round(base, 1)))
    r["cvss"] = base

    # Build rationale
    cwe = r.get("cwe", "")
    original = r.get("cvss", base)
    parts = [f"Base: {CWE_PROFILES.get(cwe, {}).get('cvss', original):.1f} from {cwe or 'profile'}"]
    if adjustments:
        parts.extend(adjustments)
    parts.append(f"Final: {base:.1f} ({SEV_FROM_CVSS(base)})")
    r["cvss_rationale"] = " | ".join(parts)


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
    if any(k in t for k in ["jwt", "json web token", "bearer token", "token security"]):
        if "none_alg" in method:
            return "Critical"
        if "error_handling" in method:
            return "Medium"
        return "High"
    if any(k in t for k in ["sensitive data", "data exposure", "credential", "api key",
                             "secret", "data leak"]):
        return "Medium"
    if any(k in t for k in ["cors", "cross-origin resource"]):
        acao = details.get("acao", "")
        if acao == "*" and details.get("acac") == "true":
            return "High"
        return "Low"
    if any(k in t for k in ["information disclosure", "server version", "verbose error",
                             "stack trace", "debug", "x-powered-by"]):
        return "Low"
    if any(k in t for k in ["tls", "ssl", "transport security", "certificate", "https enforcement"]):
        return "Low"
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
    if "cors" in t:
        return "Configure CORS with specific allowed origins. Never use * with credentials."
    if any(k in t for k in ["information disclosure", "server version", "x-powered-by", "debug"]):
        return "Remove version headers. Disable debug mode in production. Return generic error pages."
    if any(k in t for k in ["tls", "ssl", "transport", "hsts", "certificate"]):
        return "Enforce TLS 1.2+. Add HSTS header. Disable weak ciphers."
    if any(k in t for k in ["sensitive data", "credential", "api key", "secret", "data leak"]):
        return "Remove secrets from client-side code. Use environment variables. Review response content."
    if any(k in t for k in ["jwt", "json web token", "bearer", "token security"]):
        return "Validate JWT signatures. Reject alg=none. Check token expiry. Return 401 not 500."
    return "Fix the confirmed vulnerability."


def _runtime_cwe(r: dict, title: str):
    """Apply CWE/CVSS for runtime-confirmed findings."""
    t = title.lower()
    mapping = {
        "sql": "sqli_confirmed", "xss": "xss_confirmed", "ssrf": "ssrf_confirmed",
        "xxe": "xxe_confirmed", "path traversal": "path_traversal_confirmed",
        "directory traversal": "path_traversal_confirmed",
        "command injection": "rce_confirmed", "remote code": "rce_confirmed",
        "idor": "idor_confirmed", "bola": "bola_confirmed", "bfla": "bfla_confirmed",
        "csrf": "csrf", "rate limit": "rate_limit",
        "brute force": "rate_limit", "hsts": "missing_hsts", "csp": "missing_csp",
        "cookie": "session_mgmt", "open redirect": "open_redirect",
        "cors": "cors",
        "information disclosure": "info_disclosure", "server version": "info_disclosure",
        "verbose error": "error_info", "stack trace": "error_info",
        "x-powered-by": "info_disclosure", "debug": "debug_staging",
        "tls": "missing_hsts", "ssl": "missing_hsts",
        "transport security": "missing_hsts", "certificate": "missing_hsts",
        "sensitive data": "info_disclosure", "credential": "info_disclosure",
        "api key": "info_disclosure", "data leak": "info_disclosure",
        "data exposure": "info_disclosure", "secret": "info_disclosure",
        "jwt": "auth_bypass", "json web token": "auth_bypass",
        "bearer token": "auth_bypass", "token security": "auth_bypass",
    }
    for keyword, profile in mapping.items():
        if keyword in t:
            _cwe_apply(r, profile)
            return


# ══════════════════════════════════════════════════════════════════════
# HELPER: extract evidence signals from finding + test logs
# ══════════════════════════════════════════════════════════════════════

def find_tests(finding, test_log, limit=5, _index=None):
    raw_url = finding.get("url", "") or ""
    if isinstance(raw_url, list):
        raw_url = raw_url[0] if raw_url else ""
    url = str(raw_url).split("?")[0]
    param = finding.get("parameter", "") or ""
    if isinstance(param, list):
        param = param[0] if param else ""
    if isinstance(param, dict):
        param = json.dumps(param, default=str)
    param = str(param).lower()

    if _index is not None:
        candidates = _index.get(url, []) if url else _index.get("__all__", [])
        if not candidates and url:
            candidates = _index.get("__all__", [])
        matched = []
        for t in candidates:
            req = t.get("request", {})
            if not isinstance(req, dict):
                continue
            t_url = req.get("url", "") or req.get("endpoint", "")
            score = 0
            if url and url in t_url:
                score += 3
            if param and param in t.get("_req_json_lower", ""):
                score += 2
            if score > 0:
                matched.append((score, t))
        matched.sort(key=lambda x: -x[0])
        return [m[1] for m in matched[:limit]]

    matched = []
    for t in test_log:
        req = t.get("request", {})
        if not isinstance(req, dict):
            continue
        t_url = req.get("url", "") or req.get("endpoint", "")
        score = 0
        if url and url in t_url:
            score += 3
        if param and param in json.dumps(req, default=str).lower():
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
            try:
                statuses.append(int(s))
            except (ValueError, TypeError):
                pass
        for r in resp.get("results", []):
            if isinstance(r, dict) and r.get("status"):
                try:
                    statuses.append(int(r["status"]))
                except (ValueError, TypeError):
                    pass
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
    headers = req.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
    for k, v in list(headers.items())[:8]:
        parts.append(f"  -H '{k}: {str(v)[:120]}'")
    body = req.get("body", "")
    if body:
        if isinstance(body, (dict, list)):
            try:
                b = json.dumps(body, indent=2, default=str)
            except (TypeError, ValueError):
                b = str(body)
        else:
            b = str(body)
        if "content-type" not in {k.lower() for k in headers}:
            parts.append("  -H 'Content-Type: application/json'")
        parts.append(f"  -d '{b[:600]}'")
    parts.append(f"  '{u[:300]}'")
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
    # BUT penalize if this looks like a SPA catch-all (HTML response for non-HTML URL)
    _spa_markers = ("<!doctype", "<html", "__react", "__vue__", "ng-version")
    if any(s == 200 for s in statuses) and not all_redirects:
        url_lower = str(finding.get("url", "")).lower()
        is_file_probe = any(ext in url_lower for ext in (
            ".git/", ".env", ".svn/", "wp-config", "web.config", ".bak",
        ))
        body_is_spa = any(any(m in b for m in _spa_markers) for b in bodies)
        if is_file_probe and body_is_spa:
            score -= 5  # SPA catch-all returning index.html for sensitive file path
        else:
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
# SMART INCONCLUSIVE RESOLVER
# Combines partial runtime signals with HTTP evidence to auto-decide
# instead of pushing to manual review
# ══════════════════════════════════════════════════════════════════════

_CONFIG_TITLES = frozenset([
    "header", "config", "setting", "policy", "cookie", "cache",
    "transport", "tls", "ssl", "certificate", "encryption",
    "hardening", "best practice", "recommendation", "cors",
    "referrer", "permissions", "feature", "hsts", "csp",
    "x-frame", "x-content-type", "sri", "subresource",
    "missing", "absent", "lack", "logging",
])

_INJECTION_TITLES = frozenset([
    "sql", "xss", "ssrf", "xxe", "injection", "traversal",
    "command", "deserialization", "rce", "idor",
])


def _resolve_inconclusive(finding, title, confidence, statuses, bodies,
                           evidence, rv_evidence, rv_details, rv_method):
    """Try to auto-resolve INCONCLUSIVE runtime results.

    Returns a dict to update the result if resolved, or None to fall through.
    """
    rv_ev_lower = (rv_evidence or "").lower()
    is_config = any(k in title for k in _CONFIG_TITLES)
    is_injection = any(k in title for k in _INJECTION_TITLES)

    # ── Rule 1: Config/header findings that were inconclusive are almost always
    #    real (the header IS missing or it ISN'T). Promote to Low TP.
    if is_config and not is_injection:
        return dict(
            verdict="TRUE_POSITIVE", final_severity="Low",
            reason=f"[AUTO-RESOLVED] Runtime inconclusive for configuration finding. "
                   f"Config/header findings are verifiable by inspection — {rv_evidence}. "
                   "Classified as Low TP (defense-in-depth).",
            dev_action="Apply the suggested hardening measure.",
        )

    # ── Rule 2: Injection + all responses were 4xx/5xx errors + no evidence
    #    of actual exploitation → safe to auto-FP
    if is_injection:
        all_error_or_denied = statuses and all(s >= 400 for s in statuses)
        no_positive_indicators = confidence <= 0
        if all_error_or_denied and no_positive_indicators:
            return dict(
                verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                reason=f"[AUTO-RESOLVED] Injection claim but all {len(statuses)} responses "
                       f"returned {list(set(statuses))} (errors/denied). Runtime verifier also "
                       f"inconclusive. No evidence of successful exploitation.",
                dev_action="No action — server rejected attack payloads.",
            )

    # ── Rule 3: Runtime verifier evidence contains strong negative signals
    negative_runtime_signals = [
        "rejected", "blocked", "denied", "not reflected", "sanitized",
        "not accepted", "not found", "404", "403", "filtered",
        "encoded", "escaped", "removed",
    ]
    neg_count = sum(1 for s in negative_runtime_signals if s in rv_ev_lower)
    if neg_count >= 2 and confidence <= 0:
        return dict(
            verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
            reason=f"[AUTO-RESOLVED] Runtime verifier shows strong rejection signals "
                   f"({neg_count} indicators: {rv_evidence[:120]}). Combined with low "
                   f"confidence ({confidence}/10) → auto-dismissed.",
            dev_action="No action — server defenses appear effective.",
        )

    # ── Rule 4: Runtime evidence has partial positive signals + moderate confidence
    positive_runtime_signals = [
        "accepted", "reflected", "200", "success", "executed",
        "returned data", "internal", "delayed",
    ]
    pos_count = sum(1 for s in positive_runtime_signals if s in rv_ev_lower)
    if pos_count >= 1 and confidence >= 1:
        return dict(
            verdict="TRUE_POSITIVE", final_severity="Low",
            reason=f"[AUTO-RESOLVED] Runtime verifier shows partial positive signals "
                   f"({pos_count} indicators) and moderate confidence ({confidence}/10). "
                   f"Verification detail: {rv_evidence[:150]}. Classified as Low TP.",
            dev_action="Investigate — some evidence supports this finding.",
        )

    # ── Rule 5: If confidence is clearly negative AND runtime didn't find anything
    if confidence <= -2 and pos_count == 0:
        return dict(
            verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
            reason=f"[AUTO-RESOLVED] Low confidence ({confidence}/10) plus inconclusive "
                   f"runtime verification with no positive indicators. {rv_evidence[:120]}",
            dev_action="No action — insufficient evidence.",
        )

    # ── Rule 6: If confidence is clearly positive, just classify as Low TP
    if confidence >= 1 and not is_injection:
        return dict(
            verdict="TRUE_POSITIVE", final_severity="Low",
            reason=f"[AUTO-RESOLVED] Positive confidence ({confidence}/10) with "
                   f"inconclusive runtime. Non-injection finding — classified as Low TP. "
                   f"{rv_evidence[:120]}",
            dev_action="Review recommended but likely a valid low-severity observation.",
        )

    return None


# ══════════════════════════════════════════════════════════════════════
# TRIAGE NARRATIVE: step-by-step breakdown for end users
# ══════════════════════════════════════════════════════════════════════

def _build_triage_narrative(finding, result, tests, statuses, bodies):
    """Build structured narrative separating AI scanner actions from triage validation.

    Returns dict with two sections:
      ai_tested  - what the AI agent did (payloads, requests, observations)
      triage_validated - how the triage engine independently verified the claim
    """
    title = _safe_str(finding.get("title", ""))
    url = _safe_str(finding.get("url", ""))
    payload = _safe_str(finding.get("payload", ""))
    ev_raw = finding.get("evidence", "") or ""
    evidence_str = str(ev_raw)[:300] if not isinstance(ev_raw, (dict, list)) else json.dumps(ev_raw, default=str)[:300]
    source = finding.get("source", "ai")
    verdict = result.get("verdict", "")
    tier = result.get("exploitation_tier", "informational")
    verification_method = result.get("verification_method", "none")

    # --- Section 1: What the AI Agent Tested ---
    ai_steps = []

    if finding.get("_finding_source") == "garak":
        probe = finding.get("_garak_probe", "unknown")
        detector = finding.get("_garak_detector", "unknown")
        chat_response = finding.get("response_snippet", "") or ""
        resp_info = finding.get("response_summary", {})
        if resp_info and isinstance(resp_info, dict):
            chat_response = chat_response or str(resp_info.get("body", ""))[:500]

        ai_steps.append(f"Garak LLM probe: {probe}")
        ai_steps.append(f"Detector: {detector}")
        ai_steps.append(f"Target: {url[:120]}")
        ai_steps.append(f"Payload sent: {payload[:300]}")
        ai_steps.append(f"Chatbot response: {chat_response[:500]}")
        ai_steps.append(f"Garak verdict: FAIL (guardrail bypass confirmed)")
        ai_steps.append(f"AI classified as: {_safe_str(finding.get('severity', 'Info'))}")

        triage_steps = [
            f"[GARAK VERIFIED] Probe {probe} triggered a failure via detector {detector}.",
            "Garak findings represent actual chatbot behavior — the model produced harmful output.",
            f"Mapped to: {result.get('cwe', '')}",
        ]
        if result.get("cvss") and result["cvss"] > 0:
            triage_steps.append(f"CVSS: {result['cvss']} ({result.get('cvss_vector', '')})")
        triage_steps.append(f"Final verdict: {verdict} | Tier: {tier}")

        return {
            "ai_tested": "\n".join(f"  - {s}" for s in ai_steps),
            "triage_validated": "\n".join(f"  - {s}" for s in triage_steps),
        }

    if source == "passive_recon" or finding.get("finding_type") == "passive_recon":
        ai_steps.append(f"Passively analyzed JavaScript/HTML at: {url[:120]}")
        if evidence_str:
            ai_steps.append(f"Detected pattern: {evidence_str[:150]}")
    else:
        if url:
            ai_steps.append(f"Targeted endpoint: {url[:120]}")
        if payload:
            ai_steps.append(f"Injected payload: {payload[:150]}")
        elif evidence_str:
            ai_steps.append(f"Observed: {evidence_str[:150]}")

        if finding.get("request_response"):
            rr = finding["request_response"]
            num_reqs = len(rr) if isinstance(rr, list) else 1
            ai_steps.append(f"Sent {num_reqs} HTTP request(s) and captured response(s)")

        rv_method = finding.get("verification_method", "")
        if rv_method and rv_method != "none":
            ai_steps.append(f"Runtime verification attempted: {rv_method}")

        rv_evidence = finding.get("verification_evidence", "")
        if rv_evidence:
            ai_steps.append(f"AI verification result: {str(rv_evidence)[:120]}")

    ai_severity = _safe_str(finding.get("severity", "Info"))
    ai_steps.append(f"AI classified as: {ai_severity}")

    # --- Section 2: How Triage Engine Validated ---
    triage_steps = []

    if statuses:
        status_summary = ", ".join(str(s) for s in sorted(set(statuses))[:5])
        triage_steps.append(f"Checked HTTP response codes: [{status_summary}]")

    if bodies:
        body_lengths = [len(b) for b in bodies[:5]]
        triage_steps.append(f"Analyzed {len(bodies)} response body/bodies ({min(body_lengths)}-{max(body_lengths)} bytes)")

    reason = result.get("reason", "")
    if "[RUNTIME VERIFIED]" in reason:
        triage_steps.append("Runtime replay confirmed exploitation")
    elif "[RUNTIME DISPROVED]" in reason:
        triage_steps.append("Runtime replay failed to reproduce the issue")
    elif "[PASSIVE RECON]" in reason:
        triage_steps.append("Deterministic pattern match (no network replay needed)")
    elif "SPA catch-all" in reason:
        triage_steps.append("Detected SPA catch-all: response is HTML app shell, not actual file content")
    elif "fake secret" in reason.lower() or "framework constant" in reason.lower():
        triage_steps.append("Entropy analysis: value is a framework constant, not a real secret")
    elif "reflected" in reason.lower() and "payload" in reason.lower():
        triage_steps.append("Confirmed: injected payload reflected in response body")
    elif "sql error" in reason.lower():
        triage_steps.append("Confirmed: SQL error strings found in response body")
    elif "no sql" in reason.lower() or "no internal" in reason.lower() or "not reflected" in reason.lower():
        triage_steps.append("Searched response body for exploitation evidence - none found")

    if result.get("cwe"):
        triage_steps.append(f"Mapped to: {result['cwe']}")
    if result.get("cvss") and result["cvss"] > 0:
        triage_steps.append(f"CVSS scored: {result['cvss']:.1f}")

    final_sev = result.get("final_severity", "Info")
    if final_sev != ai_severity:
        triage_steps.append(f"Severity adjusted: {ai_severity} -> {final_sev}")
    else:
        triage_steps.append(f"Severity confirmed: {final_sev}")

    triage_steps.append(f"Verdict: {verdict.replace('_', ' ')}")
    if tier and tier != "n/a":
        triage_steps.append(f"Exploitation tier: {tier}")

    if reason:
        triage_steps.append(f"Reasoning: {reason[:200]}")

    return {
        "ai_tested": ai_steps,
        "triage_validated": triage_steps,
    }


# ══════════════════════════════════════════════════════════════════════
# LAYER 1 + 2 + 3: Main classify function
# ══════════════════════════════════════════════════════════════════════

def classify(finding, test_log, _index=None):
    """Universal triage: classify any scanner finding from any target.
    Returns dict with verdict, severity, CVE/CWE, evidence, steps, cvss_rationale, etc."""
    r = _classify_inner(finding, test_log, _index=_index)
    title = _safe_str(finding.get("title", "")).lower()
    ev_raw = finding.get("evidence", "") or ""
    evidence = str(ev_raw).lower() if not isinstance(ev_raw, (dict, list)) else json.dumps(ev_raw).lower()
    tests = find_tests(finding, test_log, _index=_index)
    statuses = get_statuses(tests)
    bodies = get_response_bodies(tests)
    _adjust_cvss(r, finding, statuses, bodies, evidence, title)

    source = finding.get("source", "ai")
    r["source"] = source
    if source == "both":
        conf = r.get("confidence_score") or r.get("confidence", 0)
        if isinstance(conf, (int, float)):
            r["confidence_score"] = min(conf + 2, 10)
        r.setdefault("corroborated", True)

    _assign_exploitation_tier(r, finding)
    r["triage_narrative"] = _build_triage_narrative(finding, r, tests, statuses, bodies)

    # Propagate detection labels for report clarity
    if finding.get("detection_label"):
        r["detection_label"] = finding["detection_label"]
        r["detection_method"] = finding.get("detection_method", "")

    return r


def _safe_str(val, default=""):
    """Coerce value to string, picking first element if it's a list."""
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val) if val else default


def _classify_inner(finding, test_log, _index=None):
    """Core classification logic."""
    title = _safe_str(finding.get("title", "")).lower()
    ev_raw = finding.get("evidence", "") or ""
    evidence = str(ev_raw).lower() if not isinstance(ev_raw, (dict, list)) else json.dumps(ev_raw).lower()
    severity = _safe_str(finding.get("severity", "Info"))
    url = _safe_str(finding.get("url", ""))
    payload = _safe_str(finding.get("payload", ""))

    tests = find_tests(finding, test_log, _index=_index)
    statuses = get_statuses(tests)
    bodies = get_response_bodies(tests)
    all_redirects = all(s in (301, 302, 303, 307, 308) for s in statuses) if statuses else False
    confidence = _compute_confidence(finding, tests, statuses, bodies, evidence)

    source = finding.get("source", "ai")

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
        "cvss_rationale": "",
        "exploit_evidence": "",
        "steps": "",
        "dev_action": "",
        "reason": "",
        "confidence": confidence,
        "curl": _build_curl(tests[0]) if tests else "",
        "response_status": list(set(statuses))[:6],
        "verification_method": finding.get("verification_method", "none"),
        "verification_evidence": finding.get("verification_evidence", ""),
        "source": source,
    }

    _cwe_from_hint(r, finding)

    # ==================================================================
    # LAYER 0: GARAK LLM PROBES — trust Garak's own verdict
    # Garak findings are chatbot behavior tests, not web injection tests.
    # The evidence is the chatbot's actual response to a toxic/jailbreak prompt.
    # ==================================================================

    if finding.get("_finding_source") == "garak":
        probe = finding.get("_garak_probe", "unknown")
        detector = finding.get("_garak_detector", "unknown")
        garak_payload = finding.get("payload", "")
        chat_response = finding.get("response_snippet", "") or ""
        owasp_llm = finding.get("owasp_llm", "LLM01")
        req_info = finding.get("request", {})
        resp_info = finding.get("response_summary", {})

        r.update(
            verdict="TRUE_POSITIVE",
            final_severity=severity,
            cwe=finding.get("cwe", "") or _OWASP_CWE.get(owasp_llm, "CWE-77"),
            owasp=f"OWASP LLM {owasp_llm}",
            confidence=8,
            confidence_score=8,
            verification_method="garak_probe",
            reason=(
                f"[GARAK VERIFIED] Probe {probe} (detector: {detector}) confirmed "
                f"the chatbot responded to a harmful prompt without adequate guardrails."
            ),
            exploit_evidence=(
                f"Payload sent: {garak_payload[:300]}\n\n"
                f"Chatbot response: {chat_response[:500]}"
            ),
            dev_action=(
                f"Review {owasp_llm} controls. The chatbot should refuse or "
                f"deflect this type of request. See OWASP Top 10 for LLM Applications."
            ),
            steps=(
                f"1. Garak sent probe '{probe}' to {finding.get('url', 'chatbot endpoint')}\n"
                f"2. Payload: {garak_payload[:200]}\n"
                f"3. Chatbot responded (200 OK)\n"
                f"4. Detector '{detector}' flagged the response as a failure\n"
                f"5. Response: {chat_response[:300]}"
            ),
        )
        if req_info:
            r["curl"] = (
                f"curl -X {req_info.get('method', 'POST')} '{req_info.get('url', '')}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{req_info.get('body', '')}'"
            )
        _assign_exploitation_tier_garak(r, probe)
        return r

    # ==================================================================
    # LAYER 0A: PASSIVE RECON — deterministic checks, high confidence
    # These are verified facts (file exists, header missing, pattern found).
    # ==================================================================

    if finding.get("finding_type") == "passive_recon":
        cvss_h = finding.get("cvss_hint", 0)
        sev = SEV_FROM_CVSS(cvss_h) if cvss_h else severity
        r.update(
            verdict="TRUE_POSITIVE",
            final_severity=sev,
            reason=f"[PASSIVE RECON] Deterministic check — {str(ev_raw)[:250]}",
            dev_action=_passive_recon_action(title),
            confidence=8,
            verification_method="passive_deterministic",
        )
        if finding.get("cwe_hint"):
            r["cwe"] = finding["cwe_hint"]
        if cvss_h:
            r["cvss"] = _coerce_cvss(cvss_h)
        return r

    # ==================================================================
    # LAYER 0: RUNTIME VERIFICATION — real payload replay results
    # If the runtime verifier already tested this finding, use its verdict.
    # This takes priority over all pattern matching below.
    # ==================================================================

    rv_verdict = finding.get("verdict")
    rv_verified = finding.get("verified", False)

    if rv_verified and rv_verdict in ("CONFIRMED", "DISPROVED", "INCONCLUSIVE"):
        rv_method = finding.get("verification_method", "") or ""
        rv_evidence = finding.get("verification_evidence", "") or ""
        rv_details = finding.get("verification_details") or {}

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
                final_severity="Not Exploitable",
                reason=f"[RUNTIME DISPROVED] {rv_evidence}",
                dev_action="No action — runtime verification confirmed this is not exploitable.",
            )
            return r

        # INCONCLUSIVE — smart auto-resolve before falling through
        # Combine runtime partial signals with HTTP evidence to decide
        if rv_verdict == "INCONCLUSIVE":
            inc_decision = _resolve_inconclusive(
                finding, title, confidence, statuses, bodies, evidence,
                rv_evidence, rv_details, rv_method
            )
            if inc_decision:
                r.update(**inc_decision)
                return r
            r["reason"] = f"[RUNTIME INCONCLUSIVE] {rv_evidence} — using pattern analysis as fallback."

    # ==================================================================
    # LAYER 0B: SPA CATCH-ALL DETECTOR
    # SPAs (React, Angular, Vue) return index.html with 200 for ANY path.
    # The AI sees "200 OK" for /.git/HEAD and claims the file is exposed,
    # but the response is just the SPA shell. Detect and downgrade these.
    # ==================================================================

    _SENSITIVE_FILE_EXTENSIONS = (
        ".git/", ".env", ".svn/", ".htaccess", ".htpasswd",
        "wp-config", "web.config", "config.php", ".DS_Store",
        ".bak", ".old", ".swp", ".sql", ".dump",
    )
    _SPA_MARKERS = (
        "<!doctype", "<html", "<!DOCTYPE",
        "__react", "__vue__", "ng-version", "ng-app",
        "<div id=\"root\"", "<div id=\"app\"",
        "<noscript>", "manifest.json",
    )
    is_sensitive_file_claim = (
        any(ext in url for ext in _SENSITIVE_FILE_EXTENSIONS) or
        ("sensitive file" in title and "accessible" in title)
    )
    if is_sensitive_file_claim and statuses:
        has_200 = any(s == 200 for s in statuses)
        body_is_html = any(
            any(marker in b for marker in _SPA_MARKERS)
            for b in bodies
        )
        # Real .git/HEAD contains "ref: refs/heads/" — never HTML
        # Real .env contains KEY=VALUE lines — never HTML
        body_has_real_content = any(
            any(sig in b for sig in [
                "ref: refs/heads/", "[core]", "[remote",  # .git
                "db_password", "api_key=", "secret_key=", # .env
                "<?php", "define(", "getenv(",            # wp-config
                "<configuration>", "<appSettings>",       # web.config
            ])
            for b in bodies
        )
        all_404_or_403 = all(s in (404, 403, 410) for s in statuses) if statuses else False
        if all_404_or_403:
            r.update(
                verdict="FALSE_POSITIVE",
                final_severity="Not Exploitable",
                cwe="",
                reason=f"Sensitive file path returned HTTP {statuses[0]} — "
                       "file is not accessible. The AI reported it based on "
                       "the probe attempt, not actual file content.",
                dev_action="No action required — the file is not exposed.",
            )
            return r
        if has_200 and body_is_html and not body_has_real_content:
            r.update(
                verdict="FALSE_POSITIVE",
                final_severity="Not Exploitable",
                cwe="",
                reason="SPA catch-all: server returns the app shell (index.html) "
                       "for any URL path including sensitive file paths. "
                       "HTTP 200 does not mean the file is accessible — "
                       "the response body is HTML, not file content.",
                dev_action="No action required — the file is not actually exposed.",
            )
            return r

    # ==================================================================
    # LAYER 0C: HARDCODED SECRET VALIDATION
    # Filter out framework constants and low-entropy values the AI
    # incorrectly flagged as hardcoded secrets/API keys.
    # ==================================================================
    is_secret_claim = any(k in title for k in [
        "hardcoded", "api key", "secret in", "password in javascript",
        "master secret", "service secret", "embedded credential",
    ])
    if is_secret_claim:
        ev_str = str(ev_raw)
        secret_patterns = re.findall(
            r'["\']([^"\']{3,80})["\']', ev_str
        )
        evidence_value = ""
        for pat in secret_patterns:
            if any(k in pat.lower() for k in ["key", "secret", "token", "password", "api"]):
                continue
            if len(pat) >= 3:
                evidence_value = pat
                break
        if not evidence_value and secret_patterns:
            evidence_value = secret_patterns[0]

        if evidence_value and _is_fake_secret(evidence_value):
            r.update(
                verdict="FALSE_POSITIVE",
                final_severity="Not Exploitable",
                cwe="",
                reason=f"Flagged value '{evidence_value[:40]}' is a framework constant "
                       f"or low-entropy string (Shannon entropy: "
                       f"{_shannon_entropy(evidence_value):.1f}), not a real secret. "
                       "Real API keys have high entropy (>4.0) and are 20+ random chars.",
                dev_action="No action — this is not a credential.",
            )
            return r

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
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     reason=f"All {len(statuses)} responses were {list(set(statuses))} redirects. "
                            "Scanner was not authenticated. Injection findings require "
                            "authenticated access to the actual endpoint to be valid.",
                     dev_action="No action. Re-test with authenticated session if concerned.")
            return r

    # HPKP (deprecated by all browsers in 2018)
    if "hpkp" in title or "public key pin" in title:
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                 reason="HTTP Public Key Pinning (HPKP) was deprecated by Chrome in 2018 "
                        "and removed from all browsers. Not a valid finding.",
                 dev_action="No action. HPKP is deprecated.")
        return r

    # SameSite=Lax flagged as weak (it's the OWASP recommendation)
    if "samesite" in title and "lax" in title:
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                 reason="SameSite=Lax is the browser DEFAULT and OWASP-recommended setting. "
                        "Strict breaks legitimate cross-site navigation.",
                 dev_action="No action. SameSite=Lax is correct.")
        return r

    # performance.timing API flagged (standard browser API, not a vuln)
    if "performance" in title and ("timing" in title or "api" in title):
        if "navigation" in title or "resource" in title or "performance.timing" in evidence:
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     reason="performance.timing is a standard browser API on every website. "
                            "Not a vulnerability.",
                     dev_action="No action.")
            return r

    # Dynamic script creation (standard JS, not a vuln without XSS)
    if "dynamic script" in title and ("creation" in title or "source" in title):
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     cwe="CWE-502",
                     reason="Deserialization payload sent but zero execution markers "
                            "(no Java stack traces, no pickle errors, no class loading). "
                            "Server did not process the payload.",
                     dev_action="No action - server rejects serialized input.")
            return r

    # BOLA — confirmed two-user authorization bypass
    is_bola = "bola" in title or ("broken object" in title and "authorization" in title)
    is_bfla = "bfla" in title or ("broken function" in title and "authorization" in title)
    two_user_evidence = any(kw in evidence for kw in ["user b", "user_b", "second user", "cross-user", "two-user"])
    if is_bola or (is_bfla and two_user_evidence):
        cwe_key = "bfla_confirmed" if is_bfla else "bola_confirmed"
        _cwe_apply(r, cwe_key)
        # Merge statuses from test_log AND request_response_pairs in the finding
        all_statuses = list(statuses)
        for pair in finding.get("request_response_pairs", []):
            resp_text = pair.get("response", "") if isinstance(pair, dict) else ""
            if isinstance(resp_text, str):
                for tok in resp_text.split():
                    try:
                        code = int(tok)
                        if 100 <= code <= 599:
                            all_statuses.append(code)
                            break
                    except ValueError:
                        continue
        all_denied = all(s in (401, 403) for s in all_statuses) if all_statuses else False
        if all_denied:
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     reason=f"All {len(all_statuses)} cross-user requests returned 401/403. "
                            "Server enforces object-level authorization correctly.",
                     dev_action="No action - authorization checks are effective.")
            return r
        has_cross_access = (any(s == 200 for s in all_statuses) or "200" in evidence) and two_user_evidence
        if has_cross_access:
            sev = "Critical" if is_bola else "High"
            r.update(verdict="TRUE_POSITIVE", final_severity=sev,
                     reason=f"CONFIRMED {'BOLA' if is_bola else 'BFLA'}: User B successfully accessed "
                            f"User A's resources. Two-user test proves authorization bypass.",
                     steps=f"1. Authenticated as User A, collected resource IDs\n"
                           f"2. Authenticated as User B, replayed requests to User A's resources\n"
                           f"3. User B received 200 with User A's data — authorization bypass confirmed",
                     dev_action="Implement object-level authorization checks on every data access. "
                                "Verify the authenticated user owns the requested resource.")
            return r
        if two_user_evidence:
            r.update(verdict="TRUE_POSITIVE", final_severity="High",
                     reason=f"{'BOLA' if is_bola else 'BFLA'} pattern detected in two-user test. "
                            "Some requests succeeded — review evidence for confirmation.",
                     dev_action="Implement object-level authorization checks on every data access.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                 reason=f"{'BOLA' if is_bola else 'BFLA'} title detected but no two-user evidence found. "
                        "Manual confirmation recommended.",
                 dev_action="Implement object-level authorization checks on every data access.")
        return r

    # IDOR (Insecure Direct Object Reference) — single-user mode
    if "idor" in title or "insecure direct object" in title or "broken object" in title:
        _cwe_apply(r, "idor_confirmed")
        all_denied = all(s in (401, 403) for s in statuses) if statuses else False
        has_data_leak = any(s == 200 for s in statuses) and any(
            kw in b for b in bodies for kw in ["email", "name", "address", "phone", "ssn", "account"]
        )
        if all_denied:
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
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
    # LAYER 1F: BROAD CATCH-ALL for remaining known categories
    # ==================================================================

    # Authentication/session weakness (generic)
    if any(k in title for k in ["authentication", "auth bypass", "broken auth",
                                 "weak password", "password policy", "account lockout",
                                 "multi-factor", "mfa", "2fa", "token", "bearer"]):
        has_bypass = any(kw in evidence for kw in ["bypass", "accepted", "200", "success", "no auth"])
        if has_bypass:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-287", cvss=5.3,
                     reason="Authentication weakness with evidence of bypass or weak enforcement.",
                     dev_action="Enforce strong authentication. Implement MFA where appropriate.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-287", cvss=3.7,
                 reason="Authentication hardening recommendation. No active bypass demonstrated.",
                 dev_action="Review authentication controls. Apply defense-in-depth measures.")
        return r

    # HTTP method / verb tampering
    if any(k in title for k in ["http method", "verb tampering", "options method",
                                 "trace method", "put method", "delete method",
                                 "method not allowed", "dangerous method"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-749", cvss=3.7,
                 reason="Unnecessary HTTP methods enabled. Low risk without specific exploit path.",
                 dev_action="Disable unnecessary HTTP methods (TRACE, PUT, DELETE) on the web server.")
        return r

    # Content injection / header injection (non-XSS)
    if any(k in title for k in ["header injection", "response splitting",
                                 "crlf injection", "host header"]):
        has_injection = any(kw in evidence for kw in ["\\r\\n", "crlf", "injected", "reflected"])
        if has_injection:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-113", cvss=5.3,
                     reason="HTTP header injection/CRLF confirmed in response.",
                     dev_action="Sanitize all user input used in HTTP headers.")
            return r
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                 cwe="CWE-113", cvss=0.0,
                 reason="Header injection payload not reflected in response headers.",
                 dev_action="No action — input appears to be sanitized.")
        return r

    # File upload issues
    if any(k in title for k in ["file upload", "upload", "unrestricted file",
                                 "malicious file"]):
        upload_accepted = any(s == 200 for s in statuses)
        if upload_accepted:
            r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                     cwe="CWE-434", cvss=5.3,
                     reason="File upload accepted without apparent restriction.",
                     dev_action="Validate file type, size, and content. Store outside web root.")
            return r
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-434", cvss=3.7,
                 reason="File upload weakness reported but upload was rejected or blocked.",
                 dev_action="Ensure file type validation is comprehensive.")
        return r

    # Directory listing / path disclosure
    if any(k in title for k in ["directory listing", "directory browsing",
                                 "path disclosure", "full path", "internal path"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-548", cvss=3.7,
                 reason="Directory listing or path disclosure. Aids reconnaissance only.",
                 dev_action="Disable directory listing. Remove path info from error pages.")
        return r

    # Insecure communication / mixed content
    if any(k in title for k in ["mixed content", "insecure resource", "http resource",
                                 "insecure form", "cleartext"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-319", cvss=3.7,
                 reason="Insecure content loaded over HTTP on HTTPS page.",
                 dev_action="Load all resources over HTTPS. Fix mixed content references.")
        return r

    # Server-side includes / template issues (non-injection)
    if any(k in title for k in ["server-side include", "ssi", "source map",
                                 "backup file", ".bak", ".old", ".swp"]):
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 cwe="CWE-538", cvss=3.7,
                 reason="Potentially sensitive files or includes accessible. Information exposure.",
                 dev_action="Remove backup files and source maps from production servers.")
        return r

    # Generic "vulnerability" or "weakness" or "issue" (catch-all for remaining)
    if any(k in title for k in ["vulnerability", "weakness", "issue", "risk",
                                 "exposure", "flaw"]):
        if confidence >= 1:
            r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                     reason=f"Generic finding with positive confidence ({confidence}/10). "
                            "Classified as Low TP for review.",
                     dev_action="Review and apply recommended fix.")
            return r
        if confidence <= -2:
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     reason=f"Generic finding with negative confidence ({confidence}/10). "
                            "No evidence supports this claim.",
                     dev_action="No action — insufficient evidence.")
            return r

    # ==================================================================
    # LAYER 2: Confidence-based fallback for truly UNKNOWN finding types
    # Now with narrower bands — fewer go to manual review
    # ==================================================================

    if confidence >= 5:
        r.update(verdict="TRUE_POSITIVE", final_severity="Medium",
                 reason=f"High confidence ({confidence}/10) based on HTTP evidence. "
                        "Payload reflected or specific error content found in response.",
                 dev_action="Investigate and fix the underlying issue.")
        return r

    if confidence >= 2:
        r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                 reason=f"Moderate confidence ({confidence}/10). Some evidence present "
                        "supporting the finding. Classified as Low TP.",
                 dev_action="Investigate. May warrant manual confirmation for upgrade.")
        return r

    is_config_finding = any(k in title for k in [
        "header", "config", "setting", "policy", "cookie", "cache",
        "transport", "tls", "ssl", "certificate", "encryption",
        "hardening", "best practice", "recommendation",
    ])

    if confidence >= 0:
        if is_config_finding:
            r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                     reason=f"Configuration/hardening finding (confidence {confidence}/10). "
                            "Classified as Low TP — defense-in-depth recommendation.",
                     dev_action="Apply the suggested hardening measure.")
            return r

        all_failed = statuses and all(s >= 400 for s in statuses)
        if all_failed:
            r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                     reason=f"Ambiguous confidence ({confidence}/10) but ALL {len(statuses)} "
                            f"responses returned error/denied ({list(set(statuses))}). "
                            "Auto-dismissed — no successful exploitation observed.",
                     dev_action="No action — server rejected all test payloads.")
            return r

        r.update(verdict="MANUAL_REVIEW", final_severity="TBD",
                 reason=f"Insufficient evidence to decide (confidence {confidence}/10). "
                        "No strong positive or negative signals. Requires manual verification "
                        "or authenticated re-scan.",
                 dev_action="Manual review required. Re-test with authenticated session.")
        return r

    if confidence >= -2:
        if is_config_finding:
            r.update(verdict="TRUE_POSITIVE", final_severity="Low",
                     reason=f"Configuration finding (confidence {confidence}/10). "
                            "Config findings are valid even with weak signals.",
                     dev_action="Apply the suggested hardening measure.")
            return r
        r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
                 reason=f"Weak signals (confidence {confidence}/10). Negative signals outweigh "
                        "positive. Auto-dismissed — likely scanner noise.",
                 dev_action="No action. Re-test if concerned.")
        return r

    # Very low confidence — clearly FP
    r.update(verdict="FALSE_POSITIVE", final_severity="Not Exploitable",
             reason=f"Very low confidence ({confidence}/10). Strong negative signals: "
                    "all redirects, all 403/404, or zero evidence. Scanner noise.",
             dev_action="No action.")
    return r
