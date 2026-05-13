"""Deterministic severity classification for AI Raw findings.

The LLM emits raw findings (title, payload, evidence, ...) but its
self-assigned severity drifts run-to-run and model-to-model. This module
replaces the LLM severity with a deterministic CVSS-driven severity so
two scans of the same target always land at the same severity bucket.

Pipeline per finding (XBOW-style):
  1. Match the title against an OWASP/CWE keyword map -> profile_key.
  2. Look up the base CVSS + vector + CWE in ``CWE_PROFILES``.
  3. Apply evidence-based adjustments (verification, body keywords,
     content-type sanity, etc.).
  4. Bucket the final score: Critical >= 9.0, High >= 7.0, Medium >= 4.0,
     Low > 0, Info == 0.

Constraints:
  - Unverified findings (no runtime replay) are capped at 7.5 unless they
    are deterministic configuration issues (headers, cookies, TLS).
  - Findings with verdict ``DISPROVED`` collapse to 0 / Info.
  - Confirmed RCE / command injection floors at 9.0.

The LLM's original severity is preserved as ``llm_severity`` so reviewers
can still see model judgment without it driving reports.

This module does NOT replace the triage engine. The triage engine still
runs over the persisted findings and produces a ``final_severity`` that
factors in the live test log.  This module only normalises the AI Raw
layer.
"""
from __future__ import annotations

import json
from typing import Any

from scripts.triage_engine import (
    COMMAND_INJECTION_KEYWORDS,
    CWE_PROFILES,
    PATH_TRAVERSAL_KEYWORDS,
    SQL_ERROR_KEYWORDS,
    SSRF_SUCCESS_KEYWORDS,
    XSS_REFLECTION_KEYWORDS,
    XXE_SUCCESS_KEYWORDS,
)

__all__ = ["classify_severity", "bucket_from_cvss"]

# ── Title keyword → CWE_PROFILES key ─────────────────────────────────────
# Order matters: the first matching tuple wins, so list specific titles
# before generic fall-throughs (e.g. ``jwt alg none`` before plain ``jwt``).
_TITLE_TO_PROFILE: list[tuple[tuple[str, ...], str]] = [
    # Critical injection / RCE
    (("rce", "remote code execution", "command injection", "command exec",
      "os command", "shell injection"), "rce_confirmed"),
    (("sql injection", "sqli", "blind sql", "union-based sql",
      "time-based sql", "boolean-based sql"), "sqli_confirmed"),
    (("xxe", "xml external entity"), "xxe_confirmed"),
    (("path traversal", "directory traversal", "lfi",
      "local file inclusion"), "path_traversal_confirmed"),
    (("ssrf", "server-side request forgery",
      "server side request forgery"), "ssrf_confirmed"),
    (("insecure deserialization", "deserialization", "unsafe deserial",
      "object injection"), "deserialization"),

    # Authentication / authorisation
    (("default credentials", "credential stuffing successful",
      "brute force successful", "authentication bypass",
      "auth bypass", "login bypass"), "auth_bypass"),
    (("bola", "broken object level authorization"), "bola_confirmed"),
    (("bfla", "broken function level authorization",
      "broken function-level"), "bfla_confirmed"),
    (("idor", "insecure direct object reference"), "idor_confirmed"),

    # JWT
    (("jwt alg none", "jwt none algorithm", "jwt none alg",
      "jwt accepts none", "alg=none"), "jwt_alg_none"),
    (("jwt", "json web token"), "jwt_weakness"),

    # XSS
    (("xss", "cross-site scripting", "cross site scripting",
      "stored xss", "reflected xss", "dom xss", "dom-based xss"),
     "xss_confirmed"),

    # File upload
    (("file upload", "unrestricted upload", "arbitrary file upload"),
     "file_upload"),

    # Open redirect
    (("open redirect", "unvalidated redirect"), "open_redirect"),

    # CSRF
    (("csrf", "cross-site request forgery"), "csrf"),

    # Race conditions
    (("race condition", "toctou"), "race_condition"),

    # Host header
    (("host header injection", "host header poisoning",
      "host header attack"), "host_header_injection"),

    # CORS
    (("cors misconfiguration", "cors misconfig",
      "permissive cors", "cors wildcard"), "cors_misconfiguration"),
    (("cors",), "cors"),

    # Session
    (("session fixation",), "session_fixation"),
    (("session management", "session expiry", "session timeout"),
     "session_mgmt"),

    # Password reset / account flows
    (("password reset", "forgot password"), "password_reset"),

    # Rate limiting / brute force
    (("rate limit", "rate-limit", "no rate limiting",
      "missing rate limit", "brute force"), "rate_limit"),

    # Method override / verb tampering
    (("method override", "x-http-method-override",
      "verb tampering"), "method_override"),

    # Content type confusion
    (("content type confusion", "content-type confusion",
      "mime confusion"), "content_type_confusion"),

    # Token leakage / sensitive logging
    (("token leak", "token in telemetry", "token in logging",
      "credentials in log", "secret in log"), "token_leakage"),

    # Error / info disclosure
    (("error page", "error info", "error disclosure", "stack trace",
      "exception disclosure"), "error_disclosure"),
    (("server version", "x-powered-by", "version disclosure",
      "banner disclosure"), "info_disclosure"),
    (("information disclosure",), "info_disclosure"),

    # Headers / config (deterministic, not capped)
    (("missing hsts", "hsts missing", "no hsts", "hsts policy"),
     "missing_hsts"),
    (("hsts preload",), "hsts_preload"),
    (("missing csp", "csp missing", "no csp"), "missing_csp"),
    (("csp weakness", "csp policy weakness", "weak csp",
      "unsafe-inline", "unsafe-eval"), "csp_weakness"),
    (("missing x-frame", "x-frame-options"), "missing_xframe"),
    (("missing x-content-type", "x-content-type-options"),
     "missing_xcto"),
    (("missing sri", "subresource integrity"), "missing_sri"),
    (("referrer-policy", "referrer policy"), "referrer_policy"),
    (("permissions-policy", "permissions policy", "feature policy"),
     "permissions_policy"),
    (("mixed content",), "mixed_content"),
    (("password autocomplete", "autocomplete=on", "autocomplete on"),
     "password_autocomplete"),
    (("https redirect", "http to https", "http enforcement",
      "redirect to https"), "https_redirect"),
    (("missing cache-control", "cache-control on auth",
      "cacheable sensitive", "no-store"), "missing_cache_control"),
    (("clickjacking", "frameable"), "clickjacking"),

    # Cookies
    (("insecure cookie", "cookie security", "missing secure flag",
      "missing httponly", "missing samesite", "secure flag",
      "httponly flag", "samesite"), "insecure_cookie"),

    # Sensitive URL params
    (("sensitive url", "sensitive query", "password in url",
      "token in url", "credential in url"), "sensitive_url_params"),

    # External form / third-party
    (("external form", "form external", "third-party form"),
     "external_form"),
    (("third-party script", "untrusted cdn", "third party include"),
     "third_party"),

    # API version / API specific
    (("api version downgrade", "api version", "deprecated api"),
     "api_version_downgrade"),

    # Timing enumeration
    (("timing enum", "timing-based enum", "user enumeration",
      "username enumeration"), "timing_enumeration"),

    # Prototype pollution
    (("prototype pollution",), "prototype_pollution"),

    # Logging
    (("logging fail", "audit log", "no logging", "missing logging"),
     "logging"),

    # Debug / staging
    (("debug endpoint", "debug mode", "staging exposed",
      "swagger exposed", "actuator exposed"), "debug_staging"),

    # Attack chain
    (("attack chain", "exploit chain", "multi-step exploit"),
     "attack_chain"),

    # LLM-specific (OWASP Top 10 for LLM Applications)
    (("prompt injection", "llm01"), "llm_prompt_injection"),
    (("system prompt leakage", "prompt leakage", "llm07"), "llm_prompt_leakage"),
    (("sensitive information disclosure via llm", "llm02"),
     "llm_info_disclosure"),
    (("improper output handling", "llm05"), "llm_output_handling"),
    (("excessive agency", "llm06"), "llm_excessive_agency"),
    (("unbounded consumption", "llm10"), "llm_unbounded_consumption"),

    # Generic input validation (lowest specificity, last)
    (("input validation",), "input_validation"),
]

# Configuration / passive-recon style titles can still be Critical even
# without runtime replay because they're directly observable facts
# (a missing HSTS header is a missing HSTS header). Findings whose title
# matches one of these substrings bypass the unverified-cap.
_CONFIG_TITLE_KEYWORDS = (
    "header", "hsts", "csp", "cookie", "tls", "ssl", "cipher",
    "cors", "referrer", "permissions-policy", "permissions policy",
    "version disclosure", "x-powered-by", "x-frame", "cache-control",
    "subresource integrity", "sri", "mixed content", "https redirect",
    "clickjacking", "frameable", "samesite", "httponly", "secure flag",
    "autocomplete",
)


def bucket_from_cvss(cvss: float) -> str:
    """Map a CVSS score to a CVSS v3 severity rating."""
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def _stringify_evidence(ev: Any) -> str:
    if isinstance(ev, str):
        return ev.lower()
    if isinstance(ev, (dict, list)):
        try:
            return json.dumps(ev, default=str).lower()
        except Exception:
            return ""
    if ev is None:
        return ""
    return str(ev).lower()


def _cvss_from_llm_severity(sev: str) -> float:
    s = (sev or "").strip().lower()
    if s in ("critical", "crit"):
        return 9.0
    if s == "high":
        return 7.5
    if s in ("medium", "med", "moderate"):
        return 5.0
    if s == "low":
        return 3.0
    if s in ("informational", "info", "informative"):
        return 0.0
    return 1.0


def _match_profile(title: str) -> tuple[str, dict]:
    """First-match wins lookup of title -> CWE_PROFILES entry."""
    for keywords, key in _TITLE_TO_PROFILE:
        for kw in keywords:
            if kw in title:
                profile = CWE_PROFILES.get(key, {})
                if profile:
                    return key, profile
    return "", {}


def _is_config_title(title: str) -> bool:
    return any(kw in title for kw in _CONFIG_TITLE_KEYWORDS)


def _adjust_cvss(
    base: float,
    title: str,
    evidence: str,
    payload: str,
    verified: bool,
    verdict: str,
) -> float:
    """Apply context-aware adjustments to the base CVSS score.

    Mirrors the logic in ``scripts.triage_engine._adjust_cvss`` but works on
    raw AI findings (no test_log access) so we only use signals available
    at the finding object itself.
    """
    score = base

    # 1. Verification gate.
    #    If the finding wasn't runtime-replayed and isn't a config issue,
    #    cap at 7.5 (no Critical from a single LLM observation).
    if verdict == "DISPROVED":
        return 0.0
    if verdict == "CONFIRMED" and verified:
        # Verified findings get a small boost up to a hard ceiling.
        score = min(score + 0.5, 9.8)
    elif not verified and verdict not in ("CONFIRMED", "INCONCLUSIVE"):
        if not _is_config_title(title):
            score = min(score, 7.5)

    # 2. Evidence-keyword positives.
    if any(kw in evidence for kw in SQL_ERROR_KEYWORDS):
        score = min(score + 0.5, 10.0)
    if any(kw in evidence for kw in COMMAND_INJECTION_KEYWORDS):
        score = min(score + 0.5, 10.0)
    if any(kw in evidence for kw in PATH_TRAVERSAL_KEYWORDS):
        score = min(score + 0.5, 10.0)
    if any(kw in evidence for kw in SSRF_SUCCESS_KEYWORDS):
        score = min(score + 0.3, 10.0)
    if any(kw in evidence for kw in XXE_SUCCESS_KEYWORDS):
        score = min(score + 0.3, 10.0)
    data_extraction = (
        "union select", "1=1", "table_name", "column_name",
        "information_schema", "root:x:0", "uid=0",
    )
    if any(kw in evidence for kw in data_extraction):
        score = min(score + 0.5, 10.0)

    # 3. Reflected XSS detection (only meaningful in HTML responses).
    if ("xss" in title or "cross-site scripting" in title):
        reflected = any(kw in evidence for kw in XSS_REFLECTION_KEYWORDS)
        # XSS in pure JSON responses isn't browser-rendered.
        if "application/json" in evidence and "text/html" not in evidence:
            score = max(score - 2.0, 0.5)
        elif reflected:
            score = min(score + 0.3, 9.0)

    # 4. Server-rejected payloads (4xx/5xx responses) for injection-class
    #    findings reduce confidence.
    is_injection = any(
        k in title for k in (
            "sql", "xss", "ssrf", "xxe", "injection", "traversal",
            "command", "deserialization",
        )
    )
    if is_injection and ("all 4" in evidence and "rejected" in evidence):
        score = max(score - 2.0, 0.5)

    # 5. Floor for runtime-confirmed RCE / command injection — these are
    #    always Critical.
    if verified and verdict == "CONFIRMED":
        if any(k in title for k in (
            "rce", "remote code", "command injection", "command exec",
        )):
            score = max(score, 9.0)

    # Empty payload AND empty evidence — drop a notch (low confidence).
    if not payload and not evidence:
        score = max(score - 0.5, 0.0)

    return max(0.0, min(10.0, score))


def classify_severity(finding: dict) -> dict:
    """Return a dict of canonical fields to merge into ``finding``.

    The returned dict always contains:
        cwe, cvss, cvss_vector, severity, llm_severity

    ``finding`` is not mutated. Callers typically do::

        finding.update(classify_severity(finding))
    """
    title = (finding.get("title") or "").strip().lower()
    evidence = _stringify_evidence(finding.get("evidence", ""))
    payload = str(finding.get("payload") or "")
    verified = bool(finding.get("verified", False))
    verdict = (finding.get("verdict") or "").strip().upper()
    llm_sev = (finding.get("severity") or "").strip()
    # Preserve the original LLM severity once — repeated re-classification
    # must not lose the first observation.
    llm_severity = (finding.get("llm_severity") or llm_sev or "").strip()

    profile_key, profile = _match_profile(title)
    if not profile:
        # No keyword match — fall back to LLM severity but without CWE/CVSS
        # vector info. We still bucket via CVSS so the severity field is
        # consistent.
        cvss = _cvss_from_llm_severity(llm_severity)
        cvss = _adjust_cvss(
            cvss, title, evidence, payload, verified, verdict,
        )
        return {
            "cwe": (finding.get("cwe") or "").strip(),
            "cvss": round(cvss, 1),
            "cvss_vector": "",
            "severity": bucket_from_cvss(cvss),
            "llm_severity": llm_severity,
        }

    base = float(profile.get("cvss", 0.0))
    vector = profile.get("vec", "")
    cwe = profile.get("cwe", "")
    cvss = _adjust_cvss(
        base, title, evidence, payload, verified, verdict,
    )

    return {
        "cwe": cwe,
        "cvss": round(cvss, 1),
        "cvss_vector": vector,
        "severity": bucket_from_cvss(cvss),
        "llm_severity": llm_severity,
        "_severity_profile": profile_key,
    }
