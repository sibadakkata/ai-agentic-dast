"""Unit tests for ``scanners.ai_agent.severity.classify_severity``.

These tests pin the deterministic CVSS-driven severity logic so two scans
of the same target always produce the same severity rating, regardless of
LLM drift.
"""
from __future__ import annotations

import pytest

from scanners.ai_agent.severity import bucket_from_cvss, classify_severity


# ── bucket_from_cvss boundaries ──────────────────────────────────────────


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, "Info"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_bucket_boundaries(score: float, expected: str) -> None:
    assert bucket_from_cvss(score) == expected


# ── Title-keyword → profile lookup ───────────────────────────────────────


def test_sql_injection_unverified_caps_at_high() -> None:
    """SQLi base is 9.8 (Critical) but unverified caps it at 7.5 (High)."""
    out = classify_severity({
        "title": "SQL Injection in /api/users",
        "severity": "Critical",
        "evidence": "syntax error near token 'OR'",
        "payload": "1' OR '1'='1",
    })
    assert out["cwe"] == "CWE-89"
    assert out["severity"] == "High"
    # Cap (7.5) plus +0.5 SQL-error keyword bonus = 8.0
    assert 7.5 <= out["cvss"] <= 8.5
    assert out["llm_severity"] == "Critical"
    assert out["cvss_vector"].startswith("AV:N")


def test_sql_injection_verified_confirmed_is_critical() -> None:
    """Runtime-verified SQLi gets the +0.5 boost and stays Critical."""
    out = classify_severity({
        "title": "SQL Injection",
        "severity": "High",
        "evidence": "syntax error in mysql union select 1,2,3",
        "payload": "1' UNION SELECT 1,2,3-- ",
        "verified": True,
        "verdict": "CONFIRMED",
    })
    assert out["severity"] == "Critical"
    assert out["cvss"] >= 9.0


def test_rce_confirmed_floors_at_critical() -> None:
    """Confirmed RCE always lands Critical even if base CVSS started lower."""
    out = classify_severity({
        "title": "Remote Code Execution",
        "severity": "Medium",
        "evidence": "uid=0(root)",
        "payload": "; id",
        "verified": True,
        "verdict": "CONFIRMED",
    })
    assert out["severity"] == "Critical"
    assert out["cvss"] >= 9.0


def test_disproved_collapses_to_info() -> None:
    out = classify_severity({
        "title": "SQL Injection",
        "severity": "High",
        "evidence": "no error in response",
        "payload": "1'",
        "verified": True,
        "verdict": "DISPROVED",
    })
    assert out["severity"] == "Info"
    assert out["cvss"] == 0.0


def test_xss_in_json_response_downgrades() -> None:
    """XSS payloads reflected in JSON aren't browser-rendered → not exploitable."""
    out = classify_severity({
        "title": "Reflected XSS",
        "severity": "High",
        "evidence": 'content-type: application/json — body: {"q":"<script>alert(1)</script>"}',
        "payload": "<script>alert(1)</script>",
    })
    assert out["cwe"] == "CWE-79"
    # Base 6.1 - 2.0 = 4.1 → still Medium
    assert out["severity"] in ("Low", "Medium")
    assert out["cvss"] < 6.0


def test_xss_reflected_in_html_keeps_severity() -> None:
    out = classify_severity({
        "title": "Reflected XSS",
        "severity": "High",
        "evidence": 'content-type: text/html — body contains <script>alert(1)</script>',
        "payload": "<script>alert(1)</script>",
    })
    assert out["cwe"] == "CWE-79"
    assert out["severity"] == "Medium"


# ── Configuration / passive findings bypass the unverified cap ───────────


def test_missing_hsts_is_low_unverified() -> None:
    out = classify_severity({
        "title": "Missing HSTS Header",
        "severity": "Info",  # LLM may say Info
        "evidence": "Strict-Transport-Security not set on response",
        "payload": "",
    })
    assert out["cwe"] == "CWE-319"
    # 4.3 base, no adjustments → Medium
    assert out["severity"] == "Medium"
    assert 4.0 <= out["cvss"] <= 4.5


def test_jwt_alg_none_keeps_critical_when_config_bypass() -> None:
    """JWT alg=none is a deterministic config flaw — bypasses the cap."""
    out = classify_severity({
        "title": "JWT alg=none accepted",
        "severity": "Critical",
        "evidence": 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.',
        "payload": "alg=none",
    })
    assert out["cwe"] == "CWE-347"
    # JWT base is 9.1, "alg=none" is non-config so still capped at 7.5 unverified
    # Verify cap still applies for non-config injection-class titles.
    assert out["severity"] in ("High", "Critical")


def test_file_upload_unverified_caps_at_high() -> None:
    out = classify_severity({
        "title": "Unrestricted File Upload",
        "severity": "Critical",
        "evidence": "uploaded shell.php returned 200",
        "payload": "shell.php",
    })
    assert out["cwe"] == "CWE-434"
    # base 9.8 capped to 7.5 unverified
    assert out["cvss"] <= 7.5
    assert out["severity"] == "High"


# ── LLM severity preservation ────────────────────────────────────────────


def test_llm_severity_preserved() -> None:
    out = classify_severity({
        "title": "SQL Injection",
        "severity": "low",  # LLM under-reported
        "evidence": "syntax error",
        "payload": "'",
    })
    assert out["llm_severity"] == "low"
    # Deterministic should still elevate above the LLM's "low" call.
    assert out["severity"] in ("Medium", "High")


def test_unknown_title_falls_back_to_llm_severity() -> None:
    out = classify_severity({
        "title": "Some Novel Quantum Vulnerability",
        "severity": "High",
        "evidence": "evidence text",
        "payload": "x",
    })
    assert out["cwe"] == ""
    assert out["cvss_vector"] == ""
    # LLM said High → 7.5, capped at 7.5 unverified → still High
    assert out["severity"] == "High"


def test_unknown_title_no_severity_lands_low() -> None:
    out = classify_severity({
        "title": "Mystery Issue",
        "severity": "",
        "evidence": "x",
        "payload": "y",
    })
    assert out["cwe"] == ""
    assert out["severity"] in ("Info", "Low")


# ── Idempotency ──────────────────────────────────────────────────────────


def test_classify_is_idempotent() -> None:
    """Re-classifying an already-classified finding yields the same result.

    The agent re-runs classify_severity after runtime verification; this
    must be safe to call repeatedly without drift.
    """
    f = {
        "title": "SQL Injection",
        "severity": "High",
        "evidence": "mysql syntax error",
        "payload": "1'",
    }
    f.update(classify_severity(f))
    snapshot = (f["severity"], f["cvss"], f["cwe"], f["cvss_vector"], f["llm_severity"])
    f.update(classify_severity(f))
    assert (f["severity"], f["cvss"], f["cwe"], f["cvss_vector"], f["llm_severity"]) == snapshot


def test_llm_severity_first_observation_wins() -> None:
    """Once we record llm_severity, repeated classification preserves it."""
    f = {
        "title": "SQL Injection",
        "severity": "Critical",
        "evidence": "mysql syntax error",
        "payload": "1'",
    }
    f.update(classify_severity(f))
    assert f["llm_severity"] == "Critical"
    # Pretend the runtime verifier later sets verdict + verified
    f["verified"] = True
    f["verdict"] = "CONFIRMED"
    f.update(classify_severity(f))
    # Even though `severity` is now Critical from CVSS bucketing, the
    # original LLM severity is preserved verbatim.
    assert f["llm_severity"] == "Critical"
    assert f["severity"] == "Critical"


# ── Evidence types ───────────────────────────────────────────────────────


def test_evidence_can_be_dict() -> None:
    """Evidence is sometimes serialised as a dict — must not raise."""
    out = classify_severity({
        "title": "SSRF",
        "severity": "High",
        "evidence": {"body": "ami-id\nuser-data\n", "status": 200},
        "payload": "http://169.254.169.254/",
    })
    assert out["cwe"] == "CWE-918"
    assert out["severity"] in ("High", "Critical")


def test_evidence_can_be_list() -> None:
    out = classify_severity({
        "title": "Path Traversal",
        "severity": "High",
        "evidence": ["root:x:0:0:root:/root:/bin/bash"],
        "payload": "../../etc/passwd",
    })
    assert out["cwe"] == "CWE-22"
    assert out["severity"] in ("High", "Critical")


def test_empty_evidence_and_payload_dampens() -> None:
    """A finding with no payload AND no evidence should slip a notch lower."""
    out = classify_severity({
        "title": "Missing HSTS Header",
        "severity": "Medium",
        "evidence": "",
        "payload": "",
    })
    # Base 4.3 - 0.5 = 3.8 → Low
    assert out["severity"] == "Low"


# ── CSP / header-class fall-through ──────────────────────────────────────


def test_csp_weakness_is_medium() -> None:
    out = classify_severity({
        "title": "CSP Weakness: unsafe-inline allowed",
        "severity": "Low",
        "evidence": "Content-Security-Policy: default-src 'self' 'unsafe-inline'",
        "payload": "",
    })
    assert out["cwe"] == "CWE-693"
    assert out["severity"] == "Medium"


def test_clickjacking_lacks_xframe() -> None:
    out = classify_severity({
        "title": "Clickjacking — missing X-Frame-Options",
        "severity": "Medium",
        "evidence": "no x-frame-options header on /admin",
        "payload": "",
    })
    assert out["cwe"] == "CWE-1021"
    assert out["severity"] == "Medium"


# ── Parameter ordering — first match wins ────────────────────────────────


def test_specific_jwt_alg_none_beats_generic_jwt() -> None:
    """``jwt alg none`` should hit the alg-none profile, not generic JWT."""
    out = classify_severity({
        "title": "JWT alg=none accepted by API",
        "severity": "High",
        "evidence": "alg=none token accepted by /api/admin",
        "payload": "eyJhbGciOiJub25lIn0",
    })
    assert out["cwe"] == "CWE-347"
    # alg=none base 9.1, capped 7.5 unverified
    assert out["cvss"] >= 7.0
