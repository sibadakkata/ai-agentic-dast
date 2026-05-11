"""Tests for the email/DNS security checks module."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from scanners.ai_agent.dns_security import (
    COMMON_DKIM_SELECTORS,
    DNSSecurityResult,
    build_dns_security_findings,
    check_dkim,
    check_dmarc,
    check_dns_security,
    check_mx_security,
    check_spf,
)


class TestCheckSPF:
    def test_no_spf_record(self):
        with patch("scanners.ai_agent.dns_security._query_txt", return_value=[]):
            result = check_spf("example.com")
        assert result.status == "fail"
        assert result.severity == "High"
        assert "No SPF record" in result.detail

    def test_spf_with_hard_fail(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=spf1 include:_spf.google.com -all"]):
            result = check_spf("example.com")
        assert result.status == "pass"

    def test_spf_with_soft_fail(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=spf1 include:_spf.google.com ~all"]):
            result = check_spf("example.com")
        assert result.status == "info"
        assert result.severity == "Low"

    def test_spf_plus_all_critical(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=spf1 +all"]):
            result = check_spf("example.com")
        assert result.status == "fail"
        assert result.severity == "Critical"

    def test_spf_neutral_all(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=spf1 ?all"]):
            result = check_spf("example.com")
        assert result.status == "warn"
        assert result.severity == "Medium"

    def test_multiple_spf_records(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=spf1 include:a.com -all", "v=spf1 include:b.com -all"]):
            result = check_spf("example.com")
        assert result.status == "warn"
        assert "Multiple SPF" in result.detail

    def test_spf_too_many_lookups(self):
        spf = "v=spf1 " + " ".join(f"include:srv{i}.example.com" for i in range(12)) + " -all"
        with patch("scanners.ai_agent.dns_security._query_txt", return_value=[spf]):
            result = check_spf("example.com")
        assert result.status == "warn"
        assert "DNS lookups" in result.detail


class TestCheckDMARC:
    def test_no_dmarc_record(self):
        with patch("scanners.ai_agent.dns_security._query_txt", return_value=[]):
            result = check_dmarc("example.com")
        assert result.status == "fail"
        assert result.severity == "High"

    def test_dmarc_reject_policy(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=DMARC1; p=reject; rua=mailto:d@example.com"]):
            result = check_dmarc("example.com")
        assert result.status == "pass"

    def test_dmarc_none_policy(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=DMARC1; p=none"]):
            result = check_dmarc("example.com")
        assert result.status == "warn"
        assert result.severity == "Medium"

    def test_dmarc_quarantine_policy(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=DMARC1; p=quarantine; rua=mailto:reports@example.com"]):
            result = check_dmarc("example.com")
        assert "quarantine" in result.detail

    def test_dmarc_partial_pct(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com"]):
            result = check_dmarc("example.com")
        assert "50%" in result.detail

    def test_dmarc_weak_subdomain_policy(self):
        with patch("scanners.ai_agent.dns_security._query_txt",
                   return_value=["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"]):
            result = check_dmarc("example.com")
        assert "subdomain" in result.detail.lower()
        assert result.status == "warn"


class TestCheckDKIM:
    def test_no_dkim_found(self):
        with patch("scanners.ai_agent.dns_security._query_txt", return_value=[]):
            results = check_dkim("example.com")
        assert len(results) == 1
        assert results[0].status == "warn"
        assert "No DKIM" in results[0].detail

    def test_dkim_found_with_key(self):
        def _mock_txt(domain):
            if "google._domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg=="]
            return []
        with patch("scanners.ai_agent.dns_security._query_txt", side_effect=_mock_txt):
            results = check_dkim("example.com")
        found = [r for r in results if r.status == "pass"]
        assert len(found) >= 1

    def test_dkim_revoked_key(self):
        def _mock_txt(domain):
            if "default._domainkey" in domain:
                return ["v=DKIM1; k=rsa; p="]
            return []
        with patch("scanners.ai_agent.dns_security._query_txt", side_effect=_mock_txt):
            results = check_dkim("example.com")
        revoked = [r for r in results if "revoked" in r.detail.lower()]
        assert len(revoked) >= 1


class TestCheckMXSecurity:
    def test_no_mx_records(self):
        with patch("scanners.ai_agent.dns_security._query_mx", return_value=[]):
            result = check_mx_security("example.com")
        assert result.status == "info"

    def test_valid_mx_records(self):
        with patch("scanners.ai_agent.dns_security._query_mx",
                   return_value=["mx1.googlemail.com", "mx2.googlemail.com"]):
            result = check_mx_security("example.com")
        assert result.status == "pass"

    def test_ip_based_mx(self):
        with patch("scanners.ai_agent.dns_security._query_mx",
                   return_value=["192.168.1.1"]):
            result = check_mx_security("example.com")
        assert result.status == "warn"

    def test_null_mx(self):
        with patch("scanners.ai_agent.dns_security._query_mx", return_value=["."]):
            result = check_mx_security("example.com")
        assert result.status == "pass"
        assert "Null MX" in result.detail


class TestBuildDNSSecurityFindings:
    def test_fail_result_produces_finding(self):
        results = [DNSSecurityResult(
            domain="example.com", check_type="SPF", severity="High",
            status="fail", detail="No SPF record found.",
        )]
        findings = build_dns_security_findings(results)
        assert len(findings) == 1
        assert "SPF" in findings[0]["title"]
        assert findings[0]["severity"] == "High"

    def test_pass_info_result_skipped(self):
        results = [DNSSecurityResult(
            domain="example.com", check_type="MX", severity="Info",
            status="pass", detail="MX records found.",
        )]
        findings = build_dns_security_findings(results)
        assert len(findings) == 0

    def test_warn_result_produces_finding(self):
        results = [DNSSecurityResult(
            domain="example.com", check_type="DMARC", severity="Medium",
            status="warn", detail="DMARC policy is none.",
        )]
        findings = build_dns_security_findings(results)
        assert len(findings) == 1
        assert findings[0]["confidence"] == "Medium"


def _run(coro):
    return asyncio.run(coro)


class TestCheckDNSSecurity:
    def test_full_check_returns_results(self):
        def _mock_txt(domain):
            if "_dmarc." in domain:
                return ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
            return ["v=spf1 include:_spf.google.com -all"]
        async def _inner():
            with patch("scanners.ai_agent.dns_security._query_txt", side_effect=_mock_txt):
                with patch("scanners.ai_agent.dns_security._query_mx",
                           return_value=["mx.google.com"]):
                    return await check_dns_security("example.com")
        results = _run(_inner())
        assert len(results) >= 3
        check_types = {r.check_type for r in results}
        assert "SPF" in check_types
        assert "DMARC" in check_types
        assert "MX" in check_types

    def test_progress_callback_called(self):
        events = []
        def _cb(evt, data):
            events.append((evt, data))
        async def _inner():
            with patch("scanners.ai_agent.dns_security._query_txt", return_value=[]):
                with patch("scanners.ai_agent.dns_security._query_mx", return_value=[]):
                    return await check_dns_security("example.com", progress_callback=_cb)
        _run(_inner())
        event_types = [e[0] for e in events]
        assert "dns_security_start" in event_types
        assert "dns_security_done" in event_types

    def test_all_missing_produces_high_findings(self):
        async def _inner():
            with patch("scanners.ai_agent.dns_security._query_txt", return_value=[]):
                with patch("scanners.ai_agent.dns_security._query_mx", return_value=[]):
                    return await check_dns_security("vulnerable.example.com")
        results = _run(_inner())
        findings = build_dns_security_findings(results)
        high_findings = [f for f in findings if f["severity"] in ("High", "Critical")]
        assert len(high_findings) >= 2
