"""Tests for the subdomain takeover detection module."""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanners.ai_agent.subdomain_takeover import (
    FINGERPRINTS,
    ProviderFingerprint,
    TakeoverResult,
    _match_provider,
    _resolve_cname_chain_fallback,
    build_takeover_findings,
    check_subdomain_takeover,
)


class TestProviderFingerprints:
    def test_fingerprints_not_empty(self):
        assert len(FINGERPRINTS) >= 40

    def test_all_fingerprints_have_required_fields(self):
        for fp in FINGERPRINTS:
            assert fp.service
            assert fp.cname_patterns
            assert isinstance(fp.http_fingerprints, list)
            assert fp.severity in ("Critical", "High", "Medium", "Low", "Info")

    def test_key_providers_present(self):
        services = {fp.service for fp in FINGERPRINTS}
        required = {"AWS S3", "GitHub Pages", "Heroku", "Azure (Web Apps)", "Netlify", "Vercel"}
        for r in required:
            assert any(r.lower() in s.lower() for s in services), f"Missing: {r}"


class TestMatchProvider:
    def test_s3_cname_match(self):
        matches = _match_provider(["mybucket.s3.amazonaws.com"], "x.com")
        assert any(m.service == "AWS S3" for m in matches)

    def test_github_pages_match(self):
        matches = _match_provider(["myorg.github.io"], "docs.example.com")
        assert any(m.service == "GitHub Pages" for m in matches)

    def test_heroku_match(self):
        matches = _match_provider(["myapp.herokuapp.com"], "app.example.com")
        assert any(m.service == "Heroku" for m in matches)

    def test_azure_match(self):
        matches = _match_provider(["myapp.azurewebsites.net"], "p.example.com")
        assert any(m.service == "Azure (Web Apps)" for m in matches)

    def test_no_match_for_unrecognized(self):
        matches = _match_provider(["somehost.customcdn.internal"], "www.example.com")
        assert len(matches) == 0

    def test_netlify_match(self):
        matches = _match_provider(["site-abc123.netlify.app"], "blog.example.com")
        assert any(m.service == "Netlify" for m in matches)

    def test_vercel_match(self):
        matches = _match_provider(["cname.vercel-dns.com"], "app.example.com")
        assert any(m.service == "Vercel" for m in matches)

    def test_cloudfront_match(self):
        matches = _match_provider(["d1234.cloudfront.net"], "cdn.example.com")
        assert any(m.service == "AWS CloudFront" for m in matches)

    def test_multiple_cnames_in_chain(self):
        matches = _match_provider(["proxy.net", "mybucket.s3-website-us-east-1.amazonaws.com"], "x.com")
        assert any(m.service == "AWS S3" for m in matches)

    def test_shopify_match(self):
        matches = _match_provider(["shops.myshopify.com"], "store.example.com")
        assert any(m.service == "Shopify" for m in matches)


class TestResolveChainFallback:
    def test_nxdomain_detection(self):
        cnames, is_nx = _resolve_cname_chain_fallback("never-exist-xyz123.example.invalid")
        assert is_nx is True

    def test_live_host_not_nxdomain(self):
        cnames, is_nx = _resolve_cname_chain_fallback("google.com")
        assert is_nx is False


class TestBuildTakeoverFindings:
    def test_single_result_produces_finding(self):
        results = [TakeoverResult(
            hostname="old.example.com", vulnerable=True, service="AWS S3",
            evidence="NoSuchBucket", cname_chain=["old.example.com.s3.amazonaws.com"],
            severity="High", confidence="High",
        )]
        findings = build_takeover_findings(results)
        assert len(findings) == 1
        assert "AWS S3" in findings[0]["title"]
        assert findings[0]["severity"] == "High"
        assert findings[0]["cwe"] == "CWE-284"
        assert "Subdomain Takeover" in findings[0]["category"]

    def test_empty_results_produce_no_findings(self):
        assert build_takeover_findings([]) == []

    def test_dangling_cname_finding(self):
        results = [TakeoverResult(
            hostname="staging.example.com", vulnerable=True,
            service="Unknown (Dangling CNAME)",
            evidence="CNAME exists but target NXDOMAIN",
            cname_chain=["old-lb.dead-provider.com"],
            severity="Medium", confidence="Medium",
        )]
        findings = build_takeover_findings(results)
        assert len(findings) == 1
        assert findings[0]["severity"] == "Medium"


def _run(coro):
    return asyncio.run(coro)


class TestCheckSubdomainTakeover:
    def test_empty_hostlist_returns_empty(self):
        results = _run(check_subdomain_takeover([]))
        assert results == []

    def test_progress_callback_called(self):
        events = []
        def _cb(evt, data):
            events.append((evt, data))
        with patch("scanners.ai_agent.subdomain_takeover._resolve_cname") as m:
            m.return_value = ([], False)
            _run(check_subdomain_takeover(["safe.example.com"], progress_callback=_cb))
        event_types = [e[0] for e in events]
        assert "subdomain_takeover_start" in event_types
        assert "subdomain_takeover_done" in event_types

    def test_nxdomain_heroku_detected(self):
        async def _inner():
            with patch("scanners.ai_agent.subdomain_takeover._resolve_cname") as m:
                m.return_value = (["old-app.herokuapp.com"], True)
                return await check_subdomain_takeover(["dead.example.com"])
        results = _run(_inner())
        assert len(results) == 1
        assert results[0].vulnerable is True
        assert results[0].service == "Heroku"
        assert "NXDOMAIN" in results[0].evidence

    def test_s3_fingerprint_detected(self):
        async def _inner():
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.text = "The specified bucket does not exist"
            mock_resp.status_code = 404
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.aclose = AsyncMock()
            with patch("scanners.ai_agent.subdomain_takeover._resolve_cname") as m:
                m.return_value = (["assets.s3.amazonaws.com"], False)
                return await check_subdomain_takeover(["assets.example.com"], http_client=mock_client)
        results = _run(_inner())
        assert len(results) == 1
        assert results[0].service == "AWS S3"

    def test_no_vulnerability_for_live_cname(self):
        async def _inner():
            with patch("scanners.ai_agent.subdomain_takeover._resolve_cname") as m:
                m.return_value = (["actual-app.herokuapp.com"], False)
                mock_client = AsyncMock()
                mock_resp = MagicMock()
                mock_resp.text = "Welcome to our app!"
                mock_resp.status_code = 200
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client.aclose = AsyncMock()
                return await check_subdomain_takeover(["app.example.com"], http_client=mock_client)
        results = _run(_inner())
        assert len(results) == 0

    def test_dangling_cname_unknown_provider(self):
        async def _inner():
            with patch("scanners.ai_agent.subdomain_takeover._resolve_cname") as m:
                m.return_value = (["dead.internal-cdn.com"], True)
                return await check_subdomain_takeover(["old.example.com"])
        results = _run(_inner())
        assert len(results) == 1
        assert results[0].service == "Unknown (Dangling CNAME)"
        assert results[0].severity == "Medium"

    def test_concurrent_checks_capped(self):
        async def _inner():
            call_count = 0
            max_concurrent = 0
            current = 0
            async def _mock_resolve(hostname):
                nonlocal call_count, max_concurrent, current
                current += 1
                max_concurrent = max(max_concurrent, current)
                call_count += 1
                await asyncio.sleep(0.01)
                current -= 1
                return ([], False)
            with patch("scanners.ai_agent.subdomain_takeover._resolve_cname", side_effect=_mock_resolve):
                hosts = [f"sub{i}.example.com" for i in range(25)]
                await check_subdomain_takeover(hosts, max_concurrent=5)
            return call_count, max_concurrent
        call_count, max_concurrent = _run(_inner())
        assert call_count == 25
        assert max_concurrent <= 5
