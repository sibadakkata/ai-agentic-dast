"""Subdomain takeover detection module.

Checks discovered subdomains for dangling DNS records that point to
unclaimed third-party services (S3 buckets, Heroku apps, GitHub Pages, etc.).

Detection flow:
  1. Resolve CNAME chain for each subdomain
  2. Match CNAME targets against known vulnerable provider patterns
  3. For matches: fetch HTTP response and check for service-specific fingerprints
  4. For NXDOMAIN CNAMEs: flag as potential takeover (hosting abandoned)

Based on EdOverflow/can-i-take-over-xyz fingerprint database.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── Takeover-vulnerable provider fingerprints ───────────────────────────
# Each entry: (service, cname_patterns, http_fingerprints, nxdomain_vulnerable)
# cname_patterns: regex patterns to match in CNAME records
# http_fingerprints: strings to look for in HTTP response body
# nxdomain_vulnerable: if True, NXDOMAIN on the CNAME target = takeover possible

@dataclass
class ProviderFingerprint:
    service: str
    cname_patterns: list[str]
    http_fingerprints: list[str]
    nxdomain: bool = False
    severity: str = "High"


FINGERPRINTS: list[ProviderFingerprint] = [
    # AWS
    ProviderFingerprint(
        service="AWS S3",
        cname_patterns=[r"\.s3[.-].*\.amazonaws\.com", r"\.s3\.amazonaws\.com", r"\.s3-website[.-]"],
        http_fingerprints=["The specified bucket does not exist", "NoSuchBucket", "Code: NoSuchBucket"],
    ),
    ProviderFingerprint(
        service="AWS Elastic Beanstalk",
        cname_patterns=[r"\.elasticbeanstalk\.com"],
        http_fingerprints=[],
        nxdomain=True,
    ),
    ProviderFingerprint(
        service="AWS CloudFront",
        cname_patterns=[r"\.cloudfront\.net"],
        http_fingerprints=["Bad request", "ERROR: The request could not be satisfied"],
    ),
    # GitHub
    ProviderFingerprint(
        service="GitHub Pages",
        cname_patterns=[r"\.github\.io"],
        http_fingerprints=["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    ),
    # Heroku
    ProviderFingerprint(
        service="Heroku",
        cname_patterns=[r"\.herokuapp\.com", r"\.herokudns\.com", r"\.herokussl\.com"],
        http_fingerprints=["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"],
        nxdomain=True,
    ),
    # Azure
    ProviderFingerprint(
        service="Azure (Web Apps)",
        cname_patterns=[r"\.azurewebsites\.net", r"\.cloudapp\.azure\.com", r"\.azure-api\.net"],
        http_fingerprints=["404 Web Site not found", "Azure Web Apps"],
        nxdomain=True,
    ),
    ProviderFingerprint(
        service="Azure Traffic Manager",
        cname_patterns=[r"\.trafficmanager\.net"],
        http_fingerprints=[],
        nxdomain=True,
    ),
    ProviderFingerprint(
        service="Azure Blob Storage",
        cname_patterns=[r"\.blob\.core\.windows\.net"],
        http_fingerprints=["The specified container does not exist", "BlobNotFound", "ContainerNotFound"],
    ),
    # Netlify
    ProviderFingerprint(
        service="Netlify",
        cname_patterns=[r"\.netlify\.app", r"\.netlify\.com", r"\.bitballoon\.com"],
        http_fingerprints=["Not Found - Request ID:"],
    ),
    # Shopify
    ProviderFingerprint(
        service="Shopify",
        cname_patterns=[r"\.myshopify\.com", r"shops\.myshopify\.com"],
        http_fingerprints=["Sorry, this shop is currently unavailable", "Only one step left"],
    ),
    # Zendesk
    ProviderFingerprint(
        service="Zendesk",
        cname_patterns=[r"\.zendesk\.com"],
        http_fingerprints=["Help Center Closed", "this help center no longer exists"],
    ),
    # Fastly
    ProviderFingerprint(
        service="Fastly",
        cname_patterns=[r"\.fastly\.net", r"\.fastlylb\.net"],
        http_fingerprints=["Fastly error: unknown domain"],
    ),
    # Pantheon
    ProviderFingerprint(
        service="Pantheon",
        cname_patterns=[r"\.pantheonsite\.io", r"\.pantheon\.io"],
        http_fingerprints=["404 error unknown site", "The gods are wise"],
    ),
    # Tumblr
    ProviderFingerprint(
        service="Tumblr",
        cname_patterns=[r"\.tumblr\.com"],
        http_fingerprints=["There's nothing here", "Whatever you were looking for doesn't currently exist"],
    ),
    # WordPress.com
    ProviderFingerprint(
        service="WordPress.com",
        cname_patterns=[r"\.wordpress\.com"],
        http_fingerprints=["Do you want to register"],
    ),
    # Surge.sh
    ProviderFingerprint(
        service="Surge.sh",
        cname_patterns=[r"\.surge\.sh"],
        http_fingerprints=["project not found"],
        nxdomain=True,
    ),
    # Unbounce
    ProviderFingerprint(
        service="Unbounce",
        cname_patterns=[r"\.unbounce\.com", r"unbouncepages\.com"],
        http_fingerprints=["The requested URL was not found on this server"],
    ),
    # HubSpot
    ProviderFingerprint(
        service="HubSpot",
        cname_patterns=[r"\.hubspot\.net", r"\.hs-sites\.com"],
        http_fingerprints=["Domain not found", "does not exist in our system"],
    ),
    # Intercom
    ProviderFingerprint(
        service="Intercom",
        cname_patterns=[r"custom\.intercom\.help"],
        http_fingerprints=["This page is reserved for artistic dogs", "Uh oh. That page doesn"],
    ),
    # Ghost
    ProviderFingerprint(
        service="Ghost",
        cname_patterns=[r"\.ghost\.io"],
        http_fingerprints=["The thing you were looking for is no longer here"],
    ),
    # Cargo Collective
    ProviderFingerprint(
        service="Cargo Collective",
        cname_patterns=[r"cargocollective\.com"],
        http_fingerprints=["404 Not Found"],
    ),
    # Fly.io
    ProviderFingerprint(
        service="Fly.io",
        cname_patterns=[r"\.fly\.dev"],
        http_fingerprints=[],
        nxdomain=True,
    ),
    # Vercel
    ProviderFingerprint(
        service="Vercel",
        cname_patterns=[r"\.vercel\.app", r"\.now\.sh", r"cname\.vercel-dns\.com"],
        http_fingerprints=["The deployment could not be found"],
    ),
    # Render
    ProviderFingerprint(
        service="Render",
        cname_patterns=[r"\.onrender\.com"],
        http_fingerprints=["Not Found"],
        nxdomain=True,
    ),
    # Google Cloud
    ProviderFingerprint(
        service="Google Cloud Storage",
        cname_patterns=[r"c\.storage\.googleapis\.com", r"storage\.googleapis\.com"],
        http_fingerprints=["The specified bucket does not exist", "NoSuchBucket"],
    ),
    # Bitbucket
    ProviderFingerprint(
        service="Bitbucket",
        cname_patterns=[r"\.bitbucket\.io"],
        http_fingerprints=["Repository not found"],
    ),
    # ReadMe.io
    ProviderFingerprint(
        service="ReadMe.io",
        cname_patterns=[r"\.readme\.io"],
        http_fingerprints=["Project doesnt exist"],
    ),
    # LaunchRock
    ProviderFingerprint(
        service="LaunchRock",
        cname_patterns=[r"\.launchrock\.com"],
        http_fingerprints=["It looks like you may have taken a wrong turn somewhere"],
    ),
    # Gemfury
    ProviderFingerprint(
        service="Gemfury",
        cname_patterns=[r"\.furyns\.com"],
        http_fingerprints=["404: This page could not be found"],
    ),
    # Agile CRM
    ProviderFingerprint(
        service="Agile CRM",
        cname_patterns=[r"\.agilecrm\.com"],
        http_fingerprints=["Sorry, this page is no longer available"],
    ),
    # Anima
    ProviderFingerprint(
        service="Anima",
        cname_patterns=[r"\.animaapp\.io"],
        http_fingerprints=["The page you were looking for does not exist"],
    ),
    # Campaign Monitor
    ProviderFingerprint(
        service="Campaign Monitor",
        cname_patterns=[r"\.createsend\.com", r"\.cmail.*\.com"],
        http_fingerprints=["Trying to access your account?"],
    ),
    # Canny
    ProviderFingerprint(
        service="Canny",
        cname_patterns=[r"\.canny\.io"],
        http_fingerprints=["Company Not Found", "There is no such company"],
    ),
    # Tilda
    ProviderFingerprint(
        service="Tilda",
        cname_patterns=[r"\.tilda\.ws"],
        http_fingerprints=["Please renew your subscription"],
    ),
    # SmartJobBoard
    ProviderFingerprint(
        service="SmartJobBoard",
        cname_patterns=[r"\.smartjobboard\.com"],
        http_fingerprints=["This job board website is either expired or its domain name is invalid"],
    ),
    # Strikingly
    ProviderFingerprint(
        service="Strikingly",
        cname_patterns=[r"\.s\.strikinglydns\.com", r"\.strikingly\.com"],
        http_fingerprints=["page not found", "But if you"],
    ),
    # Uptimerobot
    ProviderFingerprint(
        service="UptimeRobot",
        cname_patterns=[r"\.uptimerobot\.com"],
        http_fingerprints=["page not found", "This public status page"],
    ),
    # Webflow
    ProviderFingerprint(
        service="Webflow",
        cname_patterns=[r"proxy-ssl\.webflow\.com", r"\.webflow\.io"],
        http_fingerprints=["The page you are looking for doesn't exist or has been moved"],
    ),
    # Wix
    ProviderFingerprint(
        service="Wix",
        cname_patterns=[r"\.wixsite\.com", r"\.wixdns\.net"],
        http_fingerprints=["Error ConnectYourDomain occurred", "Looks Like This Domain Isn"],
    ),
    # Discourse
    ProviderFingerprint(
        service="Discourse",
        cname_patterns=[r"\.trydiscourse\.com"],
        http_fingerprints=[],
        nxdomain=True,
    ),
    # Helpjuice
    ProviderFingerprint(
        service="Helpjuice",
        cname_patterns=[r"\.helpjuice\.com"],
        http_fingerprints=["We could not find what you're looking for"],
    ),
    # Helpscout
    ProviderFingerprint(
        service="Helpscout",
        cname_patterns=[r"\.helpscoutdocs\.com"],
        http_fingerprints=["No settings were found for this company"],
    ),
    # JetBrains YouTrack
    ProviderFingerprint(
        service="JetBrains YouTrack",
        cname_patterns=[r"\.myjetbrains\.com"],
        http_fingerprints=["is not a registered InCloud YouTrack"],
    ),
    # Kinsta
    ProviderFingerprint(
        service="Kinsta",
        cname_patterns=[r"\.kinsta\.cloud"],
        http_fingerprints=["No Site For Domain"],
    ),
    # Ngrok
    ProviderFingerprint(
        service="Ngrok",
        cname_patterns=[r"\.ngrok\.io", r"\.ngrok-free\.app"],
        http_fingerprints=["Tunnel *.ngrok.io not found", "ngrok.com/dns"],
        nxdomain=True,
    ),
    # Digital Ocean
    ProviderFingerprint(
        service="Digital Ocean",
        cname_patterns=[r"\.digitaloceanspaces\.com"],
        http_fingerprints=["Domain uses DO name servers with no records"],
        nxdomain=True,
    ),
]


def _resolve_cname_chain(hostname: str, max_depth: int = 10) -> list[str]:
    """Resolve CNAME chain for a hostname. Returns list of CNAME targets."""
    import dns.resolver
    import dns.exception

    cnames = []
    current = hostname
    for _ in range(max_depth):
        try:
            answers = dns.resolver.resolve(current, "CNAME")
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                cnames.append(target)
                current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.DNSException):
            break
    return cnames


def _resolve_cname_chain_fallback(hostname: str) -> tuple[list[str], bool]:
    """Fallback CNAME resolution using socket + basic DNS.
    Returns (cname_list, is_nxdomain).
    """
    cnames = []
    is_nxdomain = False
    try:
        result = socket.getaddrinfo(hostname, None)
        if not result:
            is_nxdomain = True
    except socket.gaierror as e:
        if "Name or service not known" in str(e) or "getaddrinfo failed" in str(e) or "11001" in str(e):
            is_nxdomain = True
    except Exception:
        pass
    return cnames, is_nxdomain


async def _resolve_cname(hostname: str) -> tuple[list[str], bool]:
    """Async wrapper for CNAME resolution.
    Returns (cname_chain, is_nxdomain).
    """
    loop = asyncio.get_event_loop()
    try:
        import dns.resolver  # noqa: F401
        cnames = await loop.run_in_executor(None, _resolve_cname_chain, hostname)
        is_nxdomain = False
        if cnames:
            try:
                await loop.run_in_executor(None, socket.getaddrinfo, cnames[-1], None)
            except socket.gaierror:
                is_nxdomain = True
        else:
            try:
                await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
            except socket.gaierror:
                is_nxdomain = True
        return cnames, is_nxdomain
    except ImportError:
        return await loop.run_in_executor(None, _resolve_cname_chain_fallback, hostname)


def _match_provider(cnames: list[str], hostname: str) -> list[ProviderFingerprint]:
    """Match CNAME targets against known vulnerable providers."""
    matches = []
    all_targets = " ".join(cnames + [hostname]).lower()
    for fp in FINGERPRINTS:
        for pattern in fp.cname_patterns:
            if re.search(pattern, all_targets, re.I):
                matches.append(fp)
                break
    return matches


async def _check_http_fingerprint(
    http_client: httpx.AsyncClient,
    url: str,
    fingerprints: list[str],
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """Fetch URL and check response body for takeover fingerprints.
    Returns (is_vulnerable, matched_fingerprint).
    """
    if not fingerprints:
        return False, ""
    try:
        resp = await http_client.get(url, timeout=timeout, follow_redirects=True)
        body = resp.text[:10000].lower()
        for fp in fingerprints:
            if fp.lower() in body:
                return True, fp
    except Exception:
        pass
    return False, ""


@dataclass
class TakeoverResult:
    hostname: str
    vulnerable: bool
    service: str
    evidence: str
    cname_chain: list[str]
    severity: str = "High"
    confidence: str = "High"


async def check_subdomain_takeover(
    hostnames: list[str],
    http_client: httpx.AsyncClient | None = None,
    progress_callback: Any = None,
    max_concurrent: int = 10,
) -> list[TakeoverResult]:
    """Check a list of subdomains for takeover vulnerabilities.

    Args:
        hostnames: List of hostnames/subdomains to check
        http_client: Optional httpx client (creates one if not provided)
        progress_callback: Optional callback(step, data) for live updates
        max_concurrent: Max concurrent DNS/HTTP checks

    Returns:
        List of TakeoverResult for vulnerable subdomains
    """
    if not hostnames:
        return []

    own_client = http_client is None
    if own_client:
        http_client = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        )

    results: list[TakeoverResult] = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _check_one(hostname: str) -> TakeoverResult | None:
        async with semaphore:
            try:
                cnames, is_nxdomain = await _resolve_cname(hostname)
                matched_providers = _match_provider(cnames, hostname)

                if not matched_providers and not is_nxdomain:
                    return None

                for provider in matched_providers:
                    # NXDOMAIN-based takeover
                    if provider.nxdomain and is_nxdomain:
                        return TakeoverResult(
                            hostname=hostname,
                            vulnerable=True,
                            service=provider.service,
                            evidence=f"CNAME points to {provider.service} but resolves to NXDOMAIN. "
                                     f"The service instance appears abandoned/unclaimed.",
                            cname_chain=cnames,
                            severity=provider.severity,
                            confidence="High",
                        )

                    # HTTP fingerprint-based takeover
                    if provider.http_fingerprints:
                        for scheme in ("https", "http"):
                            url = f"{scheme}://{hostname}/"
                            is_vuln, matched_fp = await _check_http_fingerprint(
                                http_client, url, provider.http_fingerprints
                            )
                            if is_vuln:
                                return TakeoverResult(
                                    hostname=hostname,
                                    vulnerable=True,
                                    service=provider.service,
                                    evidence=f"HTTP response contains takeover fingerprint: "
                                             f"'{matched_fp}'. CNAME chain: {' -> '.join(cnames) or hostname}",
                                    cname_chain=cnames,
                                    severity=provider.severity,
                                    confidence="High",
                                )

                # General NXDOMAIN with a CNAME (dangling record)
                if is_nxdomain and cnames:
                    return TakeoverResult(
                        hostname=hostname,
                        vulnerable=True,
                        service="Unknown (Dangling CNAME)",
                        evidence=f"CNAME record exists ({' -> '.join(cnames)}) but the target "
                                 f"does not resolve (NXDOMAIN). This dangling record may be claimable.",
                        cname_chain=cnames,
                        severity="Medium",
                        confidence="Medium",
                    )

            except Exception as e:
                logger.debug("Takeover check failed for %s: %s", hostname, e)
            return None

    if progress_callback:
        progress_callback("subdomain_takeover_start", {
            "total_hosts": len(hostnames),
        })

    tasks = [_check_one(h) for h in hostnames]
    completed = await asyncio.gather(*tasks, return_exceptions=True)

    for result in completed:
        if isinstance(result, TakeoverResult) and result.vulnerable:
            results.append(result)
            if progress_callback:
                progress_callback("subdomain_takeover_finding", {
                    "hostname": result.hostname,
                    "service": result.service,
                })

    if own_client:
        await http_client.aclose()

    if progress_callback:
        progress_callback("subdomain_takeover_done", {
            "checked": len(hostnames),
            "vulnerable": len(results),
        })

    return results


def build_takeover_findings(results: list[TakeoverResult]) -> list[dict]:
    """Convert TakeoverResults into scanner finding dicts."""
    findings = []
    for r in results:
        findings.append({
            "title": f"Subdomain Takeover — {r.hostname} ({r.service})",
            "severity": r.severity,
            "url": f"https://{r.hostname}",
            "description": (
                f"The subdomain {r.hostname} has a DNS record (CNAME) pointing to "
                f"{r.service}, but the destination appears unclaimed or abandoned. "
                f"An attacker can register the service endpoint and serve arbitrary "
                f"content on this subdomain, enabling phishing, cookie theft, or "
                f"bypassing same-origin protections."
            ),
            "evidence": r.evidence,
            "cwe": "CWE-284",
            "owasp": "A05:2021 - Security Misconfiguration",
            "remediation": (
                f"Remove the dangling DNS record for {r.hostname}, or reclaim the "
                f"{r.service} resource. If the subdomain is no longer needed, delete "
                f"the CNAME/A record. If still needed, re-provision the service."
            ),
            "confidence": r.confidence,
            "category": "Subdomain Takeover",
            "parameter": f"CNAME: {' -> '.join(r.cname_chain) if r.cname_chain else 'N/A'}",
        })
    return findings
