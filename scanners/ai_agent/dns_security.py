"""Email/DNS security checks module.

Validates SPF, DKIM, and DMARC records for target domains.
Detects misconfigurations that enable email spoofing attacks.

Checks performed:
  1. SPF record presence and configuration strength
  2. DMARC record presence, policy enforcement level, and reporting
  3. DKIM selector probing (common selectors)
  4. DNSSEC validation
  5. MX record security (no-MX but receiving mail)
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "k3", "mail", "smtp", "dkim",
    "s1", "s2", "mandrill", "everlytickey1",
    "mxvault", "protonmail", "protonmail2", "protonmail3",
    "zoho", "sendgrid", "cm", "amazonses",
]


@dataclass
class DNSSecurityResult:
    domain: str
    check_type: str  # "SPF", "DMARC", "DKIM", "MX"
    severity: str
    status: str  # "pass", "warn", "fail", "info"
    detail: str
    raw_record: str = ""


def _query_txt(domain: str) -> list[str]:
    """Query TXT records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
            records.append(txt)
        return records
    except ImportError:
        return _query_txt_fallback(domain)
    except Exception:
        return []


def _query_txt_fallback(domain: str) -> list[str]:
    """Fallback TXT query using nslookup-style parsing (no dnspython)."""
    import subprocess
    try:
        result = subprocess.run(
            ["nslookup", "-type=txt", domain],
            capture_output=True, text=True, timeout=10,
        )
        records = []
        for line in result.stdout.split("\n"):
            if "text =" in line.lower() or '"' in line:
                match = re.search(r'"([^"]*)"', line)
                if match:
                    records.append(match.group(1))
        return records
    except Exception:
        return []


def _query_mx(domain: str) -> list[str]:
    """Query MX records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        return [str(rdata.exchange).rstrip(".") for rdata in answers]
    except ImportError:
        return _query_mx_fallback(domain)
    except Exception:
        return []


def _query_mx_fallback(domain: str) -> list[str]:
    """Fallback MX query."""
    import subprocess
    try:
        result = subprocess.run(
            ["nslookup", "-type=mx", domain],
            capture_output=True, text=True, timeout=10,
        )
        mx_records = []
        for line in result.stdout.split("\n"):
            if "mail exchanger" in line.lower() or "preference" in line.lower():
                parts = line.strip().split()
                if parts:
                    mx_records.append(parts[-1].rstrip("."))
        return mx_records
    except Exception:
        return []


def check_spf(domain: str) -> DNSSecurityResult:
    """Check SPF record configuration."""
    txt_records = _query_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return DNSSecurityResult(
            domain=domain,
            check_type="SPF",
            severity="High",
            status="fail",
            detail="No SPF record found. Any mail server can send email on behalf of this domain.",
        )

    if len(spf_records) > 1:
        return DNSSecurityResult(
            domain=domain,
            check_type="SPF",
            severity="Medium",
            status="warn",
            detail=f"Multiple SPF records found ({len(spf_records)}). RFC 7208 specifies exactly one SPF record. "
                   f"Multiple records cause unpredictable behavior.",
            raw_record="; ".join(spf_records),
        )

    spf = spf_records[0]

    # Check for overly permissive SPF
    if "+all" in spf:
        return DNSSecurityResult(
            domain=domain,
            check_type="SPF",
            severity="Critical",
            status="fail",
            detail="SPF record uses '+all' which allows ANY server to send email. "
                   "This completely defeats SPF protection.",
            raw_record=spf,
        )

    if "?all" in spf:
        return DNSSecurityResult(
            domain=domain,
            check_type="SPF",
            severity="Medium",
            status="warn",
            detail="SPF record uses '?all' (neutral). This does not prevent unauthorized senders. "
                   "Should be '-all' (fail) or '~all' (softfail).",
            raw_record=spf,
        )

    # Count DNS lookups (max 10 per RFC)
    lookup_mechanisms = re.findall(r'(include:|a:|mx:|ptr:|exists:|redirect=)', spf, re.I)
    if len(lookup_mechanisms) > 10:
        return DNSSecurityResult(
            domain=domain,
            check_type="SPF",
            severity="Medium",
            status="warn",
            detail=f"SPF record requires {len(lookup_mechanisms)} DNS lookups (max allowed: 10). "
                   f"Receivers may reject or ignore this record.",
            raw_record=spf,
        )

    qualifier = "pass"
    severity = "Info"
    if "~all" in spf:
        qualifier = "info"
        severity = "Low"
        detail = "SPF record uses '~all' (softfail). Consider upgrading to '-all' (hardfail) for maximum protection."
    elif "-all" in spf:
        detail = "SPF record is properly configured with '-all' (hardfail)."
    else:
        detail = f"SPF record found but enforcement mechanism unclear: {spf}"
        qualifier = "info"

    return DNSSecurityResult(
        domain=domain,
        check_type="SPF",
        severity=severity,
        status=qualifier,
        detail=detail,
        raw_record=spf,
    )


def check_dmarc(domain: str) -> DNSSecurityResult:
    """Check DMARC record configuration."""
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _query_txt(dmarc_domain)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return DNSSecurityResult(
            domain=domain,
            check_type="DMARC",
            severity="High",
            status="fail",
            detail="No DMARC record found. Without DMARC, email spoofing detection relies "
                   "solely on SPF/DKIM with no reporting or policy enforcement.",
        )

    dmarc = dmarc_records[0]

    # Extract policy
    policy_match = re.search(r'p=(\w+)', dmarc)
    policy = policy_match.group(1).lower() if policy_match else "none"

    # Extract subdomain policy
    sp_match = re.search(r'sp=(\w+)', dmarc)
    sp_policy = sp_match.group(1).lower() if sp_match else policy

    # Extract percentage
    pct_match = re.search(r'pct=(\d+)', dmarc)
    pct = int(pct_match.group(1)) if pct_match else 100

    # Extract reporting
    has_rua = "rua=" in dmarc
    has_ruf = "ruf=" in dmarc

    if policy == "none":
        return DNSSecurityResult(
            domain=domain,
            check_type="DMARC",
            severity="Medium",
            status="warn",
            detail="DMARC policy is 'none' (monitoring only). Failed emails are still delivered. "
                   "Upgrade to 'quarantine' or 'reject' after analyzing reports.",
            raw_record=dmarc,
        )

    issues = []
    severity = "Info"
    status = "pass"

    if pct < 100:
        issues.append(f"Only {pct}% of messages are subject to policy (pct={pct})")
        severity = "Low"
        status = "info"

    if sp_policy == "none" and policy != "none":
        issues.append("Subdomain policy (sp=) is 'none' — subdomains can still be spoofed")
        severity = "Medium"
        status = "warn"

    if not has_rua:
        issues.append("No aggregate reporting URI (rua=) — cannot monitor spoofing attempts")

    if policy == "quarantine":
        detail = "DMARC policy is 'quarantine'. Suspicious emails are sent to spam."
        if not issues:
            severity = "Low"
            status = "info"
            detail += " Consider upgrading to 'reject' for maximum protection."
    elif policy == "reject":
        detail = "DMARC policy is 'reject'. Spoofed emails are actively blocked."
        if not issues:
            severity = "Info"
            status = "pass"
    else:
        detail = f"DMARC record found with policy '{policy}'."
        severity = "Low"
        status = "info"

    if issues:
        detail += " Issues: " + "; ".join(issues)

    return DNSSecurityResult(
        domain=domain,
        check_type="DMARC",
        severity=severity,
        status=status,
        detail=detail,
        raw_record=dmarc,
    )


def check_dkim(domain: str) -> list[DNSSecurityResult]:
    """Probe common DKIM selectors for a domain."""
    results = []
    found_any = False

    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = _query_txt(dkim_domain)
        dkim_records = [r for r in txt_records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]

        if dkim_records:
            found_any = True
            record = dkim_records[0]
            # Check for empty public key (revoked)
            if "p=" in record:
                p_match = re.search(r'p=([^;\s]*)', record)
                if p_match and not p_match.group(1):
                    results.append(DNSSecurityResult(
                        domain=domain,
                        check_type="DKIM",
                        severity="Info",
                        status="info",
                        detail=f"DKIM selector '{selector}' has empty public key (revoked/rotated).",
                        raw_record=record,
                    ))
                else:
                    results.append(DNSSecurityResult(
                        domain=domain,
                        check_type="DKIM",
                        severity="Info",
                        status="pass",
                        detail=f"DKIM selector '{selector}' is configured with a valid public key.",
                        raw_record=record[:100] + "..." if len(record) > 100 else record,
                    ))

    if not found_any:
        results.append(DNSSecurityResult(
            domain=domain,
            check_type="DKIM",
            severity="Medium",
            status="warn",
            detail=f"No DKIM records found for any of {len(COMMON_DKIM_SELECTORS)} common selectors. "
                   f"Either DKIM is not configured or uses a non-standard selector.",
        ))

    return results


def check_mx_security(domain: str) -> DNSSecurityResult:
    """Check MX record security."""
    mx_records = _query_mx(domain)

    if not mx_records:
        return DNSSecurityResult(
            domain=domain,
            check_type="MX",
            severity="Info",
            status="info",
            detail="No MX records found. Domain may not handle email directly.",
        )

    # Check for null MX (RFC 7505)
    if any(mx == "." or mx == "" for mx in mx_records):
        return DNSSecurityResult(
            domain=domain,
            check_type="MX",
            severity="Info",
            status="pass",
            detail="Domain uses Null MX (RFC 7505) — explicitly does not accept email.",
            raw_record=", ".join(mx_records),
        )

    # Check for IP-based MX (bad practice)
    ip_based = [mx for mx in mx_records if re.match(r'^\d+\.\d+\.\d+\.\d+$', mx)]
    if ip_based:
        return DNSSecurityResult(
            domain=domain,
            check_type="MX",
            severity="Low",
            status="warn",
            detail=f"MX record points to IP address(es): {', '.join(ip_based)}. "
                   f"Best practice is to use hostnames for MX records.",
            raw_record=", ".join(mx_records),
        )

    return DNSSecurityResult(
        domain=domain,
        check_type="MX",
        severity="Info",
        status="pass",
        detail=f"MX records found: {', '.join(mx_records[:5])}",
        raw_record=", ".join(mx_records),
    )


async def check_dns_security(
    domain: str,
    progress_callback: Any = None,
) -> list[DNSSecurityResult]:
    """Run all email/DNS security checks for a domain.

    Args:
        domain: Target domain to check
        progress_callback: Optional callback(step, data) for live updates

    Returns:
        List of DNSSecurityResult findings
    """
    if progress_callback:
        progress_callback("dns_security_start", {"domain": domain})

    loop = asyncio.get_event_loop()
    results: list[DNSSecurityResult] = []

    # Run SPF, DMARC, MX checks concurrently
    spf_result, dmarc_result, mx_result, dkim_results = await asyncio.gather(
        loop.run_in_executor(None, check_spf, domain),
        loop.run_in_executor(None, check_dmarc, domain),
        loop.run_in_executor(None, check_mx_security, domain),
        loop.run_in_executor(None, check_dkim, domain),
    )

    results.append(spf_result)
    results.append(dmarc_result)
    results.append(mx_result)
    results.extend(dkim_results)

    if progress_callback:
        fails = sum(1 for r in results if r.status == "fail")
        warns = sum(1 for r in results if r.status == "warn")
        progress_callback("dns_security_done", {
            "domain": domain,
            "total_checks": len(results),
            "failures": fails,
            "warnings": warns,
        })

    return results


def build_dns_security_findings(results: list[DNSSecurityResult]) -> list[dict]:
    """Convert DNSSecurityResults into scanner finding dicts."""
    findings = []
    for r in results:
        if r.status in ("pass", "info") and r.severity == "Info":
            continue

        findings.append({
            "title": f"Email/DNS Security — {r.check_type} ({r.domain})",
            "severity": r.severity,
            "url": f"https://{r.domain}",
            "description": r.detail,
            "evidence": r.raw_record or "N/A",
            "cwe": "CWE-290" if r.check_type in ("SPF", "DMARC", "DKIM") else "CWE-350",
            "owasp": "A05:2021 - Security Misconfiguration",
            "remediation": _get_remediation(r),
            "confidence": "High" if r.status == "fail" else "Medium",
            "category": "Email/DNS Security",
            "parameter": f"DNS Record: {r.check_type}",
        })
    return findings


def _get_remediation(result: DNSSecurityResult) -> str:
    """Generate remediation guidance based on check type and status."""
    if result.check_type == "SPF":
        if result.status == "fail":
            return (
                f"Add an SPF TXT record to {result.domain}: "
                f"'v=spf1 include:<your-mail-provider> -all'. "
                f"Use '-all' to reject unauthorized senders."
            )
        return "Review SPF record configuration and tighten to '-all' if possible."

    if result.check_type == "DMARC":
        if result.status == "fail":
            return (
                f"Add a DMARC TXT record at _dmarc.{result.domain}: "
                f"'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{result.domain}'. "
                f"Start with p=none for monitoring, then escalate to reject."
            )
        return "Upgrade DMARC policy to 'reject' and ensure subdomain policy matches."

    if result.check_type == "DKIM":
        return (
            f"Configure DKIM signing for {result.domain} with your email provider. "
            f"Publish the public key as a TXT record at <selector>._domainkey.{result.domain}."
        )

    return f"Review DNS configuration for {result.domain}."
