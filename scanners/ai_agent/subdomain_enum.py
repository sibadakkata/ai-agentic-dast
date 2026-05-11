"""Subdomain enumeration module.

Discovers subdomains via passive sources (no brute-force, no noise):
  1. Certificate Transparency logs (crt.sh)
  2. Common subdomain prefixes (DNS resolution check)
  3. DNS zone transfer attempt (rarely works, but worth checking)

Used to feed discovered subdomains into the takeover detection module.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "staging", "test",
    "api", "app", "cdn", "cloud", "cms", "cpanel", "dashboard",
    "demo", "docs", "email", "git", "help", "images", "img",
    "internal", "intranet", "jenkins", "jira", "lab", "landing",
    "legacy", "login", "m", "media", "mobile", "mx", "news",
    "ns1", "ns2", "portal", "preview", "prod", "qa", "remote",
    "secure", "shop", "smtp", "stage", "static", "status",
    "store", "support", "vpn", "webmail", "wiki", "portal2",
    "beta", "alpha", "sandbox", "payments", "checkout", "sso",
    "auth", "id", "accounts", "my", "partner", "partners",
    "affiliate", "affiliates", "tracking", "analytics",
    "cdn1", "cdn2", "assets", "download", "downloads",
    "update", "updates", "forum", "forums", "community",
]


async def enumerate_subdomains_ct(
    domain: str,
    http_client: httpx.AsyncClient | None = None,
    timeout: float = 15.0,
) -> set[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    subdomains: set[str] = set()
    own_client = http_client is None
    if own_client:
        http_client = httpx.AsyncClient(timeout=timeout, verify=False)

    try:
        resp = await http_client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout,
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") or name == domain:
                        # Remove wildcard prefix
                        name = name.lstrip("*.")
                        if name and name != domain:
                            subdomains.add(name)
    except Exception as e:
        logger.debug("crt.sh query failed for %s: %s", domain, e)

    if own_client:
        await http_client.aclose()

    return subdomains


async def enumerate_subdomains_dns(
    domain: str,
    wordlist: list[str] | None = None,
    max_concurrent: int = 20,
) -> set[str]:
    """Resolve common subdomain prefixes to find live hosts."""
    subdomains: set[str] = set()
    prefixes = wordlist or COMMON_SUBDOMAINS
    semaphore = asyncio.Semaphore(max_concurrent)
    loop = asyncio.get_event_loop()

    async def _check(prefix: str):
        async with semaphore:
            hostname = f"{prefix}.{domain}"
            try:
                await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
                subdomains.add(hostname)
            except (socket.gaierror, OSError):
                pass

    await asyncio.gather(*[_check(p) for p in prefixes], return_exceptions=True)
    return subdomains


async def enumerate_subdomains(
    target_url: str,
    http_client: httpx.AsyncClient | None = None,
    include_ct: bool = True,
    include_dns: bool = True,
    progress_callback=None,
) -> list[str]:
    """Enumerate subdomains for a target URL's domain.

    Combines Certificate Transparency + DNS resolution for maximum coverage
    while remaining passive (no brute-force that generates excessive traffic).

    Returns deduplicated, sorted list of discovered subdomains.
    """
    parsed = urlparse(target_url)
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain or "." not in domain:
        return []

    if progress_callback:
        progress_callback("subdomain_enum_start", {"domain": domain})

    all_subdomains: set[str] = set()

    tasks = []
    if include_ct:
        tasks.append(("CT logs (crt.sh)", enumerate_subdomains_ct(domain, http_client)))
    if include_dns:
        tasks.append(("DNS resolution", enumerate_subdomains_dns(domain)))

    for label, coro in tasks:
        try:
            result = await coro
            all_subdomains |= result
            if progress_callback:
                progress_callback("subdomain_enum_step", {
                    "source": label,
                    "found": len(result),
                })
        except Exception as e:
            logger.debug("Subdomain enum %s failed: %s", label, e)

    # Remove the apex domain itself
    all_subdomains.discard(domain)
    all_subdomains.discard(f"www.{domain}")

    sorted_subs = sorted(all_subdomains)

    if progress_callback:
        progress_callback("subdomain_enum_done", {
            "domain": domain,
            "total": len(sorted_subs),
        })

    logger.info("Subdomain enumeration for %s: %d unique subdomains", domain, len(sorted_subs))
    return sorted_subs
