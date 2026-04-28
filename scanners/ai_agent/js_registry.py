"""Global JS URL registry — collects every JS resource URL the scanner
encounters across the entire scan, regardless of which phase loaded it.

Why this exists
---------------
Library-version-CVE detection (OWASP A06) used to run only on URLs collected
during the seed-host's passive-recon pass.  That misses JS files loaded by:

* The login / SSO flow (different host, browser leaves it before passive
  recon runs).
* MFA / captcha / OAuth provider widgets.
* SPA route-specific bundles fetched after the initial passive pass.
* In-scope sibling sub-domains discovered later in the scan.

The registry is populated by listeners in:

* ``auth.py``                — Playwright ``response`` listener at login start.
* ``spa_crawler.py``         — already records per-page network traffic.
* ``tools.py.get_network_log`` — LLM tool calls that read the network log.

At end-of-scan ``agent.py`` calls
``passive_recon._check_js_library_vulnerabilities(http_client, registry.in_scope_urls(...))``
once over the *union* of all collected URLs.  De-duplication and
in-scope filtering happen inside the registry; the underlying CVE-lookup
call remains unchanged.

Design goals
------------
* Cheap and threadsafe-ish (single-event-loop, but multiple coroutines push).
* No external dependencies — pure stdlib.
* Identifying URL hash (host+path) so cache-busted but identical files
  collapse to one entry.
* Source-phase tracking so reports can say "first seen during auth" vs.
  "during SPA crawl".
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _looks_like_js(url: str) -> bool:
    """Best-effort: does this URL point at a JS asset?

    We accept .js / .mjs (also with query string version pin like ?v=1.2.3),
    plus URLs whose path *contains* a known JS-style fingerprint such as
    ``/main.js``, ``/vendor.bundle.js``.

    Stylesheets are also worth fingerprinting (Bootstrap CSS leaks its
    version in a header comment) — but we keep this strict for v1 and
    register them via a separate hook if needed.
    """
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    path = (parsed.path or "").lower()
    if path.endswith(".js") or path.endswith(".mjs"):
        return True
    # Path with a .js segment followed by a version-style query string.
    if ".js" in path and (path.endswith(".js") or "?v=" in url.lower()):
        return True
    return False


def _identity_key(url: str) -> str:
    """Collapse cache-busted variants of the same file to one identity.

    ``https://cdn.example.com/main.js?v=1234`` and
    ``https://cdn.example.com/main.js?build=abcd`` both reduce to
    ``cdn.example.com/main.js``.
    """
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        return f"{host}{p.path}"
    except Exception:
        return url


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class JSAsset:
    """One JS resource the scanner has observed.

    Attributes
    ----------
    url:
        Full original URL (with query string).  Preserved verbatim so that
        downstream fetches can reuse cached responses.
    host:
        Lowercase hostname extracted from ``url``.
    source_phase:
        Free-form label of where this URL was first observed
        (``"auth"``, ``"spa_crawl"``, ``"passive_recon"``, ``"llm_tool"``).
    """
    url: str
    host: str
    source_phase: str


# ── Registry ────────────────────────────────────────────────────────────────

class JSUrlRegistry:
    """Scan-scope set of JS URLs, deduplicated by host+path."""

    def __init__(self) -> None:
        # identity_key -> JSAsset (first observation wins for source_phase)
        self._assets: dict[str, JSAsset] = {}
        # Per-source counters for diagnostics (how many adds came from each phase).
        self._source_counts: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, url: str, source_phase: str = "unknown") -> bool:
        """Record an observation of ``url``.

        Returns True if this is the first time we've seen this identity,
        False if it was a duplicate.  Non-JS URLs and malformed inputs
        are silently dropped.
        """
        if not _looks_like_js(url):
            return False
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return False

        key = _identity_key(url)
        self._source_counts[source_phase] = self._source_counts.get(source_phase, 0) + 1
        if key in self._assets:
            return False
        self._assets[key] = JSAsset(url=url, host=host, source_phase=source_phase)
        return True

    def add_many(self, urls: Iterable[str], source_phase: str = "unknown") -> int:
        """Bulk add.  Returns count of NEW (non-duplicate) entries added."""
        added = 0
        for u in urls:
            if self.add(u, source_phase):
                added += 1
        return added

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._assets)

    def all_assets(self) -> list[JSAsset]:
        return list(self._assets.values())

    def all_urls(self) -> list[str]:
        return [a.url for a in self._assets.values()]

    def in_scope_urls(self, scope_hosts: Iterable[str]) -> list[str]:
        """Return URLs whose host matches any in-scope host (case-insensitive,
        prefix-or-exact match against hostname)."""
        scope = {h.lower().lstrip(".") for h in scope_hosts if h}
        if not scope:
            # No filter provided -> return everything
            return self.all_urls()
        out: list[str] = []
        for asset in self._assets.values():
            host = asset.host
            if host in scope:
                out.append(asset.url)
                continue
            # Match sub-domains: foo.example.com matches example.com
            for s in scope:
                if host == s or host.endswith("." + s):
                    out.append(asset.url)
                    break
        return out

    def hosts(self) -> set[str]:
        return {a.host for a in self._assets.values()}

    def by_host(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for asset in self._assets.values():
            out.setdefault(asset.host, []).append(asset.url)
        return out

    def stats(self) -> dict:
        """Diagnostic snapshot for logging at end of scan."""
        return {
            "unique_urls": len(self._assets),
            "unique_hosts": len(self.hosts()),
            "by_source": dict(self._source_counts),
        }


__all__ = [
    "JSAsset",
    "JSUrlRegistry",
]
