"""Tests for the active baseline probe.

Pins the contract for ``scanners.ai_agent.active_baseline.run_bare_root_sqli_probe``:

1. With a fake http_client that returns control responses fast and attack
   responses slow (>= 4s), the probe MUST emit one Critical finding per
   confirmed host.
2. With a fake http_client that returns all responses fast, the probe
   MUST emit zero findings (no false positives on a non-vulnerable target).
3. With a fake http_client that returns ALL responses slow (slow target,
   not SQLi), the delta is < threshold so probe MUST emit zero findings.
4. ``hosts`` input may be a mix of bare hostnames, full URLs, and
   duplicates — the probe MUST normalize and dedupe internally.
5. ``cancel_flag`` set mid-probe MUST stop iteration cleanly.
6. ``http_client`` raising on attack URL MUST NOT crash the probe (caller
   never sees an exception); the failed payload is silently skipped.

These tests use an asyncio-style mock http_client; they do NOT make any
real network requests.
"""
from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest

from scanners.ai_agent.active_baseline import (
    _BARE_ROOT_PAYLOADS,
    _normalize_hosts,
    run_bare_root_sqli_probe,
)


class _FakeResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


class _FakeAsyncHttpClient:
    """Minimal stub that returns deterministic timings.

    ``timing_for(url)`` is called for every GET and must return the
    seconds to "sleep" before responding. Any URL containing ``"SLEEP"``
    or ``"pg_sleep"`` (case-insensitive) is treated as the attack URL.
    """

    def __init__(self, *, control_s: float, attack_s: float, raise_on_attack: bool = False) -> None:
        self._control_s = control_s
        self._attack_s = attack_s
        self._raise = raise_on_attack
        self.calls: list[tuple[str, float]] = []

    async def get(self, url: str, timeout: float | None = None, **_kwargs):
        is_attack = (
            "SLEEP" in url.upper()
            or "PG_SLEEP" in url.upper()
            or "WAITFOR" in url.upper()
        )
        delay = self._attack_s if is_attack else self._control_s
        if self._raise and is_attack:
            await asyncio.sleep(0.001)
            raise RuntimeError("simulated transport error")
        await asyncio.sleep(delay)
        self.calls.append((url, delay))
        return _FakeResponse(200)


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_bare_root_probe_emits_critical_when_attack_is_slow():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["test.example.invalid"],
    ))
    assert len(findings) >= 1, "expected at least one finding when attack is >= 4s"
    f = findings[0]
    assert f["severity"] == "Critical"
    assert f["confidence"] == "High"
    assert f["owasp_category"] == "A03:2021"
    assert f["cwe"] == "CWE-89"
    assert "test.example.invalid" in f["url"]
    assert f["parameter"] == "(raw query string)"
    assert f["phase"] == "Active Baseline (Bare-Root SQLi)"
    assert f["_finding_source"] == "active_baseline"


def test_bare_root_probe_no_finding_when_target_is_clean():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["clean.example.invalid"],
    ))
    assert findings == [], "clean target must not produce findings"


def test_bare_root_probe_no_finding_when_target_is_uniformly_slow():
    """A target where every request takes 4s+ has NO delta — not SQLi."""
    client = _FakeAsyncHttpClient(control_s=4.5, attack_s=4.6)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["slow.example.invalid"],
    ))
    assert findings == [], "uniformly slow target must not produce findings"


def test_bare_root_probe_dedupes_input_hosts():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    _run_async(run_bare_root_sqli_probe(
        client,
        [
            "https://dup.example.invalid/path?q=1",
            "dup.example.invalid",
            "DUP.EXAMPLE.INVALID",
            "http://dup.example.invalid:8080",
        ],
    ))
    # 1 control + len(payloads) attack requests for the single dedup'd host
    expected = 1 + len(_BARE_ROOT_PAYLOADS)
    assert len(client.calls) == expected, (
        f"expected {expected} calls for one dedup'd host, got {len(client.calls)}: "
        f"{[c[0] for c in client.calls]}"
    )


def test_bare_root_probe_normalize_hosts_helper():
    out = _normalize_hosts([
        "https://A.example.invalid/x",
        "a.example.invalid",
        "https://b.example.invalid",
        "",
        None,
    ])
    assert out == ["a.example.invalid", "b.example.invalid"]


def test_bare_root_probe_respects_cancel_flag():
    # Set the cancel flag BEFORE calling the probe — should bail out
    # after at most a control GET on the first host.
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    cancel = threading.Event()
    cancel.set()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["c.example.invalid", "c2.example.invalid"],
        cancel_flag=cancel,
    ))
    assert findings == []
    # No requests should fire because cancel is checked at the top of
    # each host iteration.
    assert len(client.calls) == 0


def test_bare_root_probe_swallows_transport_errors_on_attack():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05, raise_on_attack=True)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["err.example.invalid"],
    ))
    # Probe must not crash; with all attacks erroring, no findings.
    assert findings == []


def test_bare_root_probe_progress_callback_is_called():
    events: list[tuple[str, dict]] = []
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    _run_async(run_bare_root_sqli_probe(
        client,
        ["p.example.invalid"],
        on_progress=lambda ev, data: events.append((ev, data)),
    ))
    assert any(ev == "active_baseline_start" for ev, _ in events)
    assert any(ev == "active_baseline_end" for ev, _ in events)
    assert any(ev == "active_baseline_step" for ev, _ in events)


def test_bare_root_probe_finding_callback_is_called_per_finding():
    callback_findings: list[dict] = []
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["cb.example.invalid"],
        on_finding=callback_findings.append,
    ))
    assert len(findings) == len(callback_findings) >= 1
    assert findings[0] is callback_findings[0]


def test_bare_root_probe_skips_host_when_control_fails():
    """If the control GET errors out, the host MUST be skipped — no
    attacks attempted, no false positive based on missing baseline."""
    class _ControlFailingClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def get(self, url, timeout=None, **_kwargs):
            self.calls.append(url)
            await asyncio.sleep(0.001)
            raise RuntimeError("control failed")

    client = _ControlFailingClient()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["bad.example.invalid"],
    ))
    assert findings == []
    # Only the control request should have been attempted.
    assert len(client.calls) == 1, (
        f"expected exactly 1 (control) call when control fails, got {len(client.calls)}"
    )


def test_bare_root_probe_emits_no_finding_when_only_one_attack_hits_then_confirm_fails():
    """Confirmation step MUST run before reporting. If the second attack
    is fast (network jitter cleared up), no finding is emitted."""
    state = {"first_attack": True}

    class _JitterClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, float]] = []

        async def get(self, url, timeout=None):
            if "SLEEP" in url.upper() or "PG_SLEEP" in url.upper():
                if state["first_attack"]:
                    state["first_attack"] = False
                    await asyncio.sleep(4.5)
                    self.calls.append((url, 4.5))
                else:
                    await asyncio.sleep(0.05)
                    self.calls.append((url, 0.05))
            else:
                await asyncio.sleep(0.05)
                self.calls.append((url, 0.05))
            return _FakeResponse(200)

    client = _JitterClient()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["jitter.example.invalid"],
    ))
    assert findings == [], (
        "single jitter spike that doesn't reproduce on confirm MUST NOT "
        "emit a finding"
    )


# ═══════════════════════════════════════════════════════════════════════
# Tests for run_cache_poisoning_probe
# ═══════════════════════════════════════════════════════════════════════
from scanners.ai_agent.active_baseline import run_cache_poisoning_probe


class _FakeCachePoisonResponse:
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


class _CachePoisonClient:
    """Simulates a server that reflects X-Forwarded-Host into the body."""
    def __init__(self, *, reflect=True, cached=False):
        self._reflect = reflect
        self._cached = cached
        self._poisoned_url = None
        self._canary = None

    async def get(self, url, timeout=None, headers=None, **_kw):
        headers = headers or {}
        xfh = headers.get("X-Forwarded-Host", "")
        if xfh and "cpcanary" in xfh:
            self._canary = xfh
            self._poisoned_url = url
            if self._reflect:
                return _FakeCachePoisonResponse(
                    text=f'<meta http-equiv="refresh" content="0;url=https://{xfh}/">',
                )
            return _FakeCachePoisonResponse(text="<html>clean</html>")
        if self._cached and self._poisoned_url == url and self._canary:
            return _FakeCachePoisonResponse(
                text=f'<meta http-equiv="refresh" content="0;url=https://{self._canary}/">',
            )
        return _FakeCachePoisonResponse(text="<html>clean</html>")


def test_cache_poison_reflected_and_cached():
    client = _CachePoisonClient(reflect=True, cached=True)
    findings = _run_async(run_cache_poisoning_probe(client, ["cp.example.invalid"]))
    assert len(findings) >= 1
    f = findings[0]
    assert "Cache Poisoning" in f["title"]
    assert f["severity"] == "High"
    assert f["confidence"] == "High"
    assert "CACHED" in f["evidence"]


def test_cache_poison_reflected_but_not_cached():
    client = _CachePoisonClient(reflect=True, cached=False)
    findings = _run_async(run_cache_poisoning_probe(client, ["cp2.example.invalid"]))
    assert len(findings) >= 1
    f = findings[0]
    assert f["severity"] == "Medium"
    assert "not cached" in f["evidence"]


def test_cache_poison_no_reflection():
    client = _CachePoisonClient(reflect=False, cached=False)
    findings = _run_async(run_cache_poisoning_probe(client, ["clean.example.invalid"]))
    assert findings == []


# ═══════════════════════════════════════════════════════════════════════
# Tests for run_reflected_xss_probe
# ═══════════════════════════════════════════════════════════════════════
from scanners.ai_agent.active_baseline import run_reflected_xss_probe


class _XSSClient:
    """Simulates a server with a search page that reflects ?q= in HTML body.

    The root page contains a discoverable link with ?q= so the dynamic
    discovery engine finds it. Canary/payload reflection is controlled
    via constructor flags.
    """
    ROOT_HTML = (
        '<html><body>'
        '<a href="?q=test">Search</a>'
        '<form action="/"><input name="search"></form>'
        '</body></html>'
    )

    def __init__(self, *, reflect_canary=True, reflect_payload=True):
        self._reflect_canary = reflect_canary
        self._reflect_payload = reflect_payload

    async def get(self, url, timeout=None, headers=None, **_kw):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Root page (no interesting params) -> serve discoverable HTML
        if not params or all(v == [''] for v in params.values()):
            return _FakeCachePoisonResponse(text=self.ROOT_HTML)
        for k, vals in params.items():
            for v in vals:
                if "xsscanary" in v:
                    if self._reflect_canary:
                        return _FakeCachePoisonResponse(text=f"<html>Results for: >{v}<br></html>")
                    return _FakeCachePoisonResponse(text="<html>safe</html>")
                if "<script>" in v.lower() or "<img" in v.lower() or "<svg" in v.lower() or "onfocus" in v.lower():
                    if self._reflect_payload:
                        return _FakeCachePoisonResponse(text=f"<html>Results for: >{v}<br></html>")
                    return _FakeCachePoisonResponse(text="<html>safe</html>")
        if "xsscanary" in parsed.path:
            if self._reflect_canary:
                return _FakeCachePoisonResponse(text=f"<html>Path: >{parsed.path}<br></html>")
        return _FakeCachePoisonResponse(text=self.ROOT_HTML)


def test_xss_finds_reflected_payload():
    client = _XSSClient(reflect_canary=True, reflect_payload=True)
    findings = _run_async(run_reflected_xss_probe(client, ["xss.example.invalid"]))
    assert len(findings) >= 1
    f = findings[0]
    assert "XSS" in f["title"]
    assert f["cwe"] == "CWE-79"


def test_xss_no_finding_when_canary_not_reflected():
    client = _XSSClient(reflect_canary=False, reflect_payload=False)
    findings = _run_async(run_reflected_xss_probe(client, ["safe.example.invalid"]))
    assert findings == []


def test_xss_canary_reflected_but_payload_encoded():
    client = _XSSClient(reflect_canary=True, reflect_payload=False)
    findings = _run_async(run_reflected_xss_probe(client, ["encoded.example.invalid"]))
    assert findings == [], "if payload is not reflected verbatim, no finding"


# ═══════════════════════════════════════════════════════════════════════
# Tests for dynamic parameter discovery
# ═══════════════════════════════════════════════════════════════════════
from scanners.ai_agent.active_baseline import (
    _classify_canary_context,
    _discover_params_from_html,
)


def test_discover_params_from_links():
    html = '<html><a href="?foo=1&bar=2">link</a></html>'
    assert _discover_params_from_html(html, "https://x") == {"foo", "bar"}


def test_discover_params_from_forms():
    html = '<form><input name="username"><input name="password"></form>'
    assert _discover_params_from_html(html, "https://x") == {"username", "password"}


def test_discover_params_from_mixed_sources():
    html = (
        '<a href="?style=a&key=b">map</a>'
        '<form><input name="token"><select name="region"></select></form>'
        '<script src="/js/app.js?v=3&lang=en"></script>'
    )
    params = _discover_params_from_html(html, "https://x")
    assert "style" in params
    assert "key" in params
    assert "token" in params
    assert "region" in params
    assert "v" in params
    assert "lang" in params


def test_discover_params_empty_page():
    html = "<html><body>Nothing here</body></html>"
    assert _discover_params_from_html(html, "https://x") == set()


# ═══════════════════════════════════════════════════════════════════════
# Tests for JS-context XSS classification
# ═══════════════════════════════════════════════════════════════════════


def test_classify_canary_in_event_handler_attr():
    body = """<html><body>
    <a href="#" onclick="return toggle_link('foo', 'xsscanary12345');">Click</a>
    </body></html>"""
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx == "event_handler_attr"


def test_classify_canary_in_script_block():
    body = """<html><script>
    var s = "xsscanary12345";
    </script></html>"""
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx == "script_block"


def test_classify_canary_in_javascript_uri():
    body = '<a href="javascript:alert(\'xsscanary12345\')">x</a>'
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx == "javascript_uri"


def test_classify_canary_in_html_body():
    body = "<html><body>Search results: <p>xsscanary12345</p></body></html>"
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx == "html_body"


def test_classify_canary_not_present():
    body = "<html>nothing here</html>"
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx is None


def test_classify_canary_in_safe_attribute_only():
    body = '<input type="text" value="xsscanary12345">'
    ctx = _classify_canary_context(body, "xsscanary12345")
    assert ctx is None, "canary inside safe value attr should not classify as XSS sink"


class _JSContextXSSClient:
    """Simulates BUGB-3057: a map-tiles server that reflects ``style``
    into an onclick handler. Root page has a discoverable link with
    ``?style=``, so the dynamic discoverer picks it up.

    WAF blocks <, >, =, /, comma but allows JS-string breakout.
    """
    ROOT_HTML = (
        '<html><body>'
        '<a href="?style=default&key=abc">View Map</a>'
        '</body></html>'
    )

    def __init__(self, *, vulnerable=True):
        self._vulnerable = vulnerable

    async def get(self, url, timeout=None, headers=None, **_kw):
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        style = params.get("style", [""])[0]
        key_param = params.get("key", [""])[0]
        decoded = unquote(style or key_param)

        if not decoded or decoded in ("default", "abc"):
            return _FakeCachePoisonResponse(text=self.ROOT_HTML)

        if any(c in decoded for c in ["<", ">", "/", ","]):
            return _FakeCachePoisonResponse(
                text="<html>blocked by WAF</html>", status_code=403,
            )

        if self._vulnerable:
            html = (
                "<html><body>"
                f'<a href="#" onclick="return toggle_link(\'foo\', \'{decoded}\');">Map</a>'
                "</body></html>"
            )
            return _FakeCachePoisonResponse(text=html)
        else:
            safe = (
                decoded
                .replace("&", "&amp;").replace("'", "&#39;")
                .replace('"', "&quot;").replace("`", "&#96;")
                .replace("(", "&#40;").replace(")", "&#41;")
                .replace(";", "&#59;")
            )
            html = (
                "<html><body>"
                f'<a href="#" onclick="return toggle_link(\'foo\', \'{safe}\');">Map</a>'
                "</body></html>"
            )
            return _FakeCachePoisonResponse(text=html)


def test_xss_js_context_detects_bugb_3057_pattern():
    """Dynamic discovery finds ?style= from the root page, canary lands in
    onclick handler, JS-breakout payload fires."""
    client = _JSContextXSSClient(vulnerable=True)
    findings = _run_async(run_reflected_xss_probe(client, ["maptiles.example.invalid"]))
    assert len(findings) >= 1, "expected JS-context XSS finding"
    js_findings = [
        f for f in findings
        if f.get("_xss_context") in ("event_handler_attr", "script_block", "javascript_uri")
    ]
    assert len(js_findings) >= 1, (
        f"expected at least one JS-context finding, got {[f.get('_xss_context') for f in findings]}"
    )
    f = js_findings[0]
    assert f["severity"] == "Critical"
    assert f["parameter"] in ("style", "key"), f"param should be dynamically discovered from page"
    assert "JavaScript Context" in f["title"]
    assert f["cwe"] == "CWE-79"


def test_xss_js_context_no_finding_when_safely_escaped():
    client = _JSContextXSSClient(vulnerable=False)
    findings = _run_async(run_reflected_xss_probe(client, ["safe.example.invalid"]))
    assert findings == [], "safely-escaped JS context must not produce finding"


def test_xss_crawled_urls_feeds_discovery():
    """When crawled_urls includes a page with ?style=, the probe discovers
    and tests that param even if the root page doesn't link to it."""
    client = _JSContextXSSClient(vulnerable=True)
    findings = _run_async(run_reflected_xss_probe(
        client,
        ["maptiles.example.invalid"],
        crawled_urls=["https://maptiles.example.invalid/maps?style=default&key=abc"],
    ))
    assert len(findings) >= 1, "crawled_urls should feed params into discovery"
    js_findings = [
        f for f in findings
        if f.get("_xss_context") in ("event_handler_attr", "script_block", "javascript_uri")
    ]
    assert len(js_findings) >= 1


# ═══════════════════════════════════════════════════════════════════════
# Tests for run_ssrf_probe (dynamic discovery)
# ═══════════════════════════════════════════════════════════════════════
from scanners.ai_agent.active_baseline import run_ssrf_probe, _discover_ssrf_params


class _SSRFClient:
    """Simulates a server with a proxy/fetch feature that accepts URLs.

    Root page has a discoverable link with ?url= so the dynamic SSRF
    discoverer picks it up by name.
    """
    ROOT_HTML = (
        '<html><body>'
        '<a href="?url=https://cdn.example.com/image.png">Load Image</a>'
        '<form action="/proxy"><input name="target"></form>'
        '</body></html>'
    )

    def __init__(self, *, vulnerable=True):
        self._vulnerable = vulnerable

    async def get(self, url, timeout=None, headers=None, **_kw):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return _FakeCachePoisonResponse(text=self.ROOT_HTML)
        for k, vals in params.items():
            for v in vals:
                if "169.254.169.254" in v or "0xa9fea9fe" in v or "2852039166" in v:
                    if self._vulnerable:
                        return _FakeCachePoisonResponse(
                            text="ami-id\ninstance-type\nhostname",
                            status_code=200,
                        )
                    return _FakeCachePoisonResponse(text="blocked", status_code=403)
                if "127.0.0.1" in v or "0x7f000001" in v or "2130706433" in v or "[::1]" in v or "127.1" in v:
                    if self._vulnerable:
                        return _FakeCachePoisonResponse(text="<html>internal</html>" * 10, status_code=200)
                    return _FakeCachePoisonResponse(text="blocked", status_code=403)
                if "example.com" in v:
                    return _FakeCachePoisonResponse(text="ok", status_code=200)
        return _FakeCachePoisonResponse(text="not found", status_code=404)


def test_ssrf_detects_metadata_access():
    client = _SSRFClient(vulnerable=True)
    findings = _run_async(run_ssrf_probe(client, ["ssrf.example.invalid"]))
    assert len(findings) >= 1
    f = findings[0]
    assert "SSRF" in f["title"]
    assert f["cwe"] == "CWE-918"
    assert f["severity"] in ("Critical", "High")


def test_ssrf_no_finding_when_blocked():
    client = _SSRFClient(vulnerable=False)
    findings = _run_async(run_ssrf_probe(client, ["secure.example.invalid"]))
    assert findings == []


def test_discover_ssrf_params_from_page():
    html = (
        '<a href="?redirect_url=https://login.example.com">Login</a>'
        '<form><input name="callback_url"></form>'
        '<img src="/proxy?image_src=https://cdn.com/pic.jpg">'
    )
    params = _discover_ssrf_params(html)
    assert "redirect_url" in params
    assert "callback_url" in params
    assert "image_src" in params


def test_discover_ssrf_params_fallback_on_empty():
    params = _discover_ssrf_params("<html>nothing</html>")
    assert "url" in params
    assert "redirect" in params


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
