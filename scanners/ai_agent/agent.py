from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

import httpx
from urllib.parse import urlparse
from playwright.async_api import async_playwright

from .api_import import (
    EndpointRegistry,
    parse_openapi_spec,
    parse_postman_collection,
)
from .auth import ScanTarget, authenticate, detect_app_type
from .llm_config import ContentFiltered, ContextWindowExceeded, MalformedMessages, LLMRouter
from .passive_recon import run_passive_recon
from .prompts import build_system_prompt, get_phases
from .tools import TOOL_DEFINITIONS, ScanTools

logger = logging.getLogger(__name__)

MAX_MSG_RESULT_CHARS = 1500


def _s(val) -> str:
    """Safely coerce any value to str — LLMs sometimes return dicts/lists where strings are expected."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return "" if not val else str(val)
    if isinstance(val, (list, tuple)):
        return "" if not val else str(val)
    return str(val)
TRIM_TARGET_TOKENS = 40000


class ScanCancelled(Exception):
    """Raised when a scan is cancelled by the user."""


def _extract_base_domain(url: str) -> str:
    """Extract the registrable domain from a URL (e.g. 'avg.com' from 'https://www.avg.com/cs-cz')."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return ""
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


AFFILIATED_DOMAIN_GROUPS: list[set[str]] = [
    # Add groups of affiliated domains here. If the target matches any domain
    # in a group, all other domains in the same group become in-scope.
    # Example: {"example.com", "example-cdn.com", "example-api.com"}
]


def _build_allowed_domains(target_url: str, extra_domains: set | None = None) -> set:
    """Build full set of allowed domains from the target URL and any affiliated groups."""
    base = _extract_base_domain(target_url)
    allowed = {base} if base else set()
    for group in AFFILIATED_DOMAIN_GROUPS:
        if base in group or any(kw in base for kw in group):
            allowed |= group
    if extra_domains:
        allowed |= extra_domains
    return allowed


def _is_in_scope(url: str, allowed_domains: set) -> bool:
    """Check if a URL belongs to one of the allowed base domains."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    for d in allowed_domains:
        if host == d or host.endswith("." + d):
            return True
    return False

_VALID_TOOL_NAME = re.compile(r"[^a-zA-Z0-9_\-]")

_LOGIN_PAGE_INDICATORS = (
    "login", "log in", "sign in", "signin", "authenticate",
    "sso", "password", "credentials", "username",
)


async def _check_session_lost(page, auth_session, target, original_url: str,
                              router=None, model: str = "",
                              interactive_session=None,
                              on_progress=None, cancel_flag=None) -> bool:
    """Detect if the session was lost (redirected to login page).

    Returns True if re-authentication was performed.
    When *interactive_session* is provided, opens the interactive browser
    for the user to re-authenticate manually.
    """
    if not auth_session or auth_session._auth_type in ("none", "bearer", "api_key"):
        return False
    try:
        current_url = page.url.lower()
        title = (await page.title() or "").lower()
    except Exception:
        return False

    try:
        parsed = urlparse(current_url)
        check_str = f"{parsed.hostname or ''}{parsed.path or ''}"
    except Exception:
        check_str = current_url
    is_login_page = any(kw in check_str for kw in _LOGIN_PAGE_INDICATORS)
    if not is_login_page:
        is_login_page = any(kw in title for kw in _LOGIN_PAGE_INDICATORS)
    if not is_login_page:
        try:
            has_pw_field = await page.evaluate(
                "() => !!document.querySelector('input[type=password]')"
            )
            if has_pw_field:
                is_login_page = True
        except Exception:
            pass

    if not is_login_page:
        return False

    logger.warning("Session lost — detected login page at %s. Re-authenticating...", page.url)
    try:
        from .auth import authenticate as _reauth
        browser = page.context.browser
        new_session = await _reauth(browser, target, router, model,
                                    interactive_session=interactive_session,
                                    on_progress=on_progress,
                                    cancel_flag=cancel_flag)
        new_cookies = await new_session.page.context.cookies()
        await page.context.add_cookies(new_cookies)
        await page.goto(original_url, wait_until="domcontentloaded", timeout=15000)
        logger.info("Re-authentication successful, resumed at %s", original_url)
        return True
    except Exception as e:
        logger.error("Re-authentication failed: %s", e)
        return False

def _sanitize_tool_name(name: str) -> str:
    """Bedrock requires tool names matching [a-zA-Z0-9_-]+ and <= 64 chars."""
    cleaned = _VALID_TOOL_NAME.sub("_", name) if name else "unknown"
    return cleaned[:64]


def _to_plain_dict(obj):
    """Convert any object (Pydantic model, dataclass, etc.) to a plain dict."""
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "__dict__"):
        return dict(vars(obj))
    return {}


def _sanitize_message(msg: dict) -> dict:
    """Ensure all tool_call function names in an assistant message are Bedrock-safe."""
    tcs = msg.get("tool_calls")
    if not tcs:
        return msg
    cleaned = []
    for tc in tcs:
        if not isinstance(tc, dict):
            tc = _to_plain_dict(tc)
        else:
            tc = dict(tc)
        fn = tc.get("function")
        if fn is not None:
            if not isinstance(fn, dict):
                fn = _to_plain_dict(fn)
            else:
                fn = dict(fn)
            fn["name"] = _sanitize_tool_name(fn.get("name") or "")
            tc["function"] = fn
        cleaned.append(tc)
    msg = dict(msg)
    msg["tool_calls"] = cleaned
    return msg


def _sanitize_all_messages(messages):
    """Pre-send sweep: sanitize tool names in all assistant messages."""
    for i, m in enumerate(messages):
        if isinstance(m, dict) and m.get("tool_calls"):
            messages[i] = _sanitize_message(m)
    return messages


def _strip_exchanges(obj):
    """Remove http_exchange from tool results before sending to the LLM."""
    if isinstance(obj, dict):
        out = {k: _strip_exchanges(v) for k, v in obj.items() if k != "http_exchange"}
        return out
    if isinstance(obj, list):
        return [_strip_exchanges(item) for item in obj]
    return obj


def _cap_result(result: dict) -> str:
    """Serialize tool result and cap its size for message history."""
    clean = _strip_exchanges(result)
    raw = json.dumps(clean, default=str)
    if len(raw) <= MAX_MSG_RESULT_CHARS:
        return raw
    return raw[:MAX_MSG_RESULT_CHARS] + '..."}'


def _estimate_tokens(messages: list[dict]) -> int:
    return len(json.dumps(messages, default=str)) // 4


_API_PATH_PATTERNS = re.compile(
    r"/(api|v\d+|graphql|rest|oauth|token|webhook|callback|ws|rpc|feed|sitemap\.xml)"
    r"(/|$|\?)", re.IGNORECASE
)
_API_EXTENSIONS = re.compile(
    r"\.(json|xml|yaml|yml|wsdl|proto|graphql)(\?|#|$)", re.IGNORECASE
)
_PAGE_EXTENSIONS = re.compile(
    r"\.(html?|php|aspx?|jsp|css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|mp[34]|webm)(\?|#|$)",
    re.IGNORECASE,
)
_SECURITY_TEST_TOOLS = frozenset({
    "inject_payload", "fuzz_parameter", "api_request",
    "test_auth_bypass", "test_method_override", "api_request_raw",
    "replay_with_modification", "ws_inject", "execute_js",
    "test_token_security",
})

def _classify_url(url: str, result: dict, tool_name: str) -> str:
    """Classify a crawled URL as 'api', 'page', or 'test' based on URL
    structure and response content — NOT the tool that was used."""
    if tool_name in _SECURITY_TEST_TOOLS:
        return "test"

    from urllib.parse import urlparse
    path = urlparse(url).path.lower().rstrip("/")

    if _PAGE_EXTENSIONS.search(path):
        return "page"
    if _API_PATH_PATTERNS.search(path) or _API_EXTENSIONS.search(path):
        return "api"

    content_type = ""
    body = ""
    if isinstance(result, dict):
        hdrs = result.get("headers") or {}
        ct_from_headers = ""
        for k, v in hdrs.items():
            if k.lower() == "content-type":
                ct_from_headers = str(v).lower()
                break
        content_type = (str(result.get("content_type") or "") or ct_from_headers).lower()
        body = str(result.get("body_snippet") or result.get("body") or "")[:300].strip()
        if not body:
            nested = result.get("results")
            if isinstance(nested, list) and nested:
                first = nested[0] if isinstance(nested[0], dict) else {}
                body = str(first.get("body_snippet") or "")[:300].strip()

    if content_type:
        if any(t in content_type for t in (
            "application/json", "application/xml", "text/xml",
            "application/graphql", "application/grpc",
            "application/protobuf", "application/msgpack",
            "application/ld+json", "application/hal+json",
            "application/problem+json", "application/vnd.",
        )):
            return "api"
        if any(t in content_type for t in ("text/html", "text/css", "image/", "font/")):
            return "page"

    if body:
        stripped = body.lstrip()
        if stripped.startswith(("{", "[", "<?xml")):
            return "api"
        if stripped.startswith(("<!DOCTYPE", "<html", "<HTML", "<head", "<HEAD")):
            return "page"

    if tool_name == "navigate":
        return "page"

    return "page"


_MAX_EVIDENCE_PER_PHASE = 120

_INJECTION_MARKERS = ("'", '"', "<", ">", "UNION", "SELECT", "script", "onerror",
                      "onload", "alert", "SLEEP", "WAITFOR", "--", "#", "{{", "${")


def _capture_evidence(
    evidence: list[dict],
    tool: str,
    args: dict,
    resp_summary: dict | str,
    full_result: dict,
):
    """Capture compact evidence records for every security test tool call.

    For fuzz_parameter, captures each individual payload result separately
    so the LLM has granular evidence to cite.  Other tools get a single
    record.  Keeps each record compact (~150 chars) so even 60 records
    fit in a single context message (~9K chars).
    """
    if len(evidence) >= _MAX_EVIDENCE_PER_PHASE:
        return
    if not isinstance(full_result, dict):
        return

    # fuzz_parameter returns multiple results — capture each separately
    if tool == "fuzz_parameter" and isinstance(full_result.get("results"), list):
        ep_url = str(full_result.get("endpoint", ""))[:120]
        param = str(full_result.get("param", ""))
        for r in full_result["results"]:
            if len(evidence) >= _MAX_EVIDENCE_PER_PHASE:
                break
            r_payload = str(r.get("payload", ""))[:150]
            r_status = str(r.get("status", ""))
            r_body = str(r.get("body_snippet", ""))[:100]
            r_anomaly = r.get("anomaly")
            r_reflected = r.get("reflected")
            flags = []
            if r_anomaly:
                flags.append("ANOMALY")
            if r_reflected:
                flags.append("REFLECTED")
            try:
                if r_status and int(r_status) >= 400:
                    flags.append("ERROR")
            except (ValueError, TypeError):
                pass
            entry = {
                "tool": f"fuzz_parameter[{param}]",
                "url": ep_url,
                "payload": r_payload,
                "status": r_status,
                "flags": " ".join(flags),
                "evidence": r_body[:200],
            }
            if r.get("http_exchange"):
                entry["http_exchange"] = r["http_exchange"]
            evidence.append(entry)
        return

    status = full_result.get("status", "")
    body = str(full_result.get("body_snippet", ""))[:120]
    error = str(full_result.get("error", ""))[:100]
    reflected = full_result.get("reflected")
    anomaly = full_result.get("anomaly")
    title = str(full_result.get("title", "") or full_result.get("error_title", ""))[:80]

    inject_errors = full_result.get("errors")
    if isinstance(inject_errors, list) and inject_errors:
        anomaly = True
        if not error:
            error = "; ".join(str(e) for e in inject_errors[:3])

    vuln_detected = full_result.get("VULNERABILITIES_DETECTED")
    if vuln_detected:
        anomaly = True

    url = ""
    if isinstance(args, dict):
        url = str(args.get("url") or args.get("endpoint") or full_result.get("url") or "")[:120]

    payload = ""
    if isinstance(args, dict):
        payload = str(args.get("body") or args.get("payload") or args.get("value") or args.get("script") or "")[:150]
        if not payload and args.get("raw"):
            payload = str(args["raw"])[:150]

    snippet_parts = []
    if title and ("error" in title.lower() or "Error" in title):
        snippet_parts.append(title)
    if error:
        snippet_parts.append(error)
    if body and not error:
        snippet_parts.append(body[:100])
    snippet = " | ".join(snippet_parts) if snippet_parts else str(status)

    flags = []
    if anomaly:
        flags.append("ANOMALY")
    if reflected:
        flags.append("REFLECTED")
    try:
        if status and int(str(status)) >= 400:
            flags.append("ERROR")
        elif status and int(str(status)) == 200:
            flags.append("OK")
    except (ValueError, TypeError):
        pass

    entry = {
        "tool": tool,
        "url": url,
        "payload": payload,
        "status": str(status),
        "flags": " ".join(flags),
        "evidence": snippet[:200],
    }
    if isinstance(full_result, dict) and full_result.get("http_exchange"):
        entry["http_exchange"] = full_result["http_exchange"]
    evidence.append(entry)


def _format_evidence_buffer(evidence: list[dict]) -> str:
    """Format the evidence buffer into a context message for finding generation."""
    if not evidence:
        return ""
    lines = [
        "=== EVIDENCE LOG FROM YOUR TOOL CALLS ===",
        "Below is a record of every security test you performed. Use these EXACT",
        "payloads and responses when writing your findings JSON.",
        "",
    ]
    for i, ev in enumerate(evidence, 1):
        flags = f" [{ev.get('flags', '')}]" if ev.get("flags") else ""
        lines.append(
            f"{i}. [{ev['tool']}]{flags} {ev['url']}"
        )
        if ev.get("payload"):
            lines.append(f"   Payload: {ev['payload']}")
        lines.append(f"   Status: {ev['status']} | Response: {ev['evidence']}")
    lines.append("")
    lines.append(
        "REQUIRED: For each finding, the 'payload' field must contain the EXACT "
        "string from a Payload line above. The 'evidence' field must contain the "
        "EXACT Status + Response that proves the issue. The 'url' field must be "
        "the EXACT URL tested. The 'parameter' must name the specific input field. "
        "Findings without these fields will be REJECTED."
    )
    return "\n".join(lines)


def _match_evidence_to_finding(finding: dict, evidence: list[dict]):
    """Attach matching tool call request/response records to a finding.

    Searches the evidence buffer for entries whose URL or payload overlap
    with the finding's url/payload, and attaches the top matches as
    ``request_response`` so the UI can display Burp-style detail.
    """
    if not evidence:
        return
    f_url = _s(finding.get("url")).lower()
    f_payload = _s(finding.get("payload")).lower()

    scored: list[tuple[int, dict]] = []
    for ev in evidence:
        score = 0
        ev_url = _s(ev.get("url")).lower()
        ev_payload = _s(ev.get("payload")).lower()
        if f_url and ev_url and (f_url in ev_url or ev_url in f_url):
            score += 2
        if f_payload and ev_payload and f_payload in ev_payload:
            score += 3
        elif f_payload and ev_payload:
            f_words = set(f_payload.split())
            ev_words = set(ev_payload.split())
            if f_words & ev_words:
                score += 1
        flags = ev.get("flags", "")
        if "ERROR" in flags or "ANOMALY" in flags or "REFLECTED" in flags:
            score += 1
        if score > 0:
            scored.append((score, ev))

    scored.sort(key=lambda x: -x[0])
    matches = [ev for _, ev in scored[:5]]
    if matches:
        finding["request_response"] = matches


def _format_passive_for_llm(passive_findings: list[dict]) -> str:
    """Summarize passive recon results so the LLM agent is aware of them."""
    if not passive_findings:
        return ""
    lines = ["## Passive Reconnaissance Results (pre-scan, no LLM)",
             f"Found {len(passive_findings)} issue(s) via deterministic checks:"]
    for f in passive_findings:
        lines.append(f"- [{_s(f.get('severity'))}] {_s(f.get('title'))} @ {_s(f.get('url'))}")
        if f.get("evidence"):
            lines.append(f"  Evidence: {_s(f['evidence'])[:200]}")
    lines.append("\nUse these findings to prioritize your active scanning. "
                 "For JS sink findings, attempt to prove exploitability by tracing user-controlled data into those sinks.")
    return "\n".join(lines)


def _hosts_match(current_host: str, target_host: str) -> bool:
    """Check if current host matches target — exact match or same root domain.
    e.g., my.norton.com matches norton.com, login.norton.com matches my.norton.com."""
    if current_host == target_host:
        return True
    from scanners.ai_agent.auth import _extract_root_domain
    return _extract_root_domain(current_host) == _extract_root_domain(target_host)


async def _ensure_on_target(page, target_url: str, target_host: str) -> bool:
    """Navigate to the target URL and confirm the browser is on the right host.

    Returns True if the current page hostname matches target_host (or same root domain).
    """
    current_host = urlparse(page.url or "").hostname or ""
    if _hosts_match(current_host, target_host):
        return True

    print(f"  [NAV] Navigating to target (current: {current_host} -> {target_host}): {target_url}")
    for attempt in range(3):
        try:
            resp = await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            status = resp.status if resp else "no-response"
            await asyncio.sleep(4 + attempt * 3)
            final_url = page.url or ""
            current_host = urlparse(final_url).hostname or ""
            if _hosts_match(current_host, target_host):
                print(f"  [NAV] Landed on target (HTTP {status}): {final_url[:120]}")
                return True
            print(f"  [NAV] Attempt {attempt+1}: HTTP {status}, landed on {current_host} ({final_url[:120]}), expected {target_host}")
        except Exception as nav_err:
            print(f"  [NAV] Attempt {attempt+1} error: {nav_err}")
            logger.debug("Target nav attempt %d: %s", attempt, nav_err)
    print(f"  [NAV] Could not reach target after 3 attempts, current page: {page.url[:150]}")
    return False


async def _wait_for_spa_ready(page, timeout_s: int = 25):
    """Generic SPA readiness wait — framework-agnostic.

    Strategy:
    1. Wait for networkidle (no new requests for 500ms).
    2. Poll the DOM content hash until it stabilises (SPA has finished
       rendering route components, lazy chunks, iframes).
    3. Cap total wait to avoid blocking forever on long-polling apps.
    """
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass

    # Poll DOM stability: hash the document.body.childElementCount + frame count
    prev_hash = ""
    stable_ticks = 0
    for _ in range(timeout_s // 2):
        try:
            cur_hash = await page.evaluate("""() => {
                const fc = document.querySelectorAll('iframe').length;
                const sc = document.querySelectorAll('script[src]').length;
                const bc = document.body ? document.body.childElementCount : 0;
                return `${bc}-${sc}-${fc}`;
            }""")
        except Exception:
            cur_hash = ""
        if cur_hash == prev_hash and cur_hash:
            stable_ticks += 1
            if stable_ticks >= 2:
                break
        else:
            stable_ticks = 0
            prev_hash = cur_hash
        await asyncio.sleep(2)

    # Final networkidle check after DOM settled
    try:
        await page.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass


def _resolve_import_path(base_dir: str, path: str | None) -> str | None:
    if not path:
        return None
    if os.path.isabs(path):
        return path if os.path.exists(path) else None
    resolved = os.path.normpath(os.path.join(base_dir, path))
    return resolved if os.path.exists(resolved) else path


async def run_scan(
    target: ScanTarget,
    model: str,
    router: LLMRouter,
    config_dir: str | None = None,
    on_progress: callable | None = None,
    extra_domains: list[str] | None = None,
    cancel_flag=None,
    pause_flag=None,
    start_from_phase: int = 0,
    initial_findings: list[dict] | None = None,
    interactive_session: dict | None = None,
) -> tuple[list[dict], dict]:
    config_dir = config_dir or os.getcwd()
    _cb = on_progress or (lambda *a, **k: None)
    findings: list[dict] = list(initial_findings) if initial_findings else []
    metrics = {
        "pages_crawled": 0,
        "forms_found": 0,
        "api_endpoints_found": 0,
        "auth_pages_detected": 0,
        "phases_completed": 0,
        "total_tool_calls": 0,
        "pages_list": [],
        "phase_log": [],
        "test_log": [],
    }
    def _check_cancel():
        if cancel_flag and cancel_flag.is_set():
            raise ScanCancelled("Scan stopped by user")
        if pause_flag and pause_flag.is_set():
            _cb("paused", {})
            while pause_flag.is_set():
                if cancel_flag and cancel_flag.is_set():
                    raise ScanCancelled("Scan stopped by user")
                time.sleep(1)
            _cb("resumed", {})

    SECURITY_TEST_TOOLS = {
        "inject_payload", "fuzz_parameter", "api_request",
        "test_auth_bypass", "test_method_override", "api_request_raw",
        "replay_with_modification", "ws_inject", "execute_js",
        "test_token_security",
    }

    _MIN_SECURITY_CALLS: dict[str, int] = {
        "web_a03_sqli": 15,
        "web_a03_xss": 15,
        "web_a03_cmdi": 8,
        "web_a03_ssti": 6,
        "web_a03_path_traversal": 6,
        "web_a03_xxe": 4,
        "web_a01": 6,
        "web_a04": 5,
        "web_a05": 5,
        "web_a07": 6,
        "web_a08": 4,
        "web_a10": 5,
        "web_extras": 5,
        "web_bfla": 5,
        "web_file_upload": 4,
        "api_injection": 12,
        "api_auth": 5,
        "api_authz": 5,
        "api_ssrf": 5,
        "api_mass_assign": 4,
        "api_graphql": 4,
        "api_data_exposure": 4,
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        has_creds = bool((target.credentials or {}).get("username") or
                         (target.credentials or {}).get("password"))

        auth_type_cfg = ((target.auth_config or {}).get("type") or "auto").lower()
        if auth_type_cfg == "interactive_login":
            print(f"  [AUTH] Interactive login mode — opening browser for {target.url}")
            _cb("auth", {"status": "interactive_login", "url": target.url})
        elif has_creds:
            print(f"  [AUTH] Authenticating to {target.url}...")
            _cb("auth", {"status": "authenticating", "url": target.url})
        else:
            print(f"  [SCAN] Opening {target.url} (unauthenticated)...")
            _cb("auth", {"status": "unauthenticated", "url": target.url})
        _max_auth_attempts = 3
        for _auth_attempt in range(1, _max_auth_attempts + 1):
            _check_cancel()
            auth_session = await authenticate(
                browser, target, router, model,
                interactive_session=interactive_session,
                on_progress=_cb,
                cancel_flag=cancel_flag,
            )
            auth_success = auth_session.success if hasattr(auth_session, "success") else True
            if auth_success:
                break

            # Small grace period for the pause signal to arrive
            # (frontend sends /done + /pause in quick succession)
            if pause_flag and not pause_flag.is_set():
                await asyncio.sleep(1.5)

            # Auth failed — if scan was paused (user hit Pause during CAPTCHA/MFA),
            # wait for resume and retry authentication
            if pause_flag and pause_flag.is_set():
                print(f"  [AUTH] Auth challenge caused pause — waiting for resume (attempt {_auth_attempt}/{_max_auth_attempts})")
                _cb("paused", {})
                _cb("progress_msg", {
                    "message": f"Scan paused — authentication challenge (CAPTCHA/MFA/SSO). "
                               f"Resume to retry login (attempt {_auth_attempt}/{_max_auth_attempts})."
                })
                while pause_flag.is_set():
                    if cancel_flag and cancel_flag.is_set():
                        raise ScanCancelled("Scan stopped by user")
                    await asyncio.sleep(1)
                _cb("resumed", {})
                if _auth_attempt >= _max_auth_attempts:
                    print(f"  [AUTH] Scan resumed — final attempt ({_auth_attempt}/{_max_auth_attempts})...")
                    _cb("progress_msg", {"message": f"Scan resumed — FINAL login attempt ({_auth_attempt}/{_max_auth_attempts}). If this fails, scan continues unauthenticated."})
                else:
                    print(f"  [AUTH] Scan resumed — retrying authentication (attempt {_auth_attempt + 1}/{_max_auth_attempts})...")
                    _cb("progress_msg", {"message": f"Scan resumed — retrying authentication (attempt {_auth_attempt + 1}/{_max_auth_attempts})..."})
                # Re-create interactive session for the retry
                if interactive_session:
                    interactive_session["done"].clear()
                    interactive_session["active"].clear()
                    interactive_session["screenshot_b64"] = ""
                continue

            # Auth failed but not paused — continue unauthenticated
            if _auth_attempt >= _max_auth_attempts:
                print(f"  [AUTH] All {_max_auth_attempts} login attempts exhausted — continuing unauthenticated")
                _cb("progress_msg", {
                    "message": f"All {_max_auth_attempts} login attempts failed — continuing scan WITHOUT authentication. "
                               f"Findings will be limited to unauthenticated checks only."
                })
            else:
                print(f"  [AUTH] Auth failed (attempt {_auth_attempt}/{_max_auth_attempts}) — continuing unauthenticated")
                _cb("progress_msg", {"message": "Authentication failed — continuing scan unauthenticated."})
            break

        page = auth_session.page

        # Network-level JS capture was started inside authenticate() on page
        # creation, so it has captured every .js since the very first navigation.
        network_js_urls = getattr(auth_session, "network_js_urls", set())

        auth_final_host = urlparse(page.url or "").hostname or ""
        auth_success = auth_session.success if hasattr(auth_session, "success") else True
        print(f"  [AUTH] Auth type: {auth_session._auth_type}, success: {auth_success}, URL after login: {page.url}")
        print(f"  [AUTH] Current host: {auth_final_host}, target host: {urlparse(target.url).hostname}")
        _cb("auth", {"status": "done", "type": auth_session._auth_type, "url": page.url,
                      "success": auth_success, "current_host": auth_final_host})
        if auth_session._auth_type not in ("bearer", "none"):
            metrics["auth_pages_detected"] += 1

        cookies = await page.context.cookies()
        cookie_dict = {c["name"]: c["value"] for c in cookies}
        cookie_dict.setdefault("language", "en")
        headers = auth_session.get_auth_header()
        http_client = httpx.AsyncClient(
            headers=headers,
            cookies=cookie_dict,
            timeout=30.0,
        )

        registry = EndpointRegistry()
        if target.scan_mode in ("api", "both"):
            postman_path = _resolve_import_path(config_dir, target.postman_file)
            if postman_path:
                registry.add(parse_postman_collection(postman_path, _resolve_import_path(config_dir, target.postman_env)))
            openapi_path = _resolve_import_path(config_dir, target.openapi_file)
            if openapi_path:
                registry.add(parse_openapi_spec(openapi_path))
            burp_path = _resolve_import_path(config_dir, getattr(target, "burp_file", None))
            if burp_path:
                try:
                    import json as _json
                    burp_data = _json.loads(Path(burp_path).read_text(encoding="utf-8"))
                    registry.add_from_traffic(burp_data)
                    print(f"  [IMPORT] Loaded Burp traffic from {burp_path}")
                except Exception as e:
                    print(f"  [IMPORT] Could not parse Burp file {burp_path}: {e}")

        extra_set = set(d.strip().lower() for d in extra_domains if d.strip()) if extra_domains else None
        allowed_domains = _build_allowed_domains(target.url, extra_set)
        logger.info("Scope restricted to domain(s): %s", allowed_domains)
        _cb("scope", {"allowed_domains": sorted(allowed_domains)})

        tools = ScanTools(
            page=page,
            http_client=http_client,
            registry=registry,
            auth_session=auth_session,
            allowed_domains=allowed_domains,
            cancel_flag=cancel_flag,
            exclude_urls=getattr(target, "exclude_urls", None) or [],
        )

        # ── Authenticate User B for BOLA/BFLA two-user testing ──────
        user_b_auth_header: dict = {}
        user_b_cookie_str: str = ""
        has_user_b = bool(target.credentials_b and
                          (target.credentials_b.get("username") or target.credentials_b.get("password")))
        if has_user_b:
            print(f"  [AUTH-B] Authenticating User B for BOLA testing...")
            _cb("auth", {"status": "authenticating_user_b", "url": target.url})
            try:
                target_b = ScanTarget(
                    id=target.id + "_b",
                    url=target.url,
                    scan_mode=target.scan_mode,
                    credentials=target.credentials_b,
                    auth_config=target.auth_config,
                )
                auth_session_b = await authenticate(browser, target_b, router, model)
                user_b_auth_header = auth_session_b.get_auth_header()
                cookies_b = await auth_session_b.page.context.cookies()
                user_b_cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies_b)
                await auth_session_b.page.close()
                print(f"  [AUTH-B] User B auth type: {auth_session_b._auth_type}")
                _cb("auth", {"status": "user_b_done", "type": auth_session_b._auth_type})
            except Exception as e:
                print(f"  [AUTH-B] User B auth failed (non-fatal): {e}")
                _cb("auth", {"status": "user_b_failed", "error": str(e)})
                has_user_b = False

        # ── Navigate to target & wait for SPA readiness (generic) ────
        # After OIDC/SSO auth the browser may still be on the login URL.
        # We must land on the actual target host before passive recon can
        # find SPA resources (iframes, CDN scripts, dynamic chunks).
        target_host = urlparse(target.url).hostname or ""
        landed_on_target = False
        try:
            landed_on_target = await _ensure_on_target(page, target.url, target_host)
            if not landed_on_target and getattr(auth_session, "captcha_detected", False):
                print(f"  [AUTH] CAPTCHA was detected — skipping retry loop")
                landed_on_target = await _ensure_on_target(page, target.url, target_host)
            elif not landed_on_target:
                # Auth didn't redirect to target. Re-authenticate with full flow.
                print(f"  [AUTH-RETRY] Not on target after auth, re-authenticating...")
                _cb("auth", {"status": "re-authenticating", "reason": "not_on_target"})
                for retry in range(2):
                    try:
                        retry_result = await auth_session._refresh_fn()
                        if retry_result.success:
                            print(f"  [AUTH-RETRY] Re-auth attempt {retry+1} succeeded")
                            fresh_cookies = await page.context.cookies()
                            cookie_dict = {c["name"]: c["value"] for c in fresh_cookies}
                            await http_client.aclose()
                            http_client = httpx.AsyncClient(
                                headers=auth_session.get_auth_header(),
                                cookies=cookie_dict,
                                timeout=30.0,
                            )
                            tools._http_client = http_client
                        else:
                            print(f"  [AUTH-RETRY] Re-auth attempt {retry+1} failed")
                    except Exception as auth_err:
                        print(f"  [AUTH-RETRY] Re-auth attempt {retry+1} error: {auth_err}")
                    landed_on_target = await _ensure_on_target(page, target.url, target_host)
                    if landed_on_target:
                        print(f"  [AUTH-RETRY] Successfully landed on target after retry {retry+1}")
                        break
                    await asyncio.sleep(3)

            if landed_on_target:
                await _wait_for_spa_ready(page)
                print(f"  [PASSIVE] Page ready on {urlparse(page.url or '').hostname}, "
                      f"network JS captured: {len(network_js_urls)}")
            else:
                current_url = page.url or ""
                current_host = urlparse(current_url).hostname or ""
                print(f"  [PASSIVE] WARNING: Still on {current_host}, NOT on {target_host}!")
                print(f"  [PASSIVE] Current URL: {current_url[:200]}")
                try:
                    title = await page.title()
                    print(f"  [PASSIVE] Page title: {title}")
                except Exception:
                    pass
                browser_cookies = await page.context.cookies()
                from scanners.ai_agent.auth import _extract_root_domain
                root_dom = _extract_root_domain(target_host)
                target_cookies = [c for c in browser_cookies if root_dom in c.get("domain", "")]
                print(f"  [PASSIVE] Browser cookies: {len(browser_cookies)} total, {len(target_cookies)} for *{root_dom}")
                if target_cookies:
                    print(f"  [PASSIVE] Target cookie names: {', '.join(c['name'] for c in target_cookies[:10])}")
                print(f"  [PASSIVE] Authentication likely failed — passive recon may have limited results")
                print(f"  [PASSIVE] TIP: Ensure cookies are from an authenticated session on {target_host} (not the login page)")
                _cb("auth", {"status": "failed_redirect", "current_host": current_host, "target_host": target_host,
                             "current_url": current_url[:200], "browser_cookies": len(browser_cookies),
                             "target_cookies": len(target_cookies)})
        except Exception as e:
            logger.warning("Pre-recon navigation failed (non-fatal): %s", e)

        # Detect app type AFTER navigation (not on the login page)
        app_info = await detect_app_type(page)
        print(f"  [DETECT] SPA: {app_info.get('is_spa')}, Framework: {app_info.get('framework')}, WebSockets: {app_info.get('has_websockets')}")
        _cb("detect", {"is_spa": app_info.get("is_spa"), "framework": app_info.get("framework")})

        def _passive_progress(event, data):
            if event == "out_of_scope":
                _cb("out_of_scope", data)
                return
            _cb("tool_call", {
                "phase": "Passive Reconnaissance",
                "tool": f"passive_{event}",
                "request": data,
                "response": {},
            })

        _phase_seq = 0

        def _next_phase():
            nonlocal _phase_seq
            _phase_seq += 1
            return _phase_seq

        p = _next_phase()
        _cb("phase_start", {"phase": p, "total": 0, "name": "Passive Reconnaissance", "id": "passive_recon"})
        current_host = urlparse(page.url or "").hostname or ""
        if current_host != target_host and target_host:
            print(f"  [PASSIVE] SKIPPING — browser on {current_host}, not target {target_host}")
            print(f"  [PASSIVE] Will retry after LLM navigates to target")
            passive_findings = []
            _cb("phase_end", {"phase": p, "name": "Passive Reconnaissance (skipped — not on target)",
                              "tool_calls": 0, "findings": 0})
        else:
            print("  [PASSIVE] Running passive reconnaissance...")
            try:
                passive_findings = await run_passive_recon(
                    page=page,
                    http_client=http_client,
                    target_url=target.url,
                    on_finding=lambda f: _cb("finding", {**f, "phase": "Passive Reconnaissance"}),
                    on_progress=_passive_progress,
                    network_js_urls=network_js_urls,
                )
                findings.extend(passive_findings)
                print(f"  [PASSIVE] Done: {len(passive_findings)} findings")
            except Exception as e:
                passive_findings = []
                print(f"  [PASSIVE] Failed (non-fatal): {e}")
                logger.warning("Passive recon failed: %s", e, exc_info=True)

        _cb("phase_end", {"phase": p, "name": "Passive Reconnaissance",
                          "tool_calls": 0, "findings": len(passive_findings)})

        # ── Baseline Execution (happy path, no LLM) ──
        baseline_context = ""
        api_endpoints = registry.get_all()
        if api_endpoints:
            from .baseline_executor import run_baseline, format_baseline_for_llm
            print(f"  [BASELINE] Running happy path for {len(api_endpoints)} API endpoints...")
            _cb("phase_start", {"phase": 0, "total": 0, "name": "API Baseline (Happy Path)", "id": "baseline"})

            def _baseline_progress(event, data):
                if event == "baseline_request":
                    _cb("tool_call", {
                        "phase": "API Baseline (Happy Path)",
                        "tool": "baseline_request",
                        "request": {"method": data["method"], "url": data["url"], "step": f"{data['step']}/{data['total']}"},
                        "response": {},
                    })
                elif event == "baseline_result":
                    _cb("tool_call", {
                        "phase": "API Baseline (Happy Path)",
                        "tool": "baseline_response",
                        "request": {"name": data["name"]},
                        "response": {"status": str(data["status"]), "success": str(data["success"]),
                                     "timing_ms": str(data["timing_ms"]),
                                     "variables": ", ".join(data["variables"]) if data["variables"] else "-"},
                    })

            collection_vars = {}
            for ep in api_endpoints:
                collection_vars.update(ep.variables)

            baseline_results = await run_baseline(
                api_endpoints,
                variables=collection_vars,
                on_progress=_baseline_progress,
            )
            baseline_context = format_baseline_for_llm(baseline_results)
            successful = sum(1 for r in baseline_results if r.success)
            print(f"  [BASELINE] Done: {successful}/{len(baseline_results)} succeeded")
            _cb("phase_end", {
                "phase": 0, "name": "API Baseline (Happy Path)",
                "tool_calls": len(baseline_results) * 2,
                "findings": 0,
            })
            metrics["total_tool_calls"] += len(baseline_results) * 2
            for r in baseline_results:
                if r.url and r.url not in metrics["pages_list"]:
                    metrics["pages_list"].append(r.url)
                    metrics["pages_crawled"] += 1
                    _cb("crawl", {"url": r.url, "type": "api", "tool": "baseline", "count": metrics["pages_crawled"]})

        # ── Hybrid Body Fuzzing (LLM plans, engine executes) ──
        body_fuzz_context = ""
        if baseline_context and baseline_results:
            from .body_fuzzer import fuzz_body, format_fuzz_results_for_llm as fmt_fuzz
            post_endpoints = [r for r in baseline_results if r.success and r.request_body and r.method in ("POST", "PUT", "PATCH")]
            if post_endpoints:
                fuzz_mode = "hybrid (LLM-planned)" if router else "static"
                print(f"  [BODY-FUZZ] Fuzzing {len(post_endpoints)} endpoint(s) — {fuzz_mode} mode...")
                _cb("phase_start", {"phase": 0, "total": 0, "name": f"Body Fuzzing ({fuzz_mode})", "id": "body_fuzz"})
                all_fuzz_results = []
                all_llm_findings = []
                for br in post_endpoints:
                    def _fuzz_progress(event, data):
                        if event == "fuzz_request":
                            _cb("tool_call", {
                                "phase": f"Body Fuzzing ({fuzz_mode})",
                                "tool": "body_fuzz",
                                "request": {"field": data["field"], "payload": data["payload"],
                                            "step": f"{data['request_num']}/{data['total']}"},
                                "response": {},
                            })
                        elif event == "llm_planning":
                            _cb("tool_call", {
                                "phase": f"Body Fuzzing ({fuzz_mode})",
                                "tool": "llm_payload_planning",
                                "request": {"fields": data["fields_count"], "mode": data["mode"]},
                                "response": {},
                            })
                    fuzz_results, ep_llm_findings = await fuzz_body(
                        http_client, br.method, br.url, br.request_body,
                        headers=br.request_headers, on_progress=_fuzz_progress,
                        llm_router=router, llm_model=model,
                    )
                    all_fuzz_results.extend(fuzz_results)
                    all_llm_findings.extend(ep_llm_findings)
                body_fuzz_context = fmt_fuzz(all_fuzz_results, all_llm_findings)
                anomalies = sum(1 for r in all_fuzz_results if r.anomaly)
                llm_issues = len(all_llm_findings)
                print(f"  [BODY-FUZZ] Done: {len(all_fuzz_results)} tests, {anomalies} anomalies, {llm_issues} LLM-identified API issues")

                for lf in all_llm_findings:
                    findings.append({
                        "title": lf.title,
                        "severity": lf.severity,
                        "url": target.url,
                        "parameter": lf.field,
                        "evidence": lf.evidence,
                        "payload": lf.payload,
                        "owasp_category": "",
                        "source": "body_fuzzer_llm_analysis",
                        "explanation": lf.explanation,
                        "finding_type": lf.finding_type,
                    })
                    _cb("finding", {
                        "title": lf.title, "severity": lf.severity,
                        "url": target.url, "parameter": lf.field,
                        "evidence": lf.evidence, "payload": lf.payload,
                        "phase": "Body Fuzzing",
                        "explanation": lf.explanation,
                    })

                _cb("phase_end", {
                    "phase": 0, "name": f"Body Fuzzing ({fuzz_mode})",
                    "tool_calls": len(all_fuzz_results), "findings": anomalies + llm_issues,
                })
                metrics["total_tool_calls"] += len(all_fuzz_results)

        phases = get_phases(target.scan_mode, app_info, scan_scope=getattr(target, "scan_scope", "directory"), focus_areas=getattr(target, "focus_areas", None))
        system_prompt = build_system_prompt(target, registry, app_info, extra_domains=extra_domains)
        if passive_findings:
            passive_summary = _format_passive_for_llm(passive_findings)
            system_prompt += "\n\n" + passive_summary
        if baseline_context:
            system_prompt += "\n\n" + baseline_context
        if body_fuzz_context:
            system_prompt += "\n\n" + body_fuzz_context

        # ── Workflow Replay + Context ──
        workflow_replayed = False
        if getattr(target, "workflow_id", None):
            from .workflow import load_workflow, replay_workflow, build_workflow_prompt
            wf = load_workflow(target.workflow_id)
            if wf:
                print(f"  [WORKFLOW] Loaded workflow: {wf.name} ({len(wf.steps)} steps)")
                _cb("phase_start", {"phase": 0, "total": 0, "name": f"Workflow Replay: {wf.name}", "id": "workflow_replay"})
                wf_vars = {"username": (target.credentials or {}).get("username", ""),
                           "password": (target.credentials or {}).get("password", "")}
                try:
                    wf_result = await replay_workflow(
                        page, wf, variables=wf_vars,
                        on_step=lambda idx, step, st: _cb("workflow_step", {"step": idx, "action": step.action, "status": st}),
                    )
                    workflow_replayed = wf_result.success
                    status = "completed" if wf_result.success else f"failed at step {wf_result.failed_step}"
                    print(f"  [WORKFLOW] Replay {status}: {wf_result.steps_completed}/{wf_result.steps_total} steps")
                    if wf_result.adapted_steps:
                        print(f"  [WORKFLOW] LLM adapted steps: {wf_result.adapted_steps}")
                except Exception as e:
                    print(f"  [WORKFLOW] Replay failed: {e}")
                    logger.warning("Workflow replay failed: %s", e, exc_info=True)
                _cb("phase_end", {"phase": 0, "name": f"Workflow Replay: {wf.name}",
                                  "tool_calls": wf.steps.__len__(), "findings": 0})
                system_prompt += "\n\n" + build_workflow_prompt(wf)
            else:
                print(f"  [WORKFLOW] Workflow {target.workflow_id} not found — skipping")

        if getattr(target, "business_flow", None) and not getattr(target, "workflow_id", None):
            from .workflow import Workflow, build_workflow_prompt
            nl_wf = Workflow(name="User-Defined Business Flow", description=target.business_flow)
            system_prompt += "\n\n" + build_workflow_prompt(nl_wf)
            print(f"  [WORKFLOW] Natural language flow injected: {target.business_flow[:100]}")

        messages: list[dict] = [{"role": "system", "content": system_prompt}]

        has_baseline = bool(baseline_context)
        has_body_fuzz = bool(body_fuzz_context)
        has_workflow = workflow_replayed or bool(getattr(target, "business_flow", None))
        extra_phases = (1 if has_baseline else 0) + (1 if has_body_fuzz else 0) + (1 if workflow_replayed else 0)
        total_phases = len(phases) + 1 + extra_phases  # +1 verification
        print(f"  [SCAN] Starting {len(phases)} scan phases + verification...")
        _cb("scan_start", {"total_phases": total_phases})
        phase_offset = extra_phases
        for phase_idx, phase in enumerate(phases):
            _check_cancel()
            phase_num = phase_idx + 1 + phase_offset
            if start_from_phase > 0 and phase_idx < start_from_phase:
                print(f"  [{phase_num}/{total_phases}] Phase: {phase.name} — skipped (already completed)")
                _cb("phase_start", {"phase": phase_num, "total": total_phases, "name": f"{phase.name} (skipped)", "id": phase.id})
                _cb("phase_end", {"phase": phase_num, "name": f"{phase.name} (skipped)", "tool_calls": 0, "findings": 0})
                metrics["phases_completed"] += 1
                continue
            phase_tool_calls = 0
            phase_findings_before = len(findings)
            print(f"  [{phase_num}/{total_phases}] Phase: {phase.name} ({phase.id})...", end="", flush=True)
            _cb("phase_start", {"phase": phase_num, "total": total_phases, "name": phase.name, "id": phase.id})

            phase_prompt = phase.prompt
            if phase.id == "attack_chain_analysis" and findings:
                summary_lines = []
                for i, f in enumerate(findings, 1):
                    line = f"{i}. [{f.get('severity','?')}] {f.get('title','?')} @ {f.get('url','?')}"
                    ev = f.get("evidence", "")
                    if ev:
                        line += f" — {ev[:150]}"
                    summary_lines.append(line)
                findings_text = "\n".join(summary_lines) if summary_lines else "(no findings yet)"
                phase_prompt = phase_prompt.replace("{findings_summary}", findings_text)

            # Inject User B context into BOLA/authorization phases
            bola_web_placeholder = "{bola_user_b_web}"
            bola_api_placeholder = "{bola_user_b_api}"
            if has_user_b and (bola_web_placeholder in phase_prompt or bola_api_placeholder in phase_prompt):
                user_b_hdr_str = ", ".join(f'"{k}: {v}"' for k, v in user_b_auth_header.items()) if user_b_auth_header else "(none)"
                user_b_block = (
                    "\n\n--- TWO-USER BOLA/BFLA TESTING MODE ---\n"
                    "A second user (User B) has been authenticated. You are currently logged in as User A.\n"
                    "STEP 1: As User A, browse the application and collect resource IDs (user profiles, orders, "
                    "documents, settings, etc.). Note every ID you find in URLs, responses, and hidden fields.\n"
                    "STEP 2: For each resource ID belonging to User A, make the SAME request but with "
                    "User B's credentials. Use the api_request tool with these EXACT headers to act as User B:\n"
                    f"  Authorization headers: {user_b_hdr_str}\n"
                    f"  Cookie: {user_b_cookie_str}\n"
                    "STEP 3: Compare responses. If User B can read/modify/delete User A's resources, this is "
                    "a CONFIRMED BOLA (Broken Object Level Authorization) — severity Critical.\n"
                    "STEP 4: Also test vertical privilege escalation: use User B's creds to access admin-only "
                    "endpoints or perform privileged actions (BFLA — Broken Function Level Authorization).\n"
                    "For EVERY test, record: User A's resource ID, the endpoint, User B's response status "
                    "and body snippet as evidence.\n"
                    "--- END BOLA MODE ---"
                )
                phase_prompt = phase_prompt.replace(bola_web_placeholder, user_b_block)
                phase_prompt = phase_prompt.replace(bola_api_placeholder, user_b_block)
            else:
                phase_prompt = phase_prompt.replace(bola_web_placeholder, "")
                phase_prompt = phase_prompt.replace(bola_api_placeholder, "")

            messages.append({"role": "user", "content": phase_prompt})

            phase_evidence: list[dict] = []

            for step in range(phase.max_steps):
                _check_cancel()
                try:
                    _sanitize_all_messages(messages)
                    messages = _repair_tool_pairs(messages)
                    response = router.complete(
                        model=model,
                        messages=messages,
                        tools=TOOL_DEFINITIONS,
                        cancel_flag=cancel_flag,
                    )
                except ScanCancelled:
                    raise
                except ContentFiltered:
                    logger.warning(
                        "Content filtered by %s at phase %s step %d — model guardrails blocked request",
                        model, phase.id, step,
                    )
                    print(f" [BLOCKED] Model guardrails filtered content")
                    raise ContentFiltered(
                        f"Model {model} refuses security-testing prompts (content guardrails). "
                        "Use a model without content filters (e.g. Claude Haiku or Sonnet)."
                    )
                except ContextWindowExceeded:
                    logger.warning("Context window exceeded at phase %s step %d, trimming aggressively", phase.id, step)
                    messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS // 2)
                    try:
                        _sanitize_all_messages(messages)
                        messages = _repair_tool_pairs(messages)
                        response = router.complete(model=model, messages=messages, tools=TOOL_DEFINITIONS, cancel_flag=cancel_flag)
                    except ContentFiltered:
                        raise ContentFiltered(
                            f"Model {model} refuses security-testing prompts (content guardrails). "
                            "Use a model without content filters (e.g. Claude Haiku or Sonnet)."
                        )
                    except ContextWindowExceeded:
                        logger.error("Still exceeded after aggressive trim, skipping rest of phase %s", phase.id)
                        break
                except MalformedMessages:
                    logger.warning("Malformed message sequence at phase %s step %d, recovering", phase.id, step)
                    messages = _recover_messages(messages)
                    try:
                        response = router.complete(model=model, messages=messages, tools=TOOL_DEFINITIONS, cancel_flag=cancel_flag)
                    except MalformedMessages:
                        logger.error("Recovery failed at phase %s, skipping to next phase", phase.id)
                        break
                _check_cancel()
                if not response or not getattr(response, "choices", None):
                    logger.warning("Empty response from %s at phase %s step %d", model, phase.id, step)
                    break
                msg = response.choices[0].message
                msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
                msg_dict = _sanitize_message(msg_dict)
                messages.append(msg_dict)

                tool_calls = msg_dict.get("tool_calls") or getattr(msg, "tool_calls", None) or []
                unknown_in_batch = 0
                if tool_calls:
                    for tc in tool_calls:
                        _check_cancel()
                        tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                        fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                        fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                        fn_name = _sanitize_tool_name(fn_name)
                        fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")
                        result = await tools.execute(fn_name, fn_args)
                        if isinstance(result, dict) and "Unknown tool" in result.get("error", ""):
                            unknown_in_batch += 1
                        phase_tool_calls += 1
                        metrics["total_tool_calls"] += 1
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": _cap_result(result),
                        })
                        try:
                            args_parsed = json.loads(fn_args) if isinstance(fn_args, str) else fn_args
                        except Exception:
                            args_parsed = {"raw": fn_args}
                        resp_summary = {
                            k: v for k, v in result.items()
                            if k in ("status", "url", "error", "reflected", "anomaly", "body_snippet", "results", "accessible", "title", "forms")
                        } if isinstance(result, dict) else str(result)[:200]

                        _cb("tool_call", {
                            "phase": phase.name,
                            "tool": fn_name,
                            "request": {k: str(v)[:300] for k, v in args_parsed.items()} if isinstance(args_parsed, dict) else str(args_parsed)[:400],
                            "response": {k: str(v)[:200] for k, v in resp_summary.items()} if isinstance(resp_summary, dict) else str(resp_summary)[:400],
                        })

                        if isinstance(result, dict) and result.get("skipped"):
                            blocked_url = args_parsed.get("url") or args_parsed.get("endpoint") or args_parsed.get("raw", "")
                            parsed_blocked = urlparse(blocked_url) if blocked_url else None
                            if parsed_blocked and parsed_blocked.scheme and parsed_blocked.hostname:
                                _cb("out_of_scope", {"url": blocked_url, "tool": fn_name, "phase": phase.name})

                        needs_reauth = False
                        if fn_name in ("navigate", "click") and page:
                            original = args_parsed.get("url") or target.url
                            needs_reauth = await _check_session_lost(
                                page, auth_session, target, original,
                                router=router, model=model,
                                interactive_session=interactive_session,
                                on_progress=_cb, cancel_flag=cancel_flag)
                        elif fn_name in ("api_request", "fuzz_parameter", "api_request_raw",
                                         "test_auth_bypass", "replay_with_modification"):
                            resp_status = result.get("status") if isinstance(result, dict) else None
                            if resp_status in (401, 403) and page and auth_session:
                                needs_reauth = await _check_session_lost(
                                    page, auth_session, target, target.url,
                                    router=router, model=model,
                                    interactive_session=interactive_session,
                                    on_progress=_cb, cancel_flag=cancel_flag)
                        if needs_reauth:
                            _cb("auth", {"status": "re-authenticated", "reason": "session_lost"})
                            cookies = await page.context.cookies()
                            cookie_dict = {c["name"]: c["value"] for c in cookies}
                            cookie_dict.setdefault("language", "en")
                            http_client = httpx.AsyncClient(
                                headers=auth_session.get_auth_header(),
                                cookies=cookie_dict,
                                timeout=30.0,
                            )
                            tools._http_client = http_client

                        crawl_url = None
                        if fn_name == "navigate" and result.get("url"):
                            crawl_url = result["url"]
                        elif fn_name in ("api_request", "api_request_raw"):
                            crawl_url = args_parsed.get("url") or args_parsed.get("raw", "")
                        elif fn_name in ("fuzz_parameter", "test_auth_bypass",
                                         "test_method_override"):
                            crawl_url = args_parsed.get("endpoint") or args_parsed.get("url") or ""
                        elif fn_name == "replay_with_modification":
                            req = args_parsed.get("request") if isinstance(args_parsed.get("request"), dict) else {}
                            crawl_url = req.get("url") or args_parsed.get("url") or ""
                        elif fn_name == "inject_payload":
                            crawl_url = result.get("url") or ""
                        crawl_type = _classify_url(crawl_url, result, fn_name) if crawl_url else "page"
                        if crawl_url and not crawl_url.startswith("http"):
                            crawl_url = None
                        if crawl_url and not _is_in_scope(crawl_url, allowed_domains):
                            crawl_url = None
                        if crawl_url and crawl_url not in metrics["pages_list"]:
                            metrics["pages_list"].append(crawl_url)
                            metrics["pages_crawled"] += 1
                            _cb("crawl", {"url": crawl_url, "type": crawl_type, "tool": fn_name, "count": metrics["pages_crawled"]})
                        if fn_name == "get_forms" and result.get("forms"):
                            metrics["forms_found"] += len(result["forms"])
                        elif fn_name in ("get_network_log", "intercept_requests"):
                            registry.add_from_traffic(result)
                        is_security_test = fn_name in SECURITY_TEST_TOOLS
                        if not is_security_test and fn_name == "navigate":
                            nav_url = (args_parsed.get("url") or "") if isinstance(args_parsed, dict) else ""
                            if any(m in nav_url for m in _INJECTION_MARKERS):
                                is_security_test = True
                        if is_security_test:
                            metrics["test_log"].append({
                                "phase": phase.id,
                                "tool": fn_name,
                                "request": args_parsed,
                                "response_summary": resp_summary,
                            })
                            _capture_evidence(phase_evidence, fn_name, args_parsed, resp_summary, result)
                    if unknown_in_batch > 0 and unknown_in_batch == len(tool_calls):
                        correction = (
                            " | IMPORTANT: All tool calls in this batch were invalid. "
                            "Use ONLY the tools listed in your system prompt. "
                            "Do NOT invent tool names."
                        )
                        if messages and messages[-1].get("role") == "tool":
                            messages[-1]["content"] = str(messages[-1].get("content", "")) + correction
                        else:
                            messages.append({"role": "user", "content": correction.strip(" |")})
                    if phase_tool_calls % 5 == 0 and _estimate_tokens(messages) > TRIM_TARGET_TOKENS:
                        messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)
                else:
                    content = msg_dict.get("content") or getattr(msg, "content", "") or ""
                    if not isinstance(content, str):
                        content = json.dumps(content) if isinstance(content, (dict, list)) else str(content)
                    snippet = content[:300].replace("\n", " ").strip()
                    _cb("tool_call", {
                        "phase": phase.name,
                        "tool": "[LLM analysis]",
                        "request": {"prompt": phase.prompt[:120] + "..." if len(phase.prompt) > 120 else phase.prompt},
                        "response": {"text": snippet[:200] + "..." if len(snippet) > 200 else snippet},
                    })

                    # Check if the LLM has done enough security testing
                    security_calls = sum(
                        1 for t in metrics.get("test_log", [])
                        if t.get("phase") == phase.id
                    )
                    min_calls = _MIN_SECURITY_CALLS.get(phase.id, 0)
                    if security_calls < min_calls and step < phase.max_steps - 5:
                        continuation = (
                            f"STOP — you have only performed {security_calls} security test calls "
                            f"but this phase requires at least {min_calls}. You MUST continue testing.\n"
                            "DO NOT output findings yet. Instead:\n"
                            "1. Use fuzz_parameter to send MULTIPLE payloads to DIFFERENT endpoints\n"
                            "2. Test the LOGIN endpoint with injection payloads (api_request POST)\n"
                            "3. Navigate to MORE pages and test their inputs (search, profile, order tracking)\n"
                            "4. Call get_network_log to find API endpoints you haven't tested yet\n"
                            "5. If you found an error/vulnerability, ESCALATE — try UNION SELECT, data extraction\n"
                            "6. Test URL parameters on SPA routes (navigate to /#/route?param=PAYLOAD)\n"
                            "Keep going until you've tested at least " + str(min_calls) + " distinct test calls."
                        )
                        logger.info(
                            "Phase %s: only %d/%d security calls, forcing continuation at step %d",
                            phase.name, security_calls, min_calls, step,
                        )
                        messages.append({"role": "user", "content": continuation})
                        continue

                    new_f = extract_findings(str(content))

                    rejected = extract_findings(str(content), require_evidence=False)
                    has_ungrounded = len(rejected) > len(new_f)

                    if has_ungrounded and phase_evidence:
                        evidence_text = _format_evidence_buffer(phase_evidence)
                        logger.info(
                            "Phase %s: %d findings lacked evidence, retrying with %d evidence records",
                            phase.name, len(rejected) - len(new_f), len(phase_evidence),
                        )
                        messages.append({"role": "user", "content": evidence_text})
                        try:
                            _check_cancel()
                            retry_resp = router.complete(
                                model=model,
                                messages=messages,
                                tools=[],
                                cancel_flag=cancel_flag,
                            )
                            if retry_resp and getattr(retry_resp, "choices", None):
                                retry_content = retry_resp.choices[0].message.content or ""
                                retry_f = extract_findings(str(retry_content))
                                if retry_f:
                                    new_f = retry_f
                                    logger.info("Evidence retry produced %d grounded findings", len(retry_f))
                        except Exception as e:
                            logger.warning("Evidence retry failed: %s", e)

                    findings.extend(new_f)
                    for f in new_f:
                        f["phase"] = phase.name
                        _match_evidence_to_finding(f, phase_evidence)
                        _cb("finding", f)
                    break

            phase_new_findings = len(findings) - phase_findings_before

            # ── Phase Retry: if key injection phase found 0, retry with analysis ──
            _RETRY_PHASES = {"web_a03_sqli", "web_a03_xss", "web_a03_cmdi",
                            "web_a03_ssti", "web_a03_path_traversal", "web_a03_xxe",
                            "web_a01", "web_a07", "web_a10",
                            "api_injection", "api_ssrf", "api_authz"}
            if (phase.id in _RETRY_PHASES
                    and phase_new_findings == 0
                    and phase_evidence
                    and not getattr(phase, "_retried", False)):
                phase._retried = True
                evidence_text = _format_evidence_buffer(phase_evidence)
                retry_prompt = (
                    f"RETRY — Phase '{phase.name}' found 0 vulnerabilities. "
                    "Review your test results below and try a DIFFERENT approach:\n\n"
                    f"{evidence_text}\n\n"
                    "ANALYSIS REQUIRED:\n"
                    "1. Look at which endpoints you tested and their responses\n"
                    "2. Did you get any status 500, error messages, or anomalies? Those indicate injection worked.\n"
                    "3. Did you use baseline_value with fuzz_parameter? Without it, payloads like ' won't "
                    "trigger errors in SQL LIKE '%input%' clauses. Set baseline_value='test' so "
                    "the actual value sent is 'test' + payload (e.g. q=test').\n"
                    "4. Try DIFFERENT endpoints you haven't tested yet\n"
                    "5. Try api_request with the full URL and payload manually constructed\n"
                    "6. Try inject_payload on any form fields (login username, search box)\n\n"
                    "DO NOT give up. Try at least 3 more approaches before concluding."
                )
                logger.info("Phase %s: 0 findings with %d evidence records, running retry pass",
                            phase.name, len(phase_evidence))
                print(f" [RETRY] {phase.name}: 0 findings, retrying with evidence analysis...")
                _cb("phase_start", {"phase": phase_num, "total": total_phases,
                                    "name": f"{phase.name} (retry)", "id": f"{phase.id}_retry"})
                messages.append({"role": "user", "content": retry_prompt})
                phase_evidence_retry: list[dict] = []
                retry_findings_before = len(findings)
                retry_tool_calls = 0
                for retry_step in range(phase.max_steps):
                    _check_cancel()
                    try:
                        _sanitize_all_messages(messages)
                        messages = _repair_tool_pairs(messages)
                        response = router.complete(model=model, messages=messages,
                                                   tools=TOOL_DEFINITIONS, cancel_flag=cancel_flag)
                    except (ContentFiltered, ContextWindowExceeded, MalformedMessages):
                        break
                    except ScanCancelled:
                        raise
                    _check_cancel()
                    if not response or not getattr(response, "choices", None):
                        break
                    msg = response.choices[0].message
                    msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
                    msg_dict = _sanitize_message(msg_dict)
                    messages.append(msg_dict)
                    tool_calls = msg_dict.get("tool_calls") or getattr(msg, "tool_calls", None) or []
                    if tool_calls:
                        for tc in tool_calls:
                            _check_cancel()
                            tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                            fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                            fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                            fn_name = _sanitize_tool_name(fn_name)
                            fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")
                            result = await tools.execute(fn_name, fn_args)
                            retry_tool_calls += 1
                            metrics["total_tool_calls"] += 1
                            messages.append({"role": "tool", "tool_call_id": tc_id,
                                             "content": _cap_result(result)})
                            try:
                                args_parsed = json.loads(fn_args) if isinstance(fn_args, str) else fn_args
                            except Exception:
                                args_parsed = {"raw": fn_args}
                            resp_summary = {
                                k: v for k, v in result.items()
                                if k in ("status", "url", "error", "reflected", "anomaly", "body_snippet", "results", "title")
                            } if isinstance(result, dict) else str(result)[:200]
                            _cb("tool_call", {
                                "phase": f"{phase.name} (retry)",
                                "tool": fn_name,
                                "request": {k: str(v)[:300] for k, v in args_parsed.items()} if isinstance(args_parsed, dict) else str(args_parsed)[:400],
                                "response": {k: str(v)[:200] for k, v in resp_summary.items()} if isinstance(resp_summary, dict) else str(resp_summary)[:400],
                            })
                            is_sec = fn_name in SECURITY_TEST_TOOLS
                            if not is_sec and fn_name == "navigate":
                                nav_url = (args_parsed.get("url") or "") if isinstance(args_parsed, dict) else ""
                                if any(m in nav_url for m in _INJECTION_MARKERS):
                                    is_sec = True
                            if is_sec:
                                metrics["test_log"].append({"phase": phase.id, "tool": fn_name,
                                                            "request": args_parsed, "response_summary": resp_summary})
                                _capture_evidence(phase_evidence_retry, fn_name, args_parsed, resp_summary, result)
                        if retry_tool_calls % 5 == 0 and _estimate_tokens(messages) > TRIM_TARGET_TOKENS:
                            messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)
                    else:
                        content = msg_dict.get("content") or ""
                        retry_f = extract_findings(str(content))
                        if not retry_f and phase_evidence_retry:
                            ev_text = _format_evidence_buffer(phase_evidence_retry)
                            messages.append({"role": "user", "content": ev_text})
                            try:
                                ev_resp = router.complete(model=model, messages=messages, tools=[], cancel_flag=cancel_flag)
                                if ev_resp and getattr(ev_resp, "choices", None):
                                    retry_f = extract_findings(str(ev_resp.choices[0].message.content or ""))
                            except Exception:
                                pass
                        findings.extend(retry_f)
                        for f in retry_f:
                            f["phase"] = f"{phase.name} (retry)"
                            _match_evidence_to_finding(f, phase_evidence_retry or phase_evidence)
                            _cb("finding", f)
                        break
                retry_new = len(findings) - retry_findings_before
                phase_new_findings += retry_new
                phase_tool_calls += retry_tool_calls
                print(f" [RETRY] {retry_tool_calls} tool calls, {retry_new} findings")
                _cb("phase_end", {"phase": phase_num, "name": f"{phase.name} (retry)",
                                  "tool_calls": retry_tool_calls, "findings": retry_new})

            metrics["phases_completed"] += 1
            metrics["phase_log"].append({
                "phase": phase.id,
                "name": phase.name,
                "tool_calls": phase_tool_calls,
                "findings_count": phase_new_findings,
                "evidence_buffer": phase_evidence[:60],
            })
            print(f" {phase_tool_calls} tool calls, {phase_new_findings} findings")
            _cb("phase_end", {"phase": phase_num, "name": phase.name, "tool_calls": phase_tool_calls, "findings": phase_new_findings})
            messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)

            # ── Re-run passive recon after first LLM phase ──────────────
            # After the first phase the LLM has navigated/interacted with
            # the SPA. Dynamic iframes and lazy-loaded scripts may now be
            # present that weren't visible during the initial pass.
            # CRITICAL: If initial passive recon was skipped (not on target),
            # this is our second chance to run it on the actual target page.
            if phase_idx == 0:
                try:
                    print("  [PASSIVE-2] Re-running passive recon on authenticated page...")
                    _cb("phase_start", {"phase": 0, "total": 0, "name": "Passive Recon (post-auth)", "id": "passive_recon_2"})
                    p2_findings = await run_passive_recon(
                        page=page,
                        http_client=http_client,
                        target_url=target.url,
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Passive Recon (post-auth)"}),
                        on_progress=_passive_progress,
                        network_js_urls=network_js_urls,
                    )
                    existing_titles = {f.get("title", "") + f.get("url", "") for f in findings}
                    new_p2 = [f for f in p2_findings if f.get("title", "") + f.get("url", "") not in existing_titles]
                    findings.extend(new_p2)
                    print(f"  [PASSIVE-2] Done: {len(p2_findings)} total, {len(new_p2)} new findings")
                    _cb("phase_end", {"phase": 0, "name": "Passive Recon (post-auth)",
                                      "tool_calls": 0, "findings": len(new_p2)})
                    if new_p2:
                        p2_summary = _format_passive_for_llm(new_p2)
                        messages.append({"role": "user", "content":
                            f"[SYSTEM] Additional passive recon findings from the authenticated page:\n{p2_summary}\n"
                            "Use these to inform your remaining scan phases."})
                except Exception as e:
                    logger.warning("Post-auth passive recon failed (non-fatal): %s", e)

        metrics["api_endpoints_found"] = len(registry.get_all())
        print(f"  [DONE] Pages: {metrics['pages_crawled']}, Forms: {metrics['forms_found']}, APIs: {metrics['api_endpoints_found']}, Findings: {len(findings)}")

        # ── Runtime Verification Phase (no LLM, replays payloads) ──
        _check_cancel()
        if findings:
            _cb("phase_start", {"phase": total_phases, "total": total_phases, "name": "Runtime Verification", "id": "verification"})
            print("  [VERIFY] Replaying payloads to confirm findings...")
            try:
                from scripts.runtime_verifier import verify_all_findings

                def _verify_progress(idx, total, title, verdict):
                    _cb("tool_call", {
                        "phase": "Runtime Verification",
                        "tool": "verify_replay",
                        "request": {"finding": title[:80], "step": f"{idx}/{total}"},
                        "response": {"verdict": verdict},
                    })

                verified = await verify_all_findings(
                    findings,
                    target_url=target.url,
                    cookies=cookie_dict,
                    headers=headers,
                    on_progress=_verify_progress,
                    cancel_flag=cancel_flag,
                    pause_flag=pause_flag,
                    on_pause=_cb,
                )

                confirmed = sum(1 for f in verified if f.get("verdict") == "CONFIRMED")
                disproved = sum(1 for f in verified if f.get("verdict") == "DISPROVED")
                inconclusive = sum(1 for f in verified if f.get("verdict") == "INCONCLUSIVE")
                unverified = sum(1 for f in verified if f.get("verdict") == "UNVERIFIED")

                print(f"  [VERIFY] {confirmed} confirmed, {disproved} disproved, "
                      f"{inconclusive} inconclusive, {unverified} unverified")

                metrics["verification"] = {
                    "confirmed": confirmed,
                    "disproved": disproved,
                    "inconclusive": inconclusive,
                    "unverified": unverified,
                }
                findings = verified
            except Exception as e:
                print(f"  [VERIFY] Verification failed (non-fatal): {e}")
                logger.warning("Runtime verification failed: %s", e, exc_info=True)

            _cb("phase_end", {"phase": len(phases), "name": "Runtime Verification",
                              "tool_calls": len(findings), "findings": 0})

        auth_session.stop_monitor()
        await http_client.aclose()
        await browser.close()

    return findings, metrics


def _extract_json_objects(text: str):
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                yield text[start : i + 1]


def _has_evidence(obj: dict) -> bool:
    """Return True if the finding has real proof — a non-empty payload or evidence field."""
    payload = _s(obj.get("payload")).strip()
    evidence = _s(obj.get("evidence")).strip()
    return bool(payload) or bool(evidence)


def _process_finding_obj(obj: dict, findings: list[dict], rejected: list[str],
                         require_evidence: bool, dedup: bool = False) -> None:
    """Process a single JSON object: extract findings from it or its wrapper keys."""
    if isinstance(obj, dict):
        if "title" in obj and "severity" in obj:
            if require_evidence and not _has_evidence(obj):
                rejected.append(obj.get("title", "?"))
                return
            if dedup and any(f.get("title") == obj.get("title") and f.get("severity") == obj.get("severity") for f in findings):
                return
            findings.append(obj)
        else:
            for wrapper_key in ("findings", "results", "vulnerabilities", "issues"):
                inner = obj.get(wrapper_key)
                if isinstance(inner, list):
                    for item in inner:
                        if isinstance(item, dict) and "title" in item and "severity" in item:
                            _process_finding_obj(item, findings, rejected, require_evidence, dedup)


def extract_findings(content: str, *, require_evidence: bool = True) -> list[dict]:
    findings: list[dict] = []
    rejected: list[str] = []
    if not content:
        return findings

    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", content):
        for obj_str in _extract_json_objects(block.strip()):
            try:
                obj = json.loads(obj_str)
                _process_finding_obj(obj, findings, rejected, require_evidence)
            except json.JSONDecodeError:
                pass

    for obj_str in _extract_json_objects(content):
        try:
            obj = json.loads(obj_str)
            _process_finding_obj(obj, findings, rejected, require_evidence, dedup=True)
        except json.JSONDecodeError:
            pass

    if rejected:
        logger.warning("Rejected %d finding(s) without payload/evidence: %s",
                       len(rejected), "; ".join(rejected[:5]))

    return findings


def _recover_messages(messages: list[dict]) -> list[dict]:
    """Last-resort recovery: strip back to the last complete user/assistant exchange.
    Keeps system message + summary + walks backward to find a safe cut point."""
    if len(messages) <= 2:
        return messages

    safe = [messages[0]]
    cut = len(messages)
    for i in range(len(messages) - 1, 0, -1):
        m = messages[i]
        if m.get("role") == "user" and m.get("content"):
            cut = i + 1
            break
    safe.extend(messages[1:cut])
    safe = _repair_tool_pairs(safe)

    if len(safe) < 2:
        safe = [messages[0], {
            "role": "user",
            "content": "[Previous context was reset due to a message formatting error. Continue scanning from where you left off.]",
        }]
    logger.info("Message recovery: %d -> %d messages", len(messages), len(safe))
    return safe


def _repair_tool_pairs(messages: list[dict]) -> list[dict]:
    """Ensure every assistant(tool_calls) is followed by its tool results and
    no orphaned tool messages exist.  Bedrock rejects malformed sequences."""
    if not messages:
        return messages

    pending_tc_ids: set[str] = set()
    repaired: list[dict] = []

    for m in messages:
        role = m.get("role")
        if role == "tool":
            tc_id = m.get("tool_call_id", "")
            if tc_id not in pending_tc_ids:
                continue
            repaired.append(m)
            pending_tc_ids.discard(tc_id)
        else:
            if pending_tc_ids:
                while repaired and repaired[-1].get("role") == "tool":
                    repaired.pop()
                if repaired and repaired[-1].get("tool_calls"):
                    repaired.pop()
                pending_tc_ids.clear()

            repaired.append(m)
            if role == "assistant" and m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                    if tc_id:
                        pending_tc_ids.add(tc_id)

    if pending_tc_ids:
        while repaired and repaired[-1].get("role") == "tool":
            repaired.pop()
        if repaired and repaired[-1].get("tool_calls"):
            repaired.pop()

    return repaired


def trim_context(messages: list[dict], max_tokens: int = TRIM_TARGET_TOKENS) -> list[dict]:
    estimated = _estimate_tokens(messages)
    if estimated <= max_tokens:
        return messages

    for m in messages:
        if m.get("role") == "tool" and isinstance(m.get("content"), str) and len(m["content"]) > MAX_MSG_RESULT_CHARS:
            m["content"] = m["content"][:MAX_MSG_RESULT_CHARS] + '..."}'

    estimated = _estimate_tokens(messages)
    if estimated <= max_tokens:
        return messages

    kept: list[dict] = []
    if messages:
        kept.append(messages[0])

    phase_boundaries: list[int] = []
    for i, m in enumerate(messages[1:], 1):
        if m.get("role") == "user" and "content" in m:
            phase_boundaries.append(i)

    if len(phase_boundaries) <= 1:
        kept.extend(messages[1:])
        return _repair_tool_pairs(kept)

    last_start = phase_boundaries[-1]
    summary = {
        "role": "user",
        "content": "[Previous phases completed and summarized to fit token budget. Continue scanning with fresh context.]",
    }
    kept.append(summary)
    kept.extend(messages[last_start:])

    if _estimate_tokens(kept) > max_tokens and len(kept) > 10:
        trimmed: list[dict] = [kept[0], kept[1]]
        trimmed.extend(kept[-8:])
        return _repair_tool_pairs(trimmed)

    return _repair_tool_pairs(kept)


def save_results(
    filepath: str,
    findings: list[dict],
    cost_summary: list[dict],
    target: ScanTarget,
    model: str,
    scan_duration: float,
    scan_metrics: dict | None = None,
) -> dict:
    total_cost = sum(c.get("cost_usd", 0) for c in cost_summary)
    total_tokens = sum(c.get("input_tokens", 0) + c.get("output_tokens", 0) for c in cost_summary)
    tool_calls = sum(c.get("calls", 0) for c in cost_summary)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    owasp_counts: dict[str, int] = {}
    for f in findings:
        sev = _s(f.get("severity") or "Info")
        for key in severity_counts:
            if key.lower() == sev.lower():
                severity_counts[key] += 1
                break
        else:
            severity_counts["Info"] += 1
        cat = _s(f.get("owasp_category") or "Unknown")
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    metrics = scan_metrics or {}

    output = {
        "scanner": "ai_agent",
        "model": model,
        "target": target.url,
        "target_id": target.id,
        "scan_mode": target.scan_mode,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "owasp_breakdown": owasp_counts,
            "pages_crawled": metrics.get("pages_crawled", 0),
            "pages_list": metrics.get("pages_list", []),
            "forms_found": metrics.get("forms_found", 0),
            "api_endpoints_found": metrics.get("api_endpoints_found", 0),
            "auth_pages_detected": metrics.get("auth_pages_detected", 0),
            "phases_completed": metrics.get("phases_completed", 0),
            "total_tool_calls": metrics.get("total_tool_calls", 0),
            "phase_log": metrics.get("phase_log", []),
            "test_log": metrics.get("test_log", []),
        },
        "findings": findings,
        "metadata": {
            "model": model,
            "scan_duration_seconds": round(scan_duration, 2),
            "llm_calls": tool_calls,
            "total_tokens": total_tokens,
            "cost_usd": round(total_cost, 4),
            "cost_summary_by_model": cost_summary,
        },
    }
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    return output


class DryRunScanTools(ScanTools):
    async def inject_payload(self, selector: str, payload: str) -> dict:
        return {"status": "DRY RUN", "message": "No payload injected in dry run"}


async def run_dry_scan(
    target: ScanTarget,
    model: str,
    router: LLMRouter,
    config_dir: str | None = None,
) -> dict:
    config_dir = config_dir or os.getcwd()

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        auth_session = await authenticate(browser, target, router, model)
        page = auth_session.page

        cookies = await page.context.cookies()
        cookie_dict = {c["name"]: c["value"] for c in cookies}
        headers = auth_session.get_auth_header()
        http_client = httpx.AsyncClient(
            headers=headers,
            cookies=cookie_dict,
            timeout=30.0,
        )

        registry = EndpointRegistry()
        if target.scan_mode in ("api", "both"):
            postman_path = _resolve_import_path(config_dir, target.postman_file)
            if postman_path:
                registry.add(parse_postman_collection(postman_path, _resolve_import_path(config_dir, target.postman_env)))
            openapi_path = _resolve_import_path(config_dir, target.openapi_file)
            if openapi_path:
                registry.add(parse_openapi_spec(openapi_path))
            burp_path = _resolve_import_path(config_dir, getattr(target, "burp_file", None))
            if burp_path:
                try:
                    import json as _json
                    burp_data = _json.loads(Path(burp_path).read_text(encoding="utf-8"))
                    registry.add_from_traffic(burp_data)
                except Exception:
                    pass

        tools = DryRunScanTools(
            page=page,
            http_client=http_client,
            registry=registry,
            auth_session=auth_session,
        )

        app_info = await detect_app_type(page)
        phases = get_phases(target.scan_mode, app_info, scan_scope=getattr(target, "scan_scope", "directory"), focus_areas=getattr(target, "focus_areas", None))
        recon_phases = [ph for ph in phases if "recon" in ph.id.lower()]
        if not recon_phases:
            recon_phases = phases[:1]

        system_prompt = build_system_prompt(target, registry, app_info)
        messages: list[dict] = [{"role": "system", "content": system_prompt}]

        pages_discovered: list[str] = []
        forms_discovered: list[dict] = []
        apis_discovered: list[dict] = []

        for phase in recon_phases:
            messages.append({"role": "user", "content": phase.prompt})

            for step in range(min(phase.max_steps, 20)):
                _sanitize_all_messages(messages)
                response = router.complete(
                    model=model,
                    messages=messages,
                    tools=TOOL_DEFINITIONS,
                )
                if not response or not getattr(response, "choices", None):
                    logger.warning("Empty response from %s at phase %s step %d", model, phase.id, step)
                    break
                msg = response.choices[0].message
                msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
                msg_dict = _sanitize_message(msg_dict)
                messages.append(msg_dict)

                tool_calls = msg_dict.get("tool_calls") or []
                if tool_calls:
                    for tc in tool_calls:
                        fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                        fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                        fn_name = _sanitize_tool_name(fn_name)
                        fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")
                        result = await tools.execute(fn_name, fn_args)
                        tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": json.dumps(result),
                        })
                        if fn_name == "navigate" and "url" in result:
                            pages_discovered.append(result.get("url", ""))
                        elif fn_name == "get_forms" and "forms" in result:
                            forms_discovered.extend(result.get("forms", []))
                        elif fn_name in ("get_network_log", "intercept_requests"):
                            registry.add_from_traffic(result)
                else:
                    break

        eps = registry.get_all()
        for ep in eps:
            apis_discovered.append({"method": ep.method, "path": ep.path, "url": ep.url})

        auth_session.stop_monitor()
        await http_client.aclose()
        await browser.close()

    return {
        "pages_discovered": list(dict.fromkeys(pages_discovered)),
        "forms_discovered": forms_discovered,
        "apis_discovered": apis_discovered,
    }
