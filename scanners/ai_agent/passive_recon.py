"""Passive Reconnaissance Phase — deterministic checks, no LLM needed.

Runs before the LLM scan phases. Checks for:
  - JavaScript source maps exposed in production
  - Dangerous JS sinks (trustAsHtml, innerHTML, eval, etc.)
  - Hardcoded secrets in JS files
  - Internal URLs/IPs in JS
  - Sensitive files (.git, .env, .bak, etc.)
  - Security headers missing
  - HTML comments with secrets
  - Server version disclosure
  - Security tokens leaked into telemetry/logging endpoints
  - Cookie security audit (Secure, HttpOnly, SameSite flags)
  - JWT token analysis (weak algorithms, missing claims)
  - CORS misconfiguration (permissive Access-Control-Allow-Origin)
  - Cache-Control on authenticated pages
  - Subresource Integrity (SRI) missing on external scripts
  - API version downgrade discovery
  - Form action targets on external domains
  - TLS protocol + cipher audit (TLS 1.0/1.1, 3DES/Sweet32, RC4, NULL, EXPORT, anon DH)
    — runs per-host across every in-scope https hostname harvested from
      the landing-page DOM, robots.txt, and sitemap.xml
    — uses sslyze (if installed) for authoritative cipher enumeration,
      falling back to native OpenSSL per-cipher probes
  - Vulnerable JavaScript library detection (OSV.dev + NVD enrichment)
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ── Dangerous JS sink patterns (DOM XSS vectors) ──────────────────────
_DANGEROUS_SINKS = [
    (r'\$sce\.trustAsHtml\s*\(', "$sce.trustAsHtml() — bypasses Angular sanitization", "CWE-79", 6.1),
    (r'\$sce\.trustAs\s*\(', "$sce.trustAs() — bypasses Angular sanitization", "CWE-79", 5.3),
    (r'\.innerHTML\s*=', ".innerHTML assignment — direct DOM XSS vector", "CWE-79", 5.3),
    (r'\.outerHTML\s*=', ".outerHTML assignment — direct DOM XSS vector", "CWE-79", 5.3),
    (r'document\.write\s*\(', "document.write() — legacy DOM XSS vector", "CWE-79", 5.3),
    (r'document\.writeln\s*\(', "document.writeln() — legacy DOM XSS vector", "CWE-79", 5.3),
    (r'v-html\s*=', "v-html directive — Vue.js raw HTML rendering", "CWE-79", 5.3),
    (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML — React raw HTML", "CWE-79", 5.3),
    (r'bypassSecurityTrust', "bypassSecurityTrust — Angular DomSanitizer bypass", "CWE-79", 6.1),
    (r'\beval\s*\(', "eval() — code injection vector", "CWE-95", 7.5),
    (r'new\s+Function\s*\(', "new Function() — dynamic code execution", "CWE-95", 6.1),
    (r'setTimeout\s*\(\s*["\']', "setTimeout with string — potential code injection", "CWE-95", 4.3),
    (r'setInterval\s*\(\s*["\']', "setInterval with string — potential code injection", "CWE-95", 4.3),
]

# ── Secret patterns in JS ─────────────────────────────────────────────
_SECRET_PATTERNS = [
    (r'''(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]''', "API key"),
    (r'''(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]''', "Password/Secret"),
    (r'''(?:aws_access_key_id)\s*[:=]\s*['"]AKIA[A-Z0-9]{16}['"]''', "AWS Access Key"),
    (r'''(?:private[_-]?key)\s*[:=]\s*['"][^'"]{20,}['"]''', "Private key"),
    (r'''Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+''', "Hardcoded JWT token"),
    (r'''(?:token)\s*[:=]\s*['"]eyJ[A-Za-z0-9_-]{20,}['"]''', "Hardcoded token"),
    (r'''(?:connection[_-]?string|database[_-]?url)\s*[:=]\s*['"][^'"]{15,}['"]''', "Database connection string"),
]

# ── Internal URL/IP patterns ──────────────────────────────────────────
_INTERNAL_PATTERNS = [
    (r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})[\w/.-]*', "Internal IP address"),
    (r'https?://localhost[:\d]*[\w/.-]*', "Localhost reference"),
    (r'https?://[a-z0-9.-]*(?:staging|stage|dev|internal|test|qa|uat|preprod)[a-z0-9.-]*\.[a-z]{2,}[\w/.-]*', "Staging/dev URL"),
]

# ── Sensitive file paths to probe ─────────────────────────────────────
_SENSITIVE_PATHS = [
    (".git/HEAD", "Git repository", "Critical", "CWE-538", 9.1,
     "Git repository exposed — attacker can download full source code with `git-dumper`"),
    (".env", "Environment file", "Critical", "CWE-200", 9.1,
     "Environment file with secrets/API keys accessible"),
    (".git/config", "Git config", "High", "CWE-538", 7.5,
     "Git config exposed — reveals remote repository URL and branches"),
    ("wp-config.php.bak", "WordPress config backup", "High", "CWE-530", 7.5,
     "Backup of WordPress config with database credentials"),
    (".DS_Store", "macOS directory listing", "Low", "CWE-538", 3.7,
     "macOS .DS_Store file reveals directory structure"),
    ("web.config", "IIS/ASP.NET config", "Medium", "CWE-200", 5.3,
     "IIS configuration file may contain connection strings"),
    (".htaccess", "Apache config", "Low", "CWE-200", 3.7,
     "Apache config may reveal rewrite rules and internal paths"),
    ("robots.txt", "Robots file", "Info", "CWE-200", 0.0, None),
    ("sitemap.xml", "Sitemap", "Info", "CWE-200", 0.0, None),
    ("crossdomain.xml", "Flash cross-domain policy", "Low", "CWE-942", 3.7,
     "Cross-domain policy may allow unauthorized cross-origin access"),
    ("clientaccesspolicy.xml", "Silverlight cross-domain policy", "Low", "CWE-942", 3.7,
     "Client access policy may allow unauthorized cross-origin access"),
]

# ── Security headers to check ─────────────────────────────────────────
_REQUIRED_HEADERS = {
    "strict-transport-security": ("HSTS", "CWE-319", 4.3),
    "content-security-policy": ("CSP", "CWE-693", 4.7),
    "x-frame-options": ("X-Frame-Options", "CWE-1021", 4.3),
    "x-content-type-options": ("X-Content-Type-Options", "CWE-16", 3.1),
}

_VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

# ── HTML comment patterns ─────────────────────────────────────────────
_COMMENT_SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*\S+', "Password in HTML comment"),
    (r'(?:api[_-]?key|token|secret)\s*[:=]\s*\S+', "Secret in HTML comment"),
    (r'(?:TODO|FIXME|HACK|XXX)\s*:?\s*.{10,}', "Developer note"),
    (r'(?:admin|root|debug|test)\s*(?:user|pass|account|login)', "Debug/test credential reference"),
]

# ── Telemetry / logging endpoint URL patterns ─────────────────────────
_TELEMETRY_URL_PATTERNS = re.compile(
    r"(/log[s]?(/|$|\?)|/log/post|/log[-_]?event"
    r"|/beacon|/pixel|/telemetry|/analytics"
    r"|/collect|/track(ing)?(/|$|\?)|/event[s]?(/|$|\?)"
    r"|/metric[s]?(/|$|\?)|/diagnostic[s]?"
    r"|/report[s]?(/|$|\?)|/monitor(ing)?"
    r"|/ingest|/intake|/capture"
    r"|/error[-_]?report|/crash[-_]?report"
    r"|/client[-_]?log|/client[-_]?event"
    r"|/browser[-_]?log|/perf(ormance)?"
    r"|/rum(/|$|\?)|/csp[-_]?report"
    r"|/feedback|/heartbeat|/health[-_]?check"
    r"|/audit(/|$|\?)|/trace[s]?(/|$|\?))",
    re.IGNORECASE,
)

# Known third-party telemetry/analytics domains (token-leakage destination check)
_TELEMETRY_DOMAINS = (
    "sentry.io", "browser-intake-datadoghq", "rum-http-intake",
    "bam.nr-data.net", "js-agent.newrelic.com",
    "fullstory.com", "rs.fullstory.com",
    "logrocket.io", "lr-ingest",
    "hotjar.com", "script.hotjar.com",
    "bugsnag.com", "sessions.bugsnag.com",
    "rollbar.com", "raygun.io",
    "analytics.google.com", "google-analytics.com",
    "omtrdc.net", "2o7.net", "demdex.net",
    "splunk", "logz.io", "sumo", "elastic-cloud",
    "applicationinsights.azure.com", "dc.services.visualstudio.com",
)

# Third-party vendor domains whose JS should NOT be analyzed for DOM sinks,
# secrets, or source maps — findings on these are noise, not actionable by
# the target owner.  Token leakage TO these domains is still checked (TC-8).
_THIRD_PARTY_JS_DOMAINS = (
    "ensighten.com", "nexus.ensighten.com",
    "qualtrics.com", "siteintercept.qualtrics.com",
    "omtrdc.net", "2o7.net", "demdex.net",
    "tt.omtrdc.net",
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "googleadservices.com", "doubleclick.net",
    "facebook.net", "fbcdn.net", "connect.facebook.net",
    "twitter.com", "platform.twitter.com",
    "linkedin.com", "snap.licdn.com",
    "hotjar.com", "script.hotjar.com",
    "fullstory.com", "rs.fullstory.com",
    "sentry.io", "browser.sentry-cdn.com",
    "newrelic.com", "js-agent.newrelic.com", "bam.nr-data.net",
    "datadoghq.com", "browser-intake-datadoghq.com",
    "logrocket.io", "cdn.logrocket.io",
    "bugsnag.com", "sessions.bugsnag.com",
    "rollbar.com", "raygun.io",
    "segment.io", "cdn.segment.com", "api.segment.io",
    "amplitude.com", "cdn.amplitude.com",
    "mixpanel.com", "cdn.mxpnl.com",
    "optimizely.com", "cdn.optimizely.com",
    "adobedtm.com", "assets.adobedtm.com",
    "omniture.com",
    "tealiumiq.com", "tags.tiqcdn.com",
    "cookielaw.org", "cdn.cookielaw.org",
    "onetrust.com",
    "quantserve.com",
    "adsrvr.org",
    "cloudflareinsights.com",
    "clarity.ms",
    "mouseflow.com",
    "crazyegg.com",
    "heap.io", "heapanalytics.com",
    "intercom.io", "widget.intercom.io",
    "zendesk.com", "static.zdassets.com",
    "drift.com", "js.driftt.com",
    "hubspot.com", "js.hs-scripts.com", "js.hs-analytics.net",
    "marketo.net", "munchkin.marketo.net",
    "pardot.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "fonts.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "code.jquery.com",
)


def _extract_org_domains(target_url: str) -> set[str]:
    """Extract the set of 'organisation' base domains for a target.

    For ``stage.lifelock.norton.com`` this returns ``{"norton.com"}``.
    The caller can extend this with ``extra_domains`` from scan config.
    """
    host = (urlparse(target_url).hostname or "").lower()
    parts = host.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return {base}


def _is_third_party_js(url: str, target_url: str,
                        extra_domains: set[str] | None = None) -> bool:
    """Return True if a JS URL does NOT belong to the target organisation.

    Uses same-origin check (base domain match) instead of an allowlist so
    we never accidentally analyse vendor JS that isn't in our static list.
    Falls back to the known-vendor list only for edge-case CDN-hosted
    first-party JS (e.g. jsdelivr serving the target's own bundles — rare).
    """
    try:
        host = (urlparse(url).hostname or "").lower()
        target_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False

    target_parts = target_host.split(".")
    target_base = ".".join(target_parts[-2:]) if len(target_parts) >= 2 else target_host
    host_parts = host.split(".")
    host_base = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host

    # Same base domain → first-party
    if host_base == target_base or host == target_host:
        return False

    # Extra allowed domains from scan config (e.g. nortonlifelock.com)
    if extra_domains:
        for ed in extra_domains:
            ed_parts = ed.lower().split(".")
            ed_base = ".".join(ed_parts[-2:]) if len(ed_parts) >= 2 else ed.lower()
            if host_base == ed_base:
                return False

    # Everything else is third-party — no allowlist needed
    return True

# Headers whose values should never appear in telemetry payloads
_SENSITIVE_HEADERS = (
    "x-csrf-token", "x-xsrf-token", "x-c-t",
    "x-request-verification-token", "__requestverificationtoken",
    "authorization", "x-auth-token", "x-api-key",
    "x-session-token", "x-session-id", "x-access-token",
    "x-anti-forgery-token", "x-csrf", "csrf-token",
    "cookie", "set-cookie",
    "x-forwarded-for", "x-real-ip",
    "proxy-authorization",
    "x-amz-security-token", "x-ms-token",
)

# Regex for JWT-shaped strings (header.payload.signature)
_JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')

# Keys in JSON whose values are typically sensitive
_SENSITIVE_JSON_KEYS = re.compile(
    r'"(session[_-]?(?:hash|id|token|key)|'
    r'user[_-]?hash|auth[_-]?token|access[_-]?token|refresh[_-]?token|'
    r'csrf[_-]?token|xsrf[_-]?token|api[_-]?key|'
    r'bearer|secret|password|passwd|credential|'
    r'private[_-]?key|signing[_-]?key|'
    r'cookie[_-]?value|session[_-]?cookie|'
    r'id[_-]?token|client[_-]?secret)"\s*:\s*"([^"]{8,})"',
    re.IGNORECASE,
)


async def run_passive_recon(
    page,
    http_client,
    target_url: str,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    network_js_urls: set | None = None,
    skip_tls_sibling_discovery: bool = False,
) -> list[dict]:
    """Run all passive recon checks. Returns list of findings.

    Args:
        network_js_urls: optional pre-collected set of .js URLs captured
            via network interception (populated by start_js_network_capture).
            Merged with DOM-snapshot collection for maximum coverage.
    """
    findings: list[dict] = []
    _cb = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    target_parsed = urlparse(target_url)
    base_url = f"{target_parsed.scheme}://{target_parsed.netloc}"

    _progress("passive_start", {"checks": "source_maps, js_sinks, secrets, sensitive_files, headers, html_comments, telemetry_token_leakage, cookie_security, jwt_analysis, cors, cache_control, sri, form_actions, api_versioning, csp_analysis, referrer_policy, permissions_policy, mixed_content, password_autocomplete, sensitive_url_params, https_redirect, hsts_preload, error_pages, clickjacking, tls_audit, js_library_cves"})

    # ── 1. Collect all JS files loaded by the page ────────────────────
    all_js_urls = await _collect_js_urls(page, target_url)
    if network_js_urls:
        before = len(all_js_urls)
        dom_set = set(all_js_urls)
        for u in network_js_urls:
            if u not in dom_set:
                all_js_urls.append(u)
        if len(all_js_urls) > before:
            logger.info("Network capture added %d JS URLs (DOM: %d, total: %d)",
                        len(all_js_urls) - before, before, len(all_js_urls))

    js_urls = []
    third_party_js = []
    for u in all_js_urls:
        if _is_third_party_js(u, target_url):
            third_party_js.append(u)
        else:
            js_urls.append(u)

    logger.info("Passive recon: %d first-party JS, %d third-party JS (skipped)",
                len(js_urls), len(third_party_js))
    _progress("passive_step", {"step": "Collected JS files", "count": len(js_urls),
                                "third_party_skipped": len(third_party_js)})

    for tp_url in third_party_js:
        _progress("out_of_scope", {"url": tp_url, "tool": "passive_recon",
                                    "phase": "Passive Reconnaissance",
                                    "reason": "Third-party vendor JS"})

    # ── 2. Check source maps (first-party only) ───────────────────────
    source_map_findings = await _check_source_maps(http_client, js_urls)
    for f in source_map_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Source map check", "found": len(source_map_findings)})

    # ── 3. Analyze JS content for dangerous sinks + secrets (first-party only)
    js_analysis_findings = await _analyze_js_files(http_client, js_urls, page)
    for f in js_analysis_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "JS analysis", "found": len(js_analysis_findings)})

    # ── 4. Check sensitive files ──────────────────────────────────────
    sensitive_findings = await _check_sensitive_files(http_client, base_url)
    for f in sensitive_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Sensitive files", "found": len(sensitive_findings)})

    # ── 5. Check security headers ─────────────────────────────────────
    header_findings = await _check_security_headers(http_client, target_url)
    for f in header_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Security headers", "found": len(header_findings)})

    # ── 6. Analyze HTML for comments with secrets ─────────────────────
    html_findings = await _check_html_comments(page)
    for f in html_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "HTML comments", "found": len(html_findings)})

    # ── 7. Check for security tokens in telemetry/logging requests ───
    telemetry_findings = await _check_telemetry_token_leakage(page, target_url)
    for f in telemetry_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Telemetry token leakage", "found": len(telemetry_findings)})

    # ── 8. Cookie security audit ────────────────────────────────────────
    cookie_findings = await _check_cookie_security(page, target_url)
    for f in cookie_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Cookie security", "found": len(cookie_findings)})

    # ── 9. JWT analysis ──────────────────────────────────────────────────
    jwt_findings = await _check_jwt_security(page, target_url)
    for f in jwt_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "JWT analysis", "found": len(jwt_findings)})

    # ── 10. CORS misconfiguration ────────────────────────────────────────
    cors_findings = await _check_cors_misconfiguration(http_client, target_url)
    for f in cors_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "CORS check", "found": len(cors_findings)})

    # ── 11. Cache-Control on authenticated pages ─────────────────────────
    cache_findings = await _check_cache_control(http_client, target_url)
    for f in cache_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Cache-Control", "found": len(cache_findings)})

    # ── 12. SRI missing on external scripts ──────────────────────────────
    sri_findings = await _check_sri(page, target_url)
    for f in sri_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "SRI check", "found": len(sri_findings)})

    # ── 13. Form action targets on external domains ──────────────────────
    form_findings = await _check_form_actions(page, target_url)
    for f in form_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Form actions", "found": len(form_findings)})

    # ── 14. API version downgrade ────────────────────────────────────────
    api_ver_findings = await _check_api_version_downgrade(http_client, target_url, js_urls)
    for f in api_ver_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "API version check", "found": len(api_ver_findings)})

    # ── 15. CSP policy weakness analysis ──────────────────────────────
    csp_findings = await _check_csp_weaknesses(http_client, target_url)
    for f in csp_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "CSP analysis", "found": len(csp_findings)})

    # ── 16. Referrer-Policy ───────────────────────────────────────────
    rp_findings = await _check_referrer_policy(http_client, target_url)
    for f in rp_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Referrer-Policy", "found": len(rp_findings)})

    # ── 17. Permissions-Policy ────────────────────────────────────────
    pp_findings = await _check_permissions_policy(http_client, target_url)
    for f in pp_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Permissions-Policy", "found": len(pp_findings)})

    # ── 18. Mixed content ─────────────────────────────────────────────
    mixed_findings = await _check_mixed_content(page, target_url)
    for f in mixed_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Mixed content", "found": len(mixed_findings)})

    # ── 19. Password autocomplete ─────────────────────────────────────
    pw_findings = await _check_password_autocomplete(page, target_url)
    for f in pw_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Password autocomplete", "found": len(pw_findings)})

    # ── 20. Sensitive data in URL parameters ──────────────────────────
    url_param_findings = await _check_sensitive_url_params(page, target_url)
    for f in url_param_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Sensitive URL params", "found": len(url_param_findings)})

    # ── 21. HTTP→HTTPS redirect validation ────────────────────────────
    redirect_findings = await _check_https_redirect(http_client, target_url)
    for f in redirect_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "HTTPS redirect", "found": len(redirect_findings)})

    # ── 22. HSTS preload readiness ────────────────────────────────────
    hsts_findings = await _check_hsts_preload(http_client, target_url)
    for f in hsts_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "HSTS preload", "found": len(hsts_findings)})

    # ── 23. Exposed error pages ───────────────────────────────────────
    error_page_findings = await _check_error_pages(http_client, target_url)
    for f in error_page_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Error pages", "found": len(error_page_findings)})

    # ── 24. Clickjacking — frame-ancestors ────────────────────────────
    cj_findings = await _check_clickjacking(http_client, target_url)
    for f in cj_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "Clickjacking", "found": len(cj_findings)})

    # ── 25. TLS protocol & cipher audit (multi-host) ───────────────────
    # Discovers sibling https hosts from the landing-page DOM + robots.txt
    # + sitemap.xml (passive — no agent navigation) and runs the TLS audit
    # against every in-scope host. Closes the gap where the LLM agent
    # doesn't visit every subdomain that Acunetix's BFS crawler reaches.
    try:
        if skip_tls_sibling_discovery:
            tls_findings = await _check_tls_configuration(target_url)
        else:
            tls_findings = await _check_tls_configuration_multi_host(
                page, http_client, target_url
            )
    except Exception as e:
        logger.debug("TLS audit failed: %s", e)
        tls_findings = []
    for f in tls_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "TLS audit", "found": len(tls_findings)})

    # ── 26. Technology fingerprinting (context for LLM) ───────────────
    tech_fingerprint = await _fingerprint_technologies(page, http_client, target_url, js_urls)
    _progress("passive_step", {"step": "Tech fingerprint", "technologies": list(tech_fingerprint.get("technologies", {}).keys())})

    # ── 27. Vulnerable JavaScript library detection (OSV.dev + NVD) ───
    try:
        js_lib_findings = await _check_js_library_vulnerabilities(
            http_client, js_urls, page=page, target_url=target_url,
            tech_fingerprint=tech_fingerprint,
        )
    except Exception as e:
        logger.debug("JS library audit failed: %s", e)
        js_lib_findings = []
    for f in js_lib_findings:
        findings.append(f)
        _cb(f)
    _progress("passive_step", {"step": "JS library CVE audit", "found": len(js_lib_findings)})

    _progress("passive_end", {"total_findings": len(findings)})
    logger.info("Passive recon complete: %d findings", len(findings))
    return findings, tech_fingerprint


def start_js_network_capture(page) -> set:
    """Attach a network request listener that captures all .js URLs.

    Call this EARLY (before page navigations/auth) so every JS request
    the browser makes is recorded, regardless of when iframes load.

    Returns a mutable set that is updated in real-time as requests happen.
    """
    captured: set = set()

    def _on_request(request):
        url = request.url
        if not url or not url.startswith("http"):
            return
        rtype = request.resource_type
        if rtype == "script" or url.split("?")[0].split("#")[0].endswith(".js"):
            captured.add(url.split("#")[0])

    page.on("request", _on_request)
    return captured


async def _collect_js_urls(page, target_url: str) -> list[str]:
    """Extract all JS file URLs loaded by the page, including iframes.

    Performs multiple collection passes with short waits in between to
    catch dynamically/lazily loaded scripts and iframe content that may
    not be present on the initial DOM snapshot.
    """
    seen: set[str] = set()

    async def _gather_once() -> list[str]:
        """Single-pass collection from main frame + all iframes."""
        batch: list[str] = []
        try:
            urls = await page.evaluate("""() => {
                const scripts = [...document.querySelectorAll('script[src]')];
                return scripts.map(s => s.src).filter(u => u.startsWith('http'));
            }""")
            batch.extend(urls)
        except Exception:
            pass
        try:
            perf = await page.evaluate("""() => {
                return performance.getEntriesByType('resource')
                    .filter(r => r.initiatorType === 'script' || r.name.endsWith('.js'))
                    .map(r => r.name);
            }""")
            batch.extend(u for u in perf if u.startswith("http"))
        except Exception:
            pass

        for frame in page.frames:
            if frame == page.main_frame:
                continue
            try:
                iframe_js = await frame.evaluate("""() => {
                    const scripts = [...document.querySelectorAll('script[src]')];
                    const perf = performance.getEntriesByType('resource')
                        .filter(r => r.initiatorType === 'script' || r.name.endsWith('.js'))
                        .map(r => r.name);
                    return [...new Set([...scripts.map(s=>s.src), ...perf].filter(u=>u.startsWith('http')))];
                }""")
                batch.extend(iframe_js)
            except Exception:
                pass
        return batch

    # Pass 1: immediate collection
    for u in await _gather_once():
        seen.add(u)
    initial_count = len(seen)

    # Pass 2 & 3: wait for late-loading iframes/dynamic scripts
    for wait_s in (4, 6):
        await asyncio.sleep(wait_s)
        for u in await _gather_once():
            seen.add(u)
        if len(seen) > initial_count:
            logger.info("JS collection pass: %d -> %d URLs after %ds wait", initial_count, len(seen), wait_s)
            initial_count = len(seen)

    return list(seen)[:100]


async def _check_source_maps(http_client, js_urls: list[str]) -> list[dict]:
    """Check each JS file for exposed source maps."""
    findings = []
    checked = set()

    for js_url in js_urls:
        try:
            resp = await http_client.get(js_url, timeout=10.0)
            if resp.status_code != 200:
                continue
            content = resp.text[-500:] if len(resp.text) > 500 else resp.text

            map_url = None
            for pattern in [r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/']:
                m = re.search(pattern, content)
                if m:
                    raw = m.group(1).strip()
                    if raw.startswith("data:"):
                        findings.append(_make_finding(
                            "Inline Source Map Embedded in JavaScript",
                            "Medium", "CWE-540", 5.3, js_url,
                            "Inline source map (data URI) contains original source code",
                            payload=f"GET {js_url}",
                            source="passive_recon",
                        ))
                        break
                    map_url = raw if raw.startswith("http") else urljoin(js_url, raw)
                    break

            if not map_url or map_url in checked:
                continue
            checked.add(map_url)

            map_resp = await http_client.get(map_url, timeout=10.0)
            if map_resp.status_code == 200:
                ct = map_resp.headers.get("content-type", "")
                body_preview = map_resp.text[:200]
                is_map = ("json" in ct or body_preview.strip().startswith("{")) and \
                         any(k in body_preview for k in ['"sources"', '"mappings"', '"sourceRoot"', '"version"'])

                if is_map:
                    size_kb = len(map_resp.content) / 1024
                    findings.append(_make_finding(
                        "JavaScript Source Map Exposed in Production",
                        "Medium", "CWE-540", 5.3, map_url,
                        f"GET {map_url} returned HTTP 200 ({size_kb:.0f}KB). "
                        f"Response contains valid source map with original unminified source code "
                        f"and developer comments. Referenced from: {js_url}",
                        payload=f"GET {map_url}",
                        source="passive_recon",
                    ))
                    logger.info("  FOUND: Source map at %s (%.0fKB)", map_url, size_kb)
            else:
                findings.append(_make_finding(
                    "Source Map Reference in JavaScript (Map Not Accessible)",
                    "Low", "CWE-540", 3.1, js_url,
                    f"sourceMappingURL directive found pointing to {map_url} "
                    f"(HTTP {map_resp.status_code}). Reveals build toolchain details.",
                    payload=f"GET {map_url}",
                    source="passive_recon",
                ))

        except Exception as e:
            logger.debug("Source map check failed for %s: %s", js_url, e)

    return findings


async def _analyze_js_files(http_client, js_urls: list[str], page) -> list[dict]:
    """Analyze JS file contents for dangerous sinks, secrets, internal URLs."""
    findings = []
    analyzed = set()

    for js_url in js_urls[:20]:
        if js_url in analyzed:
            continue
        analyzed.add(js_url)

        try:
            resp = await http_client.get(js_url, timeout=10.0)
            if resp.status_code != 200:
                continue
            content = resp.text
            if len(content) < 50:
                continue

            js_filename = urlparse(js_url).path.split("/")[-1] or js_url

            for pattern, desc, cwe, cvss in _DANGEROUS_SINKS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    contexts = []
                    for m in matches[:3]:
                        start = max(0, m.start() - 40)
                        end = min(len(content), m.end() + 60)
                        snippet = content[start:end].replace("\n", " ").strip()
                        contexts.append(snippet)
                    evidence = f"Found in {js_filename}: " + " | ".join(contexts)
                    findings.append(_make_finding(
                        f"Dangerous DOM Sink — {desc.split('—')[0].strip()}",
                        "Medium", cwe, cvss, js_url,
                        f"{desc}. {len(matches)} occurrence(s) in {js_filename}. "
                        f"Context: {evidence[:300]}",
                        source="passive_recon",
                    ))

            for pattern, secret_type in _SECRET_PATTERNS:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    redacted = []
                    for m in matches[:3]:
                        val = m.group(0)
                        redacted.append(val[:20] + "..." + val[-4:] if len(val) > 24 else val[:20] + "...")
                    findings.append(_make_finding(
                        f"Hardcoded {secret_type} in Client-Side JavaScript",
                        "High", "CWE-798", 7.5, js_url,
                        f"{secret_type} found in {js_filename}: {', '.join(redacted)}",
                        source="passive_recon",
                    ))

            for pattern, desc in _INTERNAL_PATTERNS:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    urls_found = list(set(m.group(0) for m in matches))[:5]
                    findings.append(_make_finding(
                        f"Internal {desc} in Client-Side JavaScript",
                        "Low", "CWE-200", 3.7, js_url,
                        f"{desc} found in {js_filename}: {', '.join(urls_found)}",
                        source="passive_recon",
                    ))

        except Exception as e:
            logger.debug("JS analysis failed for %s: %s", js_url, e)

    return findings


async def _check_sensitive_files(http_client, base_url: str) -> list[dict]:
    """Probe for common sensitive files."""
    findings = []

    for path, name, severity, cwe, cvss, desc in _SENSITIVE_PATHS:
        try:
            url = f"{base_url.rstrip('/')}/{path}"
            resp = await http_client.get(url, timeout=8.0, follow_redirects=False)
            exchange = _exchange_from_httpx(resp)

            if resp.status_code == 200 and len(resp.content) > 10:
                body = resp.text[:300]

                if path == ".git/HEAD" and "ref:" in body:
                    findings.append(_make_finding(
                        f"Git Repository Exposed — {path}",
                        severity, cwe, cvss, url,
                        f"{desc}. Content: {body[:100]}",
                        source="passive_recon",
                        http_exchange=exchange,
                    ))
                elif path == ".env" and ("=" in body and not body.strip().startswith("<")):
                    findings.append(_make_finding(
                        f"Environment File Accessible — {path}",
                        severity, cwe, cvss, url,
                        f"{desc}. Preview: {body[:80]}...",
                        source="passive_recon",
                        http_exchange=exchange,
                    ))
                elif path == ".git/config" and "[core]" in body:
                    findings.append(_make_finding(
                        f"Git Config Exposed — {path}",
                        severity, cwe, cvss, url,
                        f"{desc}. Content: {body[:120]}",
                        source="passive_recon",
                        http_exchange=exchange,
                    ))
                elif path == ".DS_Store" and b"\x00\x00\x00\x01Bud1" in resp.content[:8]:
                    findings.append(_make_finding(
                        f"macOS .DS_Store File Accessible",
                        severity, cwe, cvss, url, desc,
                        source="passive_recon",
                        http_exchange=exchange,
                    ))
                elif path in ("robots.txt", "sitemap.xml"):
                    interesting = _extract_interesting_paths(body, path)
                    if interesting:
                        findings.append(_make_finding(
                            f"Interesting Paths in {path}",
                            "Info", cwe, 0.0, url,
                            f"Discovered paths: {', '.join(interesting[:10])}",
                            source="passive_recon",
                            http_exchange=exchange,
                        ))
                elif desc and not body.strip().startswith("<!DOCTYPE") and not body.strip().startswith("<html"):
                    findings.append(_make_finding(
                        f"Sensitive File Accessible — {path}",
                        severity, cwe, cvss, url,
                        f"{desc}. Content preview: {body[:80]}...",
                        source="passive_recon",
                        http_exchange=exchange,
                    ))

        except Exception as e:
            logger.debug("Sensitive file check failed for %s: %s", path, e)

    return findings


def _extract_interesting_paths(body: str, filename: str) -> list[str]:
    """Extract interesting/hidden paths from robots.txt or sitemap.xml."""
    interesting = []
    keywords = ["admin", "debug", "staging", "internal", "api", "config",
                "backup", "test", "private", "secret", "dashboard", "panel"]

    if filename == "robots.txt":
        for line in body.splitlines():
            line = line.strip()
            if line.startswith(("Disallow:", "Allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and any(k in path.lower() for k in keywords):
                    interesting.append(path)
    elif filename == "sitemap.xml":
        for m in re.finditer(r'<loc>([^<]+)</loc>', body):
            url = m.group(1)
            if any(k in url.lower() for k in keywords):
                interesting.append(url)

    return interesting


async def _check_security_headers(http_client, target_url: str) -> list[dict]:
    """Check for missing security headers and version disclosure."""
    findings = []

    try:
        resp = await http_client.get(target_url, timeout=10.0)
        exchange = _exchange_from_httpx(resp)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        missing = []
        for header, (name, cwe, cvss) in _REQUIRED_HEADERS.items():
            if header not in headers_lower:
                missing.append(name)

        if missing:
            findings.append(_make_finding(
                f"Missing Security Headers: {', '.join(missing)}",
                "Low", "CWE-693", 4.3, target_url,
                f"The following recommended security headers are absent: {', '.join(missing)}. "
                "These are defense-in-depth measures that mitigate various attack vectors.",
                source="passive_recon",
                http_exchange=exchange,
            ))

        for header in _VERSION_HEADERS:
            if header in headers_lower:
                value = headers_lower[header]
                findings.append(_make_finding(
                    f"Server Version Disclosure — {header}: {value}",
                    "Low", "CWE-200", 3.7, target_url,
                    f"Response header '{header}: {value}' discloses technology stack. "
                    "Aids attacker reconnaissance.",
                    source="passive_recon",
                    http_exchange=exchange,
                ))

    except Exception as e:
        logger.debug("Header check failed: %s", e)

    return findings


async def _check_html_comments(page) -> list[dict]:
    """Extract HTML comments and check for secrets/sensitive info."""
    findings = []

    try:
        comments = await page.evaluate("""() => {
            const walker = document.createTreeWalker(
                document.documentElement, NodeFilter.SHOW_COMMENT, null, false
            );
            const comments = [];
            let node;
            while (node = walker.nextNode()) {
                const text = node.nodeValue.trim();
                if (text.length > 10 && text.length < 2000) {
                    comments.push(text);
                }
            }
            return comments.slice(0, 30);
        }""")

        for comment in comments:
            for pattern, desc in _COMMENT_SECRET_PATTERNS:
                if re.search(pattern, comment, re.IGNORECASE):
                    findings.append(_make_finding(
                        f"{desc} in HTML Comment",
                        "Medium" if "password" in desc.lower() or "secret" in desc.lower() else "Low",
                        "CWE-615", 4.3 if "password" in desc.lower() else 3.1,
                        "HTML source",
                        f"HTML comment contains: ...{comment[:150]}...",
                        source="passive_recon",
                    ))
                    break

    except Exception as e:
        logger.debug("HTML comment check failed: %s", e)

    return findings


async def _check_telemetry_token_leakage(page, target_url: str) -> list[dict]:
    """Broad check for security tokens leaked into telemetry/logging requests.

    Test cases covered:
      TC-1  CSRF token values (window object, meta tags, hidden inputs) in POST bodies
      TC-2  Session cookie values serialized inside JSON/form telemetry payloads
      TC-3  Bearer/OAuth tokens from localStorage/sessionStorage in telemetry
      TC-4  JWT-shaped strings forwarded to logging endpoints
      TC-5  Sensitive HTTP header names echoed in request bodies (Authorization, X-CSRF-Token, …)
      TC-6  Sensitive JSON keys in telemetry payloads (sessionHash, userHash, apiKey, …)
      TC-7  Tokens leaked in query-string parameters of telemetry GET/POST URLs
      TC-8  Tokens sent to third-party analytics/error-reporting domains
      TC-9  Full HTTP request headers serialized in telemetry JSON ("headers":{…})
      TC-10 Console/debug logging intercepted (window.console monkey-patch detection)
      TC-11 Logging endpoints that return sensitive data in their response bodies
      TC-12 Performance entries showing telemetry endpoints for manual review
    """
    findings = []

    # ────────────────────────────────────────────────────────────────────
    # Phase 1 — Collect every security token we can find on the page
    # ────────────────────────────────────────────────────────────────────
    tokens: dict[str, str] = {}  # label -> value

    # TC-1: CSRF tokens from window object, meta tags, hidden inputs
    try:
        page_tokens = await page.evaluate("""() => {
            const out = {};
            const windowKeys = [
                'RequestVerificationToken', '__RequestVerificationToken',
                'csrfToken', 'csrf_token', '_csrf', 'XSRF_TOKEN',
                'antiForgeryToken', 'X_CSRF_TOKEN', 'CSRF_TOKEN',
                'antiForgery', 'xsrfToken', 'xsrf_token',
                'requestToken', 'verificationToken',
            ];
            for (const key of windowKeys) {
                if (window[key]) out['csrf:window.' + key] = String(window[key]);
            }
            // Nested CSRF (e.g. window.__config.csrfToken)
            try {
                for (const ns of ['__config', '__INITIAL_STATE__', '__APP_DATA__',
                                   'APP_CONFIG', '__NEXT_DATA__', 'props']) {
                    if (window[ns] && typeof window[ns] === 'object') {
                        const s = JSON.stringify(window[ns]).slice(0, 8000);
                        const m = s.match(/"(?:csrf|xsrf|token|verif)[^"]*"\\s*:\\s*"([^"]{8,})"/i);
                        if (m) out['csrf:' + ns] = m[1];
                    }
                }
            } catch(e) {}
            // Meta tags
            const metaSels = [
                'meta[name="csrf-token"]', 'meta[name="_csrf"]',
                'meta[name="csrf_token"]', 'meta[name="csrf"]',
                'meta[name="xsrf-token"]', 'meta[name="_token"]',
                'meta[content][name="request-token"]',
            ];
            for (const sel of metaSels) {
                const el = document.querySelector(sel);
                if (el) { const v = el.getAttribute('content'); if (v) out['csrf:meta'] = v; break; }
            }
            // Hidden inputs
            const inputSels = [
                'input[name="__RequestVerificationToken"]',
                'input[name="_csrf"]', 'input[name="csrf_token"]',
                'input[name="_token"]', 'input[name="authenticity_token"]',
                'input[name="csrfmiddlewaretoken"]', 'input[name="__VIEWSTATE"]',
            ];
            for (const sel of inputSels) {
                const el = document.querySelector(sel);
                if (el && el.value) { out['csrf:input(' + sel + ')'] = el.value; break; }
            }
            return out;
        }""")
        for k, v in (page_tokens or {}).items():
            if v and len(v) >= 8:
                tokens[k] = v
    except Exception as e:
        logger.debug("CSRF token collection failed: %s", e)

    # TC-2: Session cookies
    try:
        cookies = await page.context.cookies()
        session_kw = (
            "session", "sess", "sid", "auth", "token",
            "jwt", "csrf", "xsrf", "sso", "login", "identity",
            "credential", "access", "refresh", "saml", "oidc",
            "connect", "phpsessid", "jsessionid", "aspsession",
        )
        for c in cookies:
            name_lower = c["name"].lower()
            val = c.get("value", "")
            if not val or len(val) < 8:
                continue
            is_session = any(kw in name_lower for kw in session_kw)
            is_httponly = c.get("httpOnly", False)
            is_secure = c.get("secure", False)
            if is_session or is_httponly or is_secure:
                tokens[f"cookie:{c['name']}"] = val
    except Exception as e:
        logger.debug("Cookie collection failed: %s", e)

    # TC-3: Bearer/OAuth tokens and secrets from localStorage and sessionStorage
    try:
        storage_tokens = await page.evaluate("""() => {
            const out = {};
            const sensitiveKeys = /token|auth|session|hash|secret|key|jwt|bearer|csrf|xsrf|credential|access|refresh|oauth|apikey/i;
            function scan(store, label) {
                try {
                    for (let i = 0; i < store.length; i++) {
                        const k = store.key(i);
                        if (!sensitiveKeys.test(k)) continue;
                        let v = store.getItem(k) || '';
                        // Try to parse JSON and look for token-like values inside
                        try {
                            const obj = JSON.parse(v);
                            if (typeof obj === 'object' && obj !== null) {
                                for (const [ok, ov] of Object.entries(obj)) {
                                    if (sensitiveKeys.test(ok) && typeof ov === 'string' && ov.length >= 8) {
                                        out[label + ':' + k + '.' + ok] = ov.slice(0, 200);
                                    }
                                }
                                continue;
                            }
                        } catch(e) {}
                        if (v.length >= 8 && v.length <= 2000) {
                            out[label + ':' + k] = v.slice(0, 200);
                        }
                    }
                } catch(e) {}
            }
            scan(localStorage, 'localStorage');
            scan(sessionStorage, 'sessionStorage');
            return out;
        }""")
        for k, v in (storage_tokens or {}).items():
            if v and len(v) >= 8:
                tokens[k] = v
    except Exception as e:
        logger.debug("Storage token collection failed: %s", e)

    if not tokens:
        logger.info("Telemetry check: no security tokens found to monitor")
        return findings

    logger.info("Telemetry check: monitoring %d token(s) for leakage", len(tokens))

    # ────────────────────────────────────────────────────────────────────
    # Phase 2 — Set up request interception (captures ALL requests)
    # ────────────────────────────────────────────────────────────────────
    captured_telemetry: list[dict] = []
    captured_all_posts: list[dict] = []

    def _is_telemetry_url(url: str) -> bool:
        parsed = urlparse(url)
        if _TELEMETRY_URL_PATTERNS.search(parsed.path):
            return True
        host = (parsed.hostname or "").lower()
        if any(td in host for td in _TELEMETRY_DOMAINS):
            return True
        return False

    def _on_request(request):
        try:
            url = request.url
            method = request.method
            body = request.post_data or ""
            hdrs = {k.lower(): v for k, v in (request.headers or {}).items()}

            for hdr_name in _SENSITIVE_HEADERS:
                val = hdrs.get(hdr_name, "")
                if val and len(val) >= 8:
                    tkey = f"header:{hdr_name}"
                    if tkey not in tokens:
                        tokens[tkey] = val

            if _is_telemetry_url(url):
                captured_telemetry.append({
                    "url": url, "method": method,
                    "body": body[:8000], "headers": hdrs,
                    "query": urlparse(url).query or "",
                })
            elif method == "POST" and body and len(body) > 50:
                captured_all_posts.append({
                    "url": url, "method": method,
                    "body": body[:8000], "headers": hdrs,
                    "query": urlparse(url).query or "",
                })
        except Exception:
            pass

    page.on("request", _on_request)

    # ────────────────────────────────────────────────────────────────────
    # Phase 3 — Trigger user-like activity to generate telemetry
    # ────────────────────────────────────────────────────────────────────
    try:
        # Scroll down
        await page.evaluate("window.scrollBy(0, 300)")
        await asyncio.sleep(0.5)
    except Exception:
        pass
    try:
        # Click visible interactive elements to trigger AJAX telemetry
        clickable = await page.evaluate("""() => {
            const els = [...document.querySelectorAll(
                'a[href], button, [role="tab"], [role="button"], '
                + '.nav-link, .tab-link, [data-toggle], [onclick]'
            )];
            return els.slice(0, 5).map(el => {
                const rect = el.getBoundingClientRect();
                return {
                    tag: el.tagName, text: (el.textContent || '').trim().slice(0, 40),
                    visible: rect.width > 0 && rect.height > 0 && rect.top < 800,
                    href: el.getAttribute('href') || '',
                };
            });
        }""")
        for item in (clickable or [])[:3]:
            if not item.get("visible"):
                continue
            href = item.get("href", "")
            if href and href.startswith("http") and urlparse(href).hostname != urlparse(target_url).hostname:
                continue
            try:
                text = item["text"][:25].replace('"', '\\"')
                sel = f"{item['tag'].lower()}:has-text(\"{text}\")"
                await page.locator(sel).first.click(timeout=2000, no_wait_after=True)
                await asyncio.sleep(1.5)
            except Exception:
                pass
    except Exception:
        pass
    try:
        await page.evaluate("window.scrollBy(0, 600)")
        await asyncio.sleep(0.5)
        await page.evaluate("window.scrollTo(0, 0)")
        await asyncio.sleep(0.5)
    except Exception:
        pass

    # Trigger mousemove and resize events (some analytics fire on these)
    try:
        await page.evaluate("""() => {
            window.dispatchEvent(new Event('mousemove'));
            window.dispatchEvent(new Event('resize'));
            window.dispatchEvent(new Event('focus'));
        }""")
    except Exception:
        pass

    # Wait for telemetry to flush
    await asyncio.sleep(4)

    # ────────────────────────────────────────────────────────────────────
    # TC-10: Check if console methods are monkey-patched (token logging)
    # ────────────────────────────────────────────────────────────────────
    try:
        console_patched = await page.evaluate("""() => {
            const results = {};
            for (const m of ['log', 'info', 'warn', 'error', 'debug']) {
                const fn = console[m];
                const native = fn && fn.toString && fn.toString().includes('[native code]');
                if (!native) results[m] = true;
            }
            return results;
        }""")
        if console_patched:
            patched_methods = list(console_patched.keys())
            findings.append(_make_finding(
                "Console Methods Overridden — Potential Token Logging via Console",
                "Low", "CWE-532", 3.1, target_url,
                f"The following console methods have been monkey-patched (not native): "
                f"{', '.join(patched_methods)}. Overridden console methods may forward "
                f"logged data (including tokens, errors with auth context) to a remote "
                f"logging service. Verify no sensitive values are captured.",
                source="passive_recon",
            ))
    except Exception:
        pass

    # ────────────────────────────────────────────────────────────────────
    # Phase 4 — Discover telemetry endpoints from performance entries
    # ────────────────────────────────────────────────────────────────────
    perf_entries: list[str] = []
    try:
        perf_entries = await page.evaluate("""() => {
            return performance.getEntriesByType('resource')
                .filter(r => r.initiatorType === 'xmlhttprequest'
                           || r.initiatorType === 'fetch'
                           || r.initiatorType === 'beacon')
                .map(r => r.name);
        }""")
        perf_telemetry = [u for u in (perf_entries or []) if _is_telemetry_url(u)] if perf_entries else []
        if perf_telemetry:
            logger.info("Telemetry check: %d logging endpoint(s) in performance entries", len(perf_telemetry))
    except Exception:
        perf_telemetry = []

    page.remove_listener("request", _on_request)

    # ────────────────────────────────────────────────────────────────────
    # Phase 5 — Analyze all captured requests for leaked tokens
    # ────────────────────────────────────────────────────────────────────

    # Helper: check if a body contains any of our collected tokens
    def _find_leaked_tokens(body: str) -> list[tuple[str, str]]:
        leaked = []
        for tkey, tval in tokens.items():
            if len(tval) < 8:
                continue
            if tval in body:
                leaked.append((tkey, tval))
        return leaked

    def _redact(val: str) -> str:
        return val[:6] + "..." + val[-4:] if len(val) > 12 else val[:6] + "..."

    # Helper: check for sensitive header names referenced in body
    def _find_header_refs(body_lower: str) -> list[str]:
        found = []
        for hdr in _SENSITIVE_HEADERS:
            variants = [
                f'"{hdr}"', f"'{hdr}'",
                hdr.replace("-", "_"), hdr.replace("-", ""),
            ]
            if any(v in body_lower for v in variants):
                found.append(hdr)
        return found

    # Helper: check for sensitive JSON key-value pairs (TC-6)
    def _find_sensitive_json_keys(body: str) -> list[tuple[str, str]]:
        return [(m.group(1), m.group(2)) for m in _SENSITIVE_JSON_KEYS.finditer(body)]

    # Helper: check for JWTs in body (TC-4)
    def _find_jwts(body: str) -> list[str]:
        return _JWT_PATTERN.findall(body)

    # Helper: check for serialized HTTP headers block (TC-9)
    def _has_serialized_headers(body: str) -> bool:
        patterns = [
            r'"[Hh]eaders"\s*:\s*\{[^}]*"(?:Authorization|Cookie|X-CSRF|X-XSRF|X-Auth)',
            r'"request"\s*:\s*\{[^}]*"headers"',
            r'"ajax[Cc]all[^"]*"[^}]*"[Hh]eaders"',
            r'"[Xx]-[Cc]-[Tt]"\s*:\s*"[^"]{8,}"',
        ]
        for p in patterns:
            if re.search(p, body):
                return True
        return False

    already_reported_urls: set[str] = set()

    # === Analyze telemetry-targeted requests ===
    for req in captured_telemetry:
        body = req["body"]
        body_lower = body.lower()
        query = req["query"]
        req_url = req["url"]

        # TC-1/TC-2/TC-3: Actual token values in body
        leaked = _find_leaked_tokens(body)
        if leaked:
            names = [t[0] for t in leaked]
            samples = [f"{n}={_redact(v)}" for n, v in leaked[:5]]
            findings.append(_make_finding(
                "Security Tokens Written to Application Logs (Client-Side Telemetry)",
                "High", "CWE-532", 6.5, target_url,
                f"The application sends {len(leaked)} security token(s) to "
                f"logging endpoint {req_url}. Leaked: {', '.join(samples)}. "
                f"Anyone with log access can extract these for session hijacking "
                f"or CSRF bypass.",
                payload=f"Token keys: {', '.join(names)}",
                source="passive_recon",
            ))
            already_reported_urls.add(req_url)

        # TC-4: JWT tokens in body
        jwts = _find_jwts(body)
        if jwts and req_url not in already_reported_urls:
            findings.append(_make_finding(
                "JWT Token Leaked to Logging Endpoint",
                "High", "CWE-532", 6.5, target_url,
                f"A JSON Web Token (JWT) was found in the body of a POST to "
                f"{req_url}: {_redact(jwts[0])}. JWTs typically contain "
                f"authentication claims and can be replayed to impersonate users.",
                payload=f"JWT: {_redact(jwts[0])}",
                source="passive_recon",
            ))
            already_reported_urls.add(req_url)

        # TC-5: Sensitive header names in body
        header_refs = _find_header_refs(body_lower)
        if header_refs and req_url not in already_reported_urls:
            findings.append(_make_finding(
                "Sensitive HTTP Headers Referenced in Telemetry Payload",
                "Medium", "CWE-532", 5.3, target_url,
                f"The application sends sensitive HTTP header names "
                f"({', '.join(header_refs)}) to {req_url}, indicating the app "
                f"logs request headers that may include security tokens. "
                f"Verify values are redacted before persistence.",
                payload=f"Headers: {', '.join(header_refs)}",
                source="passive_recon",
            ))
            already_reported_urls.add(req_url)

        # TC-6: Sensitive JSON key-value pairs
        sensitive_kv = _find_sensitive_json_keys(body)
        if sensitive_kv and req_url not in already_reported_urls:
            redacted_kv = [f"{k}={_redact(v)}" for k, v in sensitive_kv[:5]]
            findings.append(_make_finding(
                "Sensitive Key-Value Pairs in Telemetry JSON Payload",
                "High", "CWE-532", 6.5, target_url,
                f"The application sends sensitive keys with credential-like values "
                f"to {req_url}: {', '.join(redacted_kv)}. These can "
                f"be harvested from log storage for account takeover.",
                payload=f"Keys: {', '.join(k for k, _ in sensitive_kv[:5])}",
                source="passive_recon",
            ))
            already_reported_urls.add(req_url)

        # TC-7: Tokens in URL query string
        if query:
            leaked_in_qs = _find_leaked_tokens(query)
            if leaked_in_qs:
                samples_qs = [f"{n}={_redact(v)}" for n, v in leaked_in_qs[:3]]
                findings.append(_make_finding(
                    "Security Tokens in Telemetry URL Query Parameters",
                    "High", "CWE-598", 6.5, target_url,
                    f"Token values appear in the URL query string of a telemetry "
                    f"request to {req_url}: {', '.join(samples_qs)}. Query strings "
                    f"are logged by web servers, proxies, and CDNs, exposing tokens "
                    f"in access logs.",
                    payload=f"Tokens in query: {', '.join(n for n, _ in leaked_in_qs[:3])}",
                    source="passive_recon",
                ))

        # TC-9: Full HTTP headers serialized in JSON body
        if _has_serialized_headers(body) and req_url not in already_reported_urls:
            findings.append(_make_finding(
                "Full HTTP Request Headers Serialized in Telemetry Payload",
                "Medium", "CWE-532", 5.3, target_url,
                f"The application sends serialized HTTP headers "
                f"to {req_url} with security-sensitive header names. This pattern "
                f"indicates the application logs complete request metadata including "
                f"auth tokens.",
                source="passive_recon",
            ))

    # === TC-8: Check if tokens are sent to third-party domains ===
    target_host = (urlparse(target_url).hostname or "").lower()
    for req in captured_all_posts:
        req_host = (urlparse(req["url"]).hostname or "").lower()
        if req_host == target_host:
            continue
        is_third_party_analytics = any(td in req_host for td in _TELEMETRY_DOMAINS)
        body = req["body"]
        leaked = _find_leaked_tokens(body)
        if leaked:
            names = [t[0] for t in leaked]
            samples = [f"{n}={_redact(v)}" for n, v in leaked[:3]]
            sev = "Critical" if is_third_party_analytics else "High"
            findings.append(_make_finding(
                f"Security Tokens Sent to Third-Party Domain ({req_host})",
                sev, "CWE-359", 7.5 if sev == "Critical" else 6.5, target_url,
                f"The application sends token values from the authenticated session to "
                f"third-party domain {req_host}: {', '.join(samples)}. "
                f"This exposes credentials to external parties and violates "
                f"the principle of least privilege.",
                payload=f"Third-party: {req_host}, tokens: {', '.join(names)}",
                source="passive_recon",
            ))

        jwts = _find_jwts(body)
        if jwts and not leaked:
            findings.append(_make_finding(
                f"JWT Token Sent to Third-Party Domain ({req_host})",
                "High", "CWE-359", 6.5, target_url,
                f"The application sends a JWT to third-party domain {req_host}: "
                f"{_redact(jwts[0])}. Auth tokens should never leave "
                f"the origin domain.",
                payload=f"Third-party: {req_host}",
                source="passive_recon",
            ))

    # === TC-11: Probe logging endpoints for response body leakage ===
    telemetry_urls_seen = set()
    for req in captured_telemetry:
        parsed = urlparse(req["url"])
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        telemetry_urls_seen.add(base)
    for pu in perf_telemetry:
        parsed = urlparse(pu)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        telemetry_urls_seen.add(base)

    for ep_url in list(telemetry_urls_seen)[:5]:
        try:
            from playwright.async_api import Request as _PwReq
            resp = await page.evaluate("""async (url) => {
                try {
                    const r = await fetch(url, {method: 'GET', credentials: 'include'});
                    const text = await r.text();
                    return {status: r.status, body: text.slice(0, 3000)};
                } catch(e) { return {error: e.message}; }
            }""", ep_url)
            if resp and not resp.get("error") and resp.get("status") == 200:
                resp_body = resp.get("body", "")
                leaked_in_resp = _find_leaked_tokens(resp_body)
                jwts_in_resp = _find_jwts(resp_body)
                if leaked_in_resp:
                    samples_r = [f"{n}={_redact(v)}" for n, v in leaked_in_resp[:3]]
                    findings.append(_make_finding(
                        "Logging Endpoint Response Exposes Security Tokens",
                        "High", "CWE-532", 7.5, target_url,
                        f"A logging endpoint used by the application ({ep_url}) "
                        f"returns previously logged data containing security tokens: "
                        f"{', '.join(samples_r)}. An attacker who accesses this "
                        f"endpoint can harvest active session credentials.",
                        source="passive_recon",
                    ))
                elif jwts_in_resp:
                    findings.append(_make_finding(
                        "Logging Endpoint Response Contains JWT Tokens",
                        "High", "CWE-532", 7.5, target_url,
                        f"A logging endpoint used by the application ({ep_url}) "
                        f"returns data containing a JWT: {_redact(jwts_in_resp[0])}.",
                        source="passive_recon",
                    ))
        except Exception:
            pass

    # === TC-12: Report discovered telemetry endpoints with no body capture ===
    if not captured_telemetry and perf_telemetry:
        ep_list = ", ".join(perf_telemetry[:5])
        findings.append(_make_finding(
            "Telemetry/Logging Endpoints Detected — Manual Review Recommended",
            "Info", "CWE-532", 0.0, target_url,
            f"The application sends data to {len(perf_telemetry)} logging endpoint(s): "
            f"{ep_list}. Could not intercept request bodies for automated token analysis. "
            f"Manually inspect POST bodies for sensitive token leakage.",
            source="passive_recon",
        ))

    return findings


# ══════════════════════════════════════════════════════════════════════
# NEW CONTEXT-AWARE PASSIVE CHECKS
# ══════════════════════════════════════════════════════════════════════

async def _check_cookie_security(page, target_url: str) -> list[dict]:
    """Audit cookies set by the target domain for Secure, HttpOnly, SameSite flags.

    Third-party cookies (set by analytics/tracking domains) are excluded — they
    are not actionable by the target owner.
    """
    findings = []
    try:
        cookies = await page.context.cookies()
        target_host = urlparse(target_url).hostname or ""
        target_parts = target_host.split(".")
        target_base = ".".join(target_parts[-2:]) if len(target_parts) >= 2 else target_host
        is_https = target_url.startswith("https")

        session_kw = ("session", "sess", "sid", "auth", "token", "jwt",
                      "login", "identity", "phpsessid", "jsessionid",
                      "aspsession", "connect", "sso", "oidc")

        for c in cookies:
            cookie_domain = (c.get("domain", "") or "").lower().lstrip(".")
            if cookie_domain:
                cd_parts = cookie_domain.split(".")
                cookie_base = ".".join(cd_parts[-2:]) if len(cd_parts) >= 2 else cookie_domain
                if cookie_base != target_base:
                    continue

            name = c.get("name", "")
            name_lower = name.lower()
            is_session = any(kw in name_lower for kw in session_kw)
            issues = []

            if is_https and not c.get("secure", False):
                issues.append("missing Secure flag (cookie sent over HTTP)")
            if not c.get("httpOnly", False):
                issues.append("missing HttpOnly flag (accessible via JavaScript)")
            same_site = (c.get("sameSite") or "").lower()
            if same_site not in ("strict", "lax"):
                issues.append(f"SameSite={same_site or 'None'} (vulnerable to CSRF)")

            if issues:
                sev = "Medium" if is_session else "Low"
                cvss = 5.3 if is_session else 3.1
                findings.append(_make_finding(
                    f"Insecure Cookie: {name}" + (" (Session Cookie)" if is_session else ""),
                    sev, "CWE-614", cvss, target_url,
                    f"Cookie '{name}' has: {'; '.join(issues)}."
                    + (" Session cookies require all security flags." if is_session else ""),
                    source="passive_recon",
                ))
    except Exception as e:
        logger.debug("Cookie security check failed: %s", e)
    return findings


async def _check_jwt_security(page, target_url: str) -> list[dict]:
    """Analyze JWT tokens found in cookies/storage for weak algorithms and claims."""
    findings = []
    jwts_found: list[tuple[str, str]] = []  # (source_label, token)

    try:
        cookies = await page.context.cookies()
        for c in cookies:
            val = c.get("value", "")
            if val.startswith("eyJ") and val.count(".") == 2:
                jwts_found.append((f"cookie:{c['name']}", val))
    except Exception:
        pass

    try:
        storage_jwts = await page.evaluate("""() => {
            const out = [];
            function scan(store, label) {
                try {
                    for (let i = 0; i < store.length; i++) {
                        const k = store.key(i);
                        const v = store.getItem(k) || '';
                        if (v.startsWith('eyJ') && (v.match(/\\./g) || []).length === 2) {
                            out.push([label + ':' + k, v]);
                        }
                    }
                } catch(e) {}
            }
            scan(localStorage, 'localStorage');
            scan(sessionStorage, 'sessionStorage');
            return out;
        }""")
        for item in (storage_jwts or []):
            jwts_found.append((item[0], item[1]))
    except Exception:
        pass

    for source_label, token in jwts_found[:5]:
        try:
            parts = token.split(".")
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            alg = header.get("alg", "").upper()

            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(payload_b64))

            issues = []

            if alg == "NONE":
                issues.append("alg=none — token has NO signature verification (Critical)")
            elif alg in ("HS256", "HS384", "HS512"):
                issues.append(f"alg={alg} — symmetric HMAC (susceptible to key brute-force if weak secret)")
            elif alg == "":
                issues.append("empty algorithm — may bypass signature check")

            if "exp" not in payload_data:
                issues.append("no 'exp' claim — token never expires")
            if "iss" not in payload_data and "aud" not in payload_data:
                issues.append("missing 'iss'/'aud' — no issuer/audience validation")
            if "jti" not in payload_data:
                issues.append("no 'jti' — replay attacks possible")

            sensitive_claims = []
            for key in ("email", "password", "ssn", "phone", "address", "credit_card"):
                if key in payload_data:
                    sensitive_claims.append(key)
            if sensitive_claims:
                issues.append(f"PII in token payload: {', '.join(sensitive_claims)}")

            if issues:
                sev = "High" if "alg=none" in str(issues) or "never expires" in str(issues) else "Medium"
                cvss = 7.5 if sev == "High" else 5.3
                findings.append(_make_finding(
                    f"JWT Security Weakness — {source_label}",
                    sev, "CWE-347", cvss, target_url,
                    f"JWT from {source_label} (alg={alg}): {'; '.join(issues)}. "
                    f"Header: {json.dumps(header)}",
                    payload=token[:50] + "...",
                    source="passive_recon",
                ))
        except Exception:
            pass

    return findings


async def _check_cors_misconfiguration(http_client, target_url: str) -> list[dict]:
    """Test CORS configuration with a cross-origin preflight."""
    findings = []
    try:
        evil_origin = "https://evil-attacker.com"
        resp = await http_client.get(
            target_url,
            headers={"Origin": evil_origin},
            timeout=10.0,
        )
        exchange = _exchange_from_httpx(resp)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            findings.append(_make_finding(
                "Critical CORS Misconfiguration — Wildcard Origin with Credentials",
                "High", "CWE-942", 7.5, target_url,
                "Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true. Any website can make "
                "authenticated cross-origin requests and read responses.",
                source="passive_recon",
                http_exchange=exchange,
            ))
        elif acao == evil_origin:
            sev = "High" if acac == "true" else "Medium"
            cvss = 7.5 if acac == "true" else 5.3
            findings.append(_make_finding(
                "CORS Reflects Arbitrary Origin" + (" with Credentials" if acac == "true" else ""),
                sev, "CWE-942", cvss, target_url,
                f"Server reflects attacker Origin ({evil_origin}) in "
                f"Access-Control-Allow-Origin header"
                + (". With credentials enabled, attacker can steal user data." if acac == "true"
                   else ". Without credentials, impact is limited."),
                source="passive_recon",
                http_exchange=exchange,
            ))
        elif acao == "null":
            findings.append(_make_finding(
                "CORS Allows Null Origin",
                "Medium", "CWE-942", 5.3, target_url,
                "Access-Control-Allow-Origin: null. Sandboxed iframes and "
                "data: URIs send Origin: null, enabling cross-origin attacks.",
                source="passive_recon",
                http_exchange=exchange,
            ))
    except Exception as e:
        logger.debug("CORS check failed: %s", e)
    return findings


async def _check_cache_control(http_client, target_url: str) -> list[dict]:
    """Check if authenticated pages have proper Cache-Control headers."""
    findings = []
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        cc = hdrs.get("cache-control", "").lower()

        has_auth_indicator = any(k in hdrs for k in (
            "set-cookie", "authorization", "x-csrf-token",
            "x-xsrf-token", "x-auth-token",
        ))
        body_has_auth = any(kw in resp.text[:2000].lower() for kw in (
            "logout", "sign out", "my account", "profile", "dashboard",
            "welcome,", "signed in as",
        ))

        if has_auth_indicator or body_has_auth:
            if "no-store" not in cc:
                severity = "Medium" if "private" not in cc else "Low"
                findings.append(_make_finding(
                    "Authenticated Page Missing Cache-Control: no-store",
                    severity, "CWE-525", 4.3 if severity == "Medium" else 3.1,
                    target_url,
                    f"Authenticated page does not set Cache-Control: no-store "
                    f"(current: '{cc or '(none)'}'). Sensitive content may be "
                    f"cached by browsers or proxies, accessible via back button or shared cache.",
                    source="passive_recon",
                ))
    except Exception as e:
        logger.debug("Cache-Control check failed: %s", e)
    return findings


async def _check_sri(page, target_url: str) -> list[dict]:
    """Check for external scripts/stylesheets missing Subresource Integrity."""
    findings = []
    try:
        target_host = urlparse(target_url).hostname or ""
        external_resources = await page.evaluate("""(targetHost) => {
            const results = [];
            const scripts = document.querySelectorAll('script[src]');
            const links = document.querySelectorAll('link[rel="stylesheet"][href]');
            for (const el of [...scripts, ...links]) {
                const url = el.src || el.href;
                if (!url || !url.startsWith('http')) continue;
                try {
                    const host = new URL(url).hostname;
                    if (host !== targetHost && !el.integrity) {
                        results.push({
                            tag: el.tagName.toLowerCase(),
                            url: url,
                            host: host,
                        });
                    }
                } catch(e) {}
            }
            return results.slice(0, 20);
        }""", target_host)

        cdn_resources = [r for r in (external_resources or []) if r.get("url")]
        if cdn_resources:
            urls_list = [r["url"].split("?")[0][-60:] for r in cdn_resources[:5]]
            hosts = list(set(r["host"] for r in cdn_resources))
            findings.append(_make_finding(
                f"External Resources Missing Subresource Integrity (SRI) — {len(cdn_resources)} resource(s)",
                "Low", "CWE-353", 3.7, target_url,
                f"{len(cdn_resources)} external {'/'.join(set(r['tag'] for r in cdn_resources))} "
                f"tag(s) from {', '.join(hosts[:3])} loaded without integrity= attribute. "
                f"If these CDNs are compromised, malicious code executes in user browsers. "
                f"Examples: {'; '.join(urls_list)}",
                source="passive_recon",
            ))
    except Exception as e:
        logger.debug("SRI check failed: %s", e)
    return findings


async def _check_form_actions(page, target_url: str) -> list[dict]:
    """Check for forms submitting to external domains."""
    findings = []
    try:
        target_host = urlparse(target_url).hostname or ""
        external_forms = await page.evaluate("""(targetHost) => {
            const forms = document.querySelectorAll('form[action]');
            const results = [];
            for (const form of forms) {
                const action = form.action;
                if (!action || !action.startsWith('http')) continue;
                try {
                    const host = new URL(action).hostname;
                    if (host !== targetHost) {
                        const hasPassword = !!form.querySelector('input[type="password"]');
                        const hasSensitive = !!form.querySelector(
                            'input[name*="card"], input[name*="ssn"], input[name*="credit"], '
                            + 'input[name*="account"], input[name*="routing"]'
                        );
                        results.push({action, host, hasPassword, hasSensitive,
                                     method: (form.method || 'GET').toUpperCase()});
                    }
                } catch(e) {}
            }
            return results;
        }""", target_host)

        for form in (external_forms or []):
            sev = "High" if form.get("hasPassword") or form.get("hasSensitive") else "Medium"
            cvss = 6.5 if sev == "High" else 4.3
            findings.append(_make_finding(
                f"Form Submits Data to External Domain ({form['host']})",
                sev, "CWE-200", cvss, form["action"],
                f"A {form['method']} form submits to {form['action']} (external). "
                + ("Form contains password/sensitive fields — credentials sent to third party. " if sev == "High" else "")
                + "Verify this is intentional and the receiving domain is trusted.",
                source="passive_recon",
            ))
    except Exception as e:
        logger.debug("Form action check failed: %s", e)
    return findings


async def _check_api_version_downgrade(http_client, target_url: str, js_urls: list[str]) -> list[dict]:
    """Discover API version patterns and test if older versions are accessible."""
    findings = []
    version_pattern = re.compile(r'/v(\d+)/')
    discovered_versions: dict[str, set[int]] = {}  # base_path -> set of versions

    all_urls = [target_url] + js_urls[:20]
    for url in all_urls:
        for m in version_pattern.finditer(url):
            ver = int(m.group(1))
            prefix = url[:m.start()]
            suffix = url[m.end():]
            base_key = f"{prefix}__V__{suffix}"
            discovered_versions.setdefault(base_key, set()).add(ver)

    if not discovered_versions:
        try:
            page_text = ""
            for js_url in js_urls[:5]:
                try:
                    resp = await http_client.get(js_url, timeout=8.0)
                    if resp.status_code == 200:
                        page_text += resp.text[:5000]
                except Exception:
                    pass
            for m in re.finditer(r'["\'](/api/v(\d+)/[^"\']+)["\']', page_text):
                path = m.group(1)
                ver = int(m.group(2))
                prefix = path[:path.index(f"/v{ver}/")]
                suffix = path[path.index(f"/v{ver}/") + len(f"/v{ver}/"):]
                base_key = f"{prefix}__V__{suffix}"
                discovered_versions.setdefault(base_key, set()).add(ver)
        except Exception:
            pass

    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    for base_key, versions in discovered_versions.items():
        max_ver = max(versions)
        if max_ver <= 1:
            continue

        for older_ver in range(max(1, max_ver - 2), max_ver):
            older_path = base_key.replace("__V__", f"/v{older_ver}/")
            if older_path.startswith("http"):
                test_url = older_path
            else:
                test_url = base_url + older_path

            try:
                resp = await http_client.get(test_url, timeout=8.0, follow_redirects=False)
                if resp.status_code in (200, 201) and len(resp.content) > 50:
                    body = resp.text[:200]
                    if not body.strip().startswith("<!DOCTYPE") and not body.strip().startswith("<html"):
                        current_path = base_key.replace("__V__", f"/v{max_ver}/")
                        findings.append(_make_finding(
                            f"Deprecated API Version Accessible — v{older_ver} (current: v{max_ver})",
                            "Medium", "CWE-693", 5.3, test_url,
                            f"API v{older_ver} still returns valid responses (HTTP {resp.status_code}). "
                            f"Current version is v{max_ver}. Older API versions often lack security "
                            f"controls (auth, rate limiting, input validation) added in newer versions.",
                            source="passive_recon",
                        ))
                        break
            except Exception:
                pass

    return findings


# ══════════════════════════════════════════════════════════════════════
# BATCH 2: ADDITIONAL PASSIVE CHECKS (zero FP risk)
# ══════════════════════════════════════════════════════════════════════

_CSP_UNSAFE_DIRECTIVES = {
    "'unsafe-inline'": ("Allows inline scripts/styles, defeating the purpose of CSP", "High"),
    "'unsafe-eval'": ("Allows eval() and similar dynamic code execution", "High"),
    "'unsafe-hashes'": ("Allows specific inline event handlers by hash", "Medium"),
}

_CSP_RISKY_SOURCES = {
    "*": ("Wildcard allows loading from ANY origin", "High"),
    "data:": ("data: URIs can inject arbitrary content", "Medium"),
    "blob:": ("blob: URIs can bypass CSP restrictions", "Low"),
    "http:": ("Allows loading over insecure HTTP on an HTTPS page", "Medium"),
}


async def _check_csp_weaknesses(http_client, target_url: str) -> list[dict]:
    """Analyze CSP policy for exploitable weaknesses (not just presence)."""
    findings = []
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        csp = hdrs.get("content-security-policy", "")

        if not csp:
            return findings

        directives: dict[str, str] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            directive_name = tokens[0].lower()
            directive_value = tokens[1] if len(tokens) > 1 else ""
            directives[directive_name] = directive_value

        weaknesses = []

        for directive, value in directives.items():
            for unsafe, (desc, sev) in _CSP_UNSAFE_DIRECTIVES.items():
                if unsafe in value:
                    weaknesses.append(f"{directive}: {unsafe} — {desc}")

            for risky, (desc, sev) in _CSP_RISKY_SOURCES.items():
                if risky in value.split():
                    if risky == "http:" and not target_url.startswith("https"):
                        continue
                    weaknesses.append(f"{directive}: {risky} — {desc}")

        if "default-src" not in directives and "script-src" not in directives:
            weaknesses.append("No default-src or script-src — CSP has no script restriction")

        if "frame-ancestors" not in directives:
            weaknesses.append("No frame-ancestors directive — page may be frameable (clickjacking)")

        if "object-src" not in directives and "'none'" not in directives.get("default-src", ""):
            weaknesses.append("No object-src restriction — plugin-based attacks possible (Flash/Java)")

        if "base-uri" not in directives:
            weaknesses.append("No base-uri — <base> tag injection can redirect all relative URLs")

        if "form-action" not in directives:
            weaknesses.append("No form-action — forms can submit to any origin")

        if weaknesses:
            sev = "Medium" if any("unsafe-inline" in w or "unsafe-eval" in w or "* —" in w for w in weaknesses) else "Low"
            findings.append(_make_finding(
                f"Content Security Policy Weaknesses ({len(weaknesses)} issue(s))",
                sev, "CWE-693", 4.7 if sev == "Medium" else 3.1, target_url,
                "CSP policy present but has exploitable weaknesses: " + "; ".join(weaknesses[:8]),
                payload=csp[:200],
                source="passive_recon",
            ))
    except Exception as e:
        logger.debug("CSP analysis failed: %s", e)
    return findings


async def _check_referrer_policy(http_client, target_url: str) -> list[dict]:
    """Check for missing or weak Referrer-Policy header."""
    findings = []
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        exchange = _exchange_from_httpx(resp)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        rp = hdrs.get("referrer-policy", "").lower().strip()

        if not rp:
            findings.append(_make_finding(
                "Missing Referrer-Policy Header",
                "Low", "CWE-200", 3.1, target_url,
                "No Referrer-Policy header set. Browser defaults vary — full URL "
                "(including query parameters with tokens) may be sent to third-party "
                "sites via Referer header. Set to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                source="passive_recon",
                http_exchange=exchange,
            ))
        elif rp in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(_make_finding(
                f"Weak Referrer-Policy: {rp}",
                "Low", "CWE-200", 3.1, target_url,
                f"Referrer-Policy is '{rp}' which sends the full URL (including "
                f"path and query parameters) to third-party sites. Tokens or "
                f"sensitive data in URLs will leak. Use 'strict-origin-when-cross-origin'.",
                source="passive_recon",
                http_exchange=exchange,
            ))
    except Exception as e:
        logger.debug("Referrer-Policy check failed: %s", e)
    return findings


async def _check_permissions_policy(http_client, target_url: str) -> list[dict]:
    """Check for missing Permissions-Policy (formerly Feature-Policy) header."""
    findings = []
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        exchange = _exchange_from_httpx(resp)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        pp = hdrs.get("permissions-policy", "")
        fp = hdrs.get("feature-policy", "")

        if not pp and not fp:
            findings.append(_make_finding(
                "Missing Permissions-Policy Header",
                "Low", "CWE-16", 2.1, target_url,
                "No Permissions-Policy (or legacy Feature-Policy) header set. "
                "Browser features like camera, microphone, geolocation, and payment "
                "API are not restricted. Set Permissions-Policy to disable unused features.",
                source="passive_recon",
                http_exchange=exchange,
            ))
        elif fp and not pp:
            findings.append(_make_finding(
                "Deprecated Feature-Policy Header (Use Permissions-Policy)",
                "Info", "CWE-16", 0.0, target_url,
                f"Feature-Policy header present but Permissions-Policy (the replacement) "
                f"is missing. Feature-Policy is deprecated and ignored by modern browsers.",
                source="passive_recon",
                http_exchange=exchange,
            ))
    except Exception as e:
        logger.debug("Permissions-Policy check failed: %s", e)
    return findings


async def _check_mixed_content(page, target_url: str) -> list[dict]:
    """Detect HTTP resources loaded on an HTTPS page."""
    findings = []
    if not target_url.startswith("https"):
        return findings
    try:
        mixed = await page.evaluate("""() => {
            const results = [];
            const check = (els, attr) => {
                for (const el of els) {
                    const url = el[attr] || el.getAttribute(attr) || '';
                    if (url.startsWith('http://')) {
                        results.push({tag: el.tagName, url: url.slice(0, 150), attr: attr});
                    }
                }
            };
            check(document.querySelectorAll('script[src]'), 'src');
            check(document.querySelectorAll('link[href]'), 'href');
            check(document.querySelectorAll('img[src]'), 'src');
            check(document.querySelectorAll('iframe[src]'), 'src');
            check(document.querySelectorAll('video[src], audio[src]'), 'src');
            check(document.querySelectorAll('object[data]'), 'data');
            return results.slice(0, 20);
        }""")

        if mixed:
            active_mixed = [m for m in mixed if m["tag"] in ("SCRIPT", "LINK", "IFRAME", "OBJECT")]
            passive_mixed = [m for m in mixed if m["tag"] in ("IMG", "VIDEO", "AUDIO")]

            if active_mixed:
                urls = [m["url"][:80] for m in active_mixed[:5]]
                findings.append(_make_finding(
                    f"Active Mixed Content — {len(active_mixed)} HTTP resource(s) on HTTPS page",
                    "Medium", "CWE-319", 5.3, target_url,
                    f"Scripts, stylesheets, or iframes loaded over HTTP on an HTTPS page. "
                    f"An attacker on the network can modify these resources (MitM) to inject "
                    f"malicious code. Resources: {'; '.join(urls)}",
                    source="passive_recon",
                ))
            if passive_mixed and len(passive_mixed) >= 3:
                findings.append(_make_finding(
                    f"Passive Mixed Content — {len(passive_mixed)} HTTP resource(s)",
                    "Low", "CWE-319", 2.1, target_url,
                    f"{len(passive_mixed)} images/media loaded over HTTP on HTTPS page. "
                    f"Lower risk than active mixed content but reveals browsing activity to MitM.",
                    source="passive_recon",
                ))
    except Exception as e:
        logger.debug("Mixed content check failed: %s", e)
    return findings


async def _check_password_autocomplete(page, target_url: str) -> list[dict]:
    """Check for password fields without autocomplete='off'."""
    findings = []
    try:
        pw_fields = await page.evaluate("""() => {
            const fields = document.querySelectorAll('input[type="password"]');
            return [...fields].map(f => ({
                name: f.name || f.id || '(unnamed)',
                autocomplete: f.getAttribute('autocomplete') || '(not set)',
                formAction: f.form ? (f.form.action || '') : '',
            }));
        }""")

        vulnerable = [f for f in (pw_fields or []) if f["autocomplete"] not in ("off", "new-password")]
        if vulnerable:
            names = [f["name"] for f in vulnerable[:5]]
            findings.append(_make_finding(
                f"Password Field(s) Allow Browser Autocomplete ({len(vulnerable)} field(s))",
                "Low", "CWE-522", 2.1, target_url,
                f"Password input(s) ({', '.join(names)}) do not set autocomplete='off' "
                f"or autocomplete='new-password'. Browsers may cache credentials in "
                f"plaintext on the user's device. On shared/public computers this is a risk.",
                source="passive_recon",
            ))
    except Exception as e:
        logger.debug("Password autocomplete check failed: %s", e)
    return findings


_SENSITIVE_PARAM_PATTERNS = re.compile(
    r'(?:^|&)((?:password|passwd|pwd|secret|token|api[_-]?key|'
    r'access[_-]?token|auth|session[_-]?id|ssn|credit[_-]?card|'
    r'card[_-]?number|cvv|pin|private[_-]?key|bearer)'
    r')=([^&]{4,})',
    re.IGNORECASE,
)


async def _check_sensitive_url_params(page, target_url: str) -> list[dict]:
    """Detect sensitive data in URL query parameters (logged by proxies/servers)."""
    findings = []
    try:
        all_urls = await page.evaluate("""() => {
            const urls = new Set();
            urls.add(window.location.href);
            for (const entry of performance.getEntriesByType('resource')) {
                if (entry.name.includes('?')) urls.add(entry.name);
            }
            for (const entry of performance.getEntriesByType('navigation')) {
                if (entry.name.includes('?')) urls.add(entry.name);
            }
            return [...urls].slice(0, 50);
        }""")

        flagged: list[tuple[str, str]] = []
        seen_params: set[str] = set()
        for url in (all_urls or []):
            query = urlparse(url).query
            if not query:
                continue
            for m in _SENSITIVE_PARAM_PATTERNS.finditer(query):
                param_name = m.group(1).lower()
                if param_name not in seen_params:
                    seen_params.add(param_name)
                    flagged.append((param_name, url[:120]))

        if flagged:
            param_list = [f"{p}= in {u}" for p, u in flagged[:5]]
            findings.append(_make_finding(
                f"Sensitive Data in URL Query Parameters ({len(flagged)} parameter(s))",
                "Medium", "CWE-598", 5.3, target_url,
                f"Sensitive parameters found in URL query strings: {'; '.join(param_list)}. "
                f"Query strings are logged by web servers, proxies, CDNs, browser history, "
                f"and Referer headers. Use POST body or HTTP headers for sensitive data.",
                source="passive_recon",
            ))
    except Exception as e:
        logger.debug("Sensitive URL params check failed: %s", e)
    return findings


async def _check_https_redirect(http_client, target_url: str) -> list[dict]:
    """Check if the HTTP version of the site redirects to HTTPS."""
    findings = []
    if not target_url.startswith("https://"):
        return findings
    try:
        http_url = target_url.replace("https://", "http://", 1)
        resp = await http_client.get(http_url, timeout=10.0, follow_redirects=False)
        exchange = _exchange_from_httpx(resp)

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                if resp.status_code != 301:
                    findings.append(_make_finding(
                        f"HTTP→HTTPS Redirect Uses {resp.status_code} Instead of 301",
                        "Low", "CWE-319", 2.1, http_url,
                        f"HTTP redirects to HTTPS using {resp.status_code} ({location[:100]}). "
                        f"Use 301 (permanent) for SEO and browser caching of the redirect.",
                        source="passive_recon",
                        http_exchange=exchange,
                    ))
            else:
                findings.append(_make_finding(
                    "HTTP Does Not Redirect to HTTPS",
                    "Medium", "CWE-319", 4.3, http_url,
                    f"HTTP version redirects to {location[:100]} which is not HTTPS. "
                    f"First request is unencrypted and vulnerable to MitM downgrade.",
                    source="passive_recon",
                    http_exchange=exchange,
                ))
        elif resp.status_code == 200:
            findings.append(_make_finding(
                "HTTP Version Serves Content Without HTTPS Redirect",
                "Medium", "CWE-319", 4.3, http_url,
                "The HTTP version of the site returns content (HTTP 200) without "
                "redirecting to HTTPS. Users accessing via HTTP have no transport encryption.",
                source="passive_recon",
                http_exchange=exchange,
            ))
    except Exception as e:
        logger.debug("HTTPS redirect check failed: %s", e)
    return findings


async def _check_hsts_preload(http_client, target_url: str) -> list[dict]:
    """Check HSTS header for best-practice directives."""
    findings = []
    if not target_url.startswith("https://"):
        return findings
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        hsts = hdrs.get("strict-transport-security", "")

        if not hsts:
            return findings

        hsts_lower = hsts.lower()
        issues = []

        max_age_match = re.search(r'max-age=(\d+)', hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                issues.append(f"max-age={max_age} is less than 1 year (31536000) — browsers forget quickly")
        else:
            issues.append("No max-age directive found")

        if "includesubdomains" not in hsts_lower:
            issues.append("Missing includeSubDomains — subdomains can be accessed over HTTP")

        if issues:
            exchange = _exchange_from_httpx(resp)
            findings.append(_make_finding(
                f"HSTS Header Incomplete ({len(issues)} issue(s))",
                "Low", "CWE-319", 2.1, target_url,
                f"HSTS present but could be strengthened: {'; '.join(issues)}. "
                f"Current value: {hsts[:150]}",
                source="passive_recon",
                http_exchange=exchange,
            ))
    except Exception as e:
        logger.debug("HSTS preload check failed: %s", e)
    return findings


_ERROR_DISCLOSURE_PATTERNS = [
    (r'(?:Traceback|File\s+"[^"]+",\s+line\s+\d+)', "Python stack trace"),
    (r'(?:at\s+[\w.$]+\([\w.]+:\d+:\d+\))', "JavaScript/Node.js stack trace"),
    (r'(?:Exception\s+in\s+thread|java\.\w+\.\w+Exception)', "Java exception"),
    (r'(?:Fatal\s+error|Call\s+Stack|in\s+/\w+/[\w./]+\.php)', "PHP error/stack trace"),
    (r'(?:Microsoft\s+\.NET\s+Framework|System\.Web\.Http)', "ASP.NET error page"),
    (r'(?:SQLSTATE\[|mysql_|pg_query|sqlite_)', "Database error/driver"),
    (r'(?:\/usr\/local\/|\/home\/\w+\/|\/var\/www\/|C:\\\\)', "Internal file path"),
    (r'(?:DB_HOST|DB_PASSWORD|DB_NAME|DATABASE_URL)', "Database configuration"),
    (r'(?:nginx/\d|Apache/\d|IIS/\d|LiteSpeed)', "Web server version in error body"),
]


async def _check_error_pages(http_client, target_url: str) -> list[dict]:
    """Probe error pages for information disclosure."""
    findings = []
    base = urlparse(target_url)
    base_url = f"{base.scheme}://{base.netloc}"
    test_paths = [
        f"{base_url}/{'a' * 20}_{int(__import__('time').time())}",
        f"{base_url}/%00",
        f"{base_url}/..%2f..%2f",
    ]

    for test_url in test_paths:
        try:
            resp = await http_client.get(test_url, timeout=8.0, follow_redirects=False)
            if resp.status_code not in (404, 500, 502, 503):
                continue
            body = resp.text[:3000]
            disclosed = []
            for pattern, desc in _ERROR_DISCLOSURE_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    disclosed.append(desc)
            if disclosed:
                findings.append(_make_finding(
                    f"Error Page Information Disclosure ({resp.status_code})",
                    "Low", "CWE-209", 3.7, test_url,
                    f"Error page (HTTP {resp.status_code}) reveals: {', '.join(disclosed)}. "
                    f"Attackers use this to fingerprint the tech stack and craft targeted attacks.",
                    source="passive_recon",
                    http_exchange=_exchange_from_httpx(resp),
                ))
                break
        except Exception:
            pass
    return findings


async def _check_clickjacking(http_client, target_url: str) -> list[dict]:
    """Check if the page is frameable (both X-Frame-Options and CSP frame-ancestors missing)."""
    findings = []
    try:
        resp = await http_client.get(target_url, timeout=10.0)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        xfo = hdrs.get("x-frame-options", "").upper()
        csp = hdrs.get("content-security-policy", "").lower()

        has_xfo = xfo in ("DENY", "SAMEORIGIN") or xfo.startswith("ALLOW-FROM")
        has_frame_ancestors = "frame-ancestors" in csp

        if not has_xfo and not has_frame_ancestors:
            ct = hdrs.get("content-type", "").lower()
            if "text/html" in ct or "application/xhtml" in ct:
                findings.append(_make_finding(
                    "Clickjacking — Page Frameable (No X-Frame-Options or frame-ancestors)",
                    "Medium", "CWE-1021", 4.3, target_url,
                    "Neither X-Frame-Options nor CSP frame-ancestors is set on this HTML page. "
                    "An attacker can embed this page in an iframe on a malicious site and "
                    "trick users into clicking hidden UI elements (clickjacking). "
                    "Set X-Frame-Options: DENY or CSP frame-ancestors 'self'.",
                    source="passive_recon",
                    http_exchange=_exchange_from_httpx(resp),
                ))
    except Exception as e:
        logger.debug("Clickjacking check failed: %s", e)
    return findings


async def _fingerprint_technologies(page, http_client, target_url: str, js_urls: list[str]) -> dict:
    """Fingerprint the technology stack from HTTP responses, cookies, headers, URL patterns, and page content.

    Returns a dict with detected technologies and evidence signals — NOT hardcoded
    vulnerability checks. This context is fed to the LLM so it can autonomously
    generate technology-specific security tests.
    """
    techs: dict[str, dict] = {}
    signals: list[str] = []

    def _add(name: str, confidence: str, evidence: str, category: str = ""):
        if name not in techs or confidence == "high":
            techs[name] = {"confidence": confidence, "evidence": evidence, "category": category}

    try:
        resp = await http_client.get(target_url, timeout=10.0)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text[:50000]
        except Exception:
            pass
        body_lower = body.lower()

        # ── Server / CDN headers ─────────────────────────────────────
        server = headers.get("server", "")
        if server:
            signals.append(f"Server header: {server}")
            server_lower = server.lower()
            if "apache" in server_lower: _add("Apache HTTP Server", "high", f"Server: {server}", "web_server")
            if "nginx" in server_lower: _add("Nginx", "high", f"Server: {server}", "web_server")
            if "iis" in server_lower or "microsoft" in server_lower: _add("Microsoft IIS", "high", f"Server: {server}", "web_server")
            if "cloudflare" in server_lower: _add("Cloudflare", "high", f"Server: {server}", "cdn")
            if "envoy" in server_lower: _add("Envoy Proxy", "medium", f"Server: {server}", "proxy")

        powered = headers.get("x-powered-by", "")
        if powered:
            signals.append(f"X-Powered-By: {powered}")
            powered_lower = powered.lower()
            if "php" in powered_lower: _add("PHP", "high", f"X-Powered-By: {powered}", "language")
            if "asp.net" in powered_lower: _add("ASP.NET", "high", f"X-Powered-By: {powered}", "framework")
            if "express" in powered_lower: _add("Express.js (Node.js)", "high", f"X-Powered-By: {powered}", "framework")
            if "next.js" in powered_lower: _add("Next.js", "high", f"X-Powered-By: {powered}", "framework")

        # CDN / WAF detection
        for h in ("x-akamai-transformed", "x-akamai-session-info", "akamai-grn"):
            if h in headers:
                _add("Akamai CDN", "high", f"Header: {h}", "cdn")
                break
        if "cf-ray" in headers: _add("Cloudflare", "high", "CF-Ray header", "cdn")
        if "x-amz-cf-id" in headers: _add("AWS CloudFront", "high", "X-Amz-Cf-Id header", "cdn")
        if "x-vercel-id" in headers: _add("Vercel", "high", "X-Vercel-Id header", "hosting")

        # ── Cookie-based detection ───────────────────────────────────
        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not cookies:
            raw_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"] if hasattr(resp.headers, "multi_items") else []
            cookies = raw_cookies
        cookie_str = " ".join(cookies).lower()

        if "amcv_" in cookie_str or "amcvs_" in cookie_str or "s_cc" in cookie_str:
            _add("Adobe Experience Cloud / Adobe Analytics", "high", "Adobe Marketing Cloud cookies (AMCV_*)", "analytics")
        if "wordpress" in cookie_str or "wp-settings" in cookie_str:
            _add("WordPress", "high", "WordPress cookies", "cms")
        if "drupal" in cookie_str: _add("Drupal", "high", "Drupal session cookie", "cms")
        if "jsessionid" in cookie_str: _add("Java Servlet Container (Tomcat/JBoss/etc)", "high", "JSESSIONID cookie", "runtime")
        if "phpsessid" in cookie_str: _add("PHP", "high", "PHPSESSID cookie", "language")
        if "asp.net" in cookie_str: _add("ASP.NET", "high", "ASP.NET session cookie", "framework")
        if "laravel_session" in cookie_str: _add("Laravel (PHP)", "high", "laravel_session cookie", "framework")
        if "connect.sid" in cookie_str: _add("Express.js (Node.js)", "medium", "connect.sid cookie", "framework")

        # ── URL / path pattern detection ─────────────────────────────
        js_str = " ".join(js_urls).lower()

        if "/etc.clientlibs/" in js_str or "/etc/clientlibs/" in js_str or "jcr:content" in body_lower or "/content/dam/" in body_lower:
            _add("Adobe Experience Manager (AEM)", "high", "AEM clientlib paths or JCR content references in page", "cms")
        if "/_next/" in js_str or "__next" in body_lower:
            _add("Next.js", "high", "_next/ asset paths", "framework")
        if "/wp-content/" in js_str or "/wp-includes/" in js_str or "/wp-json/" in body_lower:
            _add("WordPress", "high", "wp-content/wp-includes paths", "cms")
        if "/sites/default/files/" in body_lower or "drupal.js" in js_str:
            _add("Drupal", "high", "Drupal asset paths", "cms")
        if "/static/admin/" in body_lower and "csrfmiddlewaretoken" in body_lower:
            _add("Django", "high", "Django admin and CSRF token pattern", "framework")
        if "/rails/" in js_str or "csrf-token" in body_lower and "authenticity_token" in body_lower:
            _add("Ruby on Rails", "medium", "Rails CSRF / asset patterns", "framework")
        if "/assets/application-" in js_str:
            _add("Ruby on Rails", "medium", "Rails asset pipeline fingerprint", "framework")
        if "/bundles/" in js_str and "__requestverificationtoken" in body_lower:
            _add("ASP.NET MVC", "medium", "ASP.NET bundles and verification token", "framework")
        if "sitecore" in body_lower or "/sitecore/" in body_lower:
            _add("Sitecore", "high", "Sitecore references in page", "cms")
        if "/typo3/" in body_lower or "/typo3conf/" in js_str:
            _add("TYPO3", "high", "TYPO3 paths in page", "cms")
        if "shopify" in body_lower or "cdn.shopify.com" in js_str:
            _add("Shopify", "high", "Shopify references", "ecommerce")
        if "magento" in body_lower or "/static/version" in js_str:
            _add("Magento", "medium", "Magento asset patterns", "ecommerce")

        # ── HTML meta / generator tags ───────────────────────────────
        try:
            if page is None:
                raise RuntimeError("browserless mode")
            generator = await page.evaluate("() => { const m = document.querySelector('meta[name=generator]'); return m ? m.content : ''; }")
            if generator:
                signals.append(f"Generator meta: {generator}")
                gen_lower = generator.lower()
                if "wordpress" in gen_lower: _add("WordPress", "high", f"Generator: {generator}", "cms")
                if "drupal" in gen_lower: _add("Drupal", "high", f"Generator: {generator}", "cms")
                if "joomla" in gen_lower: _add("Joomla", "high", f"Generator: {generator}", "cms")
                if "typo3" in gen_lower: _add("TYPO3", "high", f"Generator: {generator}", "cms")
                if "ghost" in gen_lower: _add("Ghost CMS", "high", f"Generator: {generator}", "cms")
                if "hugo" in gen_lower: _add("Hugo", "high", f"Generator: {generator}", "static_site")
                if "gatsby" in gen_lower: _add("Gatsby", "high", f"Generator: {generator}", "static_site")
                else: _add(generator, "medium", f"Generator: {generator}", "unknown")
        except Exception:
            pass

        # ── Response header tech hints ───────────────────────────────
        if "x-drupal-cache" in headers or "x-drupal-dynamic-cache" in headers:
            _add("Drupal", "high", "X-Drupal-Cache header", "cms")
        if "x-generator" in headers:
            _add(headers["x-generator"], "medium", f"X-Generator: {headers['x-generator']}", "unknown")
        if "x-aspnet-version" in headers:
            _add(f"ASP.NET {headers['x-aspnet-version']}", "high", f"X-AspNet-Version header", "framework")
        if "x-django-" in " ".join(headers.keys()):
            _add("Django", "medium", "X-Django-* header", "framework")
        if "liferay-portal" in headers.get("liferay-portal", "").lower() or "liferay" in cookie_str:
            _add("Liferay", "high", "Liferay header/cookie", "cms")

    except Exception as e:
        logger.warning("Tech fingerprinting failed: %s", e)

    result = {"technologies": techs, "signals": signals}
    if techs:
        tech_list = ", ".join(f"{k} ({v['confidence']})" for k, v in techs.items())
        logger.info("Detected technologies: %s", tech_list)
    else:
        logger.info("No specific technologies fingerprinted")
    return result


_CWE_REMEDIATION: dict[str, str] = {
    "CWE-16": "Set X-Content-Type-Options: nosniff header to prevent MIME-type sniffing.",
    "CWE-79": "Sanitize all user input and use context-aware output encoding. Avoid innerHTML, eval, and dangerouslySetInnerHTML. Use a Content Security Policy (CSP).",
    "CWE-95": "Avoid dynamic code execution (eval, new Function, setTimeout with strings). Use safer alternatives like JSON.parse or static dispatch tables.",
    "CWE-200": "Remove sensitive files and directories from production. Configure the web server to deny access to dotfiles and config files.",
    "CWE-319": "Enable HSTS (Strict-Transport-Security header) and enforce HTTPS for all connections. Set max-age to at least 31536000.",
    "CWE-352": "Implement anti-CSRF tokens on all state-changing forms and verify the Origin/Referer header server-side.",
    "CWE-384": "Regenerate the session ID after successful authentication and ensure session cookies use Secure, HttpOnly, and SameSite flags.",
    "CWE-502": "Never deserialize untrusted data. Use safe serialization formats like JSON and validate schema before processing.",
    "CWE-521": "Enforce strong password policies (minimum length, complexity). Use bcrypt/argon2 for hashing and implement account lockout.",
    "CWE-522": "Never transmit credentials over unencrypted channels. Store passwords using strong one-way hashing (bcrypt, argon2).",
    "CWE-524": "Set Cache-Control: no-store, no-cache, must-revalidate on pages containing sensitive data.",
    "CWE-530": "Remove backup and configuration files from production. Add server rules to block access to .bak, .old, .config extensions.",
    "CWE-532": "Remove or restrict access to debug logs, console output, and verbose error messages in production. Sanitize logged data.",
    "CWE-538": "Remove version control directories (.git), config files, and metadata from production deployments. Use .gitignore and deploy scripts that exclude these.",
    "CWE-540": "Remove source maps and inline source references from production builds. Configure build tools to disable source map generation for production.",
    "CWE-601": "Validate and whitelist redirect URLs server-side. Never redirect to user-supplied URLs without validation.",
    "CWE-614": "Set the Secure flag on all session cookies so they are only sent over HTTPS.",
    "CWE-615": "Remove HTML comments containing sensitive information (internal paths, credentials, TODOs) from production pages.",
    "CWE-693": "Implement defense-in-depth: Content Security Policy (CSP), Subresource Integrity (SRI), and X-Frame-Options headers.",
    "CWE-798": "Never embed API keys, passwords, or secrets in client-side code. Use environment variables and server-side secret management.",
    "CWE-918": "Validate and whitelist URLs for server-side requests. Block requests to internal IPs, localhost, and metadata endpoints.",
    "CWE-942": "Remove or restrict cross-domain policy files (crossdomain.xml, clientaccesspolicy.xml). Set allow-access-from to specific trusted domains.",
    "CWE-1021": "Set X-Frame-Options: DENY (or SAMEORIGIN) and use Content-Security-Policy frame-ancestors directive to prevent clickjacking.",
    "CWE-1275": "Ensure cookies use the SameSite attribute (Strict or Lax) to prevent CSRF via cross-site requests.",
    "CWE-326": "Disable weak/null/anonymous/export cipher suites. Require AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with PFS key exchange.",
    "CWE-327": "Disable deprecated protocols (TLS 1.0/1.1) and weak ciphers (RC4, 3DES/DES-CBC3, DES). Only enable TLS 1.2+ with modern cipher suites.",
    "CWE-1104": "Upgrade the vulnerable third-party JavaScript library to a patched version. Subscribe to security advisories and automate dependency auditing (npm audit, Snyk, Dependabot).",
}


def _remediation_for(cwe: str, title: str = "") -> str:
    if cwe and cwe in _CWE_REMEDIATION:
        return _CWE_REMEDIATION[cwe]
    tl = title.lower()
    if "xss" in tl or "cross-site scripting" in tl:
        return _CWE_REMEDIATION.get("CWE-79", "")
    if "source map" in tl:
        return _CWE_REMEDIATION.get("CWE-540", "")
    if "secret" in tl or "api key" in tl or "credential" in tl or "hardcoded" in tl:
        return _CWE_REMEDIATION.get("CWE-798", "")
    if "hsts" in tl or "strict-transport" in tl:
        return _CWE_REMEDIATION.get("CWE-319", "")
    if "csp" in tl or "content-security-policy" in tl or "content security" in tl:
        return _CWE_REMEDIATION.get("CWE-693", "")
    if "csrf" in tl:
        return _CWE_REMEDIATION.get("CWE-352", "")
    if "session" in tl and ("fixation" in tl or "cookie" in tl):
        return _CWE_REMEDIATION.get("CWE-384", "")
    if "debug" in tl or "log" in tl or "verbose" in tl:
        return _CWE_REMEDIATION.get("CWE-532", "")
    if "redirect" in tl:
        return _CWE_REMEDIATION.get("CWE-601", "")
    if "clickjack" in tl or "frame" in tl:
        return _CWE_REMEDIATION.get("CWE-1021", "")
    return ""


_IMPACT_MAP = {
    "sql": "Attacker can read, modify, or delete database contents, potentially leading to full data breach.",
    "xss": "Attacker can execute JavaScript in victim browsers, steal session tokens, or redirect to malicious sites.",
    "csrf": "Attacker can force authenticated users to perform unwanted actions without their knowledge.",
    "source map": "Exposed source maps reveal original source code, internal logic, and developer comments to attackers.",
    "hardcoded": "Leaked credentials or API keys can be used for unauthorized access to backend services.",
    "secret": "Leaked credentials or API keys can be used for unauthorized access to backend services.",
    "api key": "Leaked API keys can be used to consume services, exfiltrate data, or incur costs on behalf of the owner.",
    "cookie": "Cookies without security flags can be intercepted or accessed by scripts, enabling session theft.",
    "hsts": "First-time visitors can be intercepted via HTTP before HTTPS redirect, enabling man-in-the-middle attacks.",
    "csp": "No Content Security Policy means injected scripts face no restrictions, amplifying any XSS vulnerability.",
    "clickjack": "Attacker can overlay the page in an iframe, tricking users into clicking hidden actions.",
    "frame": "Attacker can embed the page in an iframe on a malicious site for UI redressing attacks.",
    "cors": "Misconfigured CORS allows malicious sites to read sensitive API responses from authenticated users.",
    "token": "Exposed tokens can be captured and reused for unauthorized access or session hijacking.",
    "telemetry": "Security tokens sent to third-party services can be harvested from network traffic or third-party logs.",
    "log": "Sensitive data in logs can be accessed by anyone with log storage access, enabling session hijacking.",
    "git": "Exposed Git repository reveals full source code history, credentials, and internal configuration.",
    ".env": "Exposed environment file typically contains database credentials, API keys, and service secrets.",
    "jwt": "Weak JWT configuration allows token forgery, enabling unauthorized access as any user.",
    "sri": "Without Subresource Integrity, a compromised CDN can inject malicious code into your pages.",
    "mixed content": "Mixed HTTP/HTTPS content can be intercepted and modified by network attackers.",
    "redirect": "Missing HTTPS redirect allows network attackers to intercept traffic on first visit.",
    "autocomplete": "Browsers may cache credentials on shared devices, exposing them to subsequent users.",
    "cache": "Sensitive pages cached by proxies or browsers can be accessed by unauthorized users on shared devices.",
    "referrer": "Sensitive URL parameters may leak to third-party sites via the Referer header.",
    "permission": "Browser features (camera, mic, geolocation) are not restricted, increasing attack surface.",
    "error": "Detailed error pages reveal internal paths, versions, or stack traces useful for further attacks.",
    "version": "Exposed version information helps attackers find known CVEs for the specific software version.",
    "dom sink": "Dangerous DOM sinks can be exploited for DOM-based XSS if attacker-controlled data reaches them.",
    "internal": "Exposed internal URLs or IPs help attackers map the internal network for lateral movement.",
    "form action": "Forms submitting to external domains may leak credentials or sensitive data to third parties.",
    "api version": "Older API versions may lack security fixes, exposing known vulnerabilities.",
    "sensitive": "Exposed sensitive files or data can be used for unauthorized access or further attacks.",
    "tls": "Deprecated TLS protocols or weak ciphers allow network attackers to downgrade the connection, decrypt traffic, or impersonate the server.",
    "cipher": "Weak cipher suites allow network attackers to decrypt or forge TLS sessions (e.g. Sweet32 on 3DES, keystream recovery on RC4).",
    "javascript library": "Outdated JS libraries ship known CVEs (XSS, prototype pollution, ReDoS). Any client input reaching library sinks can be exploited.",
}


def _impact_for(title: str, severity: str) -> str:
    tl = title.lower()
    for key, impact in _IMPACT_MAP.items():
        if key in tl:
            return impact
    if severity in ("Critical", "High"):
        return "This vulnerability could allow unauthorized access, data theft, or system compromise if exploited."
    if severity == "Medium":
        return "This issue could be leveraged as part of a larger attack chain or expose sensitive information."
    if severity == "Low":
        return "Low direct risk, but may provide attackers with useful reconnaissance information."
    return ""


def _exchange_from_httpx(resp) -> dict:
    """Build an http_exchange dict from an httpx Response."""
    try:
        req = resp.request
        req_hdrs = dict(req.headers) if req.headers else {}
        resp_hdrs = dict(resp.headers) if resp.headers else {}
        body = ""
        try:
            body = resp.text[:8192]
        except Exception:
            pass
        return {
            "request": {
                "method": req.method,
                "url": str(req.url),
                "headers": req_hdrs,
                "body": (req.content or b"").decode("utf-8", errors="replace")[:8192],
            },
            "response": {
                "status_code": resp.status_code,
                "headers": resp_hdrs,
                "body": body,
            },
        }
    except Exception:
        return {}


def _make_finding(title, severity, cwe, cvss, url, evidence, payload="",
                  source="passive_recon", http_exchange=None) -> dict:
    finding = {
        "title": title,
        "severity": severity,
        "url": url,
        "parameter": "",
        "payload": payload,
        "evidence": evidence,
        "impact": _impact_for(title, severity),
        "owasp_category": "",
        "source": source,
        "cwe_hint": cwe,
        "cvss_hint": cvss,
        "finding_type": "passive_recon",
        "remediation": _remediation_for(cwe, title),
    }
    if http_exchange:
        finding["request_response"] = [{
            "tool": "passive_recon",
            "url": url,
            "payload": payload,
            "status": str(http_exchange.get("response", {}).get("status_code", "")),
            "flags": "",
            "evidence": evidence[:200] if evidence else "",
            "http_exchange": http_exchange,
        }]
    return finding


# ---------------------------------------------------------------------------
# HTTP-only passive recon — for pure API scans without a browser
# ---------------------------------------------------------------------------


async def _fingerprint_technologies_http_only(http_client, target_url: str) -> dict:
    """Best-effort HTTP-only tech fingerprint — reuses the header/body portion
    of :func:`_fingerprint_technologies` without relying on a Playwright page.
    """
    try:
        return await _fingerprint_technologies(None, http_client, target_url, [])
    except Exception as e:
        logger.debug("HTTP-only fingerprint failed: %s", e)
        return {"technologies": {}, "signals": []}


async def _check_actuator_exposure(http_client, target_url: str) -> list[dict]:
    """Probe Spring Boot Actuator endpoints for unauthenticated exposure."""
    findings: list[dict] = []
    try:
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return findings

    paths = [
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/configprops",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/actuator/loggers",
        "/actuator/metrics",
    ]
    exposed: list[tuple[str, int, str]] = []
    for p in paths:
        url = base + p
        try:
            resp = await http_client.get(url, timeout=8.0, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200 and "application/json" in (resp.headers.get("content-type", "").lower()):
            snippet = ""
            try:
                snippet = (resp.text or "")[:500]
            except Exception:
                pass
            exposed.append((url, resp.status_code, snippet))

    if not exposed:
        return findings

    for url, status, snippet in exposed:
        is_sensitive = any(url.endswith(x) for x in ("/env", "/heapdump", "/beans", "/configprops", "/threaddump"))
        severity = "high" if is_sensitive else "medium"
        title = f"Exposed Spring Boot Actuator endpoint: {urlparse(url).path}"
        evidence = (
            f"{urlparse(url).path} returns HTTP {status} with JSON body unauthenticated. "
            f"Snippet: {snippet[:200]}"
        )
        findings.append(_make_finding(
            title=title,
            severity=severity,
            cwe="CWE-200",
            cvss="7.5" if is_sensitive else "5.3",
            url=url,
            evidence=evidence,
        ))
    return findings


# ---------------------------------------------------------------------------
# TLS protocol & cipher audit (deterministic stdlib probes)
# ---------------------------------------------------------------------------

# Weak cipher families we explicitly probe for. Each entry is (OpenSSL cipher
# string, short label, CWE, CVSS, severity, description).
_WEAK_CIPHER_PROBES = [
    ("RC4",                     "RC4",                        "CWE-327", "5.9", "Medium",
     "RC4 stream cipher is cryptographically broken (RFC 7465). Allows biased-keystream recovery of session tokens."),
    ("3DES:DES-CBC3-SHA",       "3DES (Sweet32)",             "CWE-327", "5.9", "Medium",
     "3DES/DES-CBC3 block size is 64 bits — vulnerable to Sweet32 birthday attacks (CVE-2016-2183)."),
    ("NULL",                    "NULL cipher (no encryption)","CWE-326", "7.5", "High",
     "NULL cipher accepted — server will negotiate a session with no encryption at all."),
    ("EXPORT",                  "EXPORT-grade cipher",        "CWE-326", "7.5", "High",
     "EXPORT-grade ciphers (40/56-bit) accepted — trivially broken and enable FREAK/Logjam-class attacks."),
    ("aNULL",                   "Anonymous DH/ECDH",          "CWE-287", "7.4", "High",
     "Anonymous DH/ECDH cipher accepted — no server authentication, trivial MITM."),
]

# Deprecated TLS protocol versions we try to negotiate directly.
# ssl.TLSVersion is always present on Python 3.7+; we still guard imports.
_TLS_VERSION_PROBES = [
    ("TLSv1",   "TLS 1.0", "CWE-327", "6.5", "Medium",
     "TLS 1.0 is deprecated (RFC 8996) and no longer PCI-DSS compliant. Vulnerable to BEAST, POODLE, and Lucky13."),
    ("TLSv1_1", "TLS 1.1", "CWE-327", "5.3", "Medium",
     "TLS 1.1 is deprecated (RFC 8996). No modern AEAD ciphers; weaker than TLS 1.2/1.3."),
]


def _tls_probe_version_sync(host: str, port: int, version_attr: str) -> tuple[bool, str]:
    """Synchronous TLS version probe. Returns (supported, evidence_string).

    Runs in an executor because the ssl module is blocking.
    """
    import socket
    import ssl
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Some distro builds of OpenSSL drop old protocols at SECLEVEL>=1.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        try:
            v = getattr(ssl.TLSVersion, version_attr)
            ctx.minimum_version = v
            ctx.maximum_version = v
        except (AttributeError, ValueError):
            return False, f"{version_attr} not exposed by local OpenSSL"
    except Exception as e:
        return False, f"Unable to build SSLContext for {version_attr}: {e}"

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)
                return True, f"Negotiated {negotiated} with cipher {cipher[0]}"
    except (ssl.SSLError, OSError, ConnectionError):
        return False, ""
    except Exception as e:
        return False, f"probe error: {e}"


def _tls_probe_cipher_sync(host: str, port: int, cipher_string: str) -> tuple[bool, str]:
    """Try to negotiate using ``cipher_string``. Returns (accepted, evidence).

    IMPORTANT: SSLContext.set_ciphers() only affects TLS ≤ 1.2. TLS 1.3 uses
    a fixed set of AEAD cipher suites that OpenSSL picks automatically and
    ignores the legacy cipher list. If we let the handshake float up to 1.3
    the server will happily complete with a modern AEAD suite and we would
    mis-report "weak cipher accepted". Pin max_version to TLS 1.2 so the
    legacy cipher string is actually honoured.
    """
    import socket
    import ssl
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):
            pass
        try:
            ctx.set_ciphers(f"{cipher_string}:@SECLEVEL=0")
        except ssl.SSLError:
            return False, f"Local OpenSSL refuses cipher string {cipher_string!r}"
    except Exception as e:
        return False, f"SSLContext build failed for {cipher_string}: {e}"

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version() or ""
                cipher = ssock.cipher() or ("", "", 0)
                # Paranoid double-check: if we still somehow landed on TLS 1.3,
                # the server didn't honour the weak cipher — discard result.
                if negotiated and negotiated.upper().startswith("TLSV1.3"):
                    return False, ""
                return True, f"Server accepted cipher {cipher[0]} on {negotiated}"
    except (ssl.SSLError, OSError, ConnectionError):
        return False, ""
    except Exception as e:
        return False, f"probe error: {e}"


# Cipher-name substrings that count as "weak" when sslyze enumerates a
# server's accepted cipher suites. Matches are case-insensitive against
# the IANA cipher name (e.g. TLS_RSA_WITH_3DES_EDE_CBC_SHA).
_SSLYZE_WEAK_CIPHER_PATTERNS: list[tuple[str, str, str, str, str, str]] = [
    # (substring, label,                    cwe,        cvss,  severity, description)
    ("3DES",      "3DES (Sweet32)",          "CWE-327", "5.9", "Medium",
     "3DES/DES-CBC3 block size is 64 bits — vulnerable to Sweet32 birthday attacks (CVE-2016-2183)."),
    ("DES_CBC3",  "3DES (Sweet32)",          "CWE-327", "5.9", "Medium",
     "3DES/DES-CBC3 block size is 64 bits — vulnerable to Sweet32 birthday attacks (CVE-2016-2183)."),
    ("RC4",       "RC4",                     "CWE-327", "5.9", "Medium",
     "RC4 stream cipher is cryptographically broken (RFC 7465). Allows biased-keystream recovery of session tokens."),
    ("NULL",      "NULL cipher (no encryption)", "CWE-326", "7.5", "High",
     "NULL cipher accepted — server will negotiate a session with no encryption at all."),
    ("EXPORT",    "EXPORT-grade cipher",     "CWE-326", "7.5", "High",
     "EXPORT-grade ciphers (40/56-bit) accepted — trivially broken and enable FREAK/Logjam-class attacks."),
    ("_anon_",    "Anonymous DH/ECDH",       "CWE-287", "7.4", "High",
     "Anonymous DH/ECDH cipher accepted — no server authentication, trivial MITM."),
    ("ADH",       "Anonymous DH/ECDH",       "CWE-287", "7.4", "High",
     "Anonymous DH/ECDH cipher accepted — no server authentication, trivial MITM."),
]


def _tls_sslyze_weak_ciphers_sync(host: str, port: int) -> tuple[bool, list[dict]]:
    """Use sslyze to enumerate accepted cipher suites across TLS 1.0/1.1/1.2
    and return entries matching the weak-cipher patterns.

    Returns (sslyze_ran, [weak_cipher_info...]). ``sslyze_ran`` is False if
    the sslyze library is unavailable in the current environment, in which
    case the caller should fall back to the OpenSSL per-cipher probes.

    This runs synchronously (sslyze is blocking) — the async caller invokes
    it via ``loop.run_in_executor``.

    Why we need this fallback: OpenSSL 3.x in modern Linux distros often
    ships without the legacy provider, so ``ctx.set_ciphers("3DES")`` /
    ``"RC4"`` / ``"EXPORT"`` raises before the ClientHello is sent. Our
    native probe then silently reports "no 3DES" even when the server
    supports it. sslyze ships its own TLS client (nassl) that does not
    depend on the local OpenSSL cipher configuration, so it can still
    enumerate Sweet32/RC4/EXPORT on the server side.
    """
    try:
        from sslyze import (  # type: ignore
            Scanner,
            ScanCommand,
            ServerNetworkLocation,
            ServerScanRequest,
        )
        # ScanCommandAttemptStatusEnum moved between sslyze releases; try a
        # couple of known locations so we don't crash on minor-version drift.
        try:
            from sslyze.scanner.scan_command_attempt import (  # type: ignore
                ScanCommandAttemptStatusEnum,
            )
        except ImportError:
            try:
                from sslyze.scanner.models import (  # type: ignore
                    ScanCommandAttemptStatusEnum,
                )
            except ImportError:
                from sslyze import ScanCommandAttemptStatusEnum  # type: ignore
    except Exception as e:
        logger.debug("sslyze unavailable (%s) — falling back to OpenSSL probes", e)
        return False, []

    try:
        server_location = ServerNetworkLocation(hostname=host, port=port)
    except Exception as e:
        logger.debug("sslyze: invalid server location %s:%s: %s", host, port, e)
        return True, []

    scan_commands = {
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
    }
    try:
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(
            server_location=server_location,
            scan_commands=scan_commands,
        )])
    except Exception as e:
        logger.debug("sslyze: queue_scans failed for %s:%s: %s", host, port, e)
        return True, []

    weak: list[dict] = []
    try:
        for server_result in scanner.get_results():
            attempts = [
                ("TLSv1.0", getattr(server_result.scan_result, "tls_1_0_cipher_suites", None)),
                ("TLSv1.1", getattr(server_result.scan_result, "tls_1_1_cipher_suites", None)),
                ("TLSv1.2", getattr(server_result.scan_result, "tls_1_2_cipher_suites", None)),
            ]
            for version_label, attempt in attempts:
                if attempt is None:
                    continue
                status = getattr(attempt, "status", None)
                # sslyze >=5 puts the result on .result when status == COMPLETED
                if status != ScanCommandAttemptStatusEnum.COMPLETED:
                    continue
                result = getattr(attempt, "result", None)
                if result is None:
                    continue
                accepted = getattr(result, "accepted_cipher_suites", []) or []
                for acc in accepted:
                    suite = getattr(acc, "cipher_suite", None)
                    if suite is None:
                        continue
                    name = getattr(suite, "name", "") or ""
                    upper = name.upper()
                    for substr, label, cwe, cvss, sev, desc in _SSLYZE_WEAK_CIPHER_PATTERNS:
                        if substr.upper() in upper:
                            weak.append({
                                "version": version_label,
                                "cipher": name,
                                "label": label,
                                "cwe": cwe,
                                "cvss": cvss,
                                "severity": sev,
                                "description": desc,
                            })
                            break
    except Exception as e:
        logger.debug("sslyze: result iteration failed for %s:%s: %s", host, port, e)
        return True, weak

    return True, weak


async def _check_tls_configuration(target_url: str) -> list[dict]:
    """Audit the target's TLS configuration for deprecated protocols and
    weak cipher suites.

    - Deprecated protocols probed: TLS 1.0, TLS 1.1
    - Weak ciphers probed: RC4, 3DES (Sweet32), NULL, EXPORT, anonymous DH/ECDH

    Returns one finding per observed weakness. Only runs when the target is
    HTTPS; HTTP targets return an empty list.
    """
    findings: list[dict] = []
    try:
        parsed = urlparse(target_url)
    except Exception:
        return findings
    if parsed.scheme.lower() != "https":
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return findings

    base_url = f"https://{host}:{port}"
    loop = asyncio.get_running_loop()

    # ── Connectivity sanity check ─────────────────────────────────────
    reachable, _ = await loop.run_in_executor(
        None, _tls_probe_version_sync, host, port, "TLSv1_2"
    )
    if not reachable:
        # Try 1.3 — some hosts are TLS1.3-only now.
        reachable13, _ = await loop.run_in_executor(
            None, _tls_probe_version_sync, host, port, "TLSv1_3"
        )
        if not reachable13:
            logger.debug("TLS audit skipped: %s:%s not reachable via TLS", host, port)
            return findings

    # ── Deprecated protocol versions ──────────────────────────────────
    for version_attr, label, cwe, cvss, severity, desc in _TLS_VERSION_PROBES:
        try:
            supported, evidence = await loop.run_in_executor(
                None, _tls_probe_version_sync, host, port, version_attr
            )
        except Exception as e:
            logger.debug("TLS %s probe failed: %s", label, e)
            continue
        if not supported:
            continue
        findings.append(_make_finding(
            title=f"Deprecated TLS protocol enabled: {label}",
            severity=severity,
            cwe=cwe,
            cvss=cvss,
            url=base_url,
            evidence=f"{desc} {evidence}".strip(),
        ))

    # ── Weak ciphers (sslyze authoritative enumeration, OpenSSL fallback) ──
    # sslyze uses its own TLS stack (nassl) so it can detect 3DES / RC4 /
    # EXPORT even when the container's OpenSSL drops the legacy provider.
    # If sslyze isn't installed or returns nothing, we fall back to the
    # per-cipher OpenSSL probes below.
    sslyze_ran = False
    sslyze_weak: list[dict] = []
    try:
        sslyze_ran, sslyze_weak = await loop.run_in_executor(
            None, _tls_sslyze_weak_ciphers_sync, host, port
        )
    except Exception as e:
        logger.debug("TLS sslyze audit failed for %s: %s", base_url, e)

    if sslyze_ran and sslyze_weak:
        # Dedupe: emit one finding per (label) — the worst version observed
        seen_labels: set[str] = set()
        # Sort so oldest/most-broken protocol version is reported first
        sslyze_weak_sorted = sorted(sslyze_weak, key=lambda w: w["version"])
        for entry in sslyze_weak_sorted:
            if entry["label"] in seen_labels:
                continue
            seen_labels.add(entry["label"])
            findings.append(_make_finding(
                title=f"Weak TLS cipher accepted: {entry['label']}",
                severity=entry["severity"],
                cwe=entry["cwe"],
                cvss=entry["cvss"],
                url=base_url,
                evidence=(
                    f"{entry['description']} Accepted suite {entry['cipher']} "
                    f"on {entry['version']} (sslyze)"
                ).strip(),
            ))
    elif not sslyze_ran:
        # sslyze not available — fall back to OpenSSL per-cipher probes.
        # Caveat: these silently miss 3DES/RC4/EXPORT when OpenSSL 3.x's
        # legacy provider isn't loaded. NULL/aNULL still work.
        for cipher_string, label, cwe, cvss, severity, desc in _WEAK_CIPHER_PROBES:
            try:
                accepted, evidence = await loop.run_in_executor(
                    None, _tls_probe_cipher_sync, host, port, cipher_string
                )
            except Exception as e:
                logger.debug("TLS cipher %s probe failed: %s", label, e)
                continue
            if not accepted:
                continue
            findings.append(_make_finding(
                title=f"Weak TLS cipher accepted: {label}",
                severity=severity,
                cwe=cwe,
                cvss=cvss,
                url=base_url,
                evidence=f"{desc} {evidence}".strip(),
            ))

    if findings:
        logger.info(
            "TLS audit on %s: %d weaknesses found (sslyze=%s)",
            base_url, len(findings), "yes" if sslyze_ran else "no",
        )
    return findings


# ---------------------------------------------------------------------------
# Multi-host TLS discovery + audit
#
# Rationale: Acunetix crawls every sibling host it can discover and TLS-
# audits each one independently. Our LLM-driven crawler doesn't exhaustively
# visit every subdomain, and the single-URL TLS probe above only looks at
# the seed host. That combination caused us to miss Acunetix's Legacy-TLS
# findings on hosts like web-int.backup.norton.com and lldsp-int.norton.com
# even though the probe itself works correctly for those hosts.
#
# This section adds a light, passive "lite (2)" host-discovery pass: extract
# hostnames from the landing page DOM (anchors, scripts, iframes, forms,
# stylesheets), plus robots.txt and sitemap.xml of the seed host, filter to
# the scope the agent already honors, dedupe, and run the TLS audit against
# every unique https host. No active crawling/navigation is performed here.
# ---------------------------------------------------------------------------

_MAX_DISCOVERED_HOSTS = 25  # cap per scan to bound probe cost
_SITEMAP_MAX_BYTES = 512 * 1024  # don't download huge sitemaps
_ROBOTS_MAX_BYTES = 64 * 1024


def _registrable_domain(host: str) -> str:
    """Return the registrable (eTLD+1) domain for ``host``.

    Uses tldextract when available so we correctly handle multi-label
    public suffixes (e.g. co.uk). Falls back to the last two labels.
    """
    if not host:
        return ""
    try:
        import tldextract  # type: ignore
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _host_in_scope(host: str, target_url: str, extra_domains: set | None = None) -> bool:
    """Return True if ``host`` shares the target's registrable domain or
    matches one of ``extra_domains``.

    Mirrors ``agent._is_in_scope`` but lives here so passive_recon doesn't
    need to import from the agent package (which would create a cycle).
    """
    if not host:
        return False
    host = host.lower().strip(".")
    try:
        target_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        target_host = ""
    target_reg = _registrable_domain(target_host)
    host_reg = _registrable_domain(host)
    if target_reg and host_reg and host_reg == target_reg:
        return True
    if extra_domains:
        for d in extra_domains:
            d = (d or "").lower().strip(".")
            if not d:
                continue
            if host == d or host.endswith("." + d):
                return True
    return False


async def _harvest_hosts_from_page(page) -> set[str]:
    """Extract all https hostnames referenced by the landing-page DOM.

    Looks at anchors, scripts, stylesheets, iframes, images, and form
    actions — across the main frame and every accessible child frame.
    Runs a single page.evaluate so it's cheap. Returns a set of lowercase
    hostnames (ports stripped; scheme filtered to https only).
    """
    hosts: set[str] = set()
    if page is None:
        return hosts

    async def _gather(frame) -> list[str]:
        try:
            return await frame.evaluate("""() => {
                const urls = new Set();
                const push = (u) => { if (u && typeof u === 'string') urls.add(u); };
                document.querySelectorAll('a[href]').forEach(e => push(e.href));
                document.querySelectorAll('script[src]').forEach(e => push(e.src));
                document.querySelectorAll('link[href]').forEach(e => push(e.href));
                document.querySelectorAll('iframe[src]').forEach(e => push(e.src));
                document.querySelectorAll('img[src]').forEach(e => push(e.src));
                document.querySelectorAll('form[action]').forEach(e => push(e.action));
                try {
                    for (const entry of performance.getEntriesByType('resource')) {
                        push(entry.name);
                    }
                } catch (e) {}
                return [...urls];
            }""") or []
        except Exception:
            return []

    candidates: list[str] = []
    candidates.extend(await _gather(page))
    for frame in getattr(page, "frames", []) or []:
        if frame == page.main_frame:
            continue
        candidates.extend(await _gather(frame))

    for url in candidates:
        try:
            p = urlparse(url)
        except Exception:
            continue
        if p.scheme.lower() != "https":
            continue
        host = (p.hostname or "").lower()
        if host:
            hosts.add(host)
    return hosts


_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", re.IGNORECASE)
_ROBOTS_SITEMAP_RE = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)\s*$")
_ROBOTS_LIKE_URL_RE = re.compile(r"https?://[\w.-]+", re.IGNORECASE)


async def _harvest_hosts_from_robots_sitemap(http_client, target_url: str) -> set[str]:
    """Fetch robots.txt and sitemap.xml of the seed host and extract any
    https hostnames referenced. Best-effort — network errors are ignored.
    """
    hosts: set[str] = set()
    try:
        p = urlparse(target_url)
        base = f"{p.scheme}://{p.netloc}"
    except Exception:
        return hosts

    sitemap_urls: list[str] = [f"{base}/sitemap.xml"]

    # robots.txt — also pick up Sitemap: directives
    try:
        resp = await http_client.get(f"{base}/robots.txt", timeout=8.0)
        if resp.status_code == 200 and resp.text:
            text = resp.text[:_ROBOTS_MAX_BYTES]
            for m in _ROBOTS_SITEMAP_RE.finditer(text):
                sitemap_urls.append(m.group(1).strip())
            for m in _ROBOTS_LIKE_URL_RE.finditer(text):
                try:
                    h = urlparse(m.group(0)).hostname
                except Exception:
                    h = None
                if h:
                    hosts.add(h.lower())
    except Exception as e:
        logger.debug("robots.txt fetch failed for %s: %s", base, e)

    # sitemaps
    seen_sitemaps: set[str] = set()
    for sm_url in sitemap_urls[:5]:  # hard cap to avoid sitemap bombs
        if sm_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sm_url)
        try:
            resp = await http_client.get(sm_url, timeout=8.0)
            if resp.status_code != 200:
                continue
            body = (resp.text or "")[:_SITEMAP_MAX_BYTES]
            for m in _SITEMAP_LOC_RE.finditer(body):
                try:
                    h = urlparse(m.group(1)).hostname
                except Exception:
                    h = None
                if h:
                    hosts.add(h.lower())
        except Exception as e:
            logger.debug("sitemap fetch failed for %s: %s", sm_url, e)

    return hosts


async def _discover_in_scope_https_hosts(
    page,
    http_client,
    target_url: str,
    extra_domains: set | None = None,
) -> list[str]:
    """Build the list of https hosts to TLS-audit for this scan.

    Passive "lite (2)" discovery: combines the seed host, hostnames pulled
    from the landing page DOM, and hostnames referenced by robots.txt /
    sitemap.xml — all filtered to the agent's scope. No active crawling.

    Returns a list of ``host`` strings (no scheme/port) — seed first,
    deduped and capped at ``_MAX_DISCOVERED_HOSTS``.
    """
    hosts: list[str] = []
    seen: set[str] = set()

    try:
        seed_host = (urlparse(target_url).hostname or "").lower()
    except Exception:
        seed_host = ""
    if seed_host:
        hosts.append(seed_host)
        seen.add(seed_host)

    discovered: set[str] = set()
    try:
        discovered |= await _harvest_hosts_from_page(page)
    except Exception as e:
        logger.debug("page host harvest failed: %s", e)
    try:
        discovered |= await _harvest_hosts_from_robots_sitemap(http_client, target_url)
    except Exception as e:
        logger.debug("robots/sitemap host harvest failed: %s", e)

    for h in sorted(discovered):
        if h in seen:
            continue
        if not _host_in_scope(h, target_url, extra_domains):
            continue
        hosts.append(h)
        seen.add(h)
        if len(hosts) >= _MAX_DISCOVERED_HOSTS:
            logger.info(
                "Host discovery capped at %d — additional in-scope hosts skipped",
                _MAX_DISCOVERED_HOSTS,
            )
            break
    return hosts


async def _check_tls_configuration_multi_host(
    page,
    http_client,
    target_url: str,
    extra_domains: set | None = None,
) -> list[dict]:
    """Run ``_check_tls_configuration`` against every in-scope https host
    discovered passively (landing-page DOM + robots.txt + sitemap.xml).

    Aggregates findings across all hosts. Probes are run sequentially to
    keep network load predictable; per-host TLS audit is already cheap
    (<~3s) so total wall-clock scales linearly with the discovered set.
    """
    findings: list[dict] = []
    try:
        hosts = await _discover_in_scope_https_hosts(
            page, http_client, target_url, extra_domains
        )
    except Exception as e:
        logger.debug("TLS multi-host discovery failed: %s", e)
        # Fall back to seed-only
        return await _check_tls_configuration(target_url)

    if not hosts:
        return findings

    logger.info(
        "TLS audit: %d in-scope https host(s) discovered for %s (seed + %d sibling)",
        len(hosts), target_url, max(0, len(hosts) - 1),
    )

    for host in hosts:
        host_url = f"https://{host}"
        try:
            host_findings = await _check_tls_configuration(host_url)
        except Exception as e:
            logger.debug("TLS audit failed for %s: %s", host_url, e)
            continue
        findings.extend(host_findings)
    return findings


# Stage-A per-phase host-delta re-check: after each OWASP phase, the agent
# drains ScanTools._discovered_hosts (hosts the browser observed in XHR /
# fetch / navigation traffic during that phase) and calls
# run_host_delta_passive_check to TLS-audit and security-header-audit any
# hosts that weren't previously audited. Max new hosts per phase is bounded
# to keep wall-clock predictable; the caller-managed audited_hosts set
# persists across phases and across this function's calls.
_MAX_DELTA_HOSTS_PER_PHASE = 10


async def run_host_delta_passive_check(
    http_client,
    candidate_hosts: set,
    target_url: str,
    audited_hosts: set,
    extra_domains: set | None = None,
    max_new: int = _MAX_DELTA_HOSTS_PER_PHASE,
) -> list[dict]:
    """Run passive checks (TLS + security headers) on any in-scope https
    hosts in ``candidate_hosts`` that are not yet in ``audited_hosts``.

    Mutates ``audited_hosts`` in place, adding each host as it is probed
    (even if no findings were generated) so subsequent calls don't re-probe.

    Returns the aggregated finding list for the newly probed hosts. Per-host
    cost is roughly 1 TLS probe round-trip (~2-3s with sslyze fallback) plus
    1 HTTP GET for security headers, so worst-case ``max_new`` hosts ~= 30s.

    Typical use: call at the end of every OWASP phase; most phases will
    discover 0–2 new in-scope sibling hosts, so most calls are near-free.
    """
    findings: list[dict] = []
    if not candidate_hosts:
        return findings

    # Normalize + filter candidates → new in-scope hosts not yet audited.
    new_hosts: list[str] = []
    seen_here: set[str] = set()
    for raw in candidate_hosts:
        if not raw:
            continue
        host = str(raw).strip().lower()
        # Strip any port suffix defensively (hostnames from urlparse.hostname
        # shouldn't carry one, but be safe).
        if ":" in host:
            host = host.split(":", 1)[0]
        if not host or host in seen_here:
            continue
        if host in audited_hosts:
            continue
        if not _host_in_scope(host, target_url, extra_domains):
            continue
        seen_here.add(host)
        new_hosts.append(host)
        if len(new_hosts) >= max_new:
            break

    if not new_hosts:
        return findings

    logger.info(
        "Host-delta passive check: %d new in-scope host(s) to audit: %s",
        len(new_hosts), ", ".join(new_hosts),
    )

    for host in new_hosts:
        host_url = f"https://{host}"
        try:
            tls_findings = await _check_tls_configuration(host_url)
            findings.extend(tls_findings)
        except Exception as e:
            logger.debug("Host-delta TLS audit failed for %s: %s", host_url, e)
        try:
            hdr_findings = await _check_security_headers(http_client, host_url)
            findings.extend(hdr_findings)
        except Exception as e:
            logger.debug("Host-delta header audit failed for %s: %s", host_url, e)
        audited_hosts.add(host)

    return findings


# ---------------------------------------------------------------------------
# Vulnerable JS library detection (regex catalog + OSV.dev/NVD enrichment)
# ---------------------------------------------------------------------------

# Map extractor name -> (OSV package name, OSV ecosystem, URL regexes, content regexes)
# URL regexes run against the JS URL (path + query); content regexes run against
# the first ~8 KB of each first-party JS file.
_JS_LIB_CATALOG: list[dict] = [
    {
        "name": "jquery",
        "osv_name": "jquery",
        "ecosystem": "npm",
        "url": [
            # /jquery/3.5.1/jquery.min.js  (cdnjs, bootstrapcdn layout)
            re.compile(r"/jquery/(\d+\.\d+\.\d+)/", re.I),
            # jquery-3.5.1.js / jquery-3.5.1.min.js
            re.compile(r"jquery-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
            # bootstrap.bundle.min.js?v=4.5.0 style query-string versioning
            re.compile(r"jquery(?:\.\w+)*\.min\.js\?v=(\d+\.\d+\.\d+)", re.I),
        ],
        "content": [
            re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)", re.I),
            re.compile(r"/\*!\s*jQuery\s+JavaScript\s+Library\s+v?(\d+\.\d+\.\d+)", re.I),
        ],
    },
    {
        "name": "jquery-ui",
        "osv_name": "jquery-ui",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/jquery(?:ui|-ui)/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"jquery[.-]ui[-.](\d+\.\d+\.\d+)", re.I),
        ],
        "content": [re.compile(r"jQuery\s+UI\s+-\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "jquery-migrate",
        "osv_name": "jquery-migrate",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/jquery-migrate/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"jquery-migrate[-.](\d+\.\d+\.\d+)", re.I),
        ],
        "content": [re.compile(r"jQuery\s+Migrate\s+-\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "bootstrap",
        "osv_name": "bootstrap",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/(?:twitter-)?bootstrap/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"bootstrap-(\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", re.I),
            re.compile(r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\?v?=?(\d+\.\d+\.\d+)", re.I),
        ],
        "content": [re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "angular",  # AngularJS 1.x
        "osv_name": "angular",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/angular(?:js)?/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"angular-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "react",
        "osv_name": "react",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/react/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"react[-.](\d+\.\d+\.\d+)(?:\.min|\.development|\.production)?\.js", re.I),
        ],
        "content": [re.compile(r"\*\s*React\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "vue",
        "osv_name": "vue",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/vue(?:\.js)?/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"vue[-.](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"Vue\.js\s+v?(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "lodash",
        "osv_name": "lodash",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/lodash(?:\.js)?/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"lodash-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"lodash[^\d]{0,20}(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "moment",
        "osv_name": "moment",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/moment(?:\.js)?/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"moment-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"//!\s*moment\.js\s+version\s+:\s+(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "handlebars",
        "osv_name": "handlebars",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/handlebars\.js/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"handlebars-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"Handlebars\.VERSION\s*=\s*[\"'](\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "underscore",
        "osv_name": "underscore",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/underscore\.js/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"underscore-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"Underscore\.js\s+(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "backbone",
        "osv_name": "backbone",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/backbone\.js/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"backbone-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"Backbone\.js\s+(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "axios",
        "osv_name": "axios",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/axios/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"axios-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"axios[^\d]{0,20}(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "dompurify",
        "osv_name": "dompurify",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/dompurify/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"dompurify-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"DOMPurify\s+(\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "ckeditor",
        "osv_name": "ckeditor4",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/ckeditor(?:4)?/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"ckeditor-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"CKEDITOR\.version\s*=\s*[\"'](\d+\.\d+\.\d+)", re.I)],
    },
    {
        "name": "tinymce",
        "osv_name": "tinymce",
        "ecosystem": "npm",
        "url": [
            re.compile(r"/tinymce/(\d+\.\d+\.\d+)/", re.I),
            re.compile(r"tinymce-(\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
        ],
        "content": [re.compile(r"tinymce[^\d]{0,20}majorVersion:\s*[\"'](\d+)", re.I)],
    },
]


def _extract_js_library(url: str, content: str = "") -> list[tuple[str, str, str, str]]:
    """Identify JS libraries in a URL and optional file content.

    Returns a list of (friendly_name, osv_name, ecosystem, version) tuples.
    Duplicates are left in; dedupe at the call site.
    """
    found: list[tuple[str, str, str, str]] = []
    for lib in _JS_LIB_CATALOG:
        for rx in lib["url"]:
            m = rx.search(url or "")
            if m:
                found.append((lib["name"], lib["osv_name"], lib["ecosystem"], m.group(1)))
                break  # one hit per lib per URL is enough
        if content:
            for rx in lib["content"]:
                m = rx.search(content)
                if m:
                    found.append((lib["name"], lib["osv_name"], lib["ecosystem"], m.group(1)))
                    break
    return found


async def _collect_html_script_refs(page, target_url: str) -> list[str]:
    """Pull <script src> URLs from the live DOM so we can regex-match filenames
    even when network capture missed them (e.g. iframes already closed)."""
    if page is None:
        return []
    try:
        urls = await page.evaluate("""() => {
            const out = new Set();
            document.querySelectorAll('script[src]').forEach(s => out.add(s.src));
            document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => out.add(l.href));
            return [...out];
        }""")
        return [u for u in urls if isinstance(u, str) and u.startswith("http")]
    except Exception:
        return []


async def _check_js_library_vulnerabilities(
    http_client,
    js_urls: list[str],
    page=None,
    target_url: str = "",
    tech_fingerprint: dict | None = None,
) -> list[dict]:
    """Detect vulnerable JavaScript libraries by name+version and enrich with
    real CVE data from OSV.dev + NVD (via scripts.cve_lookup).

    Hybrid approach:
      • Deterministic regex catalog extracts (lib, version) from URLs, inline
        <script src> on the page, and the first 8 KB of each first-party JS
        file.
      • Dynamic CVE lookup (OSV.dev) pulls the authoritative CVE list and CVSS
        for that exact version — no hand-maintained CVE dictionary.
      • Detected libs are written back into ``tech_fingerprint["technologies"]``
        so downstream LLM phases see them as attack-surface context.
    """
    findings: list[dict] = []

    candidates: dict[tuple[str, str], tuple[str, str, str]] = {}
    # key = (osv_name, version)  →  (friendly_name, ecosystem, source_url)

    def _add(name: str, osv_name: str, ecosystem: str, version: str, source_url: str):
        key = (osv_name, version)
        if key not in candidates:
            candidates[key] = (name, ecosystem, source_url)

    # ── 1. Filename-based extraction on every known JS URL ────────────
    for u in js_urls or []:
        for name, osv_name, ecosystem, version in _extract_js_library(u):
            _add(name, osv_name, ecosystem, version, u)

    # ── 2. DOM-reported <script src>/<link href> (picks up CSS versions too)
    try:
        dom_urls = await _collect_html_script_refs(page, target_url)
        for u in dom_urls:
            for name, osv_name, ecosystem, version in _extract_js_library(u):
                _add(name, osv_name, ecosystem, version, u)
    except Exception as e:
        logger.debug("DOM script-ref collection failed: %s", e)

    # ── 3. Content-banner extraction — only for URLs with no URL hit and
    #      only on first-party JS (third-party already filtered upstream). ─
    hit_urls = {v[2] for v in candidates.values()}
    remaining = [u for u in (js_urls or []) if u not in hit_urls]
    for u in remaining[:40]:  # cap to keep runtime bounded
        try:
            resp = await http_client.get(u, timeout=8.0)
            if resp.status_code != 200:
                continue
            snippet = (resp.text or "")[:8000]
        except Exception:
            continue
        for name, osv_name, ecosystem, version in _extract_js_library(u, snippet):
            _add(name, osv_name, ecosystem, version, u)

    if not candidates:
        return findings

    logger.info("JS library audit: %d unique (lib, version) pairs detected", len(candidates))

    # ── 4. Dynamic CVE enrichment via OSV.dev + NVD ───────────────────
    try:
        from scripts.cve_lookup import enrich_library_finding
    except Exception as e:
        logger.warning("cve_lookup unavailable (%s) — emitting bare library findings", e)
        enrich_library_finding = None  # type: ignore

    for (osv_name, version), (friendly, ecosystem, source_url) in candidates.items():
        enriched = {}
        if enrich_library_finding:
            try:
                # enrich_library_finding() is synchronous + network-bound;
                # offload so we never block the event loop.
                loop = asyncio.get_running_loop()
                enriched = await loop.run_in_executor(
                    None, enrich_library_finding, osv_name, version, ecosystem
                )
            except Exception as e:
                logger.debug("CVE enrichment failed for %s@%s: %s", osv_name, version, e)
                enriched = {}

        # Record into tech fingerprint regardless of CVE outcome (LLM context).
        if tech_fingerprint is not None:
            try:
                techs = tech_fingerprint.setdefault("technologies", {})
                label = f"{friendly} {version}"
                suffix = ""
                if enriched.get("has_cves"):
                    suffix = f" (vulnerable — {enriched.get('cve_count', 0)} CVEs, max CVSS {enriched.get('max_cvss', 0):.1f})"
                techs[label] = {
                    "confidence": "high",
                    "evidence": f"Detected via {source_url}{suffix}",
                    "category": "js_library",
                }
            except Exception:
                pass

        if not enriched.get("has_cves"):
            continue

        cvss = float(enriched.get("max_cvss", 0.0) or 0.0)
        severity = (enriched.get("max_severity") or "").capitalize()
        if not severity:
            if cvss >= 9.0: severity = "Critical"
            elif cvss >= 7.0: severity = "High"
            elif cvss >= 4.0: severity = "Medium"
            elif cvss > 0: severity = "Low"
            else: severity = "Info"

        top_cves = enriched.get("cves", [])[:5]
        cwe_set: list[str] = []
        for c in top_cves:
            for cw in c.get("cwes", []) or []:
                if cw and cw not in cwe_set:
                    cwe_set.append(cw)
        cwe = cwe_set[0] if cwe_set else "CWE-1104"

        evidence_lines = [
            f"Detected {friendly}@{version} via {source_url}.",
            f"{enriched.get('cve_count', 0)} known CVE(s) per OSV.dev. "
            f"Highest CVSS {cvss:.1f} ({severity}).",
        ]
        for c in top_cves:
            evidence_lines.append(
                f"  • {c.get('cve')} (CVSS {c.get('cvss', 0.0):.1f}) — "
                f"{(c.get('description') or c.get('osv_summary') or '')[:140]}"
            )
        evidence = "\n".join(evidence_lines)

        findings.append(_make_finding(
            title=f"Vulnerable JavaScript library: {friendly} {version}",
            severity=severity,
            cwe=cwe,
            cvss=f"{cvss:.1f}",
            url=source_url,
            evidence=evidence,
        ))

    if findings:
        logger.info("JS library audit: %d vulnerable library findings", len(findings))
    return findings


async def run_http_only_passive_recon(
    http_client,
    target_url: str,
    on_finding: callable | None = None,
    on_progress: callable | None = None,
    skip_tls_sibling_discovery: bool = False,
) -> tuple[list[dict], dict]:
    """HTTP-only passive reconnaissance — no Playwright required.

    Mirrors :func:`run_passive_recon` but runs only the checks that depend
    purely on an ``httpx.AsyncClient``.  Intended for the API-only fast path
    where a headless browser would be blocked (e.g. by WAF/TLS fingerprint) or
    is simply unnecessary because the target is a REST API.
    """
    findings: list[dict] = []
    _cb = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    _progress("passive_start", {
        "checks": "sensitive_files, security_headers, actuator, cors, cache_control, "
                  "csp, referrer_policy, permissions_policy, https_redirect, hsts_preload, "
                  "error_pages, clickjacking, api_version_downgrade, tls_audit, "
                  "js_library_cves, tech_fingerprint",
        "mode": "http_only",
    })

    async def _run(step_name: str, coro):
        try:
            result = await coro
        except Exception as e:
            logger.debug("HTTP-only passive step %s failed: %s", step_name, e)
            result = []
        result = result or []
        for f in result:
            findings.append(f)
            _cb(f)
        _progress("passive_step", {"step": step_name, "found": len(result)})

    await _run("Sensitive files", _check_sensitive_files(http_client, _base(target_url)))
    await _run("Security headers", _check_security_headers(http_client, target_url))
    await _run("Actuator exposure", _check_actuator_exposure(http_client, target_url))
    await _run("CORS misconfiguration", _check_cors_misconfiguration(http_client, target_url))
    await _run("Cache-Control", _check_cache_control(http_client, target_url))
    await _run("CSP analysis", _check_csp_weaknesses(http_client, target_url))
    await _run("Referrer-Policy", _check_referrer_policy(http_client, target_url))
    await _run("Permissions-Policy", _check_permissions_policy(http_client, target_url))
    await _run("HTTPS redirect", _check_https_redirect(http_client, target_url))
    await _run("HSTS preload", _check_hsts_preload(http_client, target_url))
    await _run("Error pages", _check_error_pages(http_client, target_url))
    await _run("Clickjacking", _check_clickjacking(http_client, target_url))
    await _run("API version downgrade", _check_api_version_downgrade(http_client, target_url, []))
    # No Playwright page in HTTP-only mode, so DOM-based host harvesting is
    # unavailable. We still pull sibling hosts from robots.txt + sitemap.xml
    # unless skip_tls_sibling_discovery (seed host only).
    if skip_tls_sibling_discovery:
        await _run("TLS audit", _check_tls_configuration(target_url))
    else:
        await _run(
            "TLS audit",
            _check_tls_configuration_multi_host(None, http_client, target_url),
        )

    tech_fingerprint = await _fingerprint_technologies_http_only(http_client, target_url)
    _progress("passive_step", {
        "step": "Tech fingerprint",
        "technologies": list(tech_fingerprint.get("technologies", {}).keys()),
    })

    # JS library audit — HTTP-only mode has no browser, so the detector falls
    # back to URL-pattern matching against any .js links surfaced by earlier
    # fingerprinting (e.g. in HTML body regexes). For a pure API target this
    # is usually a no-op, which is the correct behaviour.
    await _run(
        "JS library CVE audit",
        _check_js_library_vulnerabilities(
            http_client, js_urls=[], page=None,
            target_url=target_url, tech_fingerprint=tech_fingerprint,
        ),
    )

    _progress("passive_end", {"total_findings": len(findings), "mode": "http_only"})
    logger.info("HTTP-only passive recon complete: %d findings", len(findings))
    return findings, tech_fingerprint


def _base(target_url: str) -> str:
    try:
        p = urlparse(target_url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return target_url
