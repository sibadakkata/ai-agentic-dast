from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
import uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from playwright.async_api import Page

if TYPE_CHECKING:
    from .auth import AuthSession

try:
    from .api_import import EndpointRegistry
except ImportError:
    EndpointRegistry = Any

try:
    import websockets
except ImportError:
    websockets = None

logger = logging.getLogger(__name__)

BODY_SNIPPET_LEN = 1500
HTML_SNIPPET_LEN = 4000
HTTP_EXCHANGE_BODY_MAX = 8192


def _build_http_exchange(
    *,
    method: str,
    url: str,
    request_headers: dict | None = None,
    request_body: str | None = None,
    status_code: int | None = None,
    response_headers: dict | None = None,
    response_body: str | None = None,
) -> dict:
    """Build a full HTTP exchange record (Burp/Acunetix-style)."""
    req_hdrs = dict(request_headers) if request_headers else {}
    resp_hdrs = dict(response_headers) if response_headers else {}
    resp_body_str = (response_body or "")[:HTTP_EXCHANGE_BODY_MAX]
    req_body_str = (request_body or "")[:HTTP_EXCHANGE_BODY_MAX]
    return {
        "request": {
            "method": (method or "GET").upper(),
            "url": url or "",
            "headers": req_hdrs,
            "body": req_body_str,
        },
        "response": {
            "status_code": status_code,
            "headers": resp_hdrs,
            "body": resp_body_str,
        },
    }

_SQL_ERROR_PATTERNS = (
    "sqlite", "sql syntax", "sql error", "mysql", "ora-", "pg_query",
    "odbc", "unrecognized token", "incomplete input", "unterminated",
    "you have an error in your sql", "near \"", "syntax error at",
    "unclosed quotation", "quoted string not properly terminated",
    "sqlstate", "jdbc", "microsoft ole db", "microsoft sql server",
)
_XSS_INDICATORS = ("<script", "onerror=", "onload=", "alert(", "javascript:", "onfocus=")
_CMDI_INDICATORS = ("uid=", "root:", "/bin/", "volume serial number", "windows\\system32")
_SSTI_INDICATORS = ("49", "7777777", "__class__", "__mro__", "config{")
_ERROR_INDICATORS = [
    "error", "exception", "sql", "syntax", "undefined", "stack trace",
    "sqlite", "mysql", "pg_", "ora-", "odbc", "uncaught", "unrecognized token",
    "internal server error", "traceback", "fatal",
]

_WAF_SIGNATURES = [
    "access denied", "request blocked", "web application firewall",
    "cloudflare", "sucuri", "modsecurity", "fortiweb", "barracuda",
    "incapsula", "imperva", "f5 big-ip", "wallarm", "akamai ghost",
    "blocked by security", "your request has been blocked",
    "this request was blocked by the security rules",
]


def _detect_waf_block(status_code: int, body: str) -> bool:
    if status_code in (403, 406, 429, 503):
        body_lower = body[:5000].lower()
        return any(sig in body_lower for sig in _WAF_SIGNATURES)
    return False


def _extract_vuln_signals(body: str, status_code: int, payload: str = "") -> dict:
    """Extract vulnerability signals from an HTTP response body.

    Returns a dict with optional keys: error_indicators, error_title, error_message,
    VULNERABILITIES_DETECTED, ACTION_REQUIRED.
    """
    signals: dict = {}
    body_lower = body.lower()

    matched = [ind for ind in _ERROR_INDICATORS if ind in body_lower]
    if matched:
        signals["error_indicators"] = matched[:5]

    import re as _re
    title_m = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.IGNORECASE | _re.DOTALL)
    if title_m:
        signals["error_title"] = title_m.group(1).strip()[:200]
    for json_key in ("message", "error"):
        json_m = _re.search(rf'"{json_key}"\s*:\s*"([^"]+)"', body)
        if json_m:
            signals["error_message"] = json_m.group(1)[:200]
            break

    vulns = []
    err_text = (signals.get("error_title") or signals.get("error_message") or "").lower()
    if any(p in err_text or p in body_lower for p in _SQL_ERROR_PATTERNS):
        vulns.append({
            "type": "SQL Injection", "payload": payload,
            "status": status_code,
            "proof": signals.get("error_title") or signals.get("error_message") or "SQL error in response",
        })
    if payload and any(p in payload.lower() for p in _XSS_INDICATORS) and payload in body:
        vulns.append({
            "type": "Cross-Site Scripting (XSS)", "payload": payload,
            "status": status_code, "proof": "Payload reflected unescaped in response",
        })
    if any(p in body_lower for p in _CMDI_INDICATORS):
        vulns.append({
            "type": "Command Injection", "payload": payload,
            "status": status_code, "proof": "OS command output detected in response",
        })

    if vulns:
        signals["VULNERABILITIES_DETECTED"] = vulns
        signals["ACTION_REQUIRED"] = (
            "CONFIRMED vulnerabilities found! You MUST report each as a finding JSON with "
            "title, severity, owasp_category, url, parameter, payload, evidence, confidence, remediation."
        )

    return signals


def _truncate(s: str | None, max_len: int = BODY_SNIPPET_LEN) -> str:
    if s is None:
        return ""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def _error_dict(msg: str) -> dict:
    logger.error(msg)
    return {"error": msg}


def _mutate_json_field(original_body: str | None, field_path: str, payload: str) -> str:
    """Mutate a single field in a JSON body, supporting nested dot-notation paths."""
    if not original_body:
        return json.dumps({field_path: payload})
    try:
        data = json.loads(original_body)
    except (json.JSONDecodeError, TypeError):
        return json.dumps({field_path: payload})
    parts = field_path.split(".")
    current = data
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return json.dumps(data)
        else:
            return json.dumps(data)
    final_key = parts[-1]
    if isinstance(current, dict):
        current[final_key] = payload
    elif isinstance(current, list):
        try:
            current[int(final_key)] = payload
        except (ValueError, IndexError):
            pass
    return json.dumps(data)


class ScanTools:
    def __init__(
        self,
        page: Page | None,
        http_client: httpx.AsyncClient,
        registry: EndpointRegistry,
        auth_session: AuthSession | None = None,
        allowed_domains: set | None = None,
        cancel_flag=None,
        exclude_urls: list[str] | None = None,
    ):
        self._page = page
        self._http_client = http_client
        self._registry = registry
        self._auth_session = auth_session
        self._allowed_domains = allowed_domains or set()
        self._cancel_flag = cancel_flag
        self._exclude_patterns: list[str] = [p.strip().rstrip("/") for p in (exclude_urls or []) if p.strip()]
        self._out_of_scope: list[str] = []
        self._excluded_hits: list[str] = []
        self._network_log: list[dict] = []
        self._ws_connections: dict[str, Any] = {}
        self._findings_ref: list[dict] = []
        self._chain_results: list[dict] = []
        # Stage-A host harvest: every in-scope https host observed in the
        # browser's network traffic (XHR, fetch, navigations, redirects) is
        # added here by _log_request. The agent drains this set after each
        # OWASP phase to run TLS + security-header audits on newly appearing
        # sibling hosts (e.g., SPA XHRs to *.example.com that only surface
        # post-authentication). Hostnames only; no scheme/port.
        self._discovered_hosts: set[str] = set()
        self._shared_tested: set[str] | None = None

    def set_shared_tested(self, shared: set[str]) -> None:
        """Bind a shared tested-endpoint set for cross-worker dedup."""
        self._shared_tested = shared

    def _already_tested(self, method: str, url: str, param: str) -> bool:
        if self._shared_tested is None:
            return False
        key = f"{method.upper()}|{url.split('?')[0]}|{param}"
        if key in self._shared_tested:
            return True
        self._shared_tested.add(key)
        return False

    def set_findings_ref(self, findings: list[dict]) -> None:
        """Bind the shared findings list so tools can read it."""
        self._findings_ref = findings
        self._intercept_pattern: str | None = None
        if self._page:
            self._page.on("requestfinished", lambda req: asyncio.ensure_future(self._log_request(req)))

    def _url_excluded(self, url: str) -> bool:
        """Return True if URL matches any user-defined exclusion pattern."""
        if not self._exclude_patterns or not url:
            return False
        url_lower = url.lower().rstrip("/")
        try:
            from urllib.parse import urlparse
            path_lower = (urlparse(url).path or "/").lower().rstrip("/")
        except Exception:
            path_lower = ""
        for pattern in self._exclude_patterns:
            p = pattern.lower().rstrip("/")
            if url_lower == p or url_lower.startswith(p + "/"):
                if url not in self._excluded_hits:
                    self._excluded_hits.append(url)
                return True
            if p.startswith("/") and path_lower:
                if path_lower == p or path_lower.startswith(p + "/"):
                    if url not in self._excluded_hits:
                        self._excluded_hits.append(url)
                    return True
        return False

    def _url_in_scope(self, url: str) -> bool:
        """Return True if URL belongs to one of the allowed target domains."""
        if not self._allowed_domains or not url:
            return True
        if url.startswith("/"):
            return True
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return True
        for d in self._allowed_domains:
            if host == d or host.endswith("." + d):
                return True
        if url not in self._out_of_scope:
            self._out_of_scope.append(url)
        return False

    def _resolve_url(self, url: str) -> str:
        """Resolve relative URLs (e.g. /api/foo) to full URLs using the page origin."""
        if not url or url.startswith("http://") or url.startswith("https://"):
            return url
        if url.startswith("/"):
            origin = ""
            if self._page:
                try:
                    p = urlparse(self._page.url)
                    origin = f"{p.scheme}://{p.netloc}"
                except Exception:
                    pass
            if not origin:
                base = str(self._http_client.base_url).rstrip("/") if self._http_client.base_url else ""
                if base and base != "":
                    origin = base
            if origin:
                return origin.rstrip("/") + url
        return url

    def get_out_of_scope_urls(self) -> list[str]:
        """Return list of unique URLs that were blocked as out-of-scope."""
        return list(self._out_of_scope)

    def get_excluded_urls(self) -> list[str]:
        """Return list of unique URLs that were blocked by exclusion rules."""
        return list(self._excluded_hits)

    _LOGOUT_PATTERNS = (
        "/logout", "/log-out", "/log_out",
        "/signout", "/sign-out", "/sign_out",
        "/disconnect", "/end-session", "/endsession",
        "action=logout", "action=signout", "action=sign_out",
        "?logout", "?signout",
    )

    @staticmethod
    def _is_logout_url(url: str) -> bool:
        """Return True if a URL looks like a logout/signout endpoint."""
        lower = (url or "").lower()
        return any(p in lower for p in ScanTools._LOGOUT_PATTERNS)

    @staticmethod
    def _is_logout_selector(selector: str) -> bool:
        """Return True if a CSS selector targets a logout element."""
        lower = (selector or "").lower()
        logout_kw = ("logout", "log-out", "log_out", "signout",
                     "sign-out", "sign_out", "disconnect")
        return any(kw in lower for kw in logout_kw)

    async def get_findings_so_far(self) -> dict:
        """Return a summary of all findings discovered in the scan so far."""
        if not self._findings_ref:
            return {"total": 0, "findings": [], "message": "No findings discovered yet."}
        by_sev: dict[str, int] = {}
        items = []
        for f in self._findings_ref:
            sev = (f.get("severity") or "info").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            items.append({
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "payload": (f.get("payload") or "")[:100],
                "owasp": f.get("owasp_category", ""),
                "phase": f.get("phase", ""),
            })
        return {
            "total": len(self._findings_ref),
            "by_severity": by_sev,
            "findings": items,
        }

    async def chain_exploit(self, chain_name: str, steps: list, target_url: str = "") -> dict:
        """Execute a multi-step exploit chain. Each step uses an existing tool.

        The agent declares the chain (name + ordered steps) and this tool
        executes each step sequentially, collecting evidence at every stage.
        If any step fails, the chain stops and reports partial results.
        """
        if not steps:
            return {"error": "No steps provided. Provide at least 2 steps for a chain."}
        if len(steps) < 2:
            return {"error": "A chain requires at least 2 steps. For single actions use the tool directly."}

        chain_evidence: list[dict] = []
        chain_success = True
        failed_step = -1

        for idx, step in enumerate(steps):
            tool_name = step.get("tool", "")
            tool_args = step.get("args", {})
            description = step.get("description", f"Step {idx + 1}")
            expect = step.get("expect", "")

            if not tool_name:
                chain_evidence.append({
                    "step": idx + 1, "description": description,
                    "status": "SKIPPED", "reason": "No tool specified",
                })
                continue

            if tool_name in ("chain_exploit", "get_findings_so_far"):
                chain_evidence.append({
                    "step": idx + 1, "description": description,
                    "status": "SKIPPED", "reason": f"Cannot nest {tool_name} inside a chain",
                })
                continue

            try:
                result = await self.execute(tool_name, json.dumps(tool_args))
            except Exception as e:
                chain_evidence.append({
                    "step": idx + 1, "tool": tool_name, "description": description,
                    "status": "ERROR", "error": str(e),
                })
                chain_success = False
                failed_step = idx + 1
                break

            is_error = isinstance(result, dict) and result.get("error")
            status_code = result.get("status") if isinstance(result, dict) else None
            body_snippet = ""
            if isinstance(result, dict):
                body_snippet = (result.get("body_snippet") or result.get("body") or
                                result.get("content") or result.get("text") or "")
                if isinstance(body_snippet, str) and len(body_snippet) > 500:
                    body_snippet = body_snippet[:500] + "..."

            step_record = {
                "step": idx + 1,
                "tool": tool_name,
                "description": description,
                "status": "ERROR" if is_error else "OK",
                "status_code": status_code,
                "body_snippet": body_snippet,
            }
            if is_error:
                step_record["error"] = result.get("error", "")
                chain_success = False
                failed_step = idx + 1
                chain_evidence.append(step_record)
                break

            if expect:
                step_record["expectation"] = expect
                body_lower = str(body_snippet).lower()
                if expect.lower() not in body_lower and str(status_code) != str(expect):
                    step_record["expectation_met"] = False
                    step_record["status"] = "UNEXPECTED"
                else:
                    step_record["expectation_met"] = True

            chain_evidence.append(step_record)

        chain_result = {
            "chain_name": chain_name,
            "total_steps": len(steps),
            "steps_completed": len(chain_evidence),
            "chain_success": chain_success,
            "evidence": chain_evidence,
        }
        if not chain_success:
            chain_result["failed_at_step"] = failed_step
            chain_result["verdict"] = "CHAIN BROKEN — partial exploitation achieved"
        else:
            chain_result["verdict"] = "CHAIN COMPLETE — all steps succeeded"
            chain_result["action_required"] = (
                "This chain succeeded end-to-end. Report it as a single finding with "
                "severity based on the COMBINED impact. Include all step evidence."
            )
        self._chain_results.append(chain_result)
        return chain_result

    def _is_cancelled(self) -> bool:
        return self._cancel_flag is not None and self._cancel_flag.is_set()

    async def execute(self, function_name: str, arguments: str) -> dict:
        if self._is_cancelled():
            from .agent import ScanCancelled
            raise ScanCancelled("Scan stopped by user")
        try:
            args = json.loads(arguments) if arguments else {}
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON arguments: {e}"}

        handlers: dict[str, Any] = {
            "navigate": self.navigate,
            "click": self.click,
            "fill": self.fill,
            "submit_form": self.submit_form,
            "inject_payload": self.inject_payload,
            "screenshot": self.screenshot,
            "get_page_source": self.get_page_source,
            "get_cookies": self.get_cookies,
            "get_network_log": self.get_network_log,
            "get_forms": self.get_forms,
            "get_links": self.get_links,
            "get_local_storage": self.get_local_storage,
            "execute_js": self.execute_js,
            "wait_for_spa_route": self.wait_for_spa_route,
            "intercept_requests": self.intercept_requests,
            "ws_connect": self.ws_connect,
            "ws_send": self.ws_send,
            "ws_receive": self.ws_receive,
            "ws_inject": self.ws_inject,
            "ws_close": self.ws_close,
            "api_request": self.api_request,
            "api_request_raw": self.api_request_raw,
            "fuzz_parameter": self.fuzz_parameter,
            "replay_with_modification": self.replay_with_modification,
            "get_api_endpoints": self.get_api_endpoints,
            "test_auth_bypass": self.test_auth_bypass,
            "test_method_override": self.test_method_override,
            "test_token_security": self.test_token_security,
            "get_findings_so_far": self.get_findings_so_far,
            "chain_exploit": self.chain_exploit,
        }

        handler = handlers.get(function_name)
        if not handler:
            valid = sorted(handlers.keys())
            return {"error": f"Unknown tool '{function_name}'. Valid tools: {', '.join(valid)}"}

        try:
            result = await handler(**args)
            return result
        except Exception as e:
            return _error_dict(str(e))

    def _require_page(self) -> bool:
        return self._page is not None

    def _record_discovered_host(self, url: str) -> None:
        """Record an https hostname seen in browser traffic for Stage-A
        per-phase host-delta passive re-check. Only https is tracked because
        the delta pass runs TLS audits. Scope is enforced against
        ``self._allowed_domains`` so third-party CDNs / analytics hosts
        don't pollute the queue.
        """
        if not url:
            return
        try:
            p = urlparse(url)
        except Exception:
            return
        if (p.scheme or "").lower() != "https":
            return
        host = (p.hostname or "").lower()
        if not host:
            return
        if self._allowed_domains:
            in_scope = False
            for d in self._allowed_domains:
                if host == d or host.endswith("." + d):
                    in_scope = True
                    break
            if not in_scope:
                return
        self._discovered_hosts.add(host)

    def get_discovered_hosts(self) -> set[str]:
        """Return a snapshot of in-scope https hostnames seen in browser
        network traffic since scan start. Caller-owned copy; safe to mutate.
        """
        return set(self._discovered_hosts)

    _HOST_LITERAL_RE = re.compile(
        r"https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)",
        re.IGNORECASE,
    )
    # Content types whose bodies we mine for hostname string literals. SPA
    # bundles (JS), server-rendered pages (HTML), inline config (JSON/XML),
    # stylesheets with url() refs (CSS) and plain text responses are all
    # cheap to scan with a pre-compiled regex. Binary types (images, fonts,
    # wasm, pdf, video) are skipped.
    _BODY_HARVEST_CT_KEYWORDS = (
        "javascript", "ecmascript", "json", "html", "xml", "css", "text/plain",
    )
    _BODY_HARVEST_MAX_BYTES = 512 * 1024  # cap per response to stay cheap

    def _harvest_hosts_from_response_body(
        self, url: str, content_type: str, body: str,
    ) -> None:
        """Scan a response body for ``https?://<host>`` literals and feed
        each match into the in-scope host discovery set. This catches
        sibling sub-domains that are referenced inside SPA bundles or
        lazy-loaded JSON configs but that the browser hasn't yet actually
        fetched — e.g. a backup/licensing micro-frontend whose base URL
        (``web-int.backup.example.com``) is baked into the main bundle as
        a string constant but only used once the user clicks into that
        feature.

        Scope is enforced by :meth:`_record_discovered_host`, so third-party
        hosts (CDNs, analytics) are naturally filtered out.
        """
        if not body:
            return
        ct = (content_type or "").lower()
        if not any(kw in ct for kw in self._BODY_HARVEST_CT_KEYWORDS):
            # Also accept known JS/CSS/JSON extensions when the server
            # returned no or a misleading content-type (common on CDNs).
            lower_url = (url or "").lower().split("?", 1)[0]
            if not lower_url.endswith((".js", ".mjs", ".cjs", ".css", ".json", ".html", ".htm")):
                return
        snippet = body if len(body) <= self._BODY_HARVEST_MAX_BYTES else body[: self._BODY_HARVEST_MAX_BYTES]
        seen_in_body: set[str] = set()
        try:
            for m in self._HOST_LITERAL_RE.finditer(snippet):
                host = (m.group(1) or "").lower().rstrip(".")
                if not host or host in seen_in_body:
                    continue
                seen_in_body.add(host)
                if host in self._discovered_hosts:
                    continue
                self._record_discovered_host(f"https://{host}")
        except Exception:
            # Pattern-matching on a huge minified bundle should never
            # bring the scanner down — harvest is best-effort.
            pass

    async def _log_request(self, request: Any) -> None:
        try:
            url = request.url
            method = request.method
            self._record_discovered_host(url)
            response = await request.response()
            status = response.status if response else None
            req_body = ""
            try:
                req_body = request.post_data or ""
            except Exception:
                pass
            resp_body = ""
            resp_headers: dict = {}
            try:
                if response:
                    resp_body = await response.text()
                    resp_headers = await response.all_headers()
            except Exception:
                pass
            req_headers: dict = {}
            try:
                req_headers = await request.all_headers()
            except Exception:
                pass
            # Deterministic sibling-host discovery from response body content:
            # SPA bundles / JSON configs / HTML often reference in-scope
            # sibling sub-domains as string literals well before the browser
            # actually fetches them (e.g. lazy-loaded micro-frontends).
            # Grepping the body feeds those into the discovery queue so
            # Stage-A passive audits and Stage-B LLM directives can cover
            # them without waiting for the user to click into that feature.
            if resp_body:
                try:
                    ct = ""
                    if isinstance(resp_headers, dict):
                        ct = resp_headers.get("content-type") or resp_headers.get("Content-Type") or ""
                    self._harvest_hosts_from_response_body(url, ct, resp_body)
                except Exception:
                    pass
            self._network_log.append({
                "url": url,
                "method": method,
                "status": status,
                "request_body": _truncate(req_body, 1000),
                "response_snippet": _truncate(resp_body),
                "http_exchange": _build_http_exchange(
                    method=method,
                    url=url,
                    request_headers=req_headers,
                    request_body=req_body,
                    status_code=status,
                    response_headers=resp_headers,
                    response_body=resp_body,
                ),
            })
        except Exception as e:
            logger.debug("Failed to log request: %s", e)

    async def navigate(self, url: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        url = self._resolve_url(url)
        if self._is_logout_url(url):
            return {"error": "BLOCKED: This is a logout/signout URL. Navigating here would destroy the authenticated session.", "skipped": True}
        if self._url_excluded(url):
            return {"error": f"EXCLUDED by user: {url} — this URL is in the exclusion list.", "skipped": True}
        if not self._url_in_scope(url):
            return {"error": f"URL out of scope (not in target domain): {url}", "skipped": True}
        try:
            response = await self._page.goto(url, wait_until="networkidle", timeout=30000)
            status_code = response.status if response else None
            title = await self._page.title()
            current_url = self._page.url

            is_spa = False
            try:
                is_spa = await self._page.evaluate("""() => {
                    if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined') return true;
                    if (document.querySelector('[ng-version]')) return true;
                    if (typeof __VUE__ !== 'undefined') return true;
                    return false;
                }""")
            except Exception:
                pass

            return {
                "title": title,
                "status_code": status_code,
                "url": current_url,
                "is_spa": is_spa,
            }
        except Exception as e:
            return _error_dict(str(e))

    async def click(self, selector: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        if self._is_logout_selector(selector):
            return {"error": "BLOCKED: Selector targets a logout element. Clicking would destroy the authenticated session.", "skipped": True}
        try:
            href = await self._page.evaluate(
                """(sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return '';
                    const h = el.getAttribute('href') || '';
                    const t = (el.textContent || '').trim().toLowerCase();
                    return h + '|' + t;
                }""", selector
            )
        except Exception:
            href = ""
        href_lower = (href or "").lower()
        logout_kw = ("logout", "log-out", "log_out", "signout", "sign-out", "sign_out", "disconnect")
        if any(kw in href_lower for kw in logout_kw):
            return {"error": "BLOCKED: This element links to logout/signout. Clicking would destroy the authenticated session.", "skipped": True}
        try:
            before_url = self._page.url
            before_count = len(self._network_log)

            await self._page.click(selector, timeout=10000)
            await self._page.wait_for_load_state("networkidle", timeout=5000)

            new_url = self._page.url
            if self._is_logout_url(new_url):
                logger.warning("Click navigated to logout URL %s — attempting to go back", new_url)
                await self._page.go_back(wait_until="networkidle", timeout=10000)
                return {"error": f"RECOVERED: Click led to logout URL ({new_url}). Navigated back to preserve session.", "skipped": True}

            triggered = self._network_log[before_count:] if len(self._network_log) > before_count else []

            return {
                "success": True,
                "new_url": new_url,
                "triggered_requests": [
                    {"url": r.get("url"), "method": r.get("method"), "status": r.get("status")}
                    for r in triggered
                ],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def fill(self, selector: str, value: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            await self._page.fill(selector, value, timeout=5000)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def submit_form(self, selector: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            form = self._page.locator(selector).first
            await form.evaluate("el => el.submit()")
            await self._page.wait_for_load_state("networkidle", timeout=10000)
            response = await self._page.evaluate("""() => {
                const perf = performance.getEntriesByType('navigation');
                const last = perf[perf.length - 1];
                return last ? last.responseStatus : null;
            }""")
            status = response if response else None
            redirect_url = self._page.url
            return {"status": status, "redirect_url": redirect_url}
        except Exception as e:
            return {"error": str(e)}

    async def inject_payload(self, selector: str, payload: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            loc = self._page.locator(selector).first
            await loc.fill(payload)

            submitted = False
            try:
                form = loc.locator("xpath=ancestor::form").first
                await form.evaluate("el => el.submit()")
                submitted = True
            except Exception:
                pass

            if not submitted:
                try:
                    submit_btn = self._page.locator(
                        "button[type='submit'], input[type='submit'], "
                        "button:has-text('Submit'), button:has-text('Login'), "
                        "button:has-text('Search'), button:has-text('Sign in'), "
                        "button:has-text('Log in'), button[mat-raised-button], "
                        "button.mat-button, button.btn-primary, button.submit-btn"
                    ).first
                    await submit_btn.click(timeout=3000)
                    submitted = True
                except Exception:
                    pass

            if not submitted:
                await loc.press("Enter")

            await self._page.wait_for_load_state("networkidle", timeout=10000)

            content = await self._page.content()
            body_snippet = _truncate(content)
            reflected = payload in content

            status_code = 200
            try:
                status_code = await self._page.evaluate("""() => {
                    const perf = performance.getEntriesByType('navigation');
                    const last = perf[perf.length - 1];
                    return last ? (last.responseStatus || 200) : 200;
                }""")
            except Exception:
                pass

            waf_likely = _detect_waf_block(status_code, content)
            result = {
                "status": status_code,
                "url": self._page.url,
                "body_snippet": body_snippet,
                "reflected": reflected,
                "waf_likely": waf_likely,
            }

            signals = _extract_vuln_signals(content, status_code, payload=payload)
            if signals:
                result.update(signals)
            elif reflected:
                result["ACTION_REQUIRED"] = (
                    "Payload was REFLECTED in the page! Check if it's inside HTML, "
                    "attributes, or script context — this may be XSS."
                )

            return result
        except Exception as e:
            return {"error": str(e)}

    async def screenshot(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            buf = await self._page.screenshot(type="jpeg", quality=70)
            b64 = base64.b64encode(buf).decode("ascii")
            if len(b64) > 100000:
                b64 = b64[:100000] + "...[truncated]"
            return {"image_base64": b64}
        except Exception as e:
            return _error_dict(str(e))

    async def get_page_source(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            html = await self._page.content()
            return {"html": _truncate(html, HTML_SNIPPET_LEN)}
        except Exception as e:
            return _error_dict(str(e))

    async def get_cookies(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            cookies = await self._page.context.cookies()
            out = [
                {
                    "name": c["name"],
                    "value": c["value"],
                    "domain": c.get("domain", ""),
                    "secure": c.get("secure", False),
                    "httpOnly": c.get("httpOnly", False),
                    "sameSite": c.get("sameSite", "Lax"),
                }
                for c in cookies
            ]
            return {"cookies": out}
        except Exception as e:
            return _error_dict(str(e))

    async def get_network_log(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        drained = list(self._network_log)
        self._network_log.clear()
        return {"requests": drained}

    async def get_forms(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            forms = await self._page.evaluate("""() => {
                const forms = [];
                // Traditional <form> elements
                document.querySelectorAll('form').forEach(f => {
                    const inputs = [];
                    f.querySelectorAll('input, textarea, select').forEach(inp => {
                        inputs.push({
                            name: inp.name || inp.id || inp.getAttribute('formControlName') || inp.getAttribute('ng-model') || inp.placeholder || '',
                            type: inp.type || inp.tagName.toLowerCase(),
                            value: inp.value || '',
                            selector: inp.id ? '#' + inp.id : (inp.name ? `[name="${inp.name}"]` : '')
                        });
                    });
                    forms.push({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: inputs,
                        source: 'form'
                    });
                });

                // SPA inputs NOT inside <form> (Angular, React, Vue)
                const formInputs = new Set();
                document.querySelectorAll('form input, form textarea, form select').forEach(el => formInputs.add(el));
                const orphanInputs = [];
                document.querySelectorAll('input, textarea, select, [contenteditable="true"]').forEach(inp => {
                    if (formInputs.has(inp)) return;
                    if (inp.type === 'hidden') return;
                    const name = inp.name || inp.id || inp.getAttribute('formControlName')
                        || inp.getAttribute('ng-model') || inp.getAttribute('data-testid')
                        || inp.getAttribute('aria-label') || inp.placeholder || '';
                    if (!name) return;
                    orphanInputs.push({
                        name: name,
                        type: inp.type || inp.tagName.toLowerCase(),
                        value: inp.value || '',
                        selector: inp.id ? '#' + inp.id : (inp.name ? `[name="${inp.name}"]` : `[placeholder="${inp.placeholder}"]`)
                    });
                });
                if (orphanInputs.length > 0) {
                    forms.push({
                        action: window.location.href,
                        method: 'SPA',
                        inputs: orphanInputs,
                        source: 'spa_orphan_inputs'
                    });
                }

                // Angular Material: mat-form-field inputs
                const matInputs = [];
                document.querySelectorAll('mat-form-field input, mat-form-field textarea').forEach(inp => {
                    if (formInputs.has(inp)) return;
                    const name = inp.getAttribute('formControlName') || inp.name || inp.id
                        || inp.getAttribute('matInput') || inp.placeholder || '';
                    if (!name) return;
                    matInputs.push({
                        name: name,
                        type: inp.type || 'text',
                        value: inp.value || '',
                        selector: inp.id ? '#' + inp.id : `[formControlName="${inp.getAttribute('formControlName')}"]`
                    });
                });
                if (matInputs.length > 0) {
                    forms.push({
                        action: window.location.href,
                        method: 'SPA',
                        inputs: matInputs,
                        source: 'angular_material'
                    });
                }

                return forms;
            }""")
            return {"forms": forms}
        except Exception as e:
            return _error_dict(str(e))

    async def get_links(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            links = await self._page.evaluate("""() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    links.push({
                        href: a.href,
                        text: a.textContent.trim().slice(0, 100),
                        tag: 'a',
                        is_spa_nav: a.hasAttribute('data-router-link') || (a.getAttribute('href') || '').startsWith('#')
                    });
                });
                document.querySelectorAll('[role="button"], button').forEach(b => {
                    if (b.onclick || b.getAttribute('data-action')) {
                        links.push({
                            href: b.getAttribute('data-href') || '',
                            text: b.textContent.trim().slice(0, 100),
                            tag: b.tagName.toLowerCase(),
                            is_spa_nav: true
                        });
                    }
                });
                return links;
            }""")
            filtered = [
                lnk for lnk in links
                if not self._is_logout_url(lnk.get("href", ""))
                and not self._url_excluded(lnk.get("href", ""))
                and not any(kw in (lnk.get("text", "").lower())
                            for kw in ("logout", "log out", "sign out", "signout", "disconnect"))
            ]
            return {"links": filtered}
        except Exception as e:
            return _error_dict(str(e))

    async def get_local_storage(self) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            local = await self._page.evaluate("() => Object.assign({}, localStorage)")
            session = await self._page.evaluate("() => Object.assign({}, sessionStorage)")
            return {"localStorage": local, "sessionStorage": session}
        except Exception as e:
            return _error_dict(str(e))

    async def execute_js(self, script: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            result = await self._page.evaluate(script)
            return {"result": str(result) if result is not None else None}
        except Exception as e:
            return {"error": str(e)}

    async def wait_for_spa_route(self, timeout: int = 5000) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            initial = self._page.url
            try:
                await self._page.wait_for_function(
                    "() => window.location.href !== arguments[0]",
                    arg=initial,
                    timeout=timeout,
                )
            except Exception:
                pass
            new_url = self._page.url
            return {"new_url": new_url, "changed": new_url != initial}
        except Exception as e:
            return {"error": str(e)}

    async def intercept_requests(self, url_pattern: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
        try:
            async def handler(route, request):
                await route.continue_()
                await self._log_request(request)

            await self._page.route(url_pattern, handler)
            self._intercept_pattern = url_pattern
            return {"success": True, "pattern": url_pattern, "captured": []}
        except Exception as e:
            return _error_dict(str(e))

    async def ws_connect(self, url: str, headers: dict | None = None) -> dict:
        url = self._resolve_url(url)
        if self._page:
            try:
                with self._page.expect_websocket(timeout=10000) as ws_info:
                    await self._page.evaluate("url => new WebSocket(url)", url)
                ws = await ws_info.value
                cid = str(uuid.uuid4())
                self._ws_connections[cid] = ws
                return {"connection_id": cid, "success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}
        if websockets:
            try:
                extra_headers = dict(headers) if headers else {}
                ws = await websockets.connect(url, extra_headers=extra_headers)
                cid = str(uuid.uuid4())
                self._ws_connections[cid] = ws
                return {"connection_id": cid, "success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"error": "No browser page and websockets library not available"}

    async def ws_send(self, connection_id: str, message: str) -> dict:
        ws = self._ws_connections.get(connection_id)
        if not ws:
            return {"error": f"Unknown connection: {connection_id}"}
        try:
            await ws.send(message)
            return {"success": True}
        except Exception as e:
            return {"error": str(e)}

    async def ws_receive(self, connection_id: str, timeout: int = 5000) -> dict:
        ws = self._ws_connections.get(connection_id)
        if not ws:
            return {"error": f"Unknown connection: {connection_id}"}
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=timeout / 1000)
            return {"message": msg, "type": "text"}
        except asyncio.TimeoutError:
            return {"error": "Timeout waiting for message"}
        except Exception as e:
            return {"error": str(e)}

    async def ws_inject(self, connection_id: str, payload: str) -> dict:
        ws = self._ws_connections.get(connection_id)
        if not ws:
            return {"error": f"Unknown connection: {connection_id}"}
        try:
            await ws.send(payload)
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
            except asyncio.TimeoutError:
                return {"response": None, "anomaly": False}
            anomaly = any(
                x in resp.lower()
                for x in ["error", "exception", "stack", "trace", "undefined"]
            )
            return {"response": _truncate(resp), "anomaly": anomaly}
        except Exception as e:
            return {"error": str(e)}

    async def ws_close(self, connection_id: str) -> dict:
        ws = self._ws_connections.pop(connection_id, None)
        if not ws:
            return {"error": f"Unknown connection: {connection_id}"}
        try:
            await ws.close()
            return {"success": True}
        except Exception as e:
            return {"error": str(e)}

    async def api_request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | None = None,
        auth_token: str | None = None,
    ) -> dict:
        url = self._resolve_url(url)
        if self._url_excluded(url):
            return {"error": f"EXCLUDED by user: {url}", "skipped": True}
        if not self._url_in_scope(url):
            return {"error": f"URL out of scope (not in target domain): {url}", "skipped": True}
        try:
            hdrs = dict(headers) if headers else {}
            if auth_token:
                hdrs.setdefault("Authorization", f"Bearer {auth_token}")
            merged_hdrs = dict(self._http_client.headers)
            merged_hdrs.update(hdrs)
            start = time.perf_counter()
            resp = await self._http_client.request(
                method=method.upper(),
                url=url,
                headers=hdrs,
                content=body,
            )
            elapsed = (time.perf_counter() - start) * 1000
            resp_body = resp.text
            result = {
                "status": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()
                            if k.lower() in ("content-type", "content-length", "set-cookie")
                            or k.lower().startswith("x-")},
                "body_snippet": _truncate(resp_body),
                "timing_ms": round(elapsed, 2),
                "http_exchange": _build_http_exchange(
                    method=method,
                    url=url,
                    request_headers=merged_hdrs,
                    request_body=body,
                    status_code=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp_body,
                ),
            }
            signals = _extract_vuln_signals(resp_body, resp.status_code, payload=body or "")
            if signals:
                result.update(signals)
            return result
        except Exception as e:
            return _error_dict(str(e))

    async def api_request_raw(self, raw_request: str) -> dict:
        try:
            lines = raw_request.strip().split("\n")
            if not lines:
                return {"error": "Empty request"}
            first = lines[0].split()
            if len(first) < 2:
                return {"error": "Invalid request line"}
            method, path_or_url = first[0], first[1]
            idx = 1
            headers = {}
            while idx < len(lines) and lines[idx].strip():
                if ":" in lines[idx]:
                    k, v = lines[idx].split(":", 1)
                    headers[k.strip()] = v.strip()
                idx += 1
            idx += 1
            body = "\n".join(lines[idx:]) if idx < len(lines) else None
            if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
                url = path_or_url
            else:
                host = headers.get("Host", "").strip()
                if not host:
                    return {"error": "No Host header"}
                scheme = "https" if "https" in raw_request[:80].lower() else "http"
                path = path_or_url if path_or_url.startswith("/") else "/" + path_or_url
                url = f"{scheme}://{host}{path}"
            if self._url_excluded(url):
                return {"error": f"EXCLUDED by user: {url}", "skipped": True}
            if not self._url_in_scope(url):
                return {"error": f"URL out of scope (not in target domain): {url}", "skipped": True}
            return await self.api_request(method=method, url=url, headers=headers, body=body)
        except Exception as e:
            return _error_dict(str(e))

    async def fuzz_parameter(
        self,
        endpoint: str,
        method: str,
        param_name: str,
        payloads: list[str],
        param_location: str = "query",
        baseline_status: int = 200,
        original_body: str | None = None,
        headers: dict | None = None,
        baseline_value: str | None = None,
    ) -> dict:
        endpoint = self._resolve_url(endpoint)
        if self._url_excluded(endpoint):
            return {"error": f"EXCLUDED by user: {endpoint}", "skipped": True}
        if not self._url_in_scope(endpoint):
            return {"error": f"URL out of scope (not in target domain): {endpoint}", "skipped": True}
        if self._already_tested(method, endpoint, param_name):
            return {"skipped": True, "reason": "already tested by another worker",
                    "endpoint": endpoint, "param": param_name}
        results = []
        hdrs = dict(headers) if headers else {}
        base_req_hdrs = dict(self._http_client.headers)
        base_req_hdrs.update(hdrs)
        for payload in payloads:
            effective_payload = f"{baseline_value}{payload}" if baseline_value else payload
            try:
                start = time.perf_counter()
                actual_url = endpoint
                actual_body: str | None = None
                actual_hdrs = dict(base_req_hdrs)
                if param_location == "query":
                    parsed = urlparse(endpoint)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param_name] = [effective_payload]
                    new_query = urlencode(qs, doseq=True)
                    actual_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    resp = await self._http_client.request(method.upper(), actual_url, headers=hdrs or None)
                elif param_location == "header":
                    fuzz_hdrs = dict(hdrs)
                    fuzz_hdrs[param_name] = effective_payload
                    actual_hdrs.update(fuzz_hdrs)
                    resp = await self._http_client.request(method.upper(), endpoint, headers=fuzz_hdrs)
                elif param_location == "path":
                    actual_url = endpoint.replace(f"{{{param_name}}}", effective_payload)
                    resp = await self._http_client.request(method.upper(), actual_url, headers=hdrs or None)
                else:
                    mutated = _mutate_json_field(original_body, param_name, effective_payload)
                    actual_body = mutated
                    content_hdrs = dict(hdrs)
                    content_hdrs.setdefault("Content-Type", "application/json")
                    actual_hdrs.update(content_hdrs)
                    resp = await self._http_client.request(
                        method.upper(), endpoint, headers=content_hdrs, content=mutated,
                    )
                elapsed_ms = (time.perf_counter() - start) * 1000
                body = resp.text
                body_lower = body.lower()
                status_diff = resp.status_code != baseline_status
                matched_indicators = [ind for ind in _ERROR_INDICATORS if ind in body_lower]
                has_errors = bool(matched_indicators)
                reflected = payload in body
                waf_likely = _detect_waf_block(resp.status_code, body)
                anomaly = (status_diff or has_errors or reflected or elapsed_ms > 3000) and not waf_likely
                result_entry = {
                    "payload": payload,
                    "status": resp.status_code,
                    "body_snippet": _truncate(body),
                    "anomaly": anomaly,
                    "reflected": reflected,
                    "waf_likely": waf_likely,
                    "timing_ms": round(elapsed_ms, 1),
                    "http_exchange": _build_http_exchange(
                        method=method,
                        url=actual_url,
                        request_headers=actual_hdrs,
                        request_body=actual_body,
                        status_code=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=body,
                    ),
                }
                if matched_indicators:
                    result_entry["error_indicators"] = matched_indicators[:5]
                signals = _extract_vuln_signals(body, resp.status_code, payload=effective_payload)
                if signals.get("error_title"):
                    result_entry["error_title"] = signals["error_title"]
                if signals.get("error_message"):
                    result_entry["error_message"] = signals["error_message"]
                results.append(result_entry)
            except Exception as e:
                results.append({
                    "payload": payload,
                    "status": None,
                    "body_snippet": str(e),
                    "anomaly": True,
                    "reflected": False,
                    "timing_ms": 0,
                })
        anomalous = [r for r in results if r.get("anomaly")]
        waf_blocked = [r for r in results if r.get("waf_likely")]
        summary: dict = {
            "endpoint": endpoint, "param": param_name, "location": param_location,
            "total_tested": len(results), "anomalies_found": len(anomalous),
            "waf_blocked": len(waf_blocked),
            "results": results,
        }
        if anomalous:
            highlights = []
            vulns_detected = []
            for r in anomalous:
                actual = f"{baseline_value}{r['payload']}" if baseline_value else r['payload']
                h = f"payload='{actual}' status={r['status']} timing={r.get('timing_ms',0)}ms"
                err_text = (r.get("error_title") or r.get("error_message") or "").lower()
                body_low = r.get("body_snippet", "").lower()
                if any(p in err_text or p in body_low for p in _SQL_ERROR_PATTERNS):
                    vuln = {
                        "type": "SQL Injection",
                        "param": param_name,
                        "payload": actual,
                        "status": r["status"],
                        "proof": r.get("error_title") or r.get("error_message") or
                                 next((ind for ind in r.get("error_indicators", [])
                                       if ind in ("sqlite", "sql", "syntax", "mysql")), "SQL error in response"),
                    }
                    vulns_detected.append(vuln)
                    h += f" *** SQL ERROR DETECTED: {vuln['proof']} ***"
                elif r.get("reflected") and any(p in r['payload'].lower() for p in _XSS_INDICATORS):
                    vulns_detected.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "param": param_name, "payload": actual,
                        "status": r["status"], "proof": "Payload reflected unescaped in response",
                    })
                    h += " *** XSS: PAYLOAD REFLECTED ***"
                elif any(p in body_low for p in _CMDI_INDICATORS):
                    vulns_detected.append({
                        "type": "Command Injection",
                        "param": param_name, "payload": actual,
                        "status": r["status"], "proof": "OS command output in response",
                    })
                    h += " *** CMDI: OS OUTPUT DETECTED ***"
                elif r.get("timing_ms", 0) > 3000:
                    h += " *** SLOW RESPONSE — possible time-based blind injection ***"
                elif r.get("error_title"):
                    h += f" error='{r['error_title']}'"
                elif r.get("error_indicators"):
                    h += f" indicators={r['error_indicators']}"
                highlights.append(h)
            summary["anomaly_summary"] = " | ".join(highlights)
            if vulns_detected:
                summary["VULNERABILITIES_DETECTED"] = vulns_detected
                summary["ACTION_REQUIRED"] = (
                    "CONFIRMED vulnerabilities found! You MUST report each as a finding JSON with "
                    "title, severity, owasp_category, url, parameter, payload, evidence, confidence, remediation. "
                    "Use the exact payload and proof from VULNERABILITIES_DETECTED above."
                )
        return summary

    async def replay_with_modification(self, request: dict, modifications: dict) -> dict:
        try:
            orig = dict(request)
            method = orig.get("method", "GET")
            url = self._resolve_url(orig.get("url", ""))
            if self._url_excluded(url):
                return {"error": f"EXCLUDED by user: {url}", "skipped": True}
            if not self._url_in_scope(url):
                return {"error": f"URL out of scope: {url}", "skipped": True}
            headers = dict(orig.get("headers", {}))
            body = orig.get("body")

            for k, v in modifications.items():
                if k == "url":
                    url = str(v)
                elif k == "method":
                    method = str(v)
                elif k == "headers":
                    headers.update(v)
                elif k == "body":
                    body = str(v) if v is not None else None

            start = time.perf_counter()
            orig_resp = await self._http_client.request(method, url, headers=headers, content=body)
            elapsed = (time.perf_counter() - start) * 1000

            result = {
                "original_status": orig.get("status"),
                "modified_status": orig_resp.status_code,
                "diff_summary": f"Status {orig.get('status')} -> {orig_resp.status_code}",
                "body_snippet": _truncate(orig_resp.text),
                "timing_ms": round(elapsed, 2),
            }
            signals = _extract_vuln_signals(orig_resp.text, orig_resp.status_code, payload=body or "")
            if signals:
                result.update(signals)
            return result
        except Exception as e:
            return _error_dict(str(e))

    async def get_api_endpoints(self) -> dict:
        try:
            return {"summary": self._registry.summary()}
        except Exception as e:
            return _error_dict(str(e))

    async def test_auth_bypass(
        self,
        endpoint: str,
        methods: list[str] | None = None,
    ) -> dict:
        endpoint = self._resolve_url(endpoint)
        if self._url_excluded(endpoint):
            return {"error": f"EXCLUDED by user: {endpoint}", "skipped": True}
        if not self._url_in_scope(endpoint):
            return {"error": f"URL out of scope: {endpoint}", "skipped": True}
        methods = methods or ["GET", "POST", "PUT", "DELETE"]
        results = []
        for method in methods:
            try:
                resp = await self._http_client.request(method.upper(), endpoint)
                st = resp.status_code
                accessible = st < 400
                entry = {
                    "method": method,
                    "status": st,
                    "accessible": accessible,
                }
                if st >= 500:
                    entry["finding"] = (
                        f"ERROR_HANDLING: {method} {endpoint} returned HTTP {st} without auth. "
                        f"Expected 401/403 but got a server error."
                    )
                    entry["server_error"] = True
                results.append(entry)
            except Exception as e:
                results.append({"method": method, "status": None, "accessible": False, "error": str(e)})
        return {"results": results}

    async def test_method_override(self, endpoint: str) -> dict:
        endpoint = self._resolve_url(endpoint)
        if self._url_excluded(endpoint):
            return {"error": f"EXCLUDED by user: {endpoint}", "skipped": True}
        if not self._url_in_scope(endpoint):
            return {"error": f"URL out of scope: {endpoint}", "skipped": True}
        methods = ["PUT", "DELETE", "PATCH", "OPTIONS"]
        results = []
        for method in methods:
            try:
                resp = await self._http_client.request(method.upper(), endpoint)
                results.append({
                    "method": method,
                    "status": resp.status_code,
                    "body_snippet": _truncate(resp.text),
                })
            except Exception as e:
                results.append({"method": method, "status": None, "error": str(e)})
        return {"results": results}

    async def test_token_security(
        self, endpoint: str, token: str, method: str = "GET",
        body: str | None = None, headers: dict | None = None,
    ) -> dict:
        """Test bearer token / JWT security."""
        endpoint = self._resolve_url(endpoint)
        if self._url_excluded(endpoint):
            return {"error": f"EXCLUDED by user: {endpoint}", "skipped": True}
        if not self._url_in_scope(endpoint):
            return {"error": f"URL out of scope: {endpoint}", "skipped": True}
        results: dict[str, Any] = {"token_analysis": {}, "tests": []}
        hdrs = dict(headers) if headers else {}
        token_parts = token.split(".")
        is_jwt = len(token_parts) == 3
        decoded_header = decoded_payload = None
        if is_jwt:
            try:
                def _b64d(s):
                    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))
                decoded_header = json.loads(_b64d(token_parts[0]))
                decoded_payload = json.loads(_b64d(token_parts[1]))
                results["token_analysis"] = {
                    "type": "JWT", "algorithm": decoded_header.get("alg", "unknown"),
                    "payload_keys": list(decoded_payload.keys()),
                    "payload_preview": {k: str(v)[:50] for k, v in list(decoded_payload.items())[:10]},
                }
            except Exception as e:
                results["token_analysis"] = {"type": "JWT", "decode_error": str(e)}
        else:
            results["token_analysis"] = {"type": "opaque", "length": len(token)}

        async def _test(name, auth_val):
            h = dict(hdrs)
            if auth_val is not None:
                h["Authorization"] = auth_val
            try:
                resp = await self._http_client.request(method.upper(), endpoint, headers=h, content=body)
                return {"test": name, "status": resp.status_code, "body_snippet": _truncate(resp.text, 200)}
            except Exception as e:
                return {"test": name, "error": str(e)}

        baseline = await _test("valid_token", f"Bearer {token}")
        results["tests"].append(baseline)
        baseline_status = baseline.get("status", 999)

        for name, auth in [
            ("no_token", None),
            ("empty_bearer", "Bearer "),
            ("tampered_token", f"Bearer {token[:-1] + ('A' if token[-1] != 'A' else 'B')}"),
            ("invalid_bearer", "Bearer INVALID_TOKEN_12345"),
            ("malformed_auth", "NotBearer xyz"),
        ]:
            r = await _test(name, auth)
            st = r.get("status", 999)
            bypassed = st < 400
            r["bypassed"] = bypassed
            if bypassed and name != "valid_token":
                r["finding"] = f"AUTH_BYPASS: {name} accepted (status {st})"
            elif st >= 500:
                r["finding"] = (
                    f"ERROR_HANDLING: Server returned HTTP {st} for {name.replace('_', ' ')}. "
                    f"Expected 401/403 but got a server error — indicates unhandled exception "
                    f"in token validation logic."
                )
                r["server_error"] = True
            results["tests"].append(r)

        if is_jwt and decoded_header and decoded_payload:
            none_hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            for name, tok in [
                ("jwt_alg_none", f"{none_hdr}.{token_parts[1]}."),
                ("jwt_stripped_sig", f"{token_parts[0]}.{token_parts[1]}."),
            ]:
                r = await _test(name, f"Bearer {tok}")
                accepted = r.get("status", 999) < 400
                r["accepted"] = accepted
                if accepted:
                    r["finding"] = f"CRITICAL: {name} bypass accepted"
                results["tests"].append(r)

            id_fields = [k for k in decoded_payload if k.lower() in ("sub", "user_id", "uid", "user", "email", "id")]
            if id_fields:
                tampered = dict(decoded_payload)
                for f in id_fields:
                    v = tampered[f]
                    tampered[f] = (v + "_tampered") if isinstance(v, str) else (v + 1 if isinstance(v, int) else v)
                tp = base64.urlsafe_b64encode(json.dumps(tampered).encode()).rstrip(b"=").decode()
                r = await _test("jwt_idor_tamper", f"Bearer {token_parts[0]}.{tp}.{token_parts[2]}")
                accepted = r.get("status", 999) < 400
                r.update(accepted=accepted, modified_fields=id_fields)
                if accepted:
                    r["finding"] = f"IDOR: tampered JWT accepted ({id_fields})"
                results["tests"].append(r)

        results["summary"] = f"{sum(1 for t in results['tests'] if t.get('finding'))} issues in {len(results['tests'])} tests"
        return results


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "navigate",
            "description": "Navigate to a URL and wait for network idle. Returns page title, status, URL, and SPA detection.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to navigate to"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "click",
            "description": "Click an element by selector, wait for network idle. Returns success, new URL, triggered requests.",
            "parameters": {
                "type": "object",
                "properties": {"selector": {"type": "string", "description": "CSS selector for element to click"}},
                "required": ["selector"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fill",
            "description": "Fill a form field with a value.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for input"},
                    "value": {"type": "string", "description": "Value to fill"},
                },
                "required": ["selector", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_form",
            "description": "Submit a form by selector. Returns status and redirect URL.",
            "parameters": {
                "type": "object",
                "properties": {"selector": {"type": "string", "description": "CSS selector for form"}},
                "required": ["selector"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inject_payload",
            "description": "Fill field with payload, submit parent form. Returns status, body snippet, errors, reflected flag.",
            "parameters": {
                "type": "object",
                "properties": {
                    "selector": {"type": "string", "description": "CSS selector for input"},
                    "payload": {"type": "string", "description": "Attack payload to inject"},
                },
                "required": ["selector", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "screenshot",
            "description": "Take a screenshot of the current page. Returns base64-encoded image.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_page_source",
            "description": "Get rendered HTML (first 4000 chars).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cookies",
            "description": "List all cookies with name, value, domain, secure, httpOnly, sameSite.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_log",
            "description": "Drain and return intercepted requests (url, method, status, request_body, response_snippet).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_forms",
            "description": "Extract all forms from DOM: action, method, inputs (name, type, value).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_links",
            "description": "Extract links and clickable elements: href, text, tag, is_spa_nav.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_local_storage",
            "description": "Read localStorage and sessionStorage.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_js",
            "description": "Run JavaScript in page context. Returns result.",
            "parameters": {
                "type": "object",
                "properties": {"script": {"type": "string", "description": "JavaScript to execute"}},
                "required": ["script"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "wait_for_spa_route",
            "description": "Wait for SPA URL/route change. Returns new_url and changed flag.",
            "parameters": {
                "type": "object",
                "properties": {"timeout": {"type": "integer", "description": "Timeout in ms", "default": 5000}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "intercept_requests",
            "description": "Set up request interception for URL pattern. Returns captured requests.",
            "parameters": {
                "type": "object",
                "properties": {"url_pattern": {"type": "string", "description": "Glob pattern for URLs to intercept"}},
                "required": ["url_pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ws_connect",
            "description": "Connect to WebSocket URL. Returns connection_id and success.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "WebSocket URL"},
                    "headers": {"type": "object", "description": "Optional headers"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ws_send",
            "description": "Send message to WebSocket connection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "connection_id": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["connection_id", "message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ws_receive",
            "description": "Receive next message from WebSocket.",
            "parameters": {
                "type": "object",
                "properties": {
                    "connection_id": {"type": "string"},
                    "timeout": {"type": "integer", "default": 5000},
                },
                "required": ["connection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ws_inject",
            "description": "Send payload via WebSocket, wait for response, check for anomalies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "connection_id": {"type": "string"},
                    "payload": {"type": "string"},
                },
                "required": ["connection_id", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ws_close",
            "description": "Close WebSocket connection.",
            "parameters": {
                "type": "object",
                "properties": {"connection_id": {"type": "string"}},
                "required": ["connection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "api_request",
            "description": "Send HTTP request. Returns status, headers, body snippet, timing_ms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {"type": "object"},
                    "body": {"type": "string"},
                    "auth_token": {"type": "string"},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "api_request_raw",
            "description": "Parse and send raw HTTP request string.",
            "parameters": {
                "type": "object",
                "properties": {"raw_request": {"type": "string"}},
                "required": ["raw_request"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fuzz_parameter",
            "description": "Fuzz a single parameter with payload list. Supports query, body (JSON), header, and path. "
                           "For body: set param_location='body', provide original_body JSON, use dot notation for nested fields. "
                           "IMPORTANT: Set baseline_value to a valid value (e.g. 'test') so payloads are APPENDED to it. "
                           "This catches injection in SQL LIKE clauses where bare payloads may not trigger errors.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "param_name": {"type": "string", "description": "Param name (dot notation for nested JSON: user.email)"},
                    "payloads": {"type": "array", "items": {"type": "string"}},
                    "param_location": {"type": "string", "enum": ["query", "body", "header", "path"]},
                    "baseline_status": {"type": "integer", "default": 200},
                    "original_body": {"type": "string", "description": "Full original JSON body (required for body fuzzing)"},
                    "headers": {"type": "object", "description": "Request headers"},
                    "baseline_value": {"type": "string", "description": "Normal valid value for the param. Payloads are APPENDED to this. E.g. 'test' means q=test' for SQLi. ALWAYS set this for injection testing."},
                },
                "required": ["endpoint", "method", "param_name", "payloads"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "replay_with_modification",
            "description": "Replay request with modifications. Returns original_status, modified_status, diff_summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {"type": "object", "description": "Original request dict"},
                    "modifications": {"type": "object", "description": "Modifications to apply"},
                },
                "required": ["request", "modifications"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_api_endpoints",
            "description": "Return endpoint registry summary.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_auth_bypass",
            "description": "Try endpoint without auth. Returns results: method, status, accessible.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string"},
                    "methods": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["endpoint"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_method_override",
            "description": "Try PUT/DELETE/PATCH/OPTIONS on endpoint.",
            "parameters": {
                "type": "object",
                "properties": {"endpoint": {"type": "string"}},
                "required": ["endpoint"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_token_security",
            "description": "Test bearer token/JWT security: decode, alg=none, strip signature, tamper identity (IDOR), empty/no token.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "API endpoint to test"},
                    "token": {"type": "string", "description": "Bearer token or JWT"},
                    "method": {"type": "string", "description": "HTTP method (default GET)"},
                    "body": {"type": "string", "description": "Request body for POST/PUT"},
                    "headers": {"type": "object", "description": "Additional headers"},
                },
                "required": ["endpoint", "token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_so_far",
            "description": "Retrieve all findings discovered in prior phases. Use to review what has been found and identify chaining opportunities.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "chain_exploit",
            "description": (
                "Execute a multi-step exploit chain. Declare the chain name and an ordered list of steps. "
                "Each step specifies a tool and its args. Steps run sequentially; if any step fails the chain "
                "stops and partial results are returned. Use this when you identify 2+ vulnerabilities that "
                "combine for higher impact (e.g. XSS + steal session cookie, SSRF + read cloud metadata, "
                "IDOR + no rate limit for mass exfiltration). Report the chain as a single Critical/High finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "chain_name": {
                        "type": "string",
                        "description": "Descriptive name for the chain (e.g. 'XSS to Session Hijack')",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Primary target URL for the chain",
                    },
                    "steps": {
                        "type": "array",
                        "description": "Ordered list of exploit steps",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": {
                                    "type": "string",
                                    "description": "Tool name to call (e.g. api_request, navigate, inject_payload, fuzz_parameter)",
                                },
                                "args": {
                                    "type": "object",
                                    "description": "Arguments to pass to the tool",
                                },
                                "description": {
                                    "type": "string",
                                    "description": "What this step does in the chain",
                                },
                                "expect": {
                                    "type": "string",
                                    "description": "Expected indicator of success (status code or string in body)",
                                },
                            },
                            "required": ["tool", "args", "description"],
                        },
                    },
                },
                "required": ["chain_name", "steps"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": (
                "Report a security finding/vulnerability. Call this whenever you discover a vulnerability. "
                "Provide a clear title, severity, description with evidence, and the affected URL."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short descriptive title (e.g. 'Reflected XSS in search parameter')",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["Critical", "High", "Medium", "Low", "Info"],
                        "description": "Severity rating",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description including what was found, how to reproduce, and impact",
                    },
                    "url": {
                        "type": "string",
                        "description": "The affected URL or endpoint",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Raw evidence: HTTP request/response snippets, error messages, payload that triggered it",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Vulnerability class (e.g. 'XSS', 'SQLi', 'SSRF', 'IDOR', 'CSRF')",
                    },
                },
                "required": ["title", "severity", "description", "url"],
            },
        },
    },
]
