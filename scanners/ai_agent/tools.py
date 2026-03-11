from __future__ import annotations

import asyncio
import base64
import json
import logging
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

BODY_SNIPPET_LEN = 500
HTML_SNIPPET_LEN = 4000


def _truncate(s: str | None, max_len: int = BODY_SNIPPET_LEN) -> str:
    if s is None:
        return ""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def _error_dict(msg: str) -> dict:
    logger.error(msg)
    return {"error": msg}


class ScanTools:
    def __init__(
        self,
        page: Page | None,
        http_client: httpx.AsyncClient,
        registry: EndpointRegistry,
        auth_session: AuthSession | None = None,
    ):
        self._page = page
        self._http_client = http_client
        self._registry = registry
        self._auth_session = auth_session
        self._network_log: list[dict] = []
        self._ws_connections: dict[str, Any] = {}
        self._intercept_pattern: str | None = None
        if self._page:
            self._page.on("requestfinished", lambda req: asyncio.ensure_future(self._log_request(req)))

    async def execute(self, function_name: str, arguments: str) -> dict:
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
        }

        handler = handlers.get(function_name)
        if not handler:
            return {"error": f"Unknown tool: {function_name}"}

        try:
            result = await handler(**args)
            return result
        except Exception as e:
            return _error_dict(str(e))

    def _require_page(self) -> bool:
        return self._page is not None

    async def _log_request(self, request: Any) -> None:
        try:
            url = request.url
            method = request.method
            response = await request.response()
            status = response.status if response else None
            req_body = ""
            try:
                req_body = request.post_data or ""
            except Exception:
                pass
            resp_body = ""
            try:
                if response:
                    resp_body = await response.text()
            except Exception:
                pass
            self._network_log.append({
                "url": url,
                "method": method,
                "status": status,
                "request_body": _truncate(req_body, 1000),
                "response_snippet": _truncate(resp_body),
            })
        except Exception as e:
            logger.debug("Failed to log request: %s", e)

    async def navigate(self, url: str) -> dict:
        if not self._require_page():
            return {"error": "No browser page (API-only mode)"}
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
        try:
            before_url = self._page.url
            before_count = len(self._network_log)

            await self._page.click(selector, timeout=10000)
            await self._page.wait_for_load_state("networkidle", timeout=5000)

            new_url = self._page.url
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
            try:
                form = loc.locator("xpath=ancestor::form").first
                await form.evaluate("el => el.submit()")
            except Exception:
                await loc.press("Enter")
            await self._page.wait_for_load_state("networkidle", timeout=10000)

            content = await self._page.content()
            body_snippet = _truncate(content)
            reflected = payload in content

            errors = []
            if "error" in content.lower() or "exception" in content.lower():
                errors.append("Error/exception text in response")
            if "sql" in content.lower() and "syntax" in content.lower():
                errors.append("Possible SQL error in response")

            return {
                "status": 200,
                "body_snippet": body_snippet,
                "errors": errors,
                "reflected": reflected,
            }
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
                document.querySelectorAll('form').forEach(f => {
                    const inputs = [];
                    f.querySelectorAll('input, textarea, select').forEach(inp => {
                        inputs.push({
                            name: inp.name || inp.id || '',
                            type: inp.type || inp.tagName.toLowerCase(),
                            value: inp.value || ''
                        });
                    });
                    forms.push({
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: inputs
                    });
                });
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
            return {"links": links}
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
        try:
            hdrs = dict(headers) if headers else {}
            if auth_token:
                hdrs.setdefault("Authorization", f"Bearer {auth_token}")
            start = time.perf_counter()
            resp = await self._http_client.request(
                method=method.upper(),
                url=url,
                headers=hdrs,
                content=body,
            )
            elapsed = (time.perf_counter() - start) * 1000
            resp_body = resp.text
            selected_headers = dict(resp.headers)
            for k in list(selected_headers):
                if k.lower() not in ("content-type", "content-length", "x-", "set-cookie"):
                    del selected_headers[k]
            return {
                "status": resp.status_code,
                "headers": selected_headers,
                "body_snippet": _truncate(resp_body),
                "timing_ms": round(elapsed, 2),
            }
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
    ) -> dict:
        results = []
        error_indicators = ["error", "exception", "sql", "syntax", "undefined", "stack trace"]
        for payload in payloads:
            try:
                if param_location == "query":
                    parsed = urlparse(endpoint)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param_name] = [payload]
                    new_query = urlencode(qs, doseq=True)
                    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    resp = await self._http_client.request(method.upper(), url)
                else:
                    resp = await self._http_client.request(
                        method.upper(),
                        endpoint,
                        json={param_name: payload},
                    )
                body = resp.text
                status_diff = resp.status_code != baseline_status
                has_errors = any(ind in body.lower() for ind in error_indicators)
                anomaly = status_diff or has_errors
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "body_snippet": _truncate(body),
                    "anomaly": anomaly,
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "status": None,
                    "body_snippet": str(e),
                    "anomaly": True,
                })
        return {"results": results}

    async def replay_with_modification(self, request: dict, modifications: dict) -> dict:
        try:
            orig = dict(request)
            method = orig.get("method", "GET")
            url = orig.get("url", "")
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

            return {
                "original_status": orig.get("status"),
                "modified_status": orig_resp.status_code,
                "diff_summary": f"Status {orig.get('status')} -> {orig_resp.status_code}",
                "body_snippet": _truncate(orig_resp.text),
                "timing_ms": round(elapsed, 2),
            }
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
        methods = methods or ["GET", "POST", "PUT", "DELETE"]
        results = []
        for method in methods:
            try:
                resp = await self._http_client.request(method.upper(), endpoint)
                accessible = resp.status_code < 400
                results.append({
                    "method": method,
                    "status": resp.status_code,
                    "accessible": accessible,
                })
            except Exception as e:
                results.append({"method": method, "status": None, "accessible": False, "error": str(e)})
        return {"results": results}

    async def test_method_override(self, endpoint: str) -> dict:
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
            "description": "Fuzz a parameter with payload list. Returns results with payload, status, body_snippet, anomaly.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string"},
                    "method": {"type": "string"},
                    "param_name": {"type": "string"},
                    "payloads": {"type": "array", "items": {"type": "string"}},
                    "param_location": {"type": "string", "default": "query"},
                    "baseline_status": {"type": "integer", "default": 200},
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
]
