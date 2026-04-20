"""Structured scan state that persists outside the LLM context window.

Tracks discovered endpoints, parameters, technology stack, and tested
combinations across all phases. Injected as a compact summary at the
start of each phase so the LLM never loses track of the attack surface.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class EndpointInfo:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    param_locations: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    auth_required: bool = False
    status_codes_seen: set[int] = field(default_factory=set)
    tested_by_phases: set[str] = field(default_factory=set)


class ScanState:
    """Accumulates structured scan intelligence across phases."""

    def __init__(self):
        self._lock = Lock()
        self._endpoints: dict[str, EndpointInfo] = {}
        self._tech_stack: dict[str, str] = {}
        self._tested_combos: set[tuple[str, str, str]] = set()
        self._interesting_responses: list[dict] = []
        self._forms: list[dict] = []
        self._cookies_seen: list[dict] = []
        self._tokens_seen: list[str] = []

    def _endpoint_key(self, url: str, method: str) -> str:
        return f"{method.upper()}:{url.split('?')[0].rstrip('/')}"

    def register_endpoint(self, url: str, method: str = "GET",
                          params: list[str] | None = None,
                          param_locations: dict[str, str] | None = None,
                          content_type: str = "",
                          auth_required: bool = False,
                          status_code: int | None = None) -> None:
        key = self._endpoint_key(url, method)
        with self._lock:
            if key not in self._endpoints:
                self._endpoints[key] = EndpointInfo(
                    url=url.split("?")[0].rstrip("/"),
                    method=method.upper(),
                )
            ep = self._endpoints[key]
            if params:
                for p in params:
                    if p not in ep.params:
                        ep.params.append(p)
            if param_locations:
                ep.param_locations.update(param_locations)
            if content_type:
                ep.content_type = content_type
            if auth_required:
                ep.auth_required = True
            if status_code is not None:
                ep.status_codes_seen.add(status_code)

    def mark_tested(self, url: str, param: str, vuln_class: str, phase_id: str) -> None:
        key = self._endpoint_key(url, "")
        combo = (key, param, vuln_class)
        with self._lock:
            self._tested_combos.add(combo)
            base_key = self._endpoint_key(url, "GET")
            for k, ep in self._endpoints.items():
                if k.endswith(base_key.split(":", 1)[-1]):
                    ep.tested_by_phases.add(phase_id)

    def register_tech(self, key: str, value: str) -> None:
        with self._lock:
            self._tech_stack[key] = value

    def register_form(self, form: dict) -> None:
        with self._lock:
            if len(self._forms) < 100:
                self._forms.append(form)

    def register_interesting_response(self, url: str, status: int, indicator: str) -> None:
        with self._lock:
            if len(self._interesting_responses) < 50:
                self._interesting_responses.append({
                    "url": url, "status": status, "indicator": indicator,
                    "time": time.time(),
                })

    def get_untested_endpoints(self, vuln_class: str) -> list[EndpointInfo]:
        with self._lock:
            untested = []
            for key, ep in self._endpoints.items():
                for param in ep.params:
                    if (key, param, vuln_class) not in self._tested_combos:
                        untested.append(ep)
                        break
            return untested

    def build_phase_context(self, phase_id: str) -> str:
        """Build a compact context string for injection into a phase prompt."""
        with self._lock:
            lines: list[str] = []

            if self._tech_stack:
                tech = ", ".join(f"{k}={v}" for k, v in sorted(self._tech_stack.items()))
                lines.append(f"## Technology Stack\n{tech}")

            if self._endpoints:
                lines.append(f"\n## Discovered Endpoints ({len(self._endpoints)} total)")
                for key, ep in sorted(self._endpoints.items()):
                    params_str = ", ".join(ep.params[:10]) if ep.params else "(no params)"
                    status_str = ",".join(str(s) for s in sorted(ep.status_codes_seen)[:5])
                    tested = "tested" if ep.tested_by_phases else "UNTESTED"
                    line = f"  {ep.method} {ep.url} — params: [{params_str}] status: [{status_str}] [{tested}]"
                    if ep.auth_required:
                        line += " [auth]"
                    if ep.content_type:
                        line += f" [{ep.content_type}]"
                    lines.append(line)
                    if len(lines) > 60:
                        lines.append(f"  ... and {len(self._endpoints) - 60} more endpoints")
                        break

            if self._forms:
                lines.append(f"\n## Forms ({len(self._forms)})")
                for f in self._forms[:10]:
                    action = f.get("action", "?")
                    method = f.get("method", "?")
                    inputs = [i.get("name", "?") for i in f.get("inputs", []) if i.get("name")]
                    lines.append(f"  {method} {action} — inputs: {inputs[:8]}")

            if self._interesting_responses:
                lines.append(f"\n## Interesting Responses ({len(self._interesting_responses)})")
                for r in self._interesting_responses[:10]:
                    lines.append(f"  {r['url']} → {r['status']} ({r['indicator']})")

            untested_sqli = self.get_untested_endpoints("sqli")
            untested_xss = self.get_untested_endpoints("xss")
            if untested_sqli or untested_xss:
                lines.append("\n## Untested Attack Surface")
                if untested_sqli:
                    urls = [ep.url for ep in untested_sqli[:5]]
                    lines.append(f"  SQLi untested: {len(untested_sqli)} endpoints — {urls}")
                if untested_xss:
                    urls = [ep.url for ep in untested_xss[:5]]
                    lines.append(f"  XSS untested: {len(untested_xss)} endpoints — {urls}")

            if not lines:
                return ""
            return "\n".join(lines)

    def update_from_tool_call(self, tool_name: str, args: dict, result: dict,
                              phase_id: str) -> None:
        """Auto-extract state from tool call results."""
        url = args.get("url") or args.get("endpoint") or ""
        method = args.get("method", "GET")
        status = result.get("status") or result.get("status_code")

        if url and isinstance(status, int):
            params = []
            if "param_name" in args:
                params.append(args["param_name"])
                loc = args.get("param_location", "query")
                self.register_endpoint(url, method, params=params,
                                       param_locations={args["param_name"]: loc},
                                       status_code=status)
            else:
                self.register_endpoint(url, method, status_code=status)

        if tool_name == "fuzz_parameter":
            param = args.get("param_name", "")
            if param and url:
                self.mark_tested(url, param, "injection", phase_id)

        if tool_name == "get_forms":
            for form in (result.get("forms") or []):
                self.register_form(form)
                action = form.get("action", "")
                fm = form.get("method", "GET")
                inputs = [i.get("name", "") for i in form.get("inputs", []) if i.get("name")]
                if action:
                    self.register_endpoint(action, fm, params=inputs)

        if tool_name == "navigate":
            if result.get("is_spa"):
                self.register_tech("framework_type", "SPA")
            if result.get("title"):
                self.register_tech("page_title", result["title"][:100])

        if tool_name in ("api_request", "fuzz_parameter"):
            if isinstance(result.get("error_indicators"), list) and result["error_indicators"]:
                self.register_interesting_response(
                    url, status or 0,
                    f"errors: {result['error_indicators'][:3]}")

        if tool_name == "get_cookies":
            for c in (result.get("cookies") or []):
                self.register_tech(f"cookie:{c.get('name','?')}", "present")
