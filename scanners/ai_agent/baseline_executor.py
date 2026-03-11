"""Baseline Executor — runs API happy path before LLM fuzzing.

Executes imported API endpoints in order, captures baseline responses,
and evaluates Postman test scripts to chain variables between requests.
When no test scripts exist, auto-chains UUID/token values from responses
into subsequent requests. No LLM is used; this is purely deterministic.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import httpx

from .api_import import APIEndpoint, _resolve_vars

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_TOKEN_KEYS = frozenset({
    "token", "id", "uuid", "key",
    "access_token", "refresh_token", "session_id", "sessionid",
    "resource_id", "resourceid", "auth_token", "api_key",
})
_ID_SUFFIXES = ("_id", "Id", "_token", "Token", "_key", "_uuid", "Uuid")


@dataclass
class BaselineResult:
    endpoint_name: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    response_json: Any
    timing_ms: float
    variables_extracted: dict[str, str]
    success: bool
    error: str = ""


def _extract_variables_from_script(script: str, response_body: str, response_json: Any) -> dict[str, str]:
    """Parse Postman test script to extract variable assignments.
    
    Handles patterns like:
      pm.collectionVariables.set('key', value)
      pm.environment.set("key", value)
      pm.variables.set("key", jsonData.field)
      var x = jsonData.uuid; pm.collectionVariables.set('key', x)
    """
    extracted: dict[str, str] = {}
    if not script or not response_json:
        return extracted

    json_data = response_json if isinstance(response_json, dict) else {}

    local_vars: dict[str, str] = {}
    var_assign = re.compile(
        r"""(?:var|let|const)\s+(\w+)\s*=\s*(.+?)(?:;|$)""",
        re.MULTILINE,
    )
    for m in var_assign.finditer(script):
        local_name = m.group(1)
        local_expr = m.group(2).strip()
        resolved = _resolve_value_expression(local_expr, json_data, response_body)
        if resolved is not None:
            local_vars[local_name] = str(resolved)

    set_pattern = re.compile(
        r"""pm\.(?:collectionVariables|environment|variables|globals)\.set\s*\(\s*"""
        r"""['"](\w+)['"]\s*,\s*(.+?)\s*\)""",
        re.MULTILINE,
    )

    for match in set_pattern.finditer(script):
        var_name = match.group(1)
        value_expr = match.group(2).strip().rstrip(";")

        resolved = _resolve_value_expression(value_expr, json_data, response_body)
        if resolved is None and value_expr in local_vars:
            resolved = local_vars[value_expr]
        if resolved is not None:
            extracted[var_name] = str(resolved)
            logger.info("Extracted variable: %s = %s", var_name, str(resolved)[:80])

    return extracted


def _resolve_value_expression(expr: str, json_data: dict, body: str) -> Any:
    """Resolve a JS-like expression to a value from the response.
    
    Handles:
      jsonData.uuid
      jsonData.id
      jsonData["field"]
      jsonData.nested.field
      "literal string"
      jsonData.uuid || jsonData.id || jsonData.token
    """
    expr = expr.strip()

    if (expr.startswith('"') and expr.endswith('"')) or \
       (expr.startswith("'") and expr.endswith("'")):
        return expr[1:-1]

    if "||" in expr:
        for part in expr.split("||"):
            result = _resolve_value_expression(part.strip(), json_data, body)
            if result is not None:
                return result
        return None

    json_ref = re.match(
        r"""(?:jsonData|json|data|responseBody|response|res|body)"""
        r"""((?:\.\w+|\[['"]?\w+['"]?\])*)""",
        expr,
    )
    if json_ref:
        path = json_ref.group(1)
        return _navigate_json(json_data, path)

    return None


def _navigate_json(data: Any, path: str) -> Any:
    """Navigate a JSON object using a dot/bracket path like .uuid or .data.id"""
    if not path:
        return data

    parts = re.findall(r'\.(\w+)|\[\'?\"?(\w+)\'?\"?\]', path)
    current = data
    for dot_key, bracket_key in parts:
        key = dot_key or bracket_key
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _is_id_key(key: str) -> bool:
    """Check if a JSON key looks like an ID/token field — generic, not API-specific."""
    lower = key.lower()
    if lower in _TOKEN_KEYS:
        return True
    if any(key.endswith(s) for s in _ID_SUFFIXES):
        return True
    return False


def _extract_id_values(data: Any, prefix: str = "") -> dict[str, str]:
    """Recursively find ID/token/UUID values in a JSON response."""
    found: dict[str, str] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, str) and v.strip():
                if _is_id_key(k) or _UUID_RE.fullmatch(v.strip()):
                    found[full_key] = v.strip()
            elif isinstance(v, (int, float)) and _is_id_key(k):
                found[full_key] = str(v)
            elif isinstance(v, (dict, list)):
                found.update(_extract_id_values(v, full_key))
    elif isinstance(data, list):
        for i, item in enumerate(data[:5]):
            found.update(_extract_id_values(item, f"{prefix}[{i}]"))
    return found


def _auto_chain_url(url: str, id_values: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Replace UUID path segments in URL with freshly extracted IDs.
    
    If a URL contains a UUID in a path segment and we have an extracted
    ID/token from a previous response, substitute it.
    Returns (new_url, dict of substitutions made).
    """
    if not id_values:
        return url, {}

    parsed = urlparse(url)
    path_parts = parsed.path.split("/")
    substitutions: dict[str, str] = {}

    uuid_values = [v for v in id_values.values() if _UUID_RE.fullmatch(v)]

    for i, part in enumerate(path_parts):
        if _UUID_RE.fullmatch(part) and uuid_values:
            best = uuid_values[0]
            if part != best:
                substitutions[part] = best
                path_parts[i] = best
                logger.info("Auto-chain: replaced path segment %s -> %s", part[:12] + "...", best[:12] + "...")

    if substitutions:
        new_path = "/".join(path_parts)
        new_url = urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        return new_url, substitutions

    return url, {}


async def run_baseline(
    endpoints: list[APIEndpoint],
    variables: dict[str, str] | None = None,
    timeout: float = 30.0,
    on_progress: Callable | None = None,
) -> list[BaselineResult]:
    """Execute all endpoints in order as a happy-path baseline.
    
    Variables extracted from test scripts are chained to subsequent requests.
    When no test scripts exist, auto-chains UUID/token values from prior
    responses into subsequent URL path segments.
    Returns baseline results for each endpoint.
    """
    results: list[BaselineResult] = []
    live_vars = dict(variables or {})
    auto_chain_ids: dict[str, str] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        for i, ep in enumerate(endpoints):
            url = _resolve_vars(ep.url, live_vars)
            headers = {k: _resolve_vars(v, live_vars) for k, v in ep.headers.items()}
            body = _resolve_vars(ep.body, live_vars) if ep.body else None

            if auto_chain_ids:
                url, subs = _auto_chain_url(url, auto_chain_ids)
                if subs:
                    logger.info("Auto-chained URL: %s", url)

            if ep.auth_type == "bearer" and ep.auth_value:
                token = _resolve_vars(ep.auth_value, live_vars)
                headers.setdefault("Authorization", f"Bearer {token}")
            elif ep.auth_type == "basic" and ep.auth_value:
                headers.setdefault("Authorization", f"Basic {_resolve_vars(ep.auth_value, live_vars)}")

            if on_progress:
                on_progress("baseline_request", {
                    "step": i + 1,
                    "total": len(endpoints),
                    "name": ep.original_name,
                    "method": ep.method,
                    "url": url,
                })

            result = BaselineResult(
                endpoint_name=ep.original_name,
                method=ep.method,
                url=url,
                request_headers=headers,
                request_body=body,
                status_code=0,
                response_headers={},
                response_body="",
                response_json=None,
                timing_ms=0,
                variables_extracted={},
                success=False,
            )

            try:
                start = time.perf_counter()
                resp = await client.request(
                    method=ep.method,
                    url=url,
                    headers=headers,
                    content=body,
                )
                elapsed = (time.perf_counter() - start) * 1000

                result.status_code = resp.status_code
                result.response_headers = dict(resp.headers)
                result.response_body = resp.text[:5000]
                result.timing_ms = round(elapsed, 2)
                result.success = 200 <= resp.status_code < 400

                try:
                    result.response_json = resp.json()
                except Exception:
                    result.response_json = None

                extracted: dict[str, str] = {}
                if ep.test_script and result.response_json:
                    extracted = _extract_variables_from_script(
                        ep.test_script, result.response_body, result.response_json
                    )
                    live_vars.update(extracted)

                if result.response_json and result.success:
                    new_ids = _extract_id_values(result.response_json)
                    if new_ids:
                        auto_chain_ids.update(new_ids)
                        for k, v in new_ids.items():
                            if k not in extracted:
                                extracted[k] = v

                result.variables_extracted = extracted

                logger.info(
                    "Baseline [%d/%d] %s %s -> %d (%.0fms) vars=%s",
                    i + 1, len(endpoints), ep.method, url,
                    resp.status_code, elapsed, list(extracted.keys()) if extracted else "-",
                )

            except Exception as e:
                result.error = str(e)
                logger.warning("Baseline [%d/%d] %s %s FAILED: %s", i + 1, len(endpoints), ep.method, url, e)

            results.append(result)

            if on_progress:
                on_progress("baseline_result", {
                    "step": i + 1,
                    "total": len(endpoints),
                    "name": ep.original_name,
                    "status": result.status_code,
                    "success": result.success,
                    "timing_ms": result.timing_ms,
                    "variables": list(result.variables_extracted.keys()),
                })

    return results


def format_baseline_for_llm(results: list[BaselineResult]) -> str:
    """Format baseline results as context for the LLM system prompt."""
    if not results:
        return ""

    lines = ["## API Baseline (Happy Path Results)", ""]
    lines.append("The following endpoints were executed in order. Use these baselines to compare against your fuzz tests.\n")

    for i, r in enumerate(results, 1):
        status_mark = "[OK]" if r.success else "[FAIL]"
        lines.append(f"### {i}. {status_mark} {r.method} {r.url}")
        lines.append(f"  Status: {r.status_code} | Time: {r.timing_ms}ms")

        if r.request_body:
            body_preview = r.request_body[:500]
            lines.append(f"  Request body: {body_preview}")

        if r.response_json:
            resp_preview = json.dumps(r.response_json, default=str)[:500]
            lines.append(f"  Response: {resp_preview}")
        elif r.response_body:
            lines.append(f"  Response: {r.response_body[:300]}")

        if r.variables_extracted:
            for k, v in r.variables_extracted.items():
                lines.append(f"  -> Extracted: {k} = {v[:80]}")

        if r.error:
            lines.append(f"  Error: {r.error}")
        lines.append("")

    lines.append("### Fuzzing Guidelines")
    lines.append("- Compare your test responses against these baselines (status code, body length, timing)")
    lines.append("- A different status code or significantly different response body = potential finding")
    lines.append("- Test IDOR by changing extracted IDs to adjacent/predictable values")
    lines.append("- Test auth bypass by removing/swapping Authorization headers")
    lines.append("- Test injection in every body field, query param, and path segment")
    lines.append("- Test business logic: negative values, zero amounts, skip required fields")
    lines.append("")

    return "\n".join(lines)
