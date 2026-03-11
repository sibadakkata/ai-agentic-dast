from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

from .api_import import (
    EndpointRegistry,
    parse_burp_export,
    parse_openapi_spec,
    parse_postman_collection,
)
from .auth import ScanTarget, authenticate, detect_app_type
from .llm_config import ContextWindowExceeded, LLMRouter
from .prompts import build_system_prompt, get_phases
from .tools import TOOL_DEFINITIONS, ScanTools

logger = logging.getLogger(__name__)

MAX_MSG_RESULT_CHARS = 1500
TRIM_TARGET_TOKENS = 40000


def _cap_result(result: dict) -> str:
    """Serialize tool result and cap its size for message history."""
    raw = json.dumps(result, default=str)
    if len(raw) <= MAX_MSG_RESULT_CHARS:
        return raw
    return raw[:MAX_MSG_RESULT_CHARS] + '..."}'


def _estimate_tokens(messages: list[dict]) -> int:
    return len(json.dumps(messages, default=str)) // 4


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
) -> tuple[list[dict], dict]:
    config_dir = config_dir or os.getcwd()
    findings: list[dict] = []
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
    SECURITY_TEST_TOOLS = {
        "inject_payload", "fuzz_parameter", "api_request",
        "test_auth_bypass", "test_method_override", "api_request_raw",
        "replay_with_modification", "ws_inject",
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        print(f"  [AUTH] Authenticating to {target.url}...")
        auth_session = await authenticate(browser, target, router, model)
        page = auth_session.page
        print(f"  [AUTH] Auth type: {auth_session._auth_type}, URL after login: {page.url}")
        if auth_session._auth_type != "bearer":
            metrics["auth_pages_detected"] += 1

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
            burp_path = _resolve_import_path(config_dir, target.burp_file)
            if burp_path:
                registry.add(parse_burp_export(burp_path))
            openapi_path = _resolve_import_path(config_dir, target.openapi_file)
            if openapi_path:
                registry.add(parse_openapi_spec(openapi_path))

        tools = ScanTools(
            page=page,
            http_client=http_client,
            registry=registry,
            auth_session=auth_session,
        )

        app_info = await detect_app_type(page)
        print(f"  [DETECT] SPA: {app_info.get('is_spa')}, Framework: {app_info.get('framework')}, WebSockets: {app_info.get('has_websockets')}")
        phases = get_phases(target.scan_mode, app_info)
        system_prompt = build_system_prompt(target, registry, app_info)
        messages: list[dict] = [{"role": "system", "content": system_prompt}]

        print(f"  [SCAN] Starting {len(phases)} phases...")
        for phase_idx, phase in enumerate(phases, 1):
            phase_tool_calls = 0
            phase_findings_before = len(findings)
            print(f"  [{phase_idx}/{len(phases)}] Phase: {phase.name} ({phase.id})...", end="", flush=True)
            messages.append({"role": "user", "content": phase.prompt})

            for step in range(phase.max_steps):
                try:
                    response = router.complete(
                        model=model,
                        messages=messages,
                        tools=TOOL_DEFINITIONS,
                    )
                except ContextWindowExceeded:
                    logger.warning("Context window exceeded at phase %s step %d, trimming aggressively", phase.id, step)
                    messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS // 2)
                    try:
                        response = router.complete(model=model, messages=messages, tools=TOOL_DEFINITIONS)
                    except ContextWindowExceeded:
                        logger.error("Still exceeded after aggressive trim, skipping rest of phase %s", phase.id)
                        break
                if not response or not getattr(response, "choices", None):
                    logger.warning("Empty response from %s at phase %s step %d", model, phase.id, step)
                    break
                msg = response.choices[0].message
                msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
                messages.append(msg_dict)

                tool_calls = getattr(msg, "tool_calls", None) or msg_dict.get("tool_calls", [])
                if tool_calls:
                    for tc in tool_calls:
                        tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                        fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                        fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                        fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")
                        result = await tools.execute(fn_name, fn_args)
                        phase_tool_calls += 1
                        metrics["total_tool_calls"] += 1
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": _cap_result(result),
                        })
                        if fn_name == "navigate" and result.get("url"):
                            url = result["url"]
                            if url not in metrics["pages_list"]:
                                metrics["pages_list"].append(url)
                                metrics["pages_crawled"] += 1
                        elif fn_name == "get_forms" and result.get("forms"):
                            metrics["forms_found"] += len(result["forms"])
                        elif fn_name in ("get_network_log", "intercept_requests"):
                            registry.add_from_traffic(result)
                        if fn_name in SECURITY_TEST_TOOLS:
                            try:
                                args_parsed = json.loads(fn_args) if isinstance(fn_args, str) else fn_args
                            except Exception:
                                args_parsed = {"raw": fn_args}
                            metrics["test_log"].append({
                                "phase": phase.id,
                                "tool": fn_name,
                                "request": args_parsed,
                                "response_summary": {
                                    k: v for k, v in result.items()
                                    if k in ("status", "error", "reflected", "anomaly", "body_snippet", "results", "accessible")
                                } if isinstance(result, dict) else str(result)[:200],
                            })
                    if phase_tool_calls % 5 == 0 and _estimate_tokens(messages) > TRIM_TARGET_TOKENS:
                        messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)
                else:
                    content = msg_dict.get("content") or getattr(msg, "content", "") or ""
                    findings.extend(extract_findings(str(content)))
                    break

            phase_new_findings = len(findings) - phase_findings_before
            metrics["phases_completed"] += 1
            metrics["phase_log"].append({
                "phase": phase.id,
                "name": phase.name,
                "tool_calls": phase_tool_calls,
                "findings": phase_new_findings,
            })
            print(f" {phase_tool_calls} tool calls, {phase_new_findings} findings")
            messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)

        metrics["api_endpoints_found"] = len(registry.get_all())
        print(f"  [DONE] Pages: {metrics['pages_crawled']}, Forms: {metrics['forms_found']}, APIs: {metrics['api_endpoints_found']}, Findings: {len(findings)}")

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


def extract_findings(content: str) -> list[dict]:
    findings: list[dict] = []
    if not content:
        return findings

    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", content):
        for obj_str in _extract_json_objects(block.strip()):
            try:
                obj = json.loads(obj_str)
                if isinstance(obj, dict) and "title" in obj and "severity" in obj:
                    findings.append(obj)
            except json.JSONDecodeError:
                pass

    for obj_str in _extract_json_objects(content):
        try:
            obj = json.loads(obj_str)
            if isinstance(obj, dict) and "title" in obj and "severity" in obj:
                if not any(f.get("title") == obj.get("title") and f.get("severity") == obj.get("severity") for f in findings):
                    findings.append(obj)
        except json.JSONDecodeError:
            pass

    return findings


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
        return kept

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
        return trimmed

    return kept


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
        sev = f.get("severity", "Info")
        for key in severity_counts:
            if key.lower() == sev.lower():
                severity_counts[key] += 1
                break
        else:
            severity_counts["Info"] += 1
        cat = f.get("owasp_category", "Unknown")
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
        browser = await p.chromium.launch(headless=True)
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
            burp_path = _resolve_import_path(config_dir, target.burp_file)
            if burp_path:
                registry.add(parse_burp_export(burp_path))
            openapi_path = _resolve_import_path(config_dir, target.openapi_file)
            if openapi_path:
                registry.add(parse_openapi_spec(openapi_path))

        tools = DryRunScanTools(
            page=page,
            http_client=http_client,
            registry=registry,
            auth_session=auth_session,
        )

        app_info = await detect_app_type(page)
        phases = get_phases(target.scan_mode, app_info)
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
                messages.append(msg_dict)

                tool_calls = getattr(msg, "tool_calls", None) or msg_dict.get("tool_calls", [])
                if tool_calls:
                    for tc in tool_calls:
                        fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", {})
                        fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
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
