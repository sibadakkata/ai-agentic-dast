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
    parse_burp_export,
    parse_openapi_spec,
    parse_postman_collection,
)
from .auth import ScanTarget, authenticate, detect_app_type
from .llm_config import ContentFiltered, ContextWindowExceeded, MalformedMessages, LLMRouter
from .prompts import build_system_prompt, get_phases
from .tools import TOOL_DEFINITIONS, ScanTools

logger = logging.getLogger(__name__)

MAX_MSG_RESULT_CHARS = 1500
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


GEN_DIGITAL_DOMAINS = {
    "norton.com", "nortonlifelock.com", "lifelock.com",
    "avast.com", "avg.com", "ccleaner.com",
    "avira.com", "reputation.com", "gendigital.com",
}


def _build_allowed_domains(target_url: str) -> set:
    """Build full set of allowed domains. If target is a Gen Digital property, include all Gen domains."""
    base = _extract_base_domain(target_url)
    allowed = {base} if base else set()
    if base in GEN_DIGITAL_DOMAINS:
        allowed |= GEN_DIGITAL_DOMAINS
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


def _cap_result(result: dict) -> str:
    """Serialize tool result and cap its size for message history."""
    raw = json.dumps(result, default=str)
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
    "inject_payload", "fuzz_parameter", "test_auth_bypass",
    "test_method_override", "replay_with_modification",
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
        "replay_with_modification", "ws_inject",
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        has_creds = bool((target.credentials or {}).get("username") or
                         (target.credentials or {}).get("password"))
        if has_creds:
            print(f"  [AUTH] Authenticating to {target.url}...")
            _cb("auth", {"status": "authenticating", "url": target.url})
        else:
            print(f"  [SCAN] Opening {target.url} (unauthenticated)...")
            _cb("auth", {"status": "unauthenticated", "url": target.url})
        auth_session = await authenticate(browser, target, router, model)
        page = auth_session.page
        print(f"  [AUTH] Auth type: {auth_session._auth_type}, URL after login: {page.url}")
        _cb("auth", {"status": "done", "type": auth_session._auth_type, "url": page.url})
        if auth_session._auth_type not in ("bearer", "none"):
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

        allowed_domains = _build_allowed_domains(target.url)
        if extra_domains:
            allowed_domains |= set(d.strip().lower() for d in extra_domains if d.strip())
        logger.info("Scope restricted to domain(s): %s", allowed_domains)
        _cb("scope", {"allowed_domains": sorted(allowed_domains)})

        tools = ScanTools(
            page=page,
            http_client=http_client,
            registry=registry,
            auth_session=auth_session,
            allowed_domains=allowed_domains,
            cancel_flag=cancel_flag,
        )

        app_info = await detect_app_type(page)
        print(f"  [DETECT] SPA: {app_info.get('is_spa')}, Framework: {app_info.get('framework')}, WebSockets: {app_info.get('has_websockets')}")
        _cb("detect", {"is_spa": app_info.get("is_spa"), "framework": app_info.get("framework")})

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
                        "url": target.url, "phase": "Body Fuzzing",
                    })

                _cb("phase_end", {
                    "phase": 0, "name": f"Body Fuzzing ({fuzz_mode})",
                    "tool_calls": len(all_fuzz_results), "findings": anomalies + llm_issues,
                })
                metrics["total_tool_calls"] += len(all_fuzz_results)

        phases = get_phases(target.scan_mode, app_info)
        system_prompt = build_system_prompt(target, registry, app_info, extra_domains=extra_domains)
        if baseline_context:
            system_prompt += "\n\n" + baseline_context
        if body_fuzz_context:
            system_prompt += "\n\n" + body_fuzz_context
        messages: list[dict] = [{"role": "system", "content": system_prompt}]

        has_baseline = bool(baseline_context)
        has_body_fuzz = bool(body_fuzz_context)
        extra_phases = (1 if has_baseline else 0) + (1 if has_body_fuzz else 0)
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
            messages.append({"role": "user", "content": phase.prompt})

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
                        if fn_name in SECURITY_TEST_TOOLS:
                            metrics["test_log"].append({
                                "phase": phase.id,
                                "tool": fn_name,
                                "request": args_parsed,
                                "response_summary": resp_summary,
                            })
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
                    snippet = content[:300].replace("\n", " ").strip()
                    _cb("tool_call", {
                        "phase": phase.name,
                        "tool": "[LLM analysis]",
                        "request": {"prompt": phase.prompt[:120] + "..." if len(phase.prompt) > 120 else phase.prompt},
                        "response": {"text": snippet[:200] + "..." if len(snippet) > 200 else snippet},
                    })
                    new_f = extract_findings(str(content))
                    findings.extend(new_f)
                    for f in new_f:
                        _cb("finding", {"title": f.get("title", ""), "severity": f.get("severity", ""), "url": f.get("url", ""), "phase": phase.name})
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
            _cb("phase_end", {"phase": phase_num, "name": phase.name, "tool_calls": phase_tool_calls, "findings": phase_new_findings})
            messages = trim_context(messages, max_tokens=TRIM_TARGET_TOKENS)

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
