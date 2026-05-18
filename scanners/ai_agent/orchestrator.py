"""Multi-agent orchestrator.

Coordinates specialist agents: runs recon first, then fans out specialist
agents in parallel, collects findings, runs the verifier, and merges
everything into a unified result set.

Each specialist agent gets its own isolated browser context, HTTP client,
and ScanTools instance -- so parallel agents don't compete for one browser
page. This mirrors the parallel-worker pattern in agent.py.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from .multi_agent_context import SharedScanContext, EndpointInfo
from .specialist_prompts import (
    SPECIALIST_AGENTS, SpecialistAgent, AgentType,
    get_all_specialists, get_specialist,
)

logger = logging.getLogger(__name__)


async def _clone_browser_context(browser, auth_cookies, target_url):
    """Create an isolated browser context with cloned auth cookies."""
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


async def _run_specialist_worker(
    agent_def: SpecialistAgent,
    context: SharedScanContext,
    model: str,
    router,
    tools,
    tool_definitions: list[dict],
    *,
    on_finding=None,
    on_progress=None,
    cancel_flag=None,
) -> list[dict]:
    """Run a single specialist agent through its focused attack loop.

    Each agent gets its own ScanTools instance (with isolated browser context).
    Uses the same router.complete() + tools.execute() pattern as the main scan.
    """
    agent_name = agent_def.name
    agent_id = agent_def.id
    _emit = on_finding or (lambda f: None)
    _progress = on_progress or (lambda event, data: None)

    context.update_metrics(agent_id, status="running", start_time=time.time())
    _progress("agent_start", {
        "agent": agent_id, "name": agent_name,
        "max_steps": agent_def.max_steps,
    })

    context_summary = _build_context_summary(context, agent_id)

    system_prompt = (
        f"{agent_def.system_prompt}\n\n"
        f"=== SHARED CONTEXT FROM RECON ===\n"
        f"{context_summary}\n"
        f"=== END CONTEXT ===\n\n"
        f"Target: {context.target_url}\n"
        f"Hosts in scope: {', '.join(context.hosts)}\n"
        f"You have {agent_def.max_steps} tool-call steps. Use them wisely.\n"
        f"Report findings by calling report_finding with title, severity, "
        f"description, url, and evidence."
    )

    endpoint_list = ""
    if context.endpoints:
        ep_samples = context.endpoints[:10]
        ep_lines = [f"  - {ep.method} {ep.url}" for ep in ep_samples]
        endpoint_list = "\n".join(ep_lines)

    initial_user_msg = (
        f"BEGIN TESTING NOW. Target: {context.target_url}\n\n"
        f"Your FIRST tool call should be one of:\n"
        f"- get_api_endpoints()\n"
        f"- navigate(url=\"{context.target_url}\")\n"
        f"- api_request(method=\"GET\", url=\"{context.target_url}\")\n\n"
        f"Do NOT explain what you plan to do. Just call a tool immediately.\n"
    )
    if endpoint_list:
        initial_user_msg += (
            f"\nEndpoints discovered by recon:\n{endpoint_list}\n"
            f"Test ALL of these endpoints with your specialist payloads.\n"
        )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_user_msg},
    ]
    findings: list[dict] = []
    total_tool_calls = 0
    consecutive_no_tool = 0

    for step in range(agent_def.max_steps):
        if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
            break

        check_messages = await context.get_messages(agent_id)
        if check_messages:
            for msg in check_messages:
                messages.append({
                    "role": "user",
                    "content": (
                        f"[Message from {msg['from']} agent]: "
                        f"{msg['type']}: {msg['data']}"
                    ),
                })

        try:
            response = router.complete(
                model=model,
                messages=messages,
                tools=tool_definitions,
                cancel_flag=cancel_flag,
            )
        except Exception as e:
            logger.warning("[%s] LLM error at step %d: %s", agent_id, step, e)
            context.update_metrics(agent_id, error=str(e))
            break

        if not response or not getattr(response, "choices", None):
            logger.warning("[%s] Empty response at step %d", agent_id, step)
            break

        choice = response.choices[0]
        msg = choice.message
        msg_dict = msg.model_dump() if hasattr(msg, "model_dump") else dict(msg)
        messages.append(msg_dict)

        tool_calls_in_msg = (
            msg_dict.get("tool_calls")
            or getattr(msg, "tool_calls", None)
            or []
        )

        if not tool_calls_in_msg:
            consecutive_no_tool += 1
            content = msg_dict.get("content") or ""
            if content:
                _progress("agent_thinking", {
                    "agent": agent_id, "step": step,
                    "content": content[:200],
                })
            if _agent_is_done(content):
                break
            if consecutive_no_tool >= 3:
                messages.append({
                    "role": "user",
                    "content": (
                        "You have NOT called any tools in your last 3 responses. "
                        "You MUST call a tool NOW. Do not explain -- just call "
                        "get_api_endpoints() or navigate() or fuzz_parameter() or "
                        "api_request(). If you have nothing left to test, say "
                        "'I have completed all testing' to finish."
                    ),
                })
                consecutive_no_tool = 0
            continue

        consecutive_no_tool = 0
        for tc in tool_calls_in_msg:
            if cancel_flag is not None and getattr(cancel_flag, "is_set", lambda: False)():
                break

            tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
            fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", None)
            if fn is None:
                continue
            fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
            fn_args_raw = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "{}")

            if isinstance(fn_args_raw, str):
                try:
                    fn_args = json.loads(fn_args_raw)
                except (json.JSONDecodeError, TypeError):
                    fn_args = {}
            else:
                fn_args = fn_args_raw or {}

            if fn_name == "report_finding":
                finding = fn_args if isinstance(fn_args, dict) else {}
                finding["_source_agent"] = agent_id
                finding["phase"] = f"Multi-Agent ({agent_name})"
                findings.append(finding)
                await context.add_finding(finding, agent_id)
                _emit(finding)
                result = "Finding reported successfully."
            else:
                try:
                    result = await tools.execute(fn_name, fn_args)
                except Exception as e:
                    result = f"Error executing {fn_name}: {e}"

            total_tool_calls += 1
            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": str(result)[:15_000] if result else "OK",
            })

        _progress("agent_step", {
            "agent": agent_id, "step": step,
            "tool_calls": total_tool_calls, "findings": len(findings),
        })

    context.update_metrics(
        agent_id,
        status="completed",
        findings=len(findings),
        tool_calls=total_tool_calls,
        elapsed_s=time.time() - context.agent_metrics[agent_id]["start_time"],
    )
    _progress("agent_end", {
        "agent": agent_id, "findings": len(findings),
        "tool_calls": total_tool_calls,
    })

    return findings


def _build_context_summary(context: SharedScanContext,
                           agent_id: str) -> str:
    """Build a text summary of shared context for a specialist's prompt."""
    parts = []

    if context.endpoints:
        ep_lines = []
        for ep in context.endpoints[:50]:
            params = ", ".join(ep.params[:10]) if ep.params else "none"
            ep_lines.append(f"  {ep.method} {ep.url} (params: {params})")
        parts.append(f"Discovered endpoints ({len(context.endpoints)}):\n"
                     + "\n".join(ep_lines))

    if context.discovered_params:
        param_lines = []
        for url, params in list(context.discovered_params.items())[:20]:
            param_lines.append(f"  {url}: {', '.join(sorted(params)[:10])}")
        parts.append(f"Discovered params ({len(context.discovered_params)} URLs):\n"
                     + "\n".join(param_lines))

    if context.tech_stack:
        parts.append(f"Tech stack: {context.tech_stack}")

    if context.forms:
        form_lines = []
        for form in context.forms[:10]:
            form_lines.append(f"  {form.get('action', '?')} ({form.get('method', 'GET')})")
        parts.append(f"Forms ({len(context.forms)}):\n" + "\n".join(form_lines))

    if context.crawled_urls:
        parts.append(f"Crawled URLs ({len(context.crawled_urls)}):\n" +
                     "\n".join(f"  {u}" for u in context.crawled_urls[:30]))

    if context.auth_token:
        parts.append(f"Auth: token available ({context.auth_token[:20]}...)")

    other_findings = []
    for f in context._findings:
        if f.get("_source_agent") != agent_id:
            other_findings.append(
                f"  [{f.get('_source_agent', '?')}] {f.get('title', '?')} "
                f"@ {f.get('url', '?')}")
    if other_findings:
        parts.append(f"Findings from other agents ({len(other_findings)}):\n"
                     + "\n".join(other_findings[:20]))

    return "\n\n".join(parts) if parts else "(No recon data yet)"


def _agent_is_done(content: str) -> bool:
    """Check if the agent explicitly declares it has finished all testing.

    Only trigger on unambiguous end-of-work declarations -- not casual mentions
    of "completed" or "done" mid-analysis. The agent must be saying *it* is done,
    not that a particular test completed.
    """
    done_signals = [
        "i have completed all testing",
        "i have completed my testing",
        "all testing is complete",
        "finished all testing",
        "no more endpoints to test",
        "all parameters have been tested",
        "scan complete. no further",
        "i'm done testing",
        "i am done testing",
        "that concludes my testing",
    ]
    lower = content.lower()
    return any(sig in lower for sig in done_signals)


async def run_multi_agent_scan(
    context: SharedScanContext,
    model: str,
    router,
    tools,
    tool_definitions: list[dict],
    *,
    browser=None,
    auth_cookies: list[dict] | None = None,
    registry=None,
    allowed_domains: set | None = None,
    auth_session=None,
    exclude_urls: list[str] | None = None,
    on_finding=None,
    on_progress=None,
    cancel_flag=None,
    agents_to_run: list[AgentType] | None = None,
) -> list[dict]:
    """Run the full multi-agent scan pipeline.

    Pipeline:
    1. Recon agent runs first (sequential) -- uses the shared tools/browser
    2. Specialist agents run in parallel -- each gets an ISOLATED browser
       context, HTTP client, and ScanTools instance
    3. Verifier agent runs last -- re-confirms findings and builds chains
    """
    from .tools import ScanTools

    _progress = on_progress or (lambda event, data: None)
    all_findings: list[dict] = []

    if agents_to_run is None:
        agents_to_run = list(SPECIALIST_AGENTS.keys())

    _progress("multi_agent_start", {
        "agents": agents_to_run,
        "target": context.target_url,
    })

    # -- Phase 1: Recon (sequential, uses shared tools) --
    if "recon" in agents_to_run:
        _progress("multi_agent_phase", {"phase": "recon", "status": "starting"})
        recon_agent = get_specialist("recon")
        recon_findings = await _run_specialist_worker(
            recon_agent, context, model, router, tools, tool_definitions,
            on_finding=on_finding, on_progress=_progress,
            cancel_flag=cancel_flag,
        )
        all_findings.extend(recon_findings)
        _progress("multi_agent_phase", {
            "phase": "recon", "status": "complete",
            "findings": len(recon_findings),
            "endpoints": len(context.endpoints),
        })

    # -- Phase 2: Specialist agents (parallel, isolated contexts) --
    specialist_agents = [
        get_specialist(aid) for aid in agents_to_run
        if aid not in ("recon", "verifier") and aid in SPECIALIST_AGENTS
    ]

    if specialist_agents:
        _progress("multi_agent_phase", {
            "phase": "specialists",
            "status": "starting",
            "count": len(specialist_agents),
            "agents": [a.id for a in specialist_agents],
        })

        async def _guarded_worker(agent_def: SpecialistAgent) -> list[dict]:
            agent_context = None
            agent_page = None
            agent_http = None
            agent_tools = tools
            try:
                if browser:
                    agent_context, agent_page = await _clone_browser_context(
                        browser, auth_cookies or [], context.target_url,
                    )
                agent_http = httpx.AsyncClient(
                    timeout=30.0, verify=False, follow_redirects=True,
                )
                agent_tools = ScanTools(
                    page=agent_page,
                    http_client=agent_http,
                    registry=registry,
                    auth_session=auth_session,
                    allowed_domains=allowed_domains,
                    cancel_flag=cancel_flag,
                    exclude_urls=exclude_urls or [],
                )

                return await _run_specialist_worker(
                    agent_def, context, model, router,
                    agent_tools, tool_definitions,
                    on_finding=on_finding, on_progress=_progress,
                    cancel_flag=cancel_flag,
                )
            except Exception as e:
                logger.error("[%s] Agent crashed: %s", agent_def.id, e,
                             exc_info=True)
                context.update_metrics(agent_def.id,
                                       status="failed", error=str(e))
                return []
            finally:
                if agent_http:
                    try:
                        await agent_http.aclose()
                    except Exception:
                        pass
                if agent_page:
                    try:
                        await agent_page.close()
                    except Exception:
                        pass
                if agent_context:
                    try:
                        await agent_context.close()
                    except Exception:
                        pass

        results = await asyncio.gather(
            *[_guarded_worker(a) for a in specialist_agents],
        )
        for agent_findings in results:
            all_findings.extend(agent_findings)

        _progress("multi_agent_phase", {
            "phase": "specialists", "status": "complete",
            "total_findings": len(all_findings),
        })

    # -- Phase 3: Verifier (sequential, uses shared tools) --
    if "verifier" in agents_to_run and all_findings:
        _progress("multi_agent_phase", {
            "phase": "verifier", "status": "starting",
            "findings_to_verify": len(all_findings),
        })
        verifier_agent = get_specialist("verifier")
        verifier_findings = await _run_specialist_worker(
            verifier_agent, context, model, router, tools, tool_definitions,
            on_finding=on_finding, on_progress=_progress,
            cancel_flag=cancel_flag,
        )
        all_findings.extend(verifier_findings)
        _progress("multi_agent_phase", {
            "phase": "verifier", "status": "complete",
            "chains": len(verifier_findings),
        })

    # -- Summary --
    _progress("multi_agent_end", {
        "total_findings": len(all_findings),
        "agents_run": len(agents_to_run),
        "elapsed_s": context.elapsed_seconds,
        "per_agent": {
            aid: context.agent_metrics.get(aid, {})
            for aid in agents_to_run
        },
    })

    return all_findings
