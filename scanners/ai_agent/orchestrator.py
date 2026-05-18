"""Multi-agent orchestrator.

Coordinates specialist agents: runs recon first, then fans out specialist
agents in parallel, collects findings, runs the verifier, and merges
everything into a unified result set.

The orchestrator reuses the existing ScanTools + TOOL_DEFINITIONS + LLMRouter
from the main scanner -- each specialist agent gets its own system prompt but
shares the same authenticated browser, HTTP client, and tool implementations.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from .multi_agent_context import SharedScanContext, EndpointInfo
from .specialist_prompts import (
    SPECIALIST_AGENTS, SpecialistAgent, AgentType,
    get_all_specialists, get_specialist,
)

logger = logging.getLogger(__name__)


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

    Uses the same router.complete() + tools.execute() pattern as the
    main scan phases.
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

    # Bedrock requires at least one user message after the system message.
    initial_user_msg = (
        f"You are the {agent_name} specialist. Begin testing "
        f"{context.target_url} now. Use your tools to probe for "
        f"vulnerabilities in your domain. Start by examining the target "
        f"and any discovered endpoints listed in the context above."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_user_msg},
    ]
    findings: list[dict] = []
    total_tool_calls = 0

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
            content = msg_dict.get("content") or ""
            if content:
                _progress("agent_thinking", {
                    "agent": agent_id, "step": step,
                    "content": content[:200],
                })
            if _agent_is_done(content):
                break
            continue

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
    """Check if the agent's response indicates it's finished."""
    done_signals = [
        "i have completed", "testing complete", "finished testing",
        "no more tests", "all parameters tested", "scan complete",
        "i'm done", "i am done", "that concludes",
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
    on_finding=None,
    on_progress=None,
    cancel_flag=None,
    agents_to_run: list[AgentType] | None = None,
) -> list[dict]:
    """Run the full multi-agent scan pipeline.

    Pipeline:
    1. Recon agent runs first (sequential) -- populates shared context
    2. Specialist agents run in parallel -- each focused on its vuln class
    3. Verifier agent runs last -- re-confirms findings and builds chains
    """
    _progress = on_progress or (lambda event, data: None)
    all_findings: list[dict] = []

    if agents_to_run is None:
        agents_to_run = list(SPECIALIST_AGENTS.keys())

    _progress("multi_agent_start", {
        "agents": agents_to_run,
        "target": context.target_url,
    })

    # -- Phase 1: Recon (sequential) --
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

    # -- Phase 2: Specialist agents (parallel) --
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
            try:
                return await _run_specialist_worker(
                    agent_def, context, model, router, tools, tool_definitions,
                    on_finding=on_finding, on_progress=_progress,
                    cancel_flag=cancel_flag,
                )
            except Exception as e:
                logger.error("[%s] Agent crashed: %s", agent_def.id, e,
                             exc_info=True)
                context.update_metrics(agent_def.id,
                                       status="failed", error=str(e))
                return []

        results = await asyncio.gather(
            *[_guarded_worker(a) for a in specialist_agents],
        )
        for agent_findings in results:
            all_findings.extend(agent_findings)

        _progress("multi_agent_phase", {
            "phase": "specialists", "status": "complete",
            "total_findings": len(all_findings),
        })

    # -- Phase 3: Verifier (sequential) --
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
