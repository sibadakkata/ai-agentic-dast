"""Standalone scan execution (PG-only). Gate 7."""
from __future__ import annotations
import asyncio, json, logging, os, time
from datetime import datetime
from pathlib import Path
import httpx
from scanners.ai_agent.agent import run_scan, save_results, ScanCancelled
from scanners.ai_agent.auth import load_targets_from_dict
from scanners.ai_agent.llm_config import LLMRouter
from web import db_pg as pgdb
from web.live_events import publish_event
log = logging.getLogger(__name__)
BASE = Path(__file__).resolve().parent.parent

async def execute_scan_job(scan_id: str, config: dict) -> None:
    os.environ["DUAL_WRITE_PG"] = "1"
    target_url = config["target_url"]
    model = config["model"]
    try:
        state = dict(pgdb.get_scan_info(scan_id) or {})
    except Exception:
        state = {}
    state.update({
        "target_url": target_url,
        "model": model,
        "status": "running",
        "started": state.get("started") or datetime.now().isoformat(),
        "scan_mode": config.get("scan_mode", state.get("scan_mode", "both")),
        "scan_profile": config.get("scan_profile", state.get("scan_profile", "crawl_only")),
        "scan_scope": config.get("scan_scope", state.get("scan_scope", "directory")),
        "scan_intensity": config.get("scan_intensity", state.get("scan_intensity", "light")),
        "model_name": config.get("model_name", state.get("model_name", "")),
    })
    pgdb.upsert_scan(scan_id, state)
    publish_event(scan_id, "runner_start", {})
    try:
        async with httpx.AsyncClient(verify=False, timeout=20.0, follow_redirects=True) as c:
            await c.get(target_url)
    except Exception as exc:
        log.warning("Preflight GET failed for %s (continuing with browser): %s", target_url, exc)
        state.setdefault("progress", []).append(f"Preflight warning: {exc}")
        pgdb.upsert_scan(scan_id, state)
        publish_event(scan_id, "preflight_warning", {"error": str(exc)})
    router = LLMRouter(models=[model])
    td = {"id": scan_id.split("_")[-1], "url": target_url, "scan_mode": config.get("scan_mode", "both"),
          "auth": {"type": config.get("auth_type", "auto"), "username": config.get("username", ""), "password": config.get("password", "")},
          "scan_scope": config.get("scan_scope", "directory"), "scan_intensity": config.get("scan_intensity", "light"),
          "scan_profile": config.get("scan_profile", state.get("scan_profile", "crawl_only"))}
    target = load_targets_from_dict(td)
    findings = []

    def on_progress(event, data):
        if event == "finding":
            pgdb.save_finding(scan_id, dict(data))
            publish_event(scan_id, "finding", data)
        elif event == "phase_start" and isinstance(data, dict):
            phase_label = f"[{data.get('phase', '?')}/{data.get('total', '?')}] {data.get('name', '')}"
            state["current_phase"] = phase_label
            pgdb.upsert_scan(scan_id, state)
            publish_event(scan_id, event, data)
        elif event == "phase_end" and isinstance(data, dict):
            phases = state.setdefault("live_phases", [])
            if isinstance(phases, list):
                phases.append(data)
            state["phases_completed"] = len(phases) if isinstance(phases, list) else state.get("phases_completed", 0)
            pgdb.upsert_scan(scan_id, state)
            publish_event(scan_id, event, data)
        else:
            publish_event(scan_id, event, data if isinstance(data, dict) else {"data": data})

    start = time.perf_counter()
    try:
        findings, metrics = await run_scan(
            target, model, router, str(BASE / "config"), on_progress=on_progress
        )
        duration = time.perf_counter() - start
        out = save_results(str(BASE / "results/raw" / f"runner_{scan_id}.json"), findings, router.get_cost_summary(), target, model, duration, metrics)
        pgdb.save_scan_result(scan_id, json.dumps(out, default=str))
        state.update({"status": "completed", "findings_count": len(findings), "duration": round(duration, 1)})
        pgdb.add_all_time_cost(out.get("metadata", {}).get("cost_usd") or 0)
        publish_event(scan_id, "completed", {"findings_count": len(findings)})
    except ScanCancelled:
        state["status"] = "completed"
    except Exception as exc:
        state.update({"status": "error", "error": str(exc)})
        publish_event(scan_id, "error", {"error": str(exc)})
    pgdb.upsert_scan(scan_id, state)
