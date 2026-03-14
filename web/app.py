"""FastAPI web UI for the AI Agentic Web Scanner."""
from __future__ import annotations

import asyncio
import glob
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners.ai_agent.agent import run_scan, save_results, ScanCancelled
from scanners.ai_agent.auth import load_targets_from_dict
from scanners.ai_agent.llm_config import LLMRouter, check_connectivity
from scripts.triage_engine import classify as triage_classify

app = FastAPI(
    title="AI Agentic Web Scanner",
    description="LLM-powered Dynamic Application Security Testing API. "
    "Start scans, poll status, download results and PDF reports programmatically.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# --- Basic Auth ---------------------------------------------------------------
_security = HTTPBasic()
_AUTH_USER = os.environ.get("DAST_AUTH_USER", "dast-admin")
_AUTH_PASS = os.environ.get("DAST_AUTH_PASS", "Dk9xMvP2wLz7nQr8")

def _verify(credentials: HTTPBasicCredentials = Depends(_security)):
    user_ok = hmac.compare_digest(credentials.username.encode(), _AUTH_USER.encode())
    pass_ok = hmac.compare_digest(credentials.password.encode(), _AUTH_PASS.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

BASE = Path(__file__).resolve().parent.parent
RAW_DIR = BASE / "results" / "raw"
REPORTS_DIR = BASE / "results" / "reports"
SCANS_META_FILE = BASE / "results" / "scans_meta.json"
RAW_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SCANS: dict[str, dict] = {}
CANCEL_FLAGS: dict[str, threading.Event] = {}
PAUSE_FLAGS: dict[str, threading.Event] = {}

def _load_scans_from_disk():
    """Restore scan metadata from disk on startup."""
    if SCANS_META_FILE.exists():
        try:
            data = json.loads(SCANS_META_FILE.read_text(encoding="utf-8"))
            for scan_id, info in data.items():
                if info.get("status") == "running":
                    info["status"] = "error"
                    info["error"] = "Server restarted during scan"
                    progress = info.get("progress", [])
                    progress.append("--- Container stopped/restarted during scan ---")
                    info["progress"] = progress
                elif info.get("status") in ("stopping", "paused", "pausing"):
                    info["status"] = "cancelled"
                    progress = info.get("progress", [])
                    progress.append("--- Container restarted — marked as cancelled ---")
                    info["progress"] = progress
                SCANS[scan_id] = info
            for scan_id in list(SCANS.keys()):
                override_file = Path("results/raw") / f"{scan_id}_cvss_overrides.json"
                if override_file.exists():
                    try:
                        SCANS[scan_id]["cvss_overrides"] = json.loads(
                            override_file.read_text(encoding="utf-8"))
                    except Exception:
                        pass
        except Exception:
            pass

_TRANSIENT_KEYS = frozenset({"live_tests", "live_findings", "live_phases", "live_crawled", "live_forms", "live_tool_calls", "live_out_of_scope"})
_SECRET_KEYS = frozenset({"_password"})

def _save_scans_to_disk():
    """Persist scan metadata to disk (excluding transient live data)."""
    try:
        persist = {}
        for scan_id, info in SCANS.items():
            persist[scan_id] = {
                k: v for k, v in info.items()
                if k not in _TRANSIENT_KEYS and k not in _SECRET_KEYS
            }
        SCANS_META_FILE.write_text(json.dumps(persist, default=str), encoding="utf-8")
    except Exception:
        pass


def _infer_scan_mode(scan_info: dict) -> str:
    """Try to infer scan_mode from old scan data that didn't store it."""
    result_file = scan_info.get("result_file")
    if result_file:
        fpath = RAW_DIR / result_file
        if fpath.exists():
            try:
                meta = json.loads(fpath.read_text(encoding="utf-8")).get("metadata", {})
                mode = meta.get("scan_mode")
                if mode:
                    return mode
            except Exception:
                pass
    progress = " ".join(scan_info.get("progress", []))
    if "API Baseline" in progress or "api" in scan_info.get("target_url", "").lower():
        return "api"
    return "both"


_load_scans_from_disk()

MODELS = [
    {"id": "bedrock/mistral.ministral-3-8b-instruct", "name": "Ministral 8B (cheapest + tools)", "cost": "~$0.15/$0.15 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/mistral.ministral-3-14b-instruct", "name": "Ministral 14B (best value + tools)", "cost": "~$0.20/$0.20 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/mistral.mistral-small-2402-v1:0", "name": "Mistral Small (legacy, weak tools)", "cost": "~$0.10/$0.30 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "name": "Claude Haiku 4.5 (recommended)", "cost": "~$0.80/$4 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/us.anthropic.claude-sonnet-4-6", "name": "Claude Sonnet 4.6 (best quality)", "cost": "~$3/$15 per 1M tokens", "provider": "Bedrock"},
]


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint (no auth) — useful for load balancers and monitoring."""
    running = sum(1 for s in SCANS.values() if s.get("status") == "running")
    return {"status": "ok", "scans_running": running, "total_scans": len(SCANS)}


@app.get("/logout", include_in_schema=False)
async def logout():
    """Return 401 to force browser to clear Basic Auth credentials."""
    return Response(
        content="Logged out. <a href='/'>Login again</a>",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Logged out"'},
        media_type="text/html",
    )


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(creds=Depends(_verify)):
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/models", tags=["System"])
async def get_models(creds=Depends(_verify)):
    return MODELS


@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    page: int = 1,
    per_page: int = 25,
    search: str = "",
    creds=Depends(_verify),
):
    per_page = min(max(per_page, 1), 100)
    page = max(page, 1)

    all_scans = []
    for scan_id, info in sorted(SCANS.items(), key=lambda x: x[1].get("started", ""), reverse=True):
        all_scans.append({
            "id": scan_id,
            "target": info.get("target_url", ""),
            "model": info.get("model_name", ""),
            "status": info.get("status", "unknown"),
            "started": info.get("started", ""),
            "duration": info.get("duration"),
            "cost": info.get("cost"),
            "findings_count": info.get("findings_count"),
            "scan_mode": info.get("scan_mode", ""),
            "phases_completed": info.get("phases_completed", len(info.get("live_phases", []))),
        })
    existing_ids = {s["id"] for s in all_scans}
    for f in sorted(RAW_DIR.glob("aiagent_*.json"), key=os.path.getmtime, reverse=True):
        fid = f.stem
        if fid in existing_ids or any(eid in fid for eid in existing_ids):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        meta = data.get("metadata", {})
        summary = data.get("summary", {})
        all_scans.append({
            "id": fid,
            "target": data.get("target", ""),
            "model": meta.get("model", ""),
            "status": "completed",
            "started": meta.get("timestamp", ""),
            "duration": meta.get("scan_duration_seconds"),
            "cost": meta.get("cost_usd"),
            "findings_count": summary.get("total_findings", len(data.get("findings", []))),
            "scan_mode": meta.get("scan_mode", ""),
        })

    if search:
        q = search.lower()
        all_scans = [s for s in all_scans if q in (s["target"] or "").lower()
                     or q in (s["model"] or "").lower()
                     or q in (s["id"] or "").lower()
                     or q in (s["status"] or "").lower()]

    total = len(all_scans)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    items = all_scans[start : start + per_page]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    }


IMPORTS_DIR = BASE / "imports"
IMPORTS_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/upload", tags=["Scans"])
async def upload_api_spec(
    file: UploadFile = File(...),
    creds=Depends(_verify),
):
    """Save an uploaded Postman/Burp/Swagger file to imports/."""
    safe_name = file.filename.replace("..", "").replace("/", "_").replace("\\", "_")
    dest = IMPORTS_DIR / safe_name
    contents = await file.read()
    dest.write_bytes(contents)
    return {"filename": safe_name, "size": len(contents)}


@app.post("/api/scan", tags=["Scans"])
async def start_scan(request: Request, creds=Depends(_verify)):
    body = await request.json()
    target_url = body.get("target_url", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    model = body.get("model", "claude-haiku-4-5-20251001")
    scan_mode = body.get("scan_mode", "both")
    auth_type = body.get("auth_type", "auto")
    api_imports = body.get("api_imports", {}) or {}
    extra_domains = body.get("extra_domains", []) or []

    if not target_url:
        return JSONResponse({"error": "Target URL is required"}, status_code=400)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    model_name = next((m["name"] for m in MODELS if m["id"] == model), model)

    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[scan_id] = cancel_flag
    PAUSE_FLAGS[scan_id] = pause_flag

    SCANS[scan_id] = {
        "target_url": target_url,
        "model": model,
        "model_name": model_name,
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [],
        "scan_mode": scan_mode,
        "auth_type": auth_type,
        "_username": username,
        "_password": password,
        "_api_imports": api_imports,
        "_extra_domains": extra_domains,
    }
    _save_scans_to_disk()

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports, extra_domains, cancel_flag, pause_flag),
        daemon=True,
    )
    thread.start()
    return {"scan_id": scan_id, "status": "started"}


def _run_scan_in_thread(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports=None, extra_domains=None, cancel_flag=None, pause_flag=None, start_from_phase=0, initial_findings=None):
    """Run scan in a separate thread with its own event loop so the main UI stays responsive."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run_scan_task(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports, extra_domains, cancel_flag, pause_flag, start_from_phase, initial_findings)
        )
    finally:
        loop.close()
        CANCEL_FLAGS.pop(scan_id, None)
        PAUSE_FLAGS.pop(scan_id, None)


async def _run_scan_task(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports=None, extra_domains=None, cancel_flag=None, pause_flag=None, start_from_phase=0, initial_findings=None):
    try:
        scan = SCANS[scan_id]
        scan["progress"].append("Initializing LLM router...")
        scan["live_phases"] = []
        scan["live_tests"] = []
        scan["live_findings"] = []
        scan["live_crawled"] = []
        scan["live_forms"] = 0
        scan["live_tool_calls"] = 0
        scan["current_phase"] = ""
        scan["live_out_of_scope"] = []

        def _on_progress(event, data):
            if event == "auth":
                status = data.get("status", "")
                if status == "unauthenticated":
                    scan["progress"].append(f"No credentials provided — scanning unauthenticated: {data.get('url', '')}")
                elif status == "done" and data.get("type") == "none":
                    scan["progress"].append("Unauthenticated scan — navigating to target...")
                else:
                    scan["progress"].append(f"Auth: {status} {data.get('type', '')}")
            elif event == "scope":
                domains = ", ".join(data.get("allowed_domains", []))
                scan["progress"].append(f"Scope: scanning only *.{domains} — third-party domains blocked")
            elif event == "detect":
                scan["progress"].append(f"Detected: SPA={data.get('is_spa')}, Framework={data.get('framework')}")
            elif event == "scan_start":
                scan["progress"].append(f"Starting {data['total_phases']} scan phases...")
            elif event == "phase_start":
                scan["current_phase"] = f"[{data['phase']}/{data['total']}] {data['name']}"
                scan["progress"].append(scan["current_phase"])
            elif event == "phase_end":
                scan["live_phases"].append({
                    "phase": data["phase"],
                    "name": data["name"],
                    "tool_calls": data["tool_calls"],
                    "findings": data["findings"],
                })
                _save_scans_to_disk()
            elif event == "tool_call":
                scan["live_tool_calls"] += 1
                tool = data.get("tool", "")
                scan["live_tests"].append({
                    "phase": data.get("phase", ""),
                    "tool": tool,
                    "request": data.get("request", {}),
                    "response": data.get("response", {}),
                })
                if len(scan["live_tests"]) > 500:
                    scan["live_tests"] = scan["live_tests"][-500:]
                if scan["live_tool_calls"] % 10 == 0:
                    _save_scans_to_disk()
            elif event == "finding":
                scan["live_findings"].append({
                    "title": data.get("title", ""),
                    "severity": data.get("severity", ""),
                    "url": data.get("url", ""),
                    "phase": data.get("phase", ""),
                })
            elif event == "crawl":
                url = data.get("url", "")
                ctype = data.get("type", "page")
                tool = data.get("tool", "")
                scan["live_crawled"].append({"url": url, "type": ctype, "tool": tool})
                label = {"page": "Page", "api": "API", "test": "Test"}.get(ctype, "URL")
                scan["progress"].append(f"Crawled ({label}): {url} (#{data.get('count', 0)})")
            elif event == "paused":
                scan["status"] = "paused"
                scan["progress"].append("Scan paused — waiting for resume...")
                _save_scans_to_disk()
            elif event == "resumed":
                scan["status"] = "running"
                scan["progress"].append("Scan resumed — continuing...")
                _save_scans_to_disk()
            elif event == "out_of_scope":
                url = data.get("url", "")
                if url and url not in [u["url"] for u in scan.get("live_out_of_scope", [])]:
                    scan.setdefault("live_out_of_scope", []).append({
                        "url": url,
                        "tool": data.get("tool", ""),
                        "phase": data.get("phase", ""),
                    })

        router = LLMRouter(models=[model])

        resolved_imports = {}
        for key in ("postman", "postman_env", "burp", "openapi"):
            fname = (api_imports or {}).get(key, "")
            if fname:
                fpath = IMPORTS_DIR / fname
                if fpath.exists():
                    resolved_imports[key] = str(fpath)

        target_dict = {
            "id": scan_id.split("_")[-1],
            "url": target_url,
            "scan_mode": scan_mode,
            "auth": {"type": auth_type, "username": username, "password": password},
            "api_imports": resolved_imports,
        }
        target = load_targets_from_dict(target_dict)

        scan["progress"].append(f"Starting scan with {model}...")
        start = time.perf_counter()
        config_dir = str(BASE / "config")
        findings, metrics = await run_scan(target, model, router, config_dir, on_progress=_on_progress, extra_domains=extra_domains, cancel_flag=cancel_flag, pause_flag=pause_flag, start_from_phase=start_from_phase, initial_findings=initial_findings)
        duration = time.perf_counter() - start

        model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
        filepath = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
        output = save_results(filepath, findings, router.get_cost_summary(), target, model, duration, metrics)

        oos = scan.get("live_out_of_scope", [])
        if oos:
            output["out_of_scope"] = oos
            import json as _json
            with open(filepath, "w") as _f:
                _json.dump(output, _f, indent=2, default=str)

        meta = output.get("metadata", {})
        summary = output.get("summary", {})
        SCANS[scan_id].update({
            "status": "completed",
            "duration": round(duration, 1),
            "cost": meta.get("cost_usd"),
            "findings_count": summary.get("total_findings", len(findings)),
            "result_file": os.path.basename(filepath),
            "progress": SCANS[scan_id]["progress"] + ["Scan completed."],
        })
        _save_scans_to_disk()
    except ScanCancelled:
        duration = time.perf_counter() - start
        model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
        filepath = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
        partial_findings = scan.get("live_findings", [])
        cost_summary = router.get_cost_summary() if router else {}
        save_results(filepath, partial_findings, cost_summary, target, model, duration, metrics={})
        phases_done = len(scan.get("live_phases", []))
        SCANS[scan_id].update({
            "status": "cancelled",
            "duration": round(duration, 1),
            "cost": cost_summary.get("total_cost_usd") if isinstance(cost_summary, dict) else None,
            "findings_count": len(partial_findings),
            "result_file": os.path.basename(filepath),
            "phases_completed": phases_done,
            "progress": SCANS[scan_id]["progress"] + ["Scan cancelled by user."],
        })
        _save_scans_to_disk()
    except Exception as e:
        duration = time.perf_counter() - start
        model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
        filepath = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
        partial_findings = scan.get("live_findings", [])
        cost_summary = router.get_cost_summary() if router else {}
        try:
            save_results(filepath, partial_findings, cost_summary, target, model, duration, metrics={})
        except Exception:
            filepath = None
        phases_done = len(scan.get("live_phases", []))
        SCANS[scan_id].update({
            "status": "error",
            "error": str(e),
            "duration": round(duration, 1),
            "cost": cost_summary.get("total_cost_usd") if isinstance(cost_summary, dict) else None,
            "findings_count": len(partial_findings),
            "result_file": os.path.basename(filepath) if filepath else None,
            "phases_completed": phases_done,
            "progress": SCANS[scan_id]["progress"] + [f"Error: {e}"],
        })
        _save_scans_to_disk()


@app.get("/api/scan/{scan_id}", tags=["Scans"])
async def get_scan_status(scan_id: str, creds=Depends(_verify)):
    if scan_id in SCANS:
        s = SCANS[scan_id]
        return {
            "scan_id": scan_id,
            "status": s.get("status"),
            "target": s.get("target_url", s.get("target", "")),
            "model": s.get("model"),
            "scan_mode": s.get("scan_mode", ""),
            "started": s.get("started"),
            "progress": s.get("progress", []),
            "current_phase": s.get("current_phase", ""),
            "result_file": s.get("result_file"),
            "error": s.get("error"),
            "duration": s.get("duration"),
            "cost": s.get("cost"),
            "findings_count": s.get("findings_count", len(s.get("live_findings", []))),
            "phases_completed": s.get("phases_completed", len(s.get("live_phases", []))),
        }
    fname = _find_result_file(scan_id)
    if fname:
        return {"status": "completed", "result_file": os.path.basename(fname)}
    return JSONResponse({"error": "Scan not found"}, status_code=404)


@app.get("/api/scan/{scan_id}/live", tags=["Scans"])
async def get_scan_live(scan_id: str, since_test: int = 0, since_finding: int = 0, creds=Depends(_verify)):
    """Return live scan activity: recent tests, findings, and phases since given offsets."""
    if scan_id not in SCANS:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    s = SCANS[scan_id]
    tests = s.get("live_tests", [])
    findings = s.get("live_findings", [])
    return {
        "status": s.get("status"),
        "current_phase": s.get("current_phase", ""),
        "phases": s.get("live_phases", []),
        "tests": tests[since_test:],
        "tests_total": len(tests),
        "findings": findings[since_finding:],
        "findings_total": len(findings),
        "pages_crawled": len(s.get("live_crawled", [])),
        "crawled_urls": s.get("live_crawled", []),
        "tool_calls": s.get("live_tool_calls", 0),
        "out_of_scope": s.get("live_out_of_scope", []),
    }


@app.post("/api/scan/{scan_id}/stop", tags=["Scans"])
async def stop_scan(scan_id: str, creds=Depends(_verify)):
    """Stop a running scan. Sets a cancellation flag that the agent checks between steps."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = SCANS[scan_id]
    if s.get("status") not in ("running", "paused", "pausing"):
        raise HTTPException(status_code=400, detail=f"Scan is not running (status: {s.get('status')})")
    flag = CANCEL_FLAGS.get(scan_id)
    if flag:
        flag.set()
    pause = PAUSE_FLAGS.get(scan_id)
    if pause:
        pause.clear()
    s["status"] = "stopping"
    s["progress"] = s.get("progress", []) + ["Stop requested by user — cancelling after current step..."]
    _save_scans_to_disk()
    return {"scan_id": scan_id, "status": "stopping", "message": "Scan stop requested. It will halt after the current step completes."}


@app.post("/api/scan/{scan_id}/pause", tags=["Scans"])
async def pause_scan(scan_id: str, creds=Depends(_verify)):
    """Pause a running scan. The agent will pause after the current LLM step."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = SCANS[scan_id]
    if s.get("status") not in ("running",):
        raise HTTPException(status_code=400, detail=f"Scan is not running (status: {s.get('status')})")
    flag = PAUSE_FLAGS.get(scan_id)
    if flag:
        flag.set()
    s["status"] = "pausing"
    s["progress"] = s.get("progress", []) + ["Pause requested — will pause after current step..."]
    _save_scans_to_disk()
    return {"scan_id": scan_id, "status": "pausing", "message": "Pause requested. Scan will pause after the current step completes."}


@app.post("/api/scan/{scan_id}/resume", tags=["Scans"])
async def resume_scan(scan_id: str, creds=Depends(_verify)):
    """Resume a paused scan."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = SCANS[scan_id]
    if s.get("status") not in ("paused", "pausing"):
        raise HTTPException(status_code=400, detail=f"Scan is not paused (status: {s.get('status')})")
    flag = PAUSE_FLAGS.get(scan_id)
    if flag:
        flag.clear()
    s["status"] = "running"
    s["progress"] = s.get("progress", []) + ["Scan resumed by user"]
    _save_scans_to_disk()
    return {"scan_id": scan_id, "status": "running"}


def _load_partial_findings(scan_info: dict) -> list[dict]:
    """Load partial findings from a scan's result file (if any)."""
    rf = scan_info.get("result_file")
    if not rf:
        return []
    try:
        data = json.loads((RAW_DIR / rf).read_text(encoding="utf-8"))
        return data.get("findings", [])
    except Exception:
        return []


def _get_phases_completed(scan_info: dict) -> int:
    """Determine how many LLM phases a scan completed."""
    pc = scan_info.get("phases_completed")
    if pc is not None:
        return int(pc)
    progress = scan_info.get("progress", [])
    count = 0
    for line in progress:
        if "] Phase:" in line and "(skipped)" not in line:
            count += 1
        elif line.startswith("[") and "/" in line.split("]")[0]:
            count += 1
    return count


def _extract_scan_params(old: dict) -> dict:
    """Extract reusable parameters from an existing scan record."""
    return {
        "target_url": old.get("target_url", ""),
        "model": old.get("model", ""),
        "model_name": old.get("model_name", old.get("model", "")),
        "scan_mode": old.get("scan_mode") or _infer_scan_mode(old),
        "auth_type": old.get("auth_type", "auto"),
        "username": old.get("_username", ""),
        "password": old.get("_password", ""),
        "api_imports": old.get("_api_imports", {}) or {},
        "extra_domains": old.get("_extra_domains", []) or [],
    }


@app.post("/api/scan/{scan_id}/retry", tags=["Scans"])
async def retry_scan(scan_id: str, request: Request, creds=Depends(_verify)):
    """Re-run an errored/cancelled scan in-place.  Tries to continue from
    the last completed phase when possible; falls back to full re-run.
    Accepts optional JSON body: {scan_mode, model, force_restart: bool}."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    old = SCANS[scan_id]
    if old.get("status") not in ("error", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Only errored/cancelled scans can be retried (status: {old.get('status')})")

    params = _extract_scan_params(old)
    if not params["target_url"] or not params["model"]:
        raise HTTPException(status_code=400, detail="Original scan parameters missing — cannot retry")

    overrides = {}
    try:
        body = await request.body()
        if body:
            overrides = json.loads(body)
    except Exception:
        pass

    scan_mode = overrides.get("scan_mode") or params["scan_mode"]
    model = overrides.get("model") or params["model"]
    force_restart = overrides.get("force_restart", False)

    start_from = 0
    prior_findings: list[dict] = []
    if not force_restart:
        phases_done = _get_phases_completed(old)
        if phases_done > 0:
            prior_findings = _load_partial_findings(old)
            start_from = phases_done

    mode_label = "continuing" if start_from > 0 else "restarting"
    phase_msg = f" from phase {start_from + 1}" if start_from > 0 else ""

    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[scan_id] = cancel_flag
    PAUSE_FLAGS[scan_id] = pause_flag

    old.update({
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [f"Retry ({mode_label}{phase_msg}, mode: {scan_mode})..."],
        "error": None,
        "duration": None,
        "cost": None,
        "findings_count": None,
        "result_file": None,
        "scan_mode": scan_mode,
    })
    _save_scans_to_disk()

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(scan_id, params["target_url"], params["username"], params["password"],
              model, scan_mode, params["auth_type"], params["api_imports"],
              params["extra_domains"], cancel_flag, pause_flag, start_from, prior_findings),
        daemon=True,
    )
    thread.start()
    return {
        "scan_id": scan_id,
        "status": "started",
        "mode": mode_label,
        "start_from_phase": start_from,
        "prior_findings": len(prior_findings),
    }


@app.post("/api/scan/{scan_id}/rescan", tags=["Scans"])
async def rescan(scan_id: str, request: Request, creds=Depends(_verify)):
    """Create a NEW scan with the same parameters as an existing (typically
    completed) scan.  Returns the new scan_id."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    old = SCANS[scan_id]

    params = _extract_scan_params(old)
    if not params["target_url"] or not params["model"]:
        raise HTTPException(status_code=400, detail="Original scan parameters missing — cannot rescan")

    overrides = {}
    try:
        body = await request.body()
        if body:
            overrides = json.loads(body)
    except Exception:
        pass

    scan_mode = overrides.get("scan_mode") or params["scan_mode"]
    model = overrides.get("model") or params["model"]

    new_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[new_id] = cancel_flag
    PAUSE_FLAGS[new_id] = pause_flag

    SCANS[new_id] = {
        "target_url": params["target_url"],
        "model": model,
        "model_name": params["model_name"],
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [f"Re-scan of {scan_id} (mode: {scan_mode})..."],
        "scan_mode": scan_mode,
        "auth_type": params["auth_type"],
        "_username": params["username"],
        "_password": params["password"],
        "_api_imports": params["api_imports"],
        "_extra_domains": params["extra_domains"],
    }
    _save_scans_to_disk()

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(new_id, params["target_url"], params["username"], params["password"],
              model, scan_mode, params["auth_type"], params["api_imports"],
              params["extra_domains"], cancel_flag, pause_flag),
        daemon=True,
    )
    thread.start()
    return {"scan_id": new_id, "status": "started", "parent_scan": scan_id}


@app.delete("/api/scan/{scan_id}", tags=["Scans"])
async def delete_scan(scan_id: str, creds=Depends(_verify)):
    """Stop (if running) and fully delete a scan, its result files, and reports."""
    deleted = []
    if scan_id in SCANS:
        cur_status = SCANS[scan_id].get("status")
        if cur_status in ("running", "paused", "pausing", "stopping"):
            flag = CANCEL_FLAGS.get(scan_id)
            if flag:
                flag.set()
            pause = PAUSE_FLAGS.get(scan_id)
            if pause:
                pause.clear()
            SCANS[scan_id]["status"] = "cancelled"
            deleted.append("stopped_running_scan")
            await asyncio.sleep(0.5)
        result_file = SCANS[scan_id].get("result_file")
        del SCANS[scan_id]
        CANCEL_FLAGS.pop(scan_id, None)
        PAUSE_FLAGS.pop(scan_id, None)
        deleted.append("scan_record")
        if result_file:
            fpath = RAW_DIR / result_file
            if fpath.exists():
                fpath.unlink()
                deleted.append(str(result_file))
    for f in RAW_DIR.glob("*.json"):
        if scan_id in f.stem:
            f.unlink()
            deleted.append(f.name)
    for f in REPORTS_DIR.glob("*.pdf"):
        if scan_id in f.stem or any(scan_id in part for part in f.stem.split("_")):
            f.unlink()
            deleted.append(f.name)
    if not deleted:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    _save_scans_to_disk()
    return {"deleted": deleted}


@app.delete("/api/scans", tags=["Scans"])
async def delete_all_scans(creds=Depends(_verify)):
    """Stop all running scans and delete all scan records, result files, and reports."""
    for sid, info in list(SCANS.items()):
        if info.get("status") in ("running", "paused", "pausing", "stopping"):
            flag = CANCEL_FLAGS.get(sid)
            if flag:
                flag.set()
            pause = PAUSE_FLAGS.get(sid)
            if pause:
                pause.clear()
    await asyncio.sleep(0.5)
    SCANS.clear()
    CANCEL_FLAGS.clear()
    PAUSE_FLAGS.clear()
    count = 0
    for f in RAW_DIR.glob("*.json"):
        f.unlink()
        count += 1
    for f in REPORTS_DIR.glob("*.pdf"):
        f.unlink()
        count += 1
    _save_scans_to_disk()
    return {"deleted_files": count, "status": "cleared"}


@app.get("/api/results/{scan_id}", tags=["Results"])
async def get_results(scan_id: str, creds=Depends(_verify)):
    fname = _find_result_file(scan_id)
    if not fname:
        return JSONResponse({"error": "Results not found"}, status_code=404)

    data = json.loads(Path(fname).read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    test_log = data.get("summary", {}).get("test_log", [])
    meta = data.get("metadata", {})
    summary = data.get("summary", {})

    ai_findings = []
    triaged_findings = []
    for f in findings:
        ai_findings.append({
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "owasp": f.get("owasp_category", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "confidence": f.get("confidence", ""),
        })
        triaged = triage_classify(f, test_log)
        finding_entry = {
            "title": triaged.get("title", ""),
            "ai_severity": f.get("severity", ""),
            "final_severity": triaged.get("final_severity", ""),
            "verdict": triaged.get("verdict", ""),
            "reason": triaged.get("reason", ""),
            "confidence_score": triaged.get("confidence_score"),
            "url": triaged.get("url", ""),
            "cwe": triaged.get("cwe", ""),
            "cvss": triaged.get("cvss"),
            "cvss_rationale": triaged.get("cvss_rationale", ""),
            "cve": triaged.get("cve", ""),
            "verified": f.get("verified", False),
            "verification_method": triaged.get("verification_method", "none"),
            "verification_evidence": triaged.get("verification_evidence", ""),
        }

        overrides = scan.get("cvss_overrides", {}) if scan_id in SCANS else {}
        key = f"{triaged.get('title', '')}||{triaged.get('url', '')}"
        if key in overrides:
            finding_entry["cvss_override"] = overrides[key]["cvss"]
            finding_entry["cvss_override_note"] = overrides[key].get("note", "")
        triaged_findings.append(finding_entry)

    crawled = _extract_crawled(summary, test_log)
    payloads_by_endpoint = _extract_payloads_by_endpoint(test_log)

    return {
        "metadata": {
            "target": data.get("target", ""),
            "model": meta.get("model", ""),
            "scan_mode": data.get("scan_mode", ""),
            "duration_seconds": meta.get("scan_duration_seconds"),
            "cost_usd": meta.get("cost_usd"),
            "total_tokens": meta.get("total_tokens"),
            "llm_calls": meta.get("llm_calls"),
            "cost_summary_by_model": meta.get("cost_summary_by_model", []),
        },
        "coverage": {
            "pages_crawled": summary.get("pages_crawled", 0),
            "forms_found": summary.get("forms_found", 0),
            "api_endpoints": summary.get("api_endpoints_found", 0),
            "auth_pages": summary.get("auth_pages_detected", 0),
            "phases_completed": summary.get("phases_completed", 0),
            "total_tool_calls": summary.get("total_tool_calls", 0),
            "total_tests": len(test_log),
            "verification": summary.get("verification", {}),
        },
        "severity_breakdown": summary.get("severity_breakdown", {}),
        "owasp_breakdown": summary.get("owasp_breakdown", {}),
        "phase_log": summary.get("phase_log", []),
        "ai_findings": ai_findings,
        "triaged_findings": triaged_findings,
        "crawled_endpoints": crawled,
        "payloads_by_endpoint": payloads_by_endpoint,
        "out_of_scope": data.get("out_of_scope", []),
    }


@app.get("/api/results/{scan_id}/download", tags=["Results"])
async def download_raw(scan_id: str, creds=Depends(_verify)):
    fname = _find_result_file(scan_id)
    if not fname:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return FileResponse(fname, filename=os.path.basename(fname), media_type="application/json")


@app.post("/api/results/{scan_id}/cvss-override", tags=["Results"])
async def cvss_override(scan_id: str, request: Request, creds=Depends(_verify)):
    """Save a CVSS override for a specific finding in a scan."""
    body = await request.json()
    title = body.get("title", "")
    url = body.get("url", "")
    cvss_value = body.get("cvss")
    note = body.get("note", "")

    if cvss_value is None or not title:
        raise HTTPException(400, "title and cvss are required")
    try:
        cvss_value = round(float(cvss_value), 1)
        if not (0.0 <= cvss_value <= 10.0):
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(400, "cvss must be a number between 0.0 and 10.0")

    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    if "cvss_overrides" not in scan:
        scan["cvss_overrides"] = {}

    key = f"{title}||{url}"
    scan["cvss_overrides"][key] = {"cvss": cvss_value, "note": note}

    # Persist to disk
    scan_dir = Path("results/raw")
    override_file = scan_dir / f"{scan_id}_cvss_overrides.json"
    try:
        import json as _json
        override_file.write_text(_json.dumps(scan["cvss_overrides"], indent=2))
    except Exception as e:
        logger.warning("Failed to persist CVSS override: %s", e)

    return {"status": "ok", "key": key, "cvss": cvss_value, "note": note}


@app.post("/api/results/{scan_id}/report", tags=["Results"])
async def generate_report(scan_id: str, creds=Depends(_verify)):
    fname = _find_result_file(scan_id)
    if not fname:
        return JSONResponse({"error": "Not found"}, status_code=404)

    try:
        data = json.loads(Path(fname).read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        test_log = data.get("summary", {}).get("test_log", [])

        import scripts.report_generator as rg
        classified = [triage_classify(f, test_log) for f in findings]
        model_key = data.get("model", "") or data.get("metadata", {}).get("model", "unknown")

        orig_out = rg.OUT_DIR
        rg.OUT_DIR = str(REPORTS_DIR)
        result = rg.gen_report(model_key, classified, data)
        rg.OUT_DIR = orig_out

        if result:
            pdf_path = result[0]
            return {"pdf": f"/api/reports/{os.path.basename(pdf_path)}"}
        return JSONResponse({"error": "No findings to report"}, status_code=400)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"error": f"Report generation failed: {str(e)}"}, status_code=500)


@app.get("/api/reports/{filename}", tags=["Results"])
async def download_report(filename: str, creds=Depends(_verify)):
    fpath = REPORTS_DIR / filename
    if not fpath.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    return FileResponse(str(fpath), filename=filename, media_type="application/pdf")


@app.get("/api/results/{scan_id}/payloads", tags=["Results"])
async def download_payloads(scan_id: str, creds=Depends(_verify)):
    """Download all payloads tested per phase as a JSON file."""
    fname = _find_result_file(scan_id)
    if not fname:
        return JSONResponse({"error": "Not found"}, status_code=404)

    data = json.loads(Path(fname).read_text(encoding="utf-8"))
    test_log = data.get("summary", {}).get("test_log", [])
    phase_log = data.get("summary", {}).get("phase_log", [])
    target = data.get("target", "")
    model = data.get("model", "")

    phases_map = {}
    for entry in test_log:
        pid = entry.get("phase", "unknown")
        if pid not in phases_map:
            phases_map[pid] = {"phase_id": pid, "phase_name": "", "payloads": []}
        phases_map[pid]["payloads"].append({
            "tool": entry.get("tool", ""),
            "request": entry.get("request", {}),
            "response": entry.get("response_summary", {}),
        })

    for p in phase_log:
        pid = p.get("phase", "")
        if pid in phases_map:
            phases_map[pid]["phase_name"] = p.get("name", "")

    output = {
        "scan_id": scan_id,
        "target": target,
        "model": model,
        "total_payloads": len(test_log),
        "phases": list(phases_map.values()),
    }

    out_file = RAW_DIR / f"payloads_{scan_id}.json"
    out_file.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    return FileResponse(str(out_file), filename=f"payloads_{scan_id}.json", media_type="application/json")


@app.get("/api/scan/{scan_id}/payloads-live", tags=["Scans"])
async def download_live_payloads(scan_id: str, creds=Depends(_verify)):
    """Download all live payloads captured so far (works for running or completed scans)."""
    if scan_id not in SCANS:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    s = SCANS[scan_id]
    tests = s.get("live_tests", [])
    phases = s.get("live_phases", [])
    output = {
        "scan_id": scan_id,
        "target": s.get("target_url", ""),
        "model": s.get("model", ""),
        "status": s.get("status", ""),
        "total_activity": len(tests),
        "phases_completed": [{"name": p["name"], "tool_calls": p["tool_calls"], "findings": p["findings"]} for p in phases],
        "activity_log": tests,
    }
    return JSONResponse(output)


def _find_result_file(scan_id: str) -> str | None:
    if scan_id in SCANS and SCANS[scan_id].get("result_file"):
        fpath = RAW_DIR / SCANS[scan_id]["result_file"]
        if fpath.exists():
            return str(fpath)
    for f in RAW_DIR.glob("*.json"):
        if scan_id in f.stem:
            return str(f)
    if (RAW_DIR / f"{scan_id}.json").exists():
        return str(RAW_DIR / f"{scan_id}.json")
    return None


def _extract_crawled(summary: dict, test_log: list) -> list[dict]:
    urls = set()
    crawled = []
    for t in test_log:
        req = t.get("request", {})
        url = req.get("url", "") or req.get("endpoint", "")
        method = req.get("method", "GET")
        if url and url not in urls:
            urls.add(url)
            resp = t.get("response_summary", {})
            status = resp.get("status", "") if isinstance(resp, dict) else ""
            crawled.append({"url": url, "method": method, "status": str(status)})
    return crawled


def _extract_payloads_by_endpoint(test_log: list) -> list[dict]:
    from collections import defaultdict
    ep_map = defaultdict(list)
    for t in test_log:
        req = t.get("request", {})
        if not isinstance(req, dict):
            continue
        url = (req.get("url", "") or req.get("endpoint", "")).split("?")[0]
        method = req.get("method", "GET")
        if not url:
            continue
        key = f"{method} {url}"
        raw_headers = req.get("headers", {})
        if isinstance(raw_headers, dict):
            headers_info = {k: _truncate(str(v), 60) for k, v in list(raw_headers.items())[:5]}
        else:
            headers_info = {"raw": _truncate(str(raw_headers), 200)}
        payload_info = {
            "full_url": req.get("url", ""),
            "method": method,
            "body": _truncate(str(req.get("body", "")), 200),
            "headers": headers_info,
        }
        resp = t.get("response_summary", {})
        if isinstance(resp, dict):
            payload_info["status"] = resp.get("status", "")
            payload_info["anomaly"] = t.get("anomaly", False)
        ep_map[key].append(payload_info)

    result = []
    for ep, payloads in sorted(ep_map.items()):
        result.append({"endpoint": ep, "payload_count": len(payloads), "payloads": payloads[:50]})
    return result


def _truncate(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
