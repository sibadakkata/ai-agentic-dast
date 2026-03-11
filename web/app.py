"""FastAPI web UI for the AI Agentic DAST Scanner."""
from __future__ import annotations

import asyncio
import glob
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanners.ai_agent.agent import run_scan, save_results
from scanners.ai_agent.auth import load_targets_from_dict
from scanners.ai_agent.llm_config import LLMRouter, check_connectivity
from scripts.triage_engine import classify as triage_classify

app = FastAPI(title="AI DAST Scanner")

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
RAW_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SCANS: dict[str, dict] = {}

MODELS = [
    {"id": "bedrock/mistral.mistral-small-2402-v1:0", "name": "Mistral Small (cheapest)", "cost": "~$0.10/$0.30 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "name": "Claude Haiku 4.5 (recommended)", "cost": "~$0.80/$4 per 1M tokens", "provider": "Bedrock"},
    {"id": "bedrock/us.anthropic.claude-sonnet-4-6", "name": "Claude Sonnet 4.6 (best quality)", "cost": "~$3/$15 per 1M tokens", "provider": "Bedrock"},
]


@app.get("/", response_class=HTMLResponse)
async def index(creds=Depends(_verify)):
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/models")
async def get_models(creds=Depends(_verify)):
    return MODELS


@app.get("/api/scans")
async def list_scans(creds=Depends(_verify)):
    scans = []
    for scan_id, info in sorted(SCANS.items(), key=lambda x: x[1].get("started", ""), reverse=True):
        scans.append({
            "id": scan_id,
            "target": info.get("target_url", ""),
            "model": info.get("model_name", ""),
            "status": info.get("status", "unknown"),
            "started": info.get("started", ""),
            "duration": info.get("duration"),
            "cost": info.get("cost"),
            "findings_count": info.get("findings_count"),
        })
    for f in sorted(RAW_DIR.glob("aiagent_*.json"), key=os.path.getmtime, reverse=True):
        fid = f.stem
        if any(s["id"] == fid for s in scans):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        meta = data.get("metadata", {})
        summary = data.get("summary", {})
        scans.append({
            "id": fid,
            "target": data.get("target", ""),
            "model": meta.get("model", ""),
            "status": "completed",
            "started": meta.get("timestamp", ""),
            "duration": meta.get("scan_duration_seconds"),
            "cost": meta.get("cost_usd"),
            "findings_count": summary.get("total_findings", len(data.get("findings", []))),
        })
    return scans


IMPORTS_DIR = BASE / "imports"
IMPORTS_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/upload")
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


@app.post("/api/scan")
async def start_scan(request: Request, background_tasks: BackgroundTasks, creds=Depends(_verify)):
    body = await request.json()
    target_url = body.get("target_url", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    model = body.get("model", "claude-haiku-4-5-20251001")
    scan_mode = body.get("scan_mode", "both")
    auth_type = body.get("auth_type", "auto")
    api_imports = body.get("api_imports", {}) or {}

    if not target_url:
        return JSONResponse({"error": "Target URL is required"}, status_code=400)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    model_name = next((m["name"] for m in MODELS if m["id"] == model), model)

    SCANS[scan_id] = {
        "target_url": target_url,
        "model": model,
        "model_name": model_name,
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [],
    }

    background_tasks.add_task(
        _run_scan_task, scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports
    )
    return {"scan_id": scan_id, "status": "started"}


async def _run_scan_task(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports=None):
    try:
        SCANS[scan_id]["progress"].append("Initializing LLM router...")
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

        SCANS[scan_id]["progress"].append(f"Starting scan with {model}...")
        start = time.perf_counter()
        config_dir = str(BASE / "config")
        findings, metrics = await run_scan(target, model, router, config_dir)
        duration = time.perf_counter() - start

        model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
        filepath = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
        output = save_results(filepath, findings, router.get_cost_summary(), target, model, duration, metrics)

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
    except Exception as e:
        SCANS[scan_id].update({
            "status": "error",
            "error": str(e),
            "progress": SCANS[scan_id]["progress"] + [f"Error: {e}"],
        })


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str, creds=Depends(_verify)):
    if scan_id in SCANS:
        return SCANS[scan_id]
    fname = _find_result_file(scan_id)
    if fname:
        return {"status": "completed", "result_file": os.path.basename(fname)}
    return JSONResponse({"error": "Scan not found"}, status_code=404)


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str, creds=Depends(_verify)):
    """Delete a scan and its result/report files."""
    deleted = []
    if scan_id in SCANS:
        result_file = SCANS[scan_id].get("result_file")
        del SCANS[scan_id]
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
    return {"deleted": deleted}


@app.delete("/api/scans")
async def delete_all_scans(creds=Depends(_verify)):
    """Delete all scan records and result files."""
    count = 0
    SCANS.clear()
    for f in RAW_DIR.glob("*.json"):
        f.unlink()
        count += 1
    for f in REPORTS_DIR.glob("*.pdf"):
        f.unlink()
        count += 1
    return {"deleted_files": count, "status": "cleared"}


@app.get("/api/results/{scan_id}")
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
        triaged_findings.append({
            "title": triaged.get("title", ""),
            "ai_severity": f.get("severity", ""),
            "final_severity": triaged.get("final_severity", ""),
            "verdict": triaged.get("verdict", ""),
            "reason": triaged.get("reason", ""),
            "confidence_score": triaged.get("confidence_score"),
            "url": triaged.get("url", ""),
            "cwe": triaged.get("cwe", ""),
            "cvss": triaged.get("cvss"),
            "cve": triaged.get("cve", ""),
        })

    crawled = _extract_crawled(summary, test_log)
    payloads_by_endpoint = _extract_payloads_by_endpoint(test_log)

    return {
        "metadata": {
            "model": meta.get("model", ""),
            "duration_seconds": meta.get("scan_duration_seconds"),
            "cost_usd": meta.get("cost_usd"),
            "total_tokens": meta.get("total_tokens"),
            "llm_calls": meta.get("llm_calls"),
        },
        "coverage": {
            "pages_crawled": summary.get("pages_crawled", 0),
            "forms_found": summary.get("forms_found", 0),
            "api_endpoints": summary.get("api_endpoints_found", 0),
            "total_tests": len(test_log),
        },
        "ai_findings": ai_findings,
        "triaged_findings": triaged_findings,
        "crawled_endpoints": crawled,
        "payloads_by_endpoint": payloads_by_endpoint,
    }


@app.get("/api/results/{scan_id}/download")
async def download_raw(scan_id: str, creds=Depends(_verify)):
    fname = _find_result_file(scan_id)
    if not fname:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return FileResponse(fname, filename=os.path.basename(fname), media_type="application/json")


@app.post("/api/results/{scan_id}/report")
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


@app.get("/api/reports/{filename}")
async def download_report(filename: str, creds=Depends(_verify)):
    fpath = REPORTS_DIR / filename
    if not fpath.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    return FileResponse(str(fpath), filename=filename, media_type="application/pdf")


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
        url = (req.get("url", "") or req.get("endpoint", "")).split("?")[0]
        method = req.get("method", "GET")
        if not url:
            continue
        key = f"{method} {url}"
        payload_info = {
            "full_url": req.get("url", ""),
            "method": method,
            "body": _truncate(str(req.get("body", "")), 200),
            "headers": {k: _truncate(str(v), 60) for k, v in list(req.get("headers", {}).items())[:5]},
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
