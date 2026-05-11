"""FastAPI web UI for the AI Agentic Web Scanner."""
from __future__ import annotations

import asyncio
import glob
import hashlib
import logging
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect, status
from io import BytesIO

from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logger = logging.getLogger(__name__)

from scanners.ai_agent.agent import run_scan, save_results, ScanCancelled
from scanners.ai_agent.severity import classify_severity
from scanners.ai_agent.api_import import (
    parse_postman_collection,
    parse_openapi_spec,
    EndpointRegistry,
)
from scanners.ai_agent.auth import load_targets_from_dict
from scanners.ai_agent.llm_config import LLMRouter, check_connectivity
from scanners.ai_agent.model_discovery import (
    discover_models,
    get_cached_models,
    get_cache_meta,
)
from scripts.triage_engine import classify as triage_classify

from starlette.middleware.gzip import GZipMiddleware

app = FastAPI(
    title="AI Agentic Web Scanner",
    description="LLM-powered Dynamic Application Security Testing API. "
    "Start scans, poll status, download results and PDF reports programmatically.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception):
    """Catch any unhandled exception and return a clean JSON error instead of a
    raw 500 HTML page.  HTTPExceptions are re-raised so FastAPI handles them."""
    if isinstance(exc, HTTPException):
        raise exc
    logger.error("Unhandled %s on %s %s: %s", type(exc).__name__,
                 request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__,
                 "detail": "An internal error occurred. Check server logs for details."},
    )

# --- Auth (cookie sessions + Basic Auth fallback for API clients) -------------
_security = HTTPBasic(auto_error=False)
_AUTH_USER = os.environ.get("DAST_AUTH_USER", "dast-admin")
_AUTH_PASS = os.environ.get("DAST_AUTH_PASS", "changeme")
_SESSION_SECRET = os.environ.get("DAST_SESSION_SECRET", secrets.token_hex(32))
_SESSION_COOKIE = "dast_session"
_SESSION_MAX_AGE = 86400 * 7  # 7 days


def _create_session_token(username: str) -> str:
    ts = str(int(time.time()))
    payload = f"{username}:{ts}"
    sig = hmac.new(_SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def _verify_session_token(token: str) -> str | None:
    if not token:
        return None
    parts = token.split(":")
    if len(parts) != 3:
        return None
    username, ts_str, sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return None
    if time.time() - ts > _SESSION_MAX_AGE:
        return None
    expected = hmac.new(_SESSION_SECRET.encode(), f"{username}:{ts_str}".encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    return username


def _check_basic_auth(credentials: HTTPBasicCredentials | None) -> bool:
    if not credentials:
        return False
    user_ok = hmac.compare_digest(credentials.username.encode(), _AUTH_USER.encode())
    pass_ok = hmac.compare_digest(credentials.password.encode(), _AUTH_PASS.encode())
    return user_ok and pass_ok


async def _verify(request: Request, credentials: HTTPBasicCredentials | None = Depends(_security)):
    """Authenticate via session cookie (browser) or Basic Auth (API/curl)."""
    cookie = request.cookies.get(_SESSION_COOKIE)
    if cookie and _verify_session_token(cookie):
        return True
    if _check_basic_auth(credentials):
        return True
    if credentials:
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})


async def _verify_or_redirect(request: Request, credentials: HTTPBasicCredentials | None = Depends(_security)):
    """For browser pages: redirect to /login if not authenticated."""
    cookie = request.cookies.get(_SESSION_COOKIE)
    if cookie and _verify_session_token(cookie):
        return True
    if _check_basic_auth(credentials):
        return True
    return False

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.middleware("http")
async def _no_cache_static(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path in ("/", "/login"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


BASE = Path(__file__).resolve().parent.parent
RAW_DIR = BASE / "results" / "raw"
REPORTS_DIR = BASE / "results" / "reports"
RAW_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from web import db as scandb
scandb.init()

SCANS: dict[str, dict] = {}
CANCEL_FLAGS: dict[str, threading.Event] = {}
PAUSE_FLAGS: dict[str, threading.Event] = {}

_RESULTS_CACHE: dict[str, dict] = {}
_RESULTS_CACHE_MAX = 20

import queue as _queue

INTERACTIVE_BROWSERS: dict[str, dict] = {}
# {scan_id: {
#   "screenshot_b64": "",        latest JPEG screenshot (overwritten each frame)
#   "events": queue.Queue(),     input events from frontend → Playwright
#   "active": threading.Event(), set while interactive session is live
#   "done": threading.Event(),   set when user clicks "I'm logged in"
#   "viewport": (1280, 720),
# }}

_FORCE_CANCEL_TIMEOUT = 10  # seconds before force-transitioning "stopping" → "cancelled"


def _schedule_force_cancel(scan_id: str):
    """Background thread that force-transitions a scan from 'stopping' to 'cancelled'
    if the graceful stop doesn't complete within the timeout."""
    def _force():
        time.sleep(_FORCE_CANCEL_TIMEOUT)
        s = SCANS.get(scan_id)
        if s and s.get("status") == "stopping":
            logger.warning("Force-cancelling scan %s (stuck in stopping for %ds)", scan_id, _FORCE_CANCEL_TIMEOUT)
            partial_findings = s.get("live_findings", [])
            phases_done = len(s.get("live_phases", []))
            s.update({
                "status": "cancelled",
                "error": f"Force-stopped: LLM call did not respond within {_FORCE_CANCEL_TIMEOUT}s. {len(partial_findings)} finding(s) preserved from {phases_done} phase(s).",
                "findings_count": len(partial_findings),
                "progress": s.get("progress", []) + ["Force-cancelled (LLM call did not respond to stop in time)."],
            })
            CANCEL_FLAGS.pop(scan_id, None)
            PAUSE_FLAGS.pop(scan_id, None)
            _save_scan(scan_id)
    t = threading.Thread(target=_force, daemon=True)
    t.start()


def _normalize_severity(raw) -> str:
    """Normalize AI-generated severity strings to standard levels."""
    if not isinstance(raw, str):
        raw = str(raw) if raw else ""
    s = raw.lower().strip()
    if "critical" in s:
        return "Critical"
    if "high" in s:
        return "High"
    if "medium" in s:
        return "Medium"
    if "low" in s:
        return "Low"
    if "info" in s or not s:
        return "Info"
    return raw.title()


def _normalize_verdict(raw) -> str:
    """Map raw AI verdicts to standard triage verdicts."""
    if not isinstance(raw, str):
        raw = str(raw) if raw else ""
    v = raw.upper().strip()
    _MAP = {
        "CONFIRMED": "TRUE_POSITIVE",
        "DISPROVED": "FALSE_POSITIVE",
        "UNVERIFIED": "UNVERIFIED",
        "INCONCLUSIVE": "INCONCLUSIVE",
    }
    return _MAP.get(v, v)


def _load_scans_from_disk():
    """Restore scan metadata from SQLite on startup.

    Also handles one-time migration from the old JSON files if needed.
    """
    _old_meta = BASE / "results" / "scans_meta.json"
    _old_ledger = BASE / "results" / "cost_ledger.json"
    if scandb.scan_count() == 0 and _old_meta.exists():
        scandb.migrate_from_json(_old_meta, _old_ledger)

    data = scandb.load_all_scans()
    dirty = False
    for scan_id, info in data.items():
        if info.get("status") == "running":
            info["status"] = "error"
            info["error"] = "Server restarted during scan"
            progress = info.get("progress", [])
            progress.append("--- Container stopped/restarted during scan ---")
            info["progress"] = progress
            dirty = True
            try:
                raw = scandb.get_scan_result(scan_id)
                if raw:
                    partial = json.loads(raw)
                    fc = len(partial.get("findings", []))
                    if fc > 0:
                        info["findings_count"] = fc
                        progress.append(f"Recovered {fc} partial finding(s) from checkpoint.")
            except Exception:
                pass
        elif info.get("status") in ("stopping", "paused", "pausing"):
            info["status"] = "cancelled"
            info["error"] = "Container restarted while scan was " + info.get("status", "active") + ". Partial results may be available."
            progress = info.get("progress", [])
            progress.append("--- Container restarted — marked as cancelled ---")
            info["progress"] = progress
            dirty = True
        SCANS[scan_id] = info

    for scan_id in list(SCANS.keys()):
        # One-time: legacy CVSS override sidecar (now stored inside scan row JSON in SQLite)
        override_file = Path("results/raw") / f"{scan_id}_cvss_overrides.json"
        if override_file.exists() and not SCANS[scan_id].get("cvss_overrides"):
            try:
                SCANS[scan_id]["cvss_overrides"] = json.loads(
                    override_file.read_text(encoding="utf-8"))
                dirty = True
            except Exception:
                pass
        # Clean up stale auth/interactive state from non-running scans
        if SCANS[scan_id].get("status") not in ("running", "paused", "pausing"):
            if SCANS[scan_id].pop("auth_challenge", None):
                dirty = True
            if SCANS[scan_id].pop("interactive_browser", None):
                dirty = True

    if dirty:
        _save_scans_to_disk()

    _backfill_scan_results_from_disk()

    if scandb.get_cost_ledger().get("all_time_cost", 0) == 0 and SCANS:
        bootstrap_cost = sum(s.get("cost", 0) or 0 for s in SCANS.values())
        if bootstrap_cost > 0:
            scandb.set_cost_ledger(bootstrap_cost)

_TRANSIENT_KEYS = frozenset({"live_tests", "live_findings", "live_phases", "live_crawled", "live_forms", "live_tool_calls", "live_out_of_scope", "live_tokens", "live_llm_calls", "live_cost", "live_cache_read", "live_cache_write", "live_phase_tools", "_router", "_findings_seen"})
_SECRET_KEYS = frozenset({"_password"})

_CRAWLED_PERSIST_CAP = 500


def _max_num(a, b):
    """Return the larger of two numeric values, tolerating None/non-numeric."""
    try:
        av = float(a) if a is not None else None
    except (TypeError, ValueError):
        av = None
    try:
        bv = float(b) if b is not None else None
    except (TypeError, ValueError):
        bv = None
    if av is None:
        return b
    if bv is None:
        return a
    return a if av >= bv else b


def _snapshot_live_metrics(info: dict) -> None:
    """Promote transient ``live_*`` metrics into persisted counterparts in place.

    This is the single guarantee that a scan which errors, is stopped, pauses,
    or is killed by a container restart still retains its latest cost, token,
    call counters, and structured summaries in the database. Counters use
    ``max()`` so a clean finalization (which writes permanent fields directly)
    never regresses from a stale ``live_*`` value.

    Runs on every ``_save_scan`` via ``_clean_scan_for_db``.
    """
    try:
        lc = info.get("live_cost")
        if lc is not None:
            info["cost"] = _max_num(info.get("cost"), lc)

        lt = info.get("live_tokens")
        if lt is not None:
            info["total_tokens"] = _max_num(info.get("total_tokens"), lt)

        ll = info.get("live_llm_calls")
        if ll is not None:
            info["llm_calls"] = _max_num(info.get("llm_calls"), ll)

        lto = info.get("live_tool_calls")
        if lto is not None:
            info["total_tool_calls"] = _max_num(info.get("total_tool_calls"), lto)

        lp = info.get("live_phases")
        if isinstance(lp, list):
            info["phases_completed"] = _max_num(info.get("phases_completed"), len(lp))
            info["phases"] = lp

        lf = info.get("live_findings")
        if isinstance(lf, list):
            info["findings_count"] = _max_num(info.get("findings_count"), len(lf))

        lpt = info.get("live_phase_tools")
        if isinstance(lpt, dict):
            info["phase_tools"] = lpt

        lcr = info.get("live_crawled")
        if isinstance(lcr, list):
            info["pages_crawled"] = _max_num(info.get("pages_crawled"), len(lcr))
            info["crawled_urls"] = lcr[-_CRAWLED_PERSIST_CAP:] if len(lcr) > _CRAWLED_PERSIST_CAP else list(lcr)

        loo = info.get("live_out_of_scope")
        if isinstance(loo, list):
            info["out_of_scope_urls"] = loo

        lfo = info.get("live_forms")
        if lfo is not None:
            info["forms_count"] = _max_num(info.get("forms_count"), lfo)
    except Exception:
        logger.debug("snapshot_live_metrics failed", exc_info=True)


def _clean_scan_for_db(info: dict) -> dict:
    """Strip transient/secret keys from a scan dict before persisting.

    Snapshots ``live_*`` metrics into persisted fields first so errored,
    stopped, paused, or crashed scans retain their latest counters and
    structured summaries in the DB.
    """
    _snapshot_live_metrics(info)
    return {k: v for k, v in info.items()
            if k not in _TRANSIENT_KEYS and k not in _SECRET_KEYS}


def _finding_key(f: dict) -> tuple | None:
    """Build a stable dedup key for a finding.

    Two findings are treated as the same if they share (title, url, parameter).
    Returns None if the finding has no usable key (shouldn't happen in practice
    but keeps us safe against malformed payloads).
    """
    if not isinstance(f, dict):
        return None
    title = (f.get("title") or "").strip().lower()
    if not title:
        return None
    url = (
        f.get("url")
        or f.get("endpoint")
        or f.get("location")
        or f.get("affected_url")
        or ""
    )
    if isinstance(url, str):
        url = url.strip().lower()
    else:
        url = str(url)
    param = (
        f.get("parameter")
        or f.get("param")
        or f.get("field")
        or ""
    )
    if isinstance(param, str):
        param = param.strip().lower()
    return (title, url, param)


def _dedupe_findings(findings: list[dict]) -> tuple[list[dict], set]:
    """Return (deduped_list, seen_keys_set) preserving the first occurrence order."""
    out: list[dict] = []
    seen: set = set()
    for f in findings or []:
        key = _finding_key(f)
        if key is None:
            out.append(f)
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out, seen


def _save_scan(scan_id: str):
    """Persist a single scan record to SQLite.  Fast, targeted, safe."""
    info = SCANS.get(scan_id)
    if not info:
        return
    try:
        scandb.upsert_scan(scan_id, _clean_scan_for_db(info))
    except Exception:
        logger.exception("Failed to persist scan %s to SQLite", scan_id)


def _save_scans_to_disk():
    """Bulk-persist ALL scan records to SQLite (startup / migration only)."""
    try:
        persist = {sid: _clean_scan_for_db(info) for sid, info in SCANS.items()}
        scandb.upsert_all(persist)
    except Exception:
        logger.exception("Failed to bulk-persist scans to SQLite")


# Periodic auto-save: flush every dirty scan to DB every 30 seconds as a
# safety net so that in-memory changes are never more than ~30 s ahead of
# the database.
_autosave_dirty: set[str] = set()
_autosave_lock = threading.Lock()


def _mark_dirty(scan_id: str):
    """Mark a scan as needing persistence on the next auto-save cycle."""
    with _autosave_lock:
        _autosave_dirty.add(scan_id)


def _autosave_loop():
    """Background thread that flushes dirty scans to SQLite periodically."""
    while True:
        time.sleep(30)
        with _autosave_lock:
            if not _autosave_dirty:
                continue
            to_flush = list(_autosave_dirty)
            _autosave_dirty.clear()
        try:
            batch = {}
            for sid in to_flush:
                info = SCANS.get(sid)
                if info:
                    batch[sid] = _clean_scan_for_db(info)
            if batch:
                scandb.upsert_all(batch)
            for sid in to_flush:
                info = SCANS.get(sid)
                if info and info.get("live_findings"):
                    try:
                        _persist_partial_findings(sid, info)
                    except Exception:
                        logger.debug("autosave partial-findings flush failed for %s", sid, exc_info=True)
        except Exception:
            logger.exception("Auto-save failed for %d scans", len(to_flush))


threading.Thread(target=_autosave_loop, daemon=True, name="db-autosave").start()


def _persist_scan_result(scan_id: str, data: dict):
    """Write full result JSON to SQLite (source of truth for API reads)."""
    _RESULTS_CACHE.pop(scan_id, None)
    try:
        scandb.save_scan_result(scan_id, json.dumps(data, default=str))
    except Exception:
        logger.exception("Failed to persist scan_results for %s", scan_id)


def _persist_partial_findings(scan_id: str, scan: dict):
    """Checkpoint partial findings + progress to scan_results so a crash doesn't lose them."""
    findings = scan.get("live_findings", [])
    if not findings:
        return
    try:
        partial = {
            "findings": findings,
            "target": scan.get("target_url", ""),
            "metadata": {
                "model": scan.get("model", ""),
                "partial": True,
                "phases_completed": len(scan.get("live_phases", [])),
            },
            "summary": {"total_findings": len(findings)},
        }
        scandb.save_scan_result(scan_id, json.dumps(partial, default=str))
    except Exception:
        logger.debug("Partial findings checkpoint failed for %s", scan_id, exc_info=True)


def _find_result_file(scan_id: str) -> str | None:
    """Legacy path on disk (optional); used only to back-fill SQLite."""
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


def _load_raw_result_dict(scan_id: str) -> dict | None:
    """Load raw result document: DB first, then legacy file (and back-fill DB).

    Defensive: ``_persist_partial_findings`` checkpoints a STRIPPED-DOWN
    document to the same DB table during the scan (no ``test_log``,
    no ``phase_log``, no ``pages_list``) and flags it
    ``metadata.partial = True``. If the final ``_persist_scan_result``
    write at completion fails, gets skipped, or races a container
    restart, that partial checkpoint is the last DB write - and the
    canonical full result file on disk is silently shadowed forever.

    Observed in production on ``scan_20260428_081209_b23cf3``: DB had
    1.6 MB partial (74 findings, phase_log=0, test_log=0); disk had
    3.4 MB complete (74 findings, phase_log=37, test_log=138). API
    served the partial version because the original code returned the
    DB row unconditionally if it parsed.

    The fix: when the DB version is flagged partial, prefer the
    on-disk file if one exists and re-persist the full version so
    subsequent reads are fast. See
    tests/test_results_endpoint_resilience.py::TestPartialDbFallback.
    """
    raw = scandb.get_scan_result(scan_id)
    cached: dict | None = None
    if raw:
        try:
            cached = json.loads(raw)
        except Exception:
            cached = None

    cached_is_partial = bool(
        isinstance(cached, dict)
        and cached.get("metadata", {}).get("partial")
    )
    if cached and not cached_is_partial:
        return cached

    fname = _find_result_file(scan_id)
    if fname:
        try:
            data = json.loads(Path(fname).read_text(encoding="utf-8"))
            disk_is_partial = bool(
                isinstance(data, dict)
                and data.get("metadata", {}).get("partial")
            )
            if not disk_is_partial:
                _persist_scan_result(scan_id, data)
            return data
        except Exception:
            pass

    return cached


def _backfill_scan_results_from_disk():
    """Startup: ensure ``scan_results`` has a row for every scan with ``result_file`` on disk.

    Syncs ``findings_count`` from the payload when it differs; clears cached triage so UI
    recomputes from canonical data.
    """
    meta_dirty = False
    for scan_id, info in list(SCANS.items()):
        try:
            if scandb.get_scan_result(scan_id):
                continue
            rf = info.get("result_file")
            if not rf:
                continue
            fpath = RAW_DIR / rf
            if not fpath.exists():
                continue
            data = json.loads(fpath.read_text(encoding="utf-8"))
            _persist_scan_result(scan_id, data)
            summary = data.get("summary", {})
            n = summary.get("total_findings")
            if n is None:
                n = len(data.get("findings", []))
            if info.get("findings_count") != n:
                SCANS[scan_id]["findings_count"] = n
                meta_dirty = True
            SCANS[scan_id].pop("triaged_findings", None)
        except Exception:
            logger.debug("Startup backfill scan_results failed for %s", scan_id, exc_info=True)
    if meta_dirty:
        _save_scans_to_disk()


def _ensure_triaged(sid: str, s: dict) -> list[dict]:
    """Return triaged findings for a scan, computing & caching if needed.

    On first call for a scan, loads raw findings from the result file,
    runs the triage engine on each one, and stores the result in
    SCANS[sid]['triaged_findings'] so the dashboard shows proper verdicts.
    """
    cached = s.get("triaged_findings")
    if cached:
        return cached

    rdata = _load_raw_result_dict(sid)
    if not rdata:
        return []

    raw_findings = rdata.get("findings", [])
    if not raw_findings:
        return []

    test_log = rdata.get("summary", {}).get("test_log", [])
    triaged = []
    for f in raw_findings:
        t = triage_classify(f, test_log)
        triaged.append({
            "title": t.get("title", ""),
            "ai_severity": f.get("severity", ""),
            "severity": t.get("final_severity", "Info"),
            "final_severity": t.get("final_severity", "Info"),
            "verdict": t.get("verdict", ""),
            "reason": t.get("reason", ""),
            "confidence_score": t.get("confidence"),
            "url": t.get("url", ""),
            "parameter": f.get("parameter", ""),
            "owasp_category": f.get("owasp_category", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "remediation": f.get("remediation", ""),
            "confidence": f.get("confidence", ""),
            "request_response": f.get("request_response", []),
            "cwe": t.get("cwe", ""),
            "cvss": t.get("cvss"),
            "cvss_rationale": t.get("cvss_rationale", ""),
            "cve": t.get("cve", ""),
            "verified": f.get("verified", False),
            "verification_method": t.get("verification_method", "none"),
            "verification_evidence": t.get("verification_evidence", ""),
        })

    s["triaged_findings"] = triaged
    s["findings_count"] = len(triaged)
    return triaged


def _infer_scan_mode(scan_info: dict, scan_id: str | None = None) -> str:
    """Try to infer scan_mode from DB result payload or legacy file."""
    if scan_id:
        data = _load_raw_result_dict(scan_id)
        if data:
            mode = data.get("scan_mode") or data.get("metadata", {}).get("scan_mode")
            if mode:
                return str(mode)
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

# --- Model registry (dynamic, auto-discovered from Bedrock) ------------------
# Fallback used when the cache is empty (discovery not yet run, or IAM missing bedrock:ListFoundationModels).
_FALLBACK_MODELS = [
    {"id": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "name": "Claude Haiku 4.5 (recommended)", "cost": "~$0.80/$4 per 1M tokens", "provider": "Anthropic", "input_cost_per_m": 0.80},
    {"id": "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0", "name": "Claude Sonnet 4.5", "cost": "~$3/$15 per 1M tokens", "provider": "Anthropic", "input_cost_per_m": 3.00},
    {"id": "bedrock/us.anthropic.claude-sonnet-4-6", "name": "Claude Sonnet 4.6 (best quality)", "cost": "~$3/$15 per 1M tokens", "provider": "Anthropic", "input_cost_per_m": 3.00},
    {"id": "bedrock/us.anthropic.claude-opus-4-6-v1", "name": "Claude Opus 4.6 (premium)", "cost": "~$15/$75 per 1M tokens", "provider": "Anthropic", "input_cost_per_m": 15.00, "high_cost": True},
]

_MODEL_DISCOVERY_INTERVAL = int(os.environ.get("MODEL_DISCOVERY_INTERVAL_H", "24")) * 3600
_model_discovery_lock = threading.Lock()
_last_discovery_time: float = 0.0


def _get_models() -> list[dict]:
    """Return the current model list — dynamic cache with fallback."""
    cached = get_cached_models()
    return cached if cached else _FALLBACK_MODELS


def _cheapest_model() -> str:
    """Return the model ID with the lowest input cost."""
    models = _get_models()
    return min(models, key=lambda m: m.get("input_cost_per_m", float("inf")))["id"]


_LITELLM_DIRECT_PREFIXES = (
    "bedrock/", "vertex_ai/", "sagemaker/", "ollama/", "openai/",
    "anthropic/", "azure/", "huggingface/", "together_ai/", "cohere/",
    "groq/", "mistral/", "gemini/", "deepseek/",
)


def _resolve_model_id(model: str) -> str:
    """Map a user-supplied model string to a valid litellm model ID.

    Accepts:
      - a real id like 'bedrock/us.anthropic.claude-haiku-4-5-...'
      - a display name like 'Claude Haiku 4.5 (recommended)'
      - a short alias like 'haiku', 'sonnet', 'claude-haiku-4-5'
      - empty / unknown → falls back to the cheapest model

    Never returns a string without a litellm provider prefix, so litellm
    can always parse it. Prevents 'LLM Provider NOT provided' errors when
    callers pass the friendly name instead of the id.
    """
    models = _get_models()
    if not model or not isinstance(model, str):
        return _cheapest_model()
    m = model.strip()
    if not m:
        return _cheapest_model()
    for entry in models:
        if entry.get("id") == m:
            return m
    low = m.lower()
    for entry in models:
        if (entry.get("name") or "").strip().lower() == low:
            return entry["id"]
    for entry in models:
        name = (entry.get("name") or "").lower()
        mid = (entry.get("id") or "").lower()
        if low and (low in name or low in mid):
            return entry["id"]
    if m.startswith(_LITELLM_DIRECT_PREFIXES):
        return m
    logger.warning("Unknown model '%s' — falling back to %s", m, _cheapest_model())
    return _cheapest_model()


def _run_model_discovery_bg():
    """Run model discovery in a background thread (non-blocking)."""
    global _last_discovery_time
    with _model_discovery_lock:
        if time.time() - _last_discovery_time < 60:
            return
        _last_discovery_time = time.time()
    logger.info("Starting background model discovery...")
    try:
        result = discover_models()
        logger.info("Model discovery complete: %d/%d passed in %.1fs",
                     result.get("passed", 0), result.get("tested", 0), result.get("duration_sec", 0))
    except Exception as e:
        logger.error("Model discovery failed: %s", e)


def _schedule_model_discovery():
    """Run discovery on startup, then schedule periodic re-checks."""
    _run_model_discovery_bg()
    def _periodic():
        while True:
            time.sleep(_MODEL_DISCOVERY_INTERVAL)
            _run_model_discovery_bg()
    t = threading.Thread(target=_periodic, daemon=True, name="model-discovery")
    t.start()
    logger.info("Model discovery scheduler started (interval=%dh)", _MODEL_DISCOVERY_INTERVAL // 3600)


# Kick off discovery on import (runs in background thread so startup isn't blocked)
threading.Thread(target=_schedule_model_discovery, daemon=True, name="model-discovery-init").start()


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint (no auth) — useful for load balancers and monitoring."""
    running = sum(1 for s in SCANS.values() if s.get("status") == "running")
    return {"status": "ok", "scans_running": running, "total_scans": len(SCANS)}


@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    """Serve the login page. If already authenticated, redirect to /."""
    cookie = request.cookies.get(_SESSION_COOKIE)
    if cookie and _verify_session_token(cookie):
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/", status_code=302)
    return FileResponse(
        Path(__file__).parent / "static" / "login.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.post("/login", include_in_schema=False)
async def login_submit(request: Request):
    """Validate credentials and set session cookie."""
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    if hmac.compare_digest(str(username).encode(), _AUTH_USER.encode()) and \
       hmac.compare_digest(str(password).encode(), _AUTH_PASS.encode()):
        from fastapi.responses import RedirectResponse
        token = _create_session_token(str(username))
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(
            key=_SESSION_COOKIE, value=token,
            max_age=_SESSION_MAX_AGE, httponly=True, samesite="lax",
        )
        return resp
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/login?error=1", status_code=302)


@app.get("/logout", include_in_schema=False)
async def logout():
    """Clear session cookie and redirect to login."""
    from fastapi.responses import RedirectResponse
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request, auth=Depends(_verify_or_redirect)):
    if auth is not True:
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/login", status_code=302)
    return FileResponse(
        Path(__file__).parent / "static" / "index.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"},
    )


@app.get("/api/dashboard", tags=["System"])
async def get_dashboard():
    """Aggregate stats for the dashboard page."""
    try:
        return await _get_dashboard_inner()
    except Exception as e:
        logger.error("get_dashboard failed: %s", e, exc_info=True)
        return JSONResponse({"error": f"Dashboard error: {type(e).__name__}: {e}"}, status_code=500)

async def _get_dashboard_inner():
    total = len(SCANS)
    running = sum(1 for s in SCANS.values() if s.get("status") == "running")
    completed = sum(1 for s in SCANS.values() if s.get("status") in ("completed", "done"))
    errored = sum(1 for s in SCANS.values() if s.get("status") in ("error", "failed"))
    cancelled = sum(1 for s in SCANS.values() if s.get("status") == "cancelled")

    severity_breakdown: dict[str, int] = {}
    verdict_breakdown: dict[str, int] = {}
    total_findings = 0
    total_cost = 0.0
    completed_cost = 0.0
    errored_cost = 0.0
    running_cost = 0.0

    for sid, s in SCANS.items():
        scan_cost = s.get("cost", 0) or s.get("live_cost", 0) or 0
        total_cost += scan_cost
        st = s.get("status", "")
        if st in ("completed", "done"):
            completed_cost += scan_cost
        elif st in ("error", "failed", "cancelled"):
            errored_cost += scan_cost
        elif st in ("running", "paused", "pausing"):
            running_cost += scan_cost
        findings = _ensure_triaged(sid, s)

        if not findings:
            total_findings += s.get("findings_count", 0) or 0
        else:
            for f in findings:
                total_findings += 1
                raw_sev_val = f.get("severity") or f.get("final_severity") or "Info"
                raw_sev = (raw_sev_val if isinstance(raw_sev_val, str) else str(raw_sev_val)).strip()
                sev = _normalize_severity(raw_sev)
                if sev and sev not in ("Not Exploitable", "TBD", ""):
                    severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
                raw_verdict = f.get("verdict", "NEEDS_VERIFICATION")
                verdict = _normalize_verdict(raw_verdict)
                verdict_breakdown[verdict] = verdict_breakdown.get(verdict, 0) + 1

    recent = []
    sorted_scans = sorted(SCANS.items(), key=lambda x: x[1].get("started", ""), reverse=True)[:10]
    for sid, s in sorted_scans:
        findings_list = _ensure_triaged(sid, s)
        recent.append({
            "id": sid,
            "target": s.get("target_url", ""),
            "model": s.get("model_name", s.get("model", "")),
            "status": s.get("status", ""),
            "findings": len(findings_list) if findings_list else s.get("findings_count", 0),
            "cost": s.get("cost"),
            "duration": s.get("duration"),
            "scan_mode": s.get("scan_mode", ""),
            "started": s.get("started", ""),
        })

    ledger = scandb.get_cost_ledger()
    all_time_cost = ledger.get("all_time_cost", 0)
    deleted_cost = ledger.get("deleted_scans_cost", 0)
    deleted_count = ledger.get("deleted_scans_count", 0)
    if all_time_cost < total_cost:
        all_time_cost = total_cost + deleted_cost

    return {
        "total_scans": total, "running": running, "completed": completed,
        "errored": errored, "cancelled": cancelled,
        "total_findings": total_findings,
        "total_cost": total_cost,
        "completed_cost": completed_cost,
        "errored_cost": errored_cost,
        "running_cost": running_cost,
        "all_time_cost": round(all_time_cost, 4),
        "deleted_cost": round(deleted_cost, 4),
        "deleted_count": deleted_count,
        "severity_breakdown": severity_breakdown, "verdict_breakdown": verdict_breakdown,
        "recent_scans": recent,
    }



_INSIGHTS_SYSTEM_PROMPT = """\
You are a security findings analyst. You MUST format every response using this exact structure:

### Summary
One or two sentences directly answering the question with key numbers.

### Details
Use ONE of these formats depending on the question:

FORMAT A — When listing findings or comparing items, ALWAYS use a markdown table:
| # | Title | Severity | Verdict | URL | CWE |
|---|-------|----------|---------|-----|-----|
| 1 | XSS in search | **High** | TRUE_POSITIVE | `https://example.com/search` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |

FORMAT B — When giving counts/statistics, use a summary table then bullet details:
| Category | Count | Percentage |
|----------|-------|------------|
| ... | ... | ...% |

FORMAT C — When explaining or summarizing, use bullet lists with bold labels:
- **Finding**: description
- **Severity**: **High**
- **URL**: `https://example.com/page`
- **CWE**: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

Formatting rules:
- ALWAYS bold severity names: **Critical**, **High**, **Medium**, **Low**, **Info**
- ALWAYS wrap URLs in backticks: `https://example.com/path`
- ALWAYS format CWEs as markdown links: [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- ALWAYS include specific counts and percentages from the data
- ALWAYS use tables for 3+ items — never use long prose paragraphs
- Truncate long URLs with ellipsis in tables to keep columns readable: `https://example.com/very/lo...`
- Keep total response under 500 words
- No filler text, no disclaimers, no "let me know if you need more"
"""


def _postprocess_insight(text: str) -> str:
    """Clean up LLM insight response for consistent rendering."""
    if not text:
        return "_No results found._"
    lines = text.strip().splitlines()
    cleaned = []
    for line in lines:
        stripped = line.rstrip()
        if stripped.startswith("```markdown"):
            continue
        if stripped == "```" and not cleaned:
            continue
        cleaned.append(stripped)
    while cleaned and cleaned[-1].strip() == "```":
        cleaned.pop()
    result = "\n".join(cleaned).strip()
    if not result:
        return "_No results found._"
    return result


@app.post("/api/insights/query", tags=["Insights"])
async def insights_query(request: Request):
    """Answer a natural-language question about scan findings using LLM.

    Always uses the cheapest available model — this is an analytics query, not a scan.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    query = body.get("query", "").strip()
    if not query:
        return JSONResponse({"error": "query is required"}, status_code=400)

    all_findings = []
    scans_analyzed = 0
    for sid, s in SCANS.items():
        findings = _ensure_triaged(sid, s)
        if findings:
            scans_analyzed += 1
            for f in findings:
                f_copy = dict(f)
                f_copy["scan_id"] = sid
                f_copy["target"] = s.get("target_url", "")
                f_copy["model"] = s.get("model_name", s.get("model", ""))
                all_findings.append(f_copy)

    if not all_findings:
        return {
            "answer": "### No Findings\nNo scan data available yet. Run a scan first, then come back to analyze the results.",
            "scans_analyzed": 0,
            "findings_analyzed": 0,
        }

    summary = json.dumps(all_findings[:200], indent=1, default=str)

    try:
        model = _cheapest_model()
        router = LLMRouter(models=[model])
        prompt = (
            f"Data: {len(all_findings)} findings across {scans_analyzed} scans.\n\n"
            f"Findings (up to 200):\n{summary}\n\n"
            f"Question: {query}"
        )
        resp = await asyncio.to_thread(
            router.complete,
            model,
            [
                {"role": "system", "content": _INSIGHTS_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        answer = _postprocess_insight(resp.choices[0].message.content or "")
        cost = None
        try:
            cost = router.get_cost_summary().get("total_cost")
        except Exception:
            pass
        return {
            "answer": answer,
            "scans_analyzed": scans_analyzed,
            "findings_analyzed": len(all_findings),
            "model_used": model,
            "cost": cost,
        }
    except Exception as e:
        logger.exception("Insights query failed")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/models", tags=["System"])
async def get_models():
    models = _get_models()
    return [m for m in models if not m.get("ui_hidden")]


@app.post("/api/models/refresh", tags=["System"])
async def refresh_models(creds=Depends(_verify)):
    """Trigger a model re-discovery (canary-tests all Bedrock models)."""
    threading.Thread(target=_run_model_discovery_bg, daemon=True).start()
    return {"status": "discovery_started", "message": "Model discovery running in background. Refresh in ~60s."}


@app.get("/api/models/status", tags=["System"])
async def models_status():
    """Return model discovery cache metadata."""
    meta = get_cache_meta()
    models = _get_models()
    return {
        **meta,
        "ui_models": len([m for m in models if not m.get("ui_hidden")]),
        "hidden_models": len([m for m in models if m.get("ui_hidden")]),
    }


@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    page: int = 1,
    per_page: int = 25,
    search: str = "",
):
    per_page = min(max(per_page, 1), 100)
    page = max(page, 1)

    all_scans = []
    for scan_id, info in sorted(SCANS.items(), key=lambda x: x[1].get("started", ""), reverse=True):
        entry: dict = {
            "id": scan_id,
            "target": info.get("target_url", ""),
            "model": info.get("model_name", ""),
            "status": info.get("status", "unknown"),
            "started": info.get("started", ""),
            "duration": info.get("duration"),
            "cost": info.get("cost") if info.get("cost") is not None else info.get("live_cost"),
            "total_tokens": info.get("total_tokens") or info.get("live_tokens", 0),
            "findings_count": info.get("findings_count"),
            "scan_mode": info.get("scan_mode", ""),
            "phases_completed": info.get("phases_completed", len(info.get("live_phases", []))),
        }
        if info.get("status") == "running":
            entry["current_phase"] = info.get("current_phase", "")
        all_scans.append(entry)
    # Scan list is DB-backed only (in-memory SCANS loaded from SQLite at startup).

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


@app.get("/api/ui-settings", tags=["Settings"])
async def get_ui_settings(creds=Depends(_verify)):
    """Column visibility and triage table prefs (stored in SQLite, not browser storage)."""
    out: dict = {}
    for key in ("scanColVisibility", "triage_cols"):
        raw = scandb.app_kv_get(key)
        if not raw:
            continue
        try:
            out[key] = json.loads(raw)
        except Exception:
            out[key] = None
    return out


@app.put("/api/ui-settings", tags=["Settings"])
async def put_ui_settings(request: Request, creds=Depends(_verify)):
    """Merge partial UI settings into app_kv."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Expected a JSON object"}, status_code=400)
    for key in ("scanColVisibility", "triage_cols"):
        if key not in body:
            continue
        scandb.app_kv_set(key, json.dumps(body[key], default=str))
    return {"status": "ok"}


IMPORTS_DIR = BASE / "imports"
IMPORTS_DIR.mkdir(parents=True, exist_ok=True)


@app.post("/api/upload", tags=["Scans"])
async def upload_api_spec(
    file: UploadFile = File(...),
):
    """Save an uploaded Postman/Burp/Swagger file to imports/."""
    if not file.filename:
        return JSONResponse({"error": "No filename provided"}, status_code=400)
    safe_name = file.filename.replace("..", "").replace("/", "_").replace("\\", "_")
    dest = IMPORTS_DIR / safe_name
    try:
        contents = await file.read()
        dest.write_bytes(contents)
    except Exception as e:
        return JSONResponse({"error": f"Failed to save file: {e}"}, status_code=500)
    return {"filename": safe_name, "size": len(contents)}


# ── Workflow / Business Logic Recorder endpoints ─────────────────────────

from scanners.ai_agent.workflow import (
    Workflow, WorkflowStep, WorkflowRecorder,
    save_workflow, load_workflow, list_workflows, delete_workflow,
)

WORKFLOW_RECORDERS: dict[str, dict] = {}


@app.get("/api/workflows", tags=["Workflows"])
async def get_workflows():
    """List all saved workflows."""
    return list_workflows()


@app.get("/api/workflow/{workflow_id}", tags=["Workflows"])
async def get_workflow(workflow_id: str):
    wf = load_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf.to_dict()


@app.post("/api/workflow", tags=["Workflows"])
async def create_workflow(request: Request):
    """Create or update a workflow from JSON (manual or recorded)."""
    body = await request.json()
    wf = Workflow.from_dict(body)
    wf_id = save_workflow(wf)
    return {"id": wf_id, "name": wf.name, "steps_count": len(wf.steps)}


@app.delete("/api/workflow/{workflow_id}", tags=["Workflows"])
async def remove_workflow(workflow_id: str):
    if delete_workflow(workflow_id):
        return {"deleted": True}
    raise HTTPException(status_code=404, detail="Workflow not found")


@app.post("/api/workflow/record/start", tags=["Workflows"])
async def start_recording(request: Request):
    """Start a workflow recording session with an interactive browser."""
    body = await request.json()
    target_url = body.get("target_url", "").strip()
    name = body.get("name", "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url required")

    recorder = WorkflowRecorder(target_url=target_url, name=name)
    session_id = recorder.workflow.id

    session = {
        "recorder": recorder,
        "screenshot_b64": "",
        "events": __import__("queue").Queue(),
        "active": threading.Event(),
        "done": threading.Event(),
        "viewport": (1280, 720),
        "page": None,
        "browser_context": None,
    }
    WORKFLOW_RECORDERS[session_id] = session

    async def _launch_browser():
        from playwright.async_api import async_playwright
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 720})
        page = await context.new_page()
        session["page"] = page
        session["browser_context"] = context
        session["_pw"] = pw
        session["_browser"] = browser

        try:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            pass

        session["active"].set()

        while session["active"].is_set() and not session["done"].is_set():
            try:
                raw = await page.screenshot(type="jpeg", quality=55)
                session["screenshot_b64"] = __import__("base64").b64encode(raw).decode("ascii")
            except Exception:
                pass

            events_q = session["events"]
            while not events_q.empty():
                try:
                    evt = events_q.get_nowait()
                except Exception:
                    break
                if evt.get("type") == "mark_test_point":
                    recorder.record_event(evt, page.url)
                elif evt.get("type") == "done":
                    session["done"].set()
                    break
                else:
                    from scanners.ai_agent.auth import _apply_browser_event
                    await _apply_browser_event(page, evt, {"width": 1280, "height": 720})
                    _translate_to_step(recorder, evt, page)

            await asyncio.sleep(0.25)

        session["active"].clear()

    import threading as _thr
    def _run_browser():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_launch_browser())
        finally:
            loop.close()

    t = _thr.Thread(target=_run_browser, daemon=True)
    t.start()

    return {"session_id": session_id, "name": name, "target_url": target_url}


def _translate_to_step(recorder: WorkflowRecorder, evt: dict, page) -> None:
    """Translate a raw browser event into a recorded workflow step."""
    etype = evt.get("type", "")
    page_url = page.url if page else ""

    if etype == "click":
        x = evt.get("x", 0)
        y = evt.get("y", 0)
        recorder.record_event({
            "type": "click",
            "selector": f"coords:{x:.4f},{y:.4f}",
            "text": "",
        }, page_url)

    elif etype == "type":
        text = evt.get("text", "")
        if text:
            recorder.record_event({
                "type": "fill",
                "selector": "active_element",
                "value": text,
            }, page_url)

    elif etype == "keypress":
        key = evt.get("key", "")
        if key in ("Enter", "Tab", "Escape"):
            recorder.record_event({"type": "keypress", "key": key}, page_url)


@app.post("/api/workflow/record/{session_id}/stop", tags=["Workflows"])
async def stop_recording(session_id: str, request: Request):
    """Stop recording and save the workflow."""
    session = WORKFLOW_RECORDERS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recording session not found")

    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    description = body.get("description", "")

    session["done"].set()
    await asyncio.sleep(1)

    recorder = session["recorder"]
    wf = recorder.finish(description=description)
    wf_id = save_workflow(wf)

    if session.get("_browser"):
        try:
            import asyncio as _aio
            loop = _aio.new_event_loop()
            loop.run_until_complete(session["_browser"].close())
            loop.run_until_complete(session["_pw"].stop())
            loop.close()
        except Exception:
            pass

    WORKFLOW_RECORDERS.pop(session_id, None)
    return {"id": wf_id, "name": wf.name, "steps_count": len(wf.steps), "test_points": wf.test_points}


@app.websocket("/ws/workflow/{session_id}/browser")
async def workflow_recorder_ws(websocket: WebSocket, session_id: str):
    """WebSocket for workflow recorder — streams screenshots, receives events."""
    await websocket.accept()
    session = WORKFLOW_RECORDERS.get(session_id)
    if not session:
        await websocket.send_json({"type": "error", "message": "No recording session found"})
        await websocket.close(code=1008)
        return

    for _ in range(60):
        if session["active"].is_set():
            break
        await asyncio.sleep(0.5)
    else:
        await websocket.send_json({"type": "error", "message": "Browser launch timeout"})
        await websocket.close(code=1008)
        return

    last_hash = None
    try:
        async def _send_screenshots():
            nonlocal last_hash
            while session["active"].is_set() and not session["done"].is_set():
                shot = session.get("screenshot_b64", "")
                if shot:
                    h = hash(shot)
                    if h != last_hash:
                        recorder = session["recorder"]
                        await websocket.send_json({
                            "type": "screenshot",
                            "data": shot,
                            "viewport": list(session["viewport"]),
                            "steps_count": len(recorder.workflow.steps),
                            "current_url": session["page"].url if session.get("page") else "",
                        })
                        last_hash = h
                await asyncio.sleep(0.3)
            await websocket.send_json({"type": "done"})

        async def _receive_events():
            while session["active"].is_set() and not session["done"].is_set():
                try:
                    data = await asyncio.wait_for(websocket.receive_json(), timeout=1.0)
                    session["events"].put(data)
                except asyncio.TimeoutError:
                    continue
                except WebSocketDisconnect:
                    break

        await asyncio.gather(_send_screenshots(), _receive_events())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Workflow recorder WS error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


def _resolve_api_imports(api_imports: dict) -> tuple[dict, dict | None]:
    """Resolve uploaded API import filenames to parsed endpoint registry + summary.

    Returns (resolved_paths, endpoint_summary_or_None).
    """
    resolved: dict[str, str] = {}
    for key in ("postman", "postman_env", "burp", "openapi"):
        fname = (api_imports or {}).get(key, "")
        if fname:
            fpath = IMPORTS_DIR / fname
            if fpath.exists():
                resolved[key] = str(fpath)

    if not resolved:
        return resolved, None

    registry = EndpointRegistry()
    try:
        if "postman" in resolved:
            eps = parse_postman_collection(resolved["postman"], resolved.get("postman_env"))
            registry.add(eps)
        if "openapi" in resolved:
            eps = parse_openapi_spec(resolved["openapi"])
            registry.add(eps)
        if "burp" in resolved:
            burp_path = Path(resolved["burp"])
            raw = burp_path.read_text(encoding="utf-8")
            try:
                traffic = json.loads(raw)
                registry.add_from_traffic(traffic)
            except json.JSONDecodeError:
                logger.warning("Burp file %s is not valid JSON — skipping", resolved["burp"])
    except Exception as e:
        logger.warning("Error parsing API imports: %s", e)

    summary = registry.summary()
    methods_detail = []
    for path, methods in list(summary.get("methods_by_path", {}).items())[:30]:
        methods_detail.append(f"  {','.join(methods)} {path}")
    summary["methods_detail"] = methods_detail
    return resolved, summary


@app.post("/api/scan/analyze", tags=["Scans"])
async def analyze_instruction(request: Request):
    """Parse a natural-language scan instruction into a structured scan plan."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    instruction = body.get("instruction", "").strip()
    selected_model = body.get("model", "").strip()
    api_imports = body.get("api_imports", {}) or {}
    if not instruction:
        return JSONResponse({"error": "instruction is required"}, status_code=400)

    _, ep_summary = _resolve_api_imports(api_imports)

    try:
        router = LLMRouter(models=[selected_model]) if selected_model else LLMRouter()

        api_context = ""
        if ep_summary and ep_summary.get("total", 0) > 0:
            api_context = (
                f"\n\nIMPORTANT — The user uploaded API spec files containing {ep_summary['total']} endpoints "
                f"across {ep_summary['unique_paths']} unique paths.\n"
                "Imported API endpoints:\n" +
                "\n".join(ep_summary.get("methods_detail", [])) +
                "\n\nUse this information to:\n"
                "- Set scan_mode to 'api' or 'both' (not 'website' — there are API endpoints to test)\n"
                "- Include relevant paths in focus_urls if the user mentions specific endpoints\n"
                "- Mention imported API endpoint count in the steps and context\n"
                "- If the user says 'scan the API' or 'test these endpoints', focus on the imported endpoints\n"
            )

        prompt = (
            "You are a DAST scan planner. Parse this instruction and return a JSON object with these fields:\n"
            "  target_url (string, required — the base URL or specific URL to scan),\n"
            "  username (string or null), password (string or null),\n"
            "  auth_type ('form'|'basic'|'bearer'|'auto'),\n"
            "  scan_mode ('website'|'api'|'both') — 'website' for HTML/browser testing, 'api' for API endpoints, 'both' for everything (default),\n"
            "  scan_scope ('url_only'|'directory'|'full_site') — IMPORTANT:\n"
            "    'url_only'   = scan ONLY this exact URL/endpoint, nothing else\n"
            "    'directory'  = scan this URL and its sub-paths (default for websites)\n"
            "    'full_site'  = crawl and scan the entire site\n"
            "  If the user says 'only this URL', 'specific page', 'just this endpoint', 'only scan X' → 'url_only'.\n"
            "  If no scope hint, default to 'directory'.\n"
            "  focus_urls (list of specific URLs/endpoints to test — extract ALL URLs from the instruction),\n"
            "  focus_areas (list like 'XSS', 'SQLi', or empty [] for all — if user doesn't mention specific vuln types, leave EMPTY to scan everything),\n"
            "  scan_intensity ('light'|'standard'|'deep') — DEFAULTS TO 'deep' ALWAYS unless user explicitly says 'quick'/'fast'/'light'. Rules:\n"
            "    - No intensity mentioned → 'deep' (full scan, maximum payloads)\n"
            "    - 'quick', 'fast', 'light' → 'light'\n"
            "    - 'standard', 'balanced', 'moderate' → 'standard'\n"
            "    - 'thorough', 'deep', 'full', 'exhaustive' → 'deep'\n"
            "    - focus_areas non-empty → ALWAYS 'deep' regardless of anything else\n"
            "  exclude_urls (list of URLs/paths the user wants to SKIP — extract from phrases like 'skip', 'exclude', 'don't scan', 'ignore', 'avoid'),\n"
            "  extra_domains (list of additional allowed domains mentioned in the instruction),\n"
            "  steps (list of human-readable steps the scan will take),\n"
            "  context (brief summary of intent),\n"
            "  estimated_time (string), estimated_cost (string).\n"
            "Return ONLY valid JSON, no markdown.\n\n"
            f"Instruction: {instruction}"
            f"{api_context}"
        )
        model = selected_model or (router.models[0] if router.models else "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0")
        resp = await asyncio.to_thread(router.complete, model, [{"role": "user", "content": prompt}])
        text = (resp.choices[0].message.content or "").strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        plan = json.loads(text)
        if not plan.get("scan_intensity"):
            plan["scan_intensity"] = "deep"
        if plan.get("focus_areas"):
            plan["scan_intensity"] = "deep"
        result = {"plan": plan, "model_used": model}
        if ep_summary:
            result["api_endpoints_summary"] = ep_summary
        return result
    except json.JSONDecodeError:
        return {"plan": {"target_url": "", "context": "Could not parse AI response", "error": "Invalid JSON from LLM"}}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/scan", tags=["Scans"])
async def start_scan(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    target_url = body.get("target_url", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    username_b = body.get("username_b", "").strip()
    password_b = body.get("password_b", "").strip()
    credentials_admin = body.get("credentials_admin") or {}
    credentials_tenant_b = body.get("credentials_tenant_b") or {}
    model = _resolve_model_id(body.get("model", ""))
    scan_mode_raw = body.get("scan_mode", "both")
    _MODE_MAP = {"standard": "both", "quick": "both", "deep": "both",
                 "full": "both", "web": "website", "site": "website"}
    scan_mode = _MODE_MAP.get(scan_mode_raw, scan_mode_raw)
    if scan_mode not in ("website", "api", "both"):
        scan_mode = "both"

    auth_type = body.get("auth_type", "auto")
    api_imports = body.get("api_imports", {}) or {}
    extra_domains = body.get("extra_domains", []) or []
    scan_scope = body.get("scan_scope", "directory")
    focus_urls = body.get("focus_urls", []) or []
    focus_areas = body.get("focus_areas", []) or []
    exclude_urls = body.get("exclude_urls", []) or []
    scan_intensity = body.get("scan_intensity", "deep")
    workflow_id = body.get("workflow_id", "").strip() or None
    business_flow = body.get("business_flow", "").strip() or None
    scan_profile = (body.get("scan_profile") or "vulnerability_scan").strip().lower()
    skip_passive_sibling_tls = bool(body.get("skip_passive_sibling_tls"))
    if scan_intensity not in ("light", "standard", "deep"):
        scan_intensity = "deep"
    if focus_areas:
        scan_intensity = "deep"

    if scan_scope not in ("url_only", "directory", "full_site"):
        scan_scope = "directory"

    if scan_profile not in ("vulnerability_scan", "crawl_only"):
        scan_profile = "vulnerability_scan"
    # Crawl-only is incompatible with focus_areas (focus_areas selects vuln
    # categories; crawl-only tests nothing). Silently drop focus_areas in
    # crawl-only mode rather than fail — the user's intent was "just crawl".
    if scan_profile == "crawl_only":
        focus_areas = []

    if not target_url:
        return JSONResponse({"error": "Target URL is required"}, status_code=400)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    model_name = next((m.get("name", m.get("id", model)) for m in _get_models() if m.get("id") == model), model)

    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[scan_id] = cancel_flag
    PAUSE_FLAGS[scan_id] = pause_flag

    interactive_session = _create_interactive_session(scan_id)

    SCANS[scan_id] = {
        "target_url": target_url,
        "model": model,
        "model_name": model_name,
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [],
        "scan_mode": scan_mode,
        "scan_scope": scan_scope,
        "focus_urls": focus_urls,
        "focus_areas": focus_areas,
        "exclude_urls": exclude_urls,
        "scan_intensity": scan_intensity,
        "scan_profile": scan_profile,
        "skip_passive_sibling_tls": skip_passive_sibling_tls,
        "workflow_id": workflow_id,
        "business_flow": business_flow,
        "auth_type": auth_type,
        "_username": username,
        "_password": password,
        "_username_b": username_b,
        "_password_b": password_b,
        "_credentials_admin": credentials_admin,
        "_credentials_tenant_b": credentials_tenant_b,
        "_api_imports": api_imports,
        "_extra_domains": extra_domains,
    }
    _save_scan(scan_id)

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports, extra_domains, cancel_flag, pause_flag),
        kwargs={"scan_scope": scan_scope, "focus_urls": focus_urls, "focus_areas": focus_areas, "scan_intensity": scan_intensity, "exclude_urls": exclude_urls, "username_b": username_b, "password_b": password_b, "credentials_admin": credentials_admin, "credentials_tenant_b": credentials_tenant_b, "interactive_session": interactive_session, "workflow_id": workflow_id, "business_flow": business_flow, "scan_profile": scan_profile, "skip_passive_sibling_tls": skip_passive_sibling_tls},
        daemon=True,
    )
    thread.start()
    return {"scan_id": scan_id, "status": "started"}


def _run_scan_in_thread(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports=None, extra_domains=None, cancel_flag=None, pause_flag=None, start_from_phase=0, initial_findings=None, scan_scope="directory", focus_urls=None, focus_areas=None, scan_intensity="deep", exclude_urls=None, username_b="", password_b="", credentials_admin=None, credentials_tenant_b=None, interactive_session=None, workflow_id=None, business_flow=None, scan_profile="vulnerability_scan", skip_passive_sibling_tls=False):
    """Run scan in a separate thread with its own event loop so the main UI stays responsive."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run_scan_task(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports, extra_domains, cancel_flag, pause_flag, start_from_phase, initial_findings, scan_scope=scan_scope, focus_urls=focus_urls, focus_areas=focus_areas, scan_intensity=scan_intensity, exclude_urls=exclude_urls, username_b=username_b, password_b=password_b, credentials_admin=credentials_admin, credentials_tenant_b=credentials_tenant_b, interactive_session=interactive_session, workflow_id=workflow_id, business_flow=business_flow, scan_profile=scan_profile, skip_passive_sibling_tls=skip_passive_sibling_tls)
        )
    finally:
        loop.close()
        CANCEL_FLAGS.pop(scan_id, None)
        PAUSE_FLAGS.pop(scan_id, None)
        INTERACTIVE_BROWSERS.pop(scan_id, None)


async def _run_scan_task(scan_id, target_url, username, password, model, scan_mode, auth_type, api_imports=None, extra_domains=None, cancel_flag=None, pause_flag=None, start_from_phase=0, initial_findings=None, scan_scope="directory", focus_urls=None, focus_areas=None, scan_intensity="deep", exclude_urls=None, username_b="", password_b="", credentials_admin=None, credentials_tenant_b=None, interactive_session=None, workflow_id=None, business_flow=None, scan_profile="vulnerability_scan", skip_passive_sibling_tls=False):
    try:
        scan = SCANS[scan_id]
        scan["progress"].append("Initializing LLM router...")
        scan["live_phases"] = []
        scan["live_tests"] = []
        seeded, _seen = _dedupe_findings(initial_findings or [])
        scan["live_findings"] = seeded
        scan["_findings_seen"] = _seen
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
                _mark_dirty(scan_id)
            elif event == "scope":
                domains = ", ".join(data.get("allowed_domains", []))
                scan["progress"].append(f"Scope: scanning only *.{domains} — third-party domains blocked")
                _mark_dirty(scan_id)
            elif event == "detect":
                scan["progress"].append(f"Detected: SPA={data.get('is_spa')}, Framework={data.get('framework')}")
                _mark_dirty(scan_id)
            elif event == "scan_start":
                scan["progress"].append(f"Starting {data['total_phases']} scan phases...")
                _save_scan(scan_id)
            elif event == "phase_start":
                scan["current_phase"] = f"[{data['phase']}/{data['total']}] {data['name']}"
                scan["progress"].append(scan["current_phase"])
                _mark_dirty(scan_id)
            elif event == "phase_end":
                phase_entry = {
                    "phase": data["phase"],
                    "name": data["name"],
                    "tool_calls": data["tool_calls"],
                    "findings": data["findings"],
                }
                if "worker" in data:
                    phase_entry["worker"] = data["worker"]
                    phase_entry["parallel"] = True
                # Preserve transient-error context from run_phases_parallel so
                # operators can see WHY a phase shows 0 findings in the live UI.
                if data.get("error"):
                    phase_entry["error"] = str(data["error"])[:200]
                scan["live_phases"].append(phase_entry)
                _save_scan(scan_id)
                _persist_partial_findings(scan_id, scan)
            elif event == "tool_call":
                scan["live_tool_calls"] += 1
                tool = data.get("tool", "")
                phase_name = data.get("phase", "")
                scan["live_tests"].append({
                    "phase": phase_name,
                    "tool": tool,
                    "request": data.get("request", {}),
                    "response": data.get("response", {}),
                })
                if len(scan["live_tests"]) > 2000:
                    scan["live_tests"] = scan["live_tests"][-2000:]
                phase_tools = scan.setdefault("live_phase_tools", {})
                pt = phase_tools.setdefault(phase_name, {})
                pt[tool] = pt.get(tool, 0) + 1
                _r = scan.get("_router")
                if _r:
                    _cs = _r.get_cost_summary()
                    scan["live_tokens"] = sum(c.get("input_tokens", 0) + c.get("output_tokens", 0) for c in _cs)
                    scan["live_llm_calls"] = sum(c.get("calls", 0) for c in _cs)
                    scan["live_cost"] = round(sum(c.get("cost_usd", 0) for c in _cs), 4)
                    scan["live_cache_read"] = sum(c.get("cache_read_tokens", 0) for c in _cs)
                    scan["live_cache_write"] = sum(c.get("cache_creation_tokens", 0) for c in _cs)
                if scan["live_tool_calls"] % 10 == 0:
                    _save_scan(scan_id)
            elif event == "finding":
                f = dict(data)
                key = _finding_key(f)
                seen = scan.setdefault("_findings_seen", set())
                if key is not None and key in seen:
                    return
                if key is not None:
                    seen.add(key)
                scan["live_findings"].append(f)
                # Intra-phase checkpoint: persist every 5 new findings so a
                # mid-phase crash doesn't lose findings discovered since the
                # last phase_end. phase_end still persists on boundaries.
                if len(scan["live_findings"]) % 5 == 0:
                    _save_scan(scan_id)
                    _persist_partial_findings(scan_id, scan)
            elif event == "crawl":
                url = data.get("url", "")
                ctype = data.get("type", "page")
                tool = data.get("tool", "")
                scan["live_crawled"].append({"url": url, "type": ctype, "tool": tool})
                label = {"page": "Page", "api": "API", "test": "Test"}.get(ctype, "URL")
                scan["progress"].append(f"Crawled ({label}): {url} (#{data.get('count', 0)})")
                _mark_dirty(scan_id)
            elif event == "paused":
                scan["status"] = "paused"
                scan["progress"].append("Scan paused — waiting for resume...")
                _save_scan(scan_id)
            elif event == "resumed":
                scan["status"] = "running"
                scan["progress"].append("Scan resumed — continuing...")
                _save_scan(scan_id)
            elif event == "auth_challenge":
                has_captcha = data.get("has_captcha", False)
                need_mfa = data.get("need_mfa", False)
                reason = data.get("reason", "")
                action = data.get("action", "")
                challenge_type = data.get("challenge_type", "")
                if not challenge_type:
                    challenge_type = "CAPTCHA" if has_captcha else ("MFA/2FA" if need_mfa else "Login failure")
                scan["auth_challenge"] = {
                    "screenshot": data.get("screenshot", ""),
                    "has_captcha": has_captcha,
                    "need_mfa": need_mfa,
                    "challenge_type": challenge_type,
                    "message": data.get("message", ""),
                    "reason": reason,
                    "action": action,
                    "waiting": True,
                }
                detail = reason or ("CAPTCHA on login page" if has_captcha else "automated login did not succeed")
                next_step = action or "Log in manually via the live browser, then click 'Login Complete'."
                scan["progress"].append(f"Auth challenge [{challenge_type}]: {detail}")
                scan["progress"].append(f"  → Action needed: {next_step}")
                _save_scan(scan_id)
            elif event == "auth_challenge_resolved":
                scan.pop("auth_challenge", None)
                scan["progress"].append("Auth challenge resolved — continuing scan...")
                _save_scan(scan_id)
            elif event == "interactive_browser_ready":
                scan["interactive_browser"] = {"active": True, "viewport": data.get("viewport", [1280, 720])}
                scan["progress"].append("Interactive browser ready — log in via the live browser view")
                _save_scan(scan_id)
            elif event == "interactive_browser_done":
                scan.pop("interactive_browser", None)
                scan["progress"].append("Interactive login completed by user — continuing scan...")
                _save_scan(scan_id)
            elif event == "progress_msg":
                msg = data.get("message", "")
                if msg:
                    scan["progress"].append(msg)
                    _save_scan(scan_id)
            elif event == "parallel_start":
                count = data.get("workers", 0)
                phase_ids = data.get("phases", [])
                scan["progress"].append(
                    f"Launching {len(phase_ids)} phases in parallel ({count} workers)..."
                )
                scan["parallel_active"] = True
                _save_scan(scan_id)
            elif event == "parallel_end":
                scan["progress"].append(
                    f"Parallel execution done: {data.get('findings', 0)} findings "
                    f"from {data.get('phases', 0)} phases"
                )
                scan["parallel_active"] = False
                _save_scan(scan_id)
            elif event == "chains_start":
                phase_ids = data.get("phases", [])
                scan["progress"].append(
                    f"Running {len(phase_ids)} attack chain categories in parallel..."
                )
                _save_scan(scan_id)
            elif event == "chains_end":
                scan["progress"].append(
                    f"Chain analysis done: {data.get('findings', 0)} chain findings"
                )
                _save_scan(scan_id)
            elif event == "out_of_scope":
                url = data.get("url", "")
                if url and url not in [u["url"] for u in scan.get("live_out_of_scope", [])]:
                    scan.setdefault("live_out_of_scope", []).append({
                        "url": url,
                        "tool": data.get("tool", ""),
                        "phase": data.get("phase", ""),
                    })

        router = LLMRouter(models=[model])
        scan["_router"] = router

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
            "scan_scope": scan_scope,
            "focus_urls": focus_urls or [],
            "focus_areas": focus_areas or [],
            "exclude_urls": exclude_urls or [],
            "scan_intensity": scan_intensity,
            "scan_profile": scan_profile,
            "skip_passive_sibling_tls": skip_passive_sibling_tls,
            "workflow_id": workflow_id,
            "business_flow": business_flow,
        }
        if username_b or password_b:
            target_dict["credentials_b"] = {"username": username_b, "password": password_b}
        if credentials_admin and any(credentials_admin.values()):
            target_dict["credentials_admin"] = credentials_admin
        if credentials_tenant_b and any(credentials_tenant_b.values()):
            target_dict["credentials_tenant_b"] = credentials_tenant_b
        target = load_targets_from_dict(target_dict)

        scan["progress"].append(f"Starting scan with {model}...")
        start = time.perf_counter()
        config_dir = str(BASE / "config")
        findings, metrics = await run_scan(target, model, router, config_dir, on_progress=_on_progress, extra_domains=extra_domains, cancel_flag=cancel_flag, pause_flag=pause_flag, start_from_phase=start_from_phase, initial_findings=initial_findings, interactive_session=interactive_session)
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

        _persist_scan_result(scan_id, output)

        meta = output.get("metadata", {})
        summary = output.get("summary", {})
        final_cost = meta.get("cost_usd") or 0
        SCANS[scan_id].update({
            "status": "completed",
            "duration": round(duration, 1),
            "cost": final_cost,
            "total_tokens": meta.get("total_tokens"),
            "llm_calls": meta.get("llm_calls"),
            "findings_count": summary.get("total_findings", len(findings)),
            "result_file": os.path.basename(filepath),
            "progress": SCANS[scan_id]["progress"] + ["Scan completed."],
        })
        SCANS[scan_id].pop("auth_challenge", None)
        SCANS[scan_id].pop("interactive_browser", None)
        scandb.add_all_time_cost(final_cost)
        _save_scan(scan_id)
    except ScanCancelled:
        duration = time.perf_counter() - start
        model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
        filepath = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
        partial_findings = scan.get("live_findings", [])
        cost_summary = router.get_cost_summary() if router else []
        _partial_metrics = {
            "test_log": scan.get("live_tests", []),
            "phase_log": scan.get("live_phases", []),
            "pages_crawled": len(scan.get("live_crawled", [])),
            "pages_list": [c.get("url", "") for c in scan.get("live_crawled", []) if isinstance(c, dict)],
            "forms_found": scan.get("live_forms", 0),
            "total_tool_calls": scan.get("live_tool_calls", 0),
            "phases_completed": len(scan.get("live_phases", [])),
        }
        try:
            _partial_out = save_results(filepath, partial_findings, cost_summary, target, model, duration, scan_metrics=_partial_metrics)
            _persist_scan_result(scan_id, _partial_out)
        except Exception:
            filepath = None
        _tok = sum(c.get("input_tokens", 0) + c.get("output_tokens", 0) for c in cost_summary) if isinstance(cost_summary, list) else None
        _calls = sum(c.get("calls", 0) for c in cost_summary) if isinstance(cost_summary, list) else None
        _cost = sum(c.get("cost_usd", 0) for c in cost_summary) if isinstance(cost_summary, list) else None
        phases_done = len(scan.get("live_phases", []))
        SCANS[scan_id].update({
            "status": "completed",
            "error": f"Scan stopped early by user after {phases_done} phase(s). {len(partial_findings)} finding(s) preserved.",
            "duration": round(duration, 1),
            "cost": _cost,
            "total_tokens": _tok,
            "llm_calls": _calls,
            "findings_count": len(partial_findings),
            "result_file": os.path.basename(filepath) if filepath else None,
            "phases_completed": phases_done,
            "progress": SCANS[scan_id]["progress"] + ["Scan stopped early — results saved and triaged."],
        })
        SCANS[scan_id].pop("auth_challenge", None)
        SCANS[scan_id].pop("interactive_browser", None)
        if _cost:
            scandb.add_all_time_cost(_cost)
        _save_scan(scan_id)
    except Exception as e:
        try:
            duration = time.perf_counter() - start
        except Exception:
            duration = 0
        filepath = None
        partial_findings = scan.get("live_findings", [])
        cost_summary = []
        err_cost = None
        try:
            cost_summary = router.get_cost_summary()
        except Exception:
            pass
        if isinstance(cost_summary, list):
            err_cost = round(sum(c.get("cost_usd", 0) for c in cost_summary), 4) or None
        elif isinstance(cost_summary, dict):
            err_cost = cost_summary.get("total_cost_usd")
        _err_metrics = {
            "test_log": scan.get("live_tests", []),
            "phase_log": scan.get("live_phases", []),
            "pages_crawled": len(scan.get("live_crawled", [])),
            "pages_list": [c.get("url", "") for c in scan.get("live_crawled", []) if isinstance(c, dict)],
            "forms_found": scan.get("live_forms", 0),
            "total_tool_calls": scan.get("live_tool_calls", 0),
            "phases_completed": len(scan.get("live_phases", [])),
        }
        try:
            model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
            fp = str(RAW_DIR / f"aiagent_{model_slug}_{scan_id}.json")
            _partial_out = save_results(fp, partial_findings, cost_summary if isinstance(cost_summary, list) else [], target, model, duration, scan_metrics=_err_metrics)
            _persist_scan_result(scan_id, _partial_out)
            filepath = fp
        except Exception:
            logger.debug("Error-handler save_results failed for %s", scan_id, exc_info=True)
        phases_done = len(scan.get("live_phases", []))
        err_msg = str(e).strip()
        if not err_msg:
            err_msg = type(e).__name__
        err_detail = f"{err_msg} — occurred during phase {phases_done + 1}. {len(partial_findings)} finding(s) preserved."
        SCANS[scan_id].update({
            "status": "error",
            "error": err_detail,
            "duration": round(duration, 1),
            "cost": err_cost,
            "findings_count": len(partial_findings),
            "result_file": os.path.basename(filepath) if filepath else None,
            "phases_completed": phases_done,
            "progress": SCANS[scan_id]["progress"] + [f"Error: {e}"],
        })
        SCANS[scan_id].pop("auth_challenge", None)
        SCANS[scan_id].pop("interactive_browser", None)
        if err_cost:
            scandb.add_all_time_cost(err_cost)
        _save_scan(scan_id)


@app.get("/api/scan/{scan_id}", tags=["Scans"])
async def get_scan_status(scan_id: str):
    if scan_id in SCANS:
        s = SCANS[scan_id]
        return {
            "scan_id": scan_id,
            "status": s.get("status"),
            "target": s.get("target_url", s.get("target", "")),
            "model": s.get("model"),
            "scan_mode": s.get("scan_mode", ""),
            "scan_scope": s.get("scan_scope", "directory"),
            "focus_urls": s.get("focus_urls", []),
            "focus_areas": s.get("focus_areas", []),
            "exclude_urls": s.get("exclude_urls", []),
            "scan_intensity": s.get("scan_intensity", "deep"),
            "scan_profile": s.get("scan_profile", "vulnerability_scan"),
            "started": s.get("started"),
            "progress": s.get("progress", []),
            "current_phase": s.get("current_phase", ""),
            "result_file": s.get("result_file"),
            "error": s.get("error"),
            "duration": s.get("duration"),
            "cost": s.get("cost") if s.get("cost") is not None else s.get("live_cost"),
            "total_tokens": s.get("total_tokens") or s.get("live_tokens", 0),
            "llm_calls": s.get("llm_calls") or s.get("live_llm_calls", 0),
            "findings_count": s.get("findings_count", len(s.get("live_findings", []))),
            "phases_completed": s.get("phases_completed", len(s.get("live_phases", []))),
            "findings": s.get("live_findings", []) or _load_partial_findings(scan_id),
        }
    data = _load_raw_result_dict(scan_id)
    if data:
        meta = data.get("metadata", {})
        return {
            "scan_id": scan_id,
            "status": "completed",
            "result_file": SCANS.get(scan_id, {}).get("result_file"),
            "target": data.get("target", ""),
            "model": meta.get("model", ""),
        }
    return JSONResponse({"error": "Scan not found"}, status_code=404)


def _slim_finding(f: dict) -> dict:
    """Return a lightweight copy of a finding for the live poll response.

    Strips large fields (evidence blobs, HTTP exchanges, full remediation
    text) that can bloat findings to ~15 KB each.  The full data is still
    available via /api/results/{scan_id}.
    """
    return {
        "title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "url": f.get("url", ""),
        "parameter": f.get("parameter", ""),
        "phase": f.get("phase", ""),
        "owasp_category": f.get("owasp_category", ""),
        "payload": str(f.get("payload", ""))[:200],
        "evidence": str(f.get("evidence", ""))[:300],
        "explanation": str(f.get("explanation", ""))[:200],
    }


@app.get("/api/scan/{scan_id}/live", tags=["Scans"])
async def get_scan_live(scan_id: str, since_test: int = 0, since_finding: int = 0):
    """Return live scan activity: recent tests, findings, and phases since given offsets."""
    if scan_id not in SCANS:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    s = SCANS[scan_id]
    tests = s.get("live_tests", [])
    findings = s.get("live_findings", [])
    # Cap per-poll batch to keep response under ~200 KB
    _MAX_TESTS_PER_POLL = 150
    _MAX_FINDINGS_PER_POLL = 50
    new_tests = tests[since_test:]
    if len(new_tests) > _MAX_TESTS_PER_POLL:
        new_tests = new_tests[:_MAX_TESTS_PER_POLL]
    new_findings = findings[since_finding:]
    if len(new_findings) > _MAX_FINDINGS_PER_POLL:
        new_findings = new_findings[:_MAX_FINDINGS_PER_POLL]
    # Slim down findings to avoid multi-MB responses
    slim_findings = [_slim_finding(f) for f in new_findings]
    return {
        "status": s.get("status"),
        "current_phase": s.get("current_phase", ""),
        "phases": s.get("live_phases", []),
        "phase_tools": s.get("live_phase_tools", {}),
        "tests": new_tests,
        "tests_total": len(tests),
        "findings": slim_findings,
        "findings_total": len(findings),
        "pages_crawled": len(s.get("live_crawled", [])),
        "crawled_urls": s.get("live_crawled", []),
        "tool_calls": s.get("live_tool_calls", 0),
        "total_tokens": s.get("live_tokens", 0),
        "llm_calls": s.get("live_llm_calls", 0),
        "live_cost": s.get("live_cost", 0),
        "out_of_scope": s.get("live_out_of_scope", []),
        "parallel_active": s.get("parallel_active", False),
        "cache_read_tokens": s.get("live_cache_read", 0),
        "cache_write_tokens": s.get("live_cache_write", 0),
    }


@app.post("/api/scan/{scan_id}/stop", tags=["Scans"])
async def stop_scan(scan_id: str):
    """Stop a running scan. Sets a cancellation flag that the agent checks between steps."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = SCANS[scan_id]
    if s.get("status") not in ("running", "paused", "pausing", "stopping"):
        raise HTTPException(status_code=400, detail=f"Scan is not running (status: {s.get('status')})")
    flag = CANCEL_FLAGS.get(scan_id)
    if flag:
        flag.set()
    pause = PAUSE_FLAGS.get(scan_id)
    if pause:
        pause.clear()
    s["status"] = "stopping"
    s["_stop_requested_at"] = time.time()
    s["progress"] = s.get("progress", []) + ["Stop requested by user — finishing up and saving results..."]
    _save_scan(scan_id)
    _schedule_force_cancel(scan_id)
    return {"scan_id": scan_id, "status": "stopping", "message": "Scan will stop within a few seconds."}


@app.post("/api/scan/{scan_id}/pause", tags=["Scans"])
async def pause_scan(scan_id: str):
    """Pause a running scan. The agent will pause after the current LLM step.
    No further LLM calls are made while paused."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    s = SCANS[scan_id]
    if s.get("status") not in ("running",):
        raise HTTPException(status_code=400, detail=f"Scan is not running (status: {s.get('status')})")
    flag = PAUSE_FLAGS.get(scan_id)
    if not flag:
        raise HTTPException(status_code=400, detail="Pause flag not found — scan may have already finished")
    flag.set()
    s["status"] = "pausing"
    s["progress"] = s.get("progress", []) + ["Pause requested — will pause after current step..."]
    _save_scan(scan_id)
    return {"scan_id": scan_id, "status": "pausing", "message": "Scan will pause after the current step completes."}


@app.post("/api/scan/{scan_id}/resume", tags=["Scans"])
async def resume_scan(scan_id: str):
    """Resume a paused scan. Clears the pause flag so the agent continues
    from exactly where it left off — no duplicate work."""
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
    _save_scan(scan_id)
    return {"scan_id": scan_id, "status": "running"}




def _create_interactive_session(scan_id: str) -> dict:
    """Create an interactive browser session for a scan."""
    session = {
        "screenshot_b64": "",
        "events": _queue.Queue(),
        "active": threading.Event(),
        "done": threading.Event(),
        "viewport": (1280, 720),
    }
    INTERACTIVE_BROWSERS[scan_id] = session
    return session


@app.websocket("/ws/scan/{scan_id}/browser")
async def browser_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket for interactive browser — streams screenshots, receives mouse/key events."""
    await websocket.accept()
    session = INTERACTIVE_BROWSERS.get(scan_id)
    if not session or not session["active"].is_set():
        await websocket.send_json({"type": "error", "message": "No interactive session active"})
        await websocket.close(code=1008)
        return

    last_hash = None
    try:
        import asyncio as _aio

        async def _send_screenshots():
            nonlocal last_hash
            while session["active"].is_set() and not session["done"].is_set():
                shot = session.get("screenshot_b64", "")
                if shot:
                    h = hash(shot)
                    if h != last_hash:
                        await websocket.send_json({"type": "screenshot", "data": shot,
                                                   "viewport": list(session["viewport"])})
                        last_hash = h
                await _aio.sleep(0.3)
            await websocket.send_json({"type": "done"})

        async def _receive_events():
            while session["active"].is_set() and not session["done"].is_set():
                try:
                    data = await _aio.wait_for(websocket.receive_json(), timeout=1.0)
                    session["events"].put(data)
                except _aio.TimeoutError:
                    continue
                except WebSocketDisconnect:
                    break

        await _aio.gather(_send_screenshots(), _receive_events())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("Interactive browser WS error: %s", e)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/api/scan/{scan_id}/interactive-browser", tags=["Scans"])
async def get_interactive_browser_status(scan_id: str):
    """Check if a scan has an active interactive browser session."""
    session = INTERACTIVE_BROWSERS.get(scan_id)
    if not session or not session["active"].is_set():
        return {"active": False}
    return {
        "active": True,
        "done": session["done"].is_set(),
        "viewport": list(session["viewport"]),
    }


@app.post("/api/scan/{scan_id}/interactive-browser/done", tags=["Scans"])
async def interactive_browser_done(scan_id: str):
    """Signal that the user has finished logging in via the interactive browser."""
    session = INTERACTIVE_BROWSERS.get(scan_id)
    if not session or not session["active"].is_set():
        raise HTTPException(status_code=400, detail="No active interactive session")
    session["done"].set()
    if scan_id in SCANS:
        SCANS[scan_id]["progress"] = SCANS[scan_id].get("progress", []) + [
            "Interactive login completed by user"
        ]
        _save_scan(scan_id)
    return {"status": "ok", "message": "Interactive login marked complete, scan will continue"}


@app.post("/api/scan/{scan_id}/interactive-browser/event", tags=["Scans"])
async def interactive_browser_event(scan_id: str, request: Request):
    """Fallback HTTP endpoint for sending input events (if WebSocket unavailable)."""
    session = INTERACTIVE_BROWSERS.get(scan_id)
    if not session or not session["active"].is_set():
        raise HTTPException(status_code=400, detail="No active interactive session")
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    session["events"].put(body)
    return {"status": "ok"}


def _load_partial_findings(scan_id: str) -> list[dict]:
    """Load findings from DB-backed result payload (or legacy file back-fill)."""
    data = _load_raw_result_dict(scan_id)
    if not data:
        return []
    return data.get("findings", []) or []


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


def _extract_scan_params(old: dict, scan_id: str | None = None) -> dict:
    """Extract reusable parameters from an existing scan record."""
    return {
        "target_url": old.get("target_url", ""),
        "model": old.get("model", ""),
        "model_name": old.get("model_name", old.get("model", "")),
        "scan_mode": old.get("scan_mode") or _infer_scan_mode(old, scan_id),
        "auth_type": old.get("auth_type", "auto"),
        "username": old.get("_username", ""),
        "password": old.get("_password", ""),
        "username_b": old.get("_username_b", ""),
        "password_b": old.get("_password_b", ""),
        "credentials_admin": old.get("_credentials_admin") or {},
        "credentials_tenant_b": old.get("_credentials_tenant_b") or {},
        "api_imports": old.get("_api_imports", {}) or {},
        "extra_domains": old.get("_extra_domains", []) or [],
        "scan_scope": old.get("scan_scope", "directory"),
        "focus_urls": old.get("focus_urls", []) or [],
        "focus_areas": old.get("focus_areas", []) or [],
        "exclude_urls": old.get("exclude_urls", []) or [],
        "scan_intensity": old.get("scan_intensity", "deep"),
        "scan_profile": old.get("scan_profile", "vulnerability_scan"),
        "skip_passive_sibling_tls": old.get("skip_passive_sibling_tls", False),
    }


@app.post("/api/scan/{scan_id}/retry", tags=["Scans"])
async def retry_scan(scan_id: str, request: Request):
    """Re-run an errored/cancelled scan in-place.  Tries to continue from
    the last completed phase when possible; falls back to full re-run.
    Accepts optional JSON body: {scan_mode, model, force_restart: bool}."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    old = SCANS[scan_id]
    if old.get("status") not in ("error", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Only errored/cancelled scans can be retried (status: {old.get('status')})")

    params = _extract_scan_params(old, scan_id)
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
    model = _resolve_model_id(overrides.get("model") or params["model"])
    force_restart = overrides.get("force_restart", False)

    start_from = 0
    prior_findings: list[dict] = []
    if not force_restart:
        phases_done = _get_phases_completed(old)
        if phases_done > 0:
            prior_findings = _load_partial_findings(scan_id)
            start_from = phases_done

    mode_label = "continuing" if start_from > 0 else "restarting"
    phase_msg = f" from phase {start_from + 1}" if start_from > 0 else ""

    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[scan_id] = cancel_flag
    PAUSE_FLAGS[scan_id] = pause_flag

    interactive_session = _create_interactive_session(scan_id)

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
    _save_scan(scan_id)

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(scan_id, params["target_url"], params["username"], params["password"],
              model, scan_mode, params["auth_type"], params["api_imports"],
              params["extra_domains"], cancel_flag, pause_flag, start_from, prior_findings),
        kwargs={"scan_scope": params["scan_scope"], "focus_urls": params["focus_urls"], "focus_areas": params["focus_areas"], "scan_intensity": params["scan_intensity"], "scan_profile": params.get("scan_profile", "vulnerability_scan"), "exclude_urls": params.get("exclude_urls", []), "username_b": params.get("username_b", ""), "password_b": params.get("password_b", ""), "credentials_admin": params.get("credentials_admin"), "credentials_tenant_b": params.get("credentials_tenant_b"), "interactive_session": interactive_session, "skip_passive_sibling_tls": params.get("skip_passive_sibling_tls", False)},
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
async def rescan(scan_id: str, request: Request):
    """Create a NEW scan with the same parameters as an existing (typically
    completed) scan.  Returns the new scan_id."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    old = SCANS[scan_id]

    params = _extract_scan_params(old, scan_id)
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
    model = _resolve_model_id(overrides.get("model") or params["model"])

    new_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    cancel_flag = threading.Event()
    pause_flag = threading.Event()
    CANCEL_FLAGS[new_id] = cancel_flag
    PAUSE_FLAGS[new_id] = pause_flag

    interactive_session = _create_interactive_session(new_id)

    SCANS[new_id] = {
        "target_url": params["target_url"],
        "model": model,
        "model_name": params["model_name"],
        "status": "running",
        "started": datetime.now().isoformat(),
        "progress": [f"Re-scan of {scan_id} (mode: {scan_mode})..."],
        "scan_mode": scan_mode,
        "scan_scope": params["scan_scope"],
        "focus_urls": params["focus_urls"],
        "focus_areas": params["focus_areas"],
        "exclude_urls": params.get("exclude_urls", []),
        "scan_intensity": params["scan_intensity"],
        "scan_profile": params.get("scan_profile", "vulnerability_scan"),
        "skip_passive_sibling_tls": params.get("skip_passive_sibling_tls", False),
        "auth_type": params["auth_type"],
        "_username": params["username"],
        "_password": params["password"],
        "_username_b": params.get("username_b", ""),
        "_password_b": params.get("password_b", ""),
        "_credentials_admin": params.get("credentials_admin") or {},
        "_credentials_tenant_b": params.get("credentials_tenant_b") or {},
        "_api_imports": params["api_imports"],
        "_extra_domains": params["extra_domains"],
    }
    _save_scan(new_id)

    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(new_id, params["target_url"], params["username"], params["password"],
              model, scan_mode, params["auth_type"], params["api_imports"],
              params["extra_domains"], cancel_flag, pause_flag),
        kwargs={"scan_scope": params["scan_scope"], "focus_urls": params["focus_urls"], "focus_areas": params["focus_areas"], "scan_intensity": params["scan_intensity"], "scan_profile": params.get("scan_profile", "vulnerability_scan"), "exclude_urls": params.get("exclude_urls", []), "username_b": params.get("username_b", ""), "password_b": params.get("password_b", ""), "credentials_admin": params.get("credentials_admin"), "credentials_tenant_b": params.get("credentials_tenant_b"), "interactive_session": interactive_session, "skip_passive_sibling_tls": params.get("skip_passive_sibling_tls", False)},
        daemon=True,
    )
    thread.start()
    return {"scan_id": new_id, "status": "started", "parent_scan": scan_id}


@app.delete("/api/scan/{scan_id}", tags=["Scans"])
async def delete_scan(scan_id: str):
    """Stop (if running) and fully delete a scan, its result files, and reports."""
    deleted = []
    errors = []
    if scan_id in SCANS:
        scan_cost = SCANS[scan_id].get("cost", 0) or SCANS[scan_id].get("live_cost", 0) or 0
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
        if scan_cost > 0:
            try:
                scandb.add_deleted_cost(scan_cost)
            except Exception as e:
                errors.append(f"cost ledger: {e}")
        result_file = SCANS[scan_id].get("result_file")
        del SCANS[scan_id]
        _RESULTS_CACHE.pop(scan_id, None)
        try:
            scandb.delete_scan(scan_id)
        except Exception as e:
            errors.append(f"db delete: {e}")
        CANCEL_FLAGS.pop(scan_id, None)
        PAUSE_FLAGS.pop(scan_id, None)
        deleted.append("scan_record")
        if result_file:
            fpath = RAW_DIR / result_file
            try:
                if fpath.exists():
                    fpath.unlink()
                    deleted.append(str(result_file))
            except Exception:
                pass
    for f in list(RAW_DIR.glob("*.json")):
        if scan_id in f.stem:
            try:
                f.unlink()
                deleted.append(f.name)
            except Exception:
                pass
    for f in list(REPORTS_DIR.glob("*.pdf")):
        if scan_id in f.stem or any(scan_id in part for part in f.stem.split("_")):
            try:
                f.unlink()
                deleted.append(f.name)
            except Exception:
                pass
    if not deleted:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    result = {"deleted": deleted}
    if errors:
        result["warnings"] = errors
    return result


@app.delete("/api/scans", tags=["Scans"])
async def delete_all_scans():
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
    bulk_cost = sum(s.get("cost", 0) or s.get("live_cost", 0) or 0 for s in SCANS.values())
    bulk_count = len(SCANS)
    if bulk_cost > 0:
        scandb.add_deleted_cost(bulk_cost, bulk_count)
    SCANS.clear()
    CANCEL_FLAGS.clear()
    PAUSE_FLAGS.clear()
    try:
        scandb.delete_all_scans()
    except Exception as e:
        logger.warning("delete_all_scans DB cleanup: %s", e)
    count = 0
    for f in list(RAW_DIR.glob("*.json")):
        try:
            f.unlink()
            count += 1
        except Exception:
            pass
    for f in list(REPORTS_DIR.glob("*.pdf")):
        try:
            f.unlink()
            count += 1
        except Exception:
            pass
    return {"deleted_files": count, "status": "cleared"}


@app.get("/api/results/{scan_id}", tags=["Results"])
async def get_results(scan_id: str, request: Request):
    try:
        data = await _get_results_inner(scan_id)
        if isinstance(data, JSONResponse):
            return data
        if request.query_params.get("enc") == "b64":
            import base64
            payload = base64.b64encode(json.dumps(data, default=str).encode()).decode()
            return JSONResponse({"_b64": payload})
        return data
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_results(%s) failed: %s", scan_id, e, exc_info=True)
        return JSONResponse({"error": f"Failed to load results: {type(e).__name__}: {e}"}, status_code=500)

async def _get_results_inner(scan_id: str):
    cached = _RESULTS_CACHE.get(scan_id)
    if cached:
        overrides = SCANS[scan_id].get("cvss_overrides", {}) if scan_id in SCANS else {}
        if overrides:
            for fe in cached.get("triaged_findings", []):
                key = f"{fe.get('title', '')}||{fe.get('url', '')}"
                if key in overrides:
                    fe["cvss_override"] = overrides[key]["cvss"]
                    fe["cvss_override_note"] = overrides[key].get("note", "")
        return cached

    data = _load_raw_result_dict(scan_id)
    if not data:
        return JSONResponse({"error": "Results not found"}, status_code=404)
    findings = data.get("findings") or []
    test_log = data.get("summary", {}).get("test_log") or []
    if not test_log and scan_id in SCANS:
        test_log = SCANS[scan_id].get("live_tests", [])
    meta = data.get("metadata") or {}
    summary = data.get("summary", {})

    _tl_index = _build_test_log_index(test_log)

    ai_findings = []
    triaged_findings = []
    overrides = SCANS[scan_id].get("cvss_overrides", {}) if scan_id in SCANS else {}
    for f in findings:
        # Defensive: legacy result files persisted before deterministic
        # severity classification only carry the LLM-assigned severity.
        # Re-classify on read so the AI Raw tab is always normalised.
        if "cvss" not in f or "cvss_vector" not in f:
            f.update(classify_severity(f))
        ai_findings.append({
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "llm_severity": f.get("llm_severity", ""),
            "cvss": f.get("cvss"),
            "cvss_vector": f.get("cvss_vector", ""),
            "cwe": f.get("cwe", ""),
            "owasp": f.get("owasp_category", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "confidence": f.get("confidence", ""),
            "remediation": f.get("remediation", ""),
            "request_response": f.get("request_response", []),
        })
        triaged = triage_classify(f, test_log, _index=_tl_index)
        final_sev = triaged.get("final_severity", "Info")
        finding_entry = {
            "title": triaged.get("title", ""),
            "ai_severity": f.get("severity", ""),
            "severity": final_sev,
            "final_severity": final_sev,
            "verdict": triaged.get("verdict", ""),
            "reason": triaged.get("reason", ""),
            "confidence_score": triaged.get("confidence_score"),
            "url": triaged.get("url", ""),
            "parameter": f.get("parameter", ""),
            "owasp_category": f.get("owasp_category", ""),
            "payload": f.get("payload", ""),
            "evidence": f.get("evidence", ""),
            "remediation": f.get("remediation", ""),
            "confidence": f.get("confidence", ""),
            "request_response": f.get("request_response", []),
            "cwe": triaged.get("cwe", ""),
            "cvss": triaged.get("cvss"),
            "cvss_rationale": triaged.get("cvss_rationale", ""),
            "cve": triaged.get("cve", ""),
            "verified": f.get("verified", False),
            "verification_method": triaged.get("verification_method", "none"),
            "verification_evidence": triaged.get("verification_evidence", ""),
        }

        key = f"{triaged.get('title', '')}||{triaged.get('url', '')}"
        if key in overrides:
            finding_entry["cvss_override"] = overrides[key]["cvss"]
            finding_entry["cvss_override_note"] = overrides[key].get("note", "")
        triaged_findings.append(finding_entry)

    crawled = _extract_crawled(summary, test_log)
    payloads_by_endpoint = _extract_payloads_by_endpoint(test_log)

    result = {
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

    if len(_RESULTS_CACHE) >= _RESULTS_CACHE_MAX:
        try:
            _RESULTS_CACHE.pop(next(iter(_RESULTS_CACHE)))
        except StopIteration:
            pass
    _RESULTS_CACHE[scan_id] = result
    return result


def _build_test_log_index(test_log: list) -> dict:
    """Pre-index test_log entries by URL base path and pre-serialize request JSON.

    Defensive: ``test_log`` may originate from in-memory ``live_tests`` which
    is *expected* to hold dicts but has been observed to contain strings/None
    in production (see test_results_endpoint_resilience.py for the
    regression fixtures). Skip non-dict entries silently rather than 500.
    """
    from collections import defaultdict
    idx: dict[str, list] = defaultdict(list)
    if not isinstance(test_log, list):
        return dict(idx)
    for t in test_log:
        if not isinstance(t, dict):
            continue
        req = t.get("request", {})
        if not isinstance(req, dict):
            continue
        t_url = req.get("url", "") or req.get("endpoint", "")
        url_base = str(t_url).split("?")[0]
        if "_req_json_lower" not in t:
            t["_req_json_lower"] = json.dumps(req, default=str).lower()
        if url_base:
            idx[url_base].append(t)
        idx["__all__"].append(t)
    return dict(idx)


@app.get("/api/results/{scan_id}/download", tags=["Results"])
async def download_raw(scan_id: str):
    data = _load_raw_result_dict(scan_id)
    if not data:
        return JSONResponse({"error": "Not found"}, status_code=404)
    blob = json.dumps(data, indent=2, default=str).encode("utf-8")
    fn = (SCANS.get(scan_id) or {}).get("result_file") or f"{scan_id}_results.json"
    return StreamingResponse(
        BytesIO(blob),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'},
    )


@app.post("/api/results/{scan_id}/cvss-override", tags=["Results"])
async def cvss_override(scan_id: str, request: Request):
    """Save a CVSS override for a specific finding in a scan."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
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
    _RESULTS_CACHE.pop(scan_id, None)
    _save_scan(scan_id)

    return {"status": "ok", "key": key, "cvss": cvss_value, "note": note}


def _apply_cvss_overrides_to_classified(classified: list, scan_id: str) -> list:
    """Merge any per-finding CVSS overrides into a classified/triaged list.

    Ensures PDF, Excel, and compliance exports reflect the same CVSS values
    that the UI shows, rather than the auto-computed scores. Sets:

    - ``cvss_override`` / ``cvss_override_note``: supplementary fields
    - ``cvss``: replaced with the override value so downstream renderers
      that read ``f['cvss']`` directly (e.g. report_generator.py) pick up
      the override automatically.
    """
    overrides = SCANS.get(scan_id, {}).get("cvss_overrides", {}) if scan_id in SCANS else {}
    if not overrides:
        return classified
    for f in classified:
        if not isinstance(f, dict):
            continue
        key = f"{f.get('title', '')}||{f.get('url', '')}"
        ov = overrides.get(key)
        if ov is None:
            continue
        f["cvss_override"] = ov["cvss"]
        f["cvss_override_note"] = ov.get("note", "")
        f["cvss"] = ov["cvss"]
    return classified


@app.post("/api/results/{scan_id}/report", tags=["Results"])
async def generate_report(scan_id: str):
    data = _load_raw_result_dict(scan_id)
    if not data:
        return JSONResponse({"error": "Not found"}, status_code=404)

    try:
        findings = data.get("findings") or []
        test_log = data.get("summary", {}).get("test_log") or []

        import scripts.report_generator as rg
        classified = [triage_classify(f, test_log) for f in findings if isinstance(f, dict)]
        _apply_cvss_overrides_to_classified(classified, scan_id)
        model_key = data.get("model", "") or data.get("metadata", {}).get("model", "unknown")

        orig_out = rg.OUT_DIR
        rg.OUT_DIR = str(REPORTS_DIR)
        result = rg.gen_report(model_key, classified, data, scan_id=scan_id)
        rg.OUT_DIR = orig_out

        if result:
            pdf_path = result[0]
            return {"pdf": f"/api/reports/{os.path.basename(pdf_path)}"}
        return JSONResponse({"error": "No findings to report"}, status_code=400)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"error": f"Report generation failed: {str(e)}"}, status_code=500)


_COMPLIANCE_FRAMEWORKS = {
    "owasp": {
        "name": "OWASP Top 10 2021",
        "subtitle": "Open Worldwide Application Security Project",
        "color": (30, 58, 138),
        "mappings": {
            "A01": {"title": "Broken Access Control", "controls": ["Authorization checks", "CORS policy", "Directory traversal prevention"],
                    "desc": "Failures in enforcing access policies, allowing users to act outside their intended permissions.",
                    "remediation": "Implement server-side access controls, deny by default, enforce record ownership, disable directory listing, rate-limit API access, invalidate JWT on logout."},
            "A02": {"title": "Cryptographic Failures", "controls": ["TLS enforcement", "Sensitive data encryption", "Cookie security flags"],
                    "desc": "Exposure of sensitive data due to weak or missing cryptographic protections.",
                    "remediation": "Enforce TLS 1.2+, classify data sensitivity, encrypt data at rest with AES-256, use strong hashing (bcrypt/Argon2) for passwords, set Secure/HttpOnly/SameSite cookie flags."},
            "A03": {"title": "Injection", "controls": ["Input validation", "Parameterized queries", "Output encoding"],
                    "desc": "User-supplied data sent to an interpreter as part of a command or query without proper validation.",
                    "remediation": "Use parameterized queries/prepared statements, validate and sanitize all inputs server-side, apply context-aware output encoding, use ORMs, deploy WAF rules."},
            "A04": {"title": "Insecure Design", "controls": ["Threat modeling", "Secure design patterns", "Business logic validation"],
                    "desc": "Missing or ineffective security controls due to flawed architectural and design decisions.",
                    "remediation": "Integrate threat modeling into SDLC, establish secure design patterns library, implement business logic unit tests, use abuse-case testing in CI/CD."},
            "A05": {"title": "Security Misconfiguration", "controls": ["Hardening", "Default credentials", "Error handling"],
                    "desc": "Insecure default configurations, incomplete setups, open cloud storage, verbose errors, or unnecessary features.",
                    "remediation": "Harden all environments uniformly, remove unused features/frameworks, automate configuration verification, implement proper error handling that does not leak stack traces."},
            "A06": {"title": "Vulnerable and Outdated Components", "controls": ["Dependency scanning", "Version management", "Patch management"],
                    "desc": "Use of components with known vulnerabilities or components no longer maintained.",
                    "remediation": "Continuously inventory and monitor dependencies with SCA tools (Snyk, Dependabot), subscribe to CVE advisories, automate patching pipelines, remove unused dependencies."},
            "A07": {"title": "Identification and Authentication Failures", "controls": ["Multi-factor auth", "Session management", "Password policy"],
                    "desc": "Weaknesses in authentication mechanisms allowing credential attacks or session hijacking.",
                    "remediation": "Implement MFA, enforce strong password policies (NIST 800-63B), use secure session management with proper timeouts, protect against credential stuffing with rate limiting and CAPTCHA."},
            "A08": {"title": "Software and Data Integrity Failures", "controls": ["SRI checks", "Signed updates", "CI/CD pipeline security"],
                    "desc": "Code and infrastructure that does not protect against integrity violations, including insecure CI/CD pipelines.",
                    "remediation": "Use Subresource Integrity (SRI) for CDN assets, sign software artifacts, verify digital signatures, secure CI/CD pipeline with least-privilege and audit logging."},
            "A09": {"title": "Security Logging and Monitoring Failures", "controls": ["Security event logging", "Monitoring", "Alerting"],
                    "desc": "Insufficient logging, monitoring, or alerting to detect and respond to active breaches.",
                    "remediation": "Log all authentication events, access control failures, and input validation errors; use centralized log management (SIEM); establish incident response runbooks; test alerting regularly."},
            "A10": {"title": "Server-Side Request Forgery (SSRF)", "controls": ["URL validation", "Network segmentation", "Allowlist enforcement"],
                    "desc": "Application fetches remote resources without validating the user-supplied URL, enabling attacks against internal services.",
                    "remediation": "Validate and sanitize all client-supplied URLs, enforce URL allowlists, segment network access, disable HTTP redirections, block metadata endpoints (169.254.169.254)."},
        },
    },
    "pci-dss": {
        "name": "PCI DSS v4.0",
        "subtitle": "Payment Card Industry Data Security Standard",
        "color": (127, 29, 29),
        "mappings": {
            "6.2": {"title": "Bespoke and Custom Software Security", "owasp": ["A03", "A04"],
                    "desc": "Develop software securely using industry best practices and addressing common vulnerabilities.",
                    "remediation": "Conduct secure code reviews, train developers on OWASP Top 10, use SAST/DAST in CI/CD, validate all input on the server side."},
            "6.4": {"title": "Public-Facing Web Application Protection", "owasp": ["A01", "A03", "A05", "A07"],
                    "desc": "Protect public-facing web applications against known attacks on an ongoing basis.",
                    "remediation": "Deploy a WAF, perform application vulnerability assessments at least annually and after changes, review web application architecture for security."},
            "6.5": {"title": "Address Common Coding Vulnerabilities", "owasp": ["A03", "A02", "A05"],
                    "desc": "Prevent common coding vulnerabilities in software development processes.",
                    "remediation": "Train developers annually on secure coding, use automated SAST scanning, validate cryptographic implementations, sanitize all outputs."},
            "11.3": {"title": "External and Internal Penetration Testing", "owasp": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
                    "desc": "Regularly test security of systems and networks through penetration testing.",
                    "remediation": "Conduct internal and external pen tests at least annually and after significant changes, remediate exploitable vulnerabilities and re-test."},
        },
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "subtitle": "Service Organization Control - Trust Services Criteria",
        "color": (88, 28, 135),
        "mappings": {
            "CC6.1": {"title": "Logical and Physical Access Controls", "owasp": ["A01", "A07"],
                      "desc": "Restrict logical access to information assets through authentication and authorization mechanisms.",
                      "remediation": "Implement RBAC, enforce MFA for privileged accounts, review access quarterly, log all access events."},
            "CC6.6": {"title": "System Boundary Protection", "owasp": ["A05", "A10"],
                      "desc": "Restrict data transmission, movement, and removal to authorized channels.",
                      "remediation": "Deploy network segmentation, restrict outbound connections, validate server-side request targets, monitor data flows."},
            "CC7.1": {"title": "Detection of Vulnerabilities", "owasp": ["A06", "A03"],
                      "desc": "Detect and manage system vulnerabilities and configuration changes.",
                      "remediation": "Run continuous vulnerability scanning, maintain a software inventory, implement automated patch management, track remediation SLAs."},
            "CC7.2": {"title": "Anomaly Detection and Monitoring", "owasp": ["A09"],
                      "desc": "Monitor system components for anomalies indicative of malicious acts or natural disasters.",
                      "remediation": "Deploy SIEM with correlation rules, establish baseline behavior, alert on anomalies, conduct regular log reviews."},
            "CC8.1": {"title": "Change Management", "owasp": ["A08"],
                      "desc": "Authorize, design, develop, configure, document, test, approve, and implement changes.",
                      "remediation": "Enforce change management process, require code reviews, implement CI/CD with security gates, verify software integrity."},
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "subtitle": "Health Insurance Portability and Accountability Act",
        "color": (21, 94, 117),
        "mappings": {
            "164.312(a)": {"title": "Access Control", "owasp": ["A01", "A07"],
                           "desc": "Implement technical policies and procedures for access to ePHI systems.",
                           "remediation": "Implement unique user identification, emergency access procedures, automatic logoff, encrypt ePHI at rest."},
            "164.312(c)": {"title": "Integrity Controls", "owasp": ["A03", "A08"],
                           "desc": "Protect ePHI from improper alteration or destruction.",
                           "remediation": "Implement mechanisms to authenticate ePHI integrity, deploy input validation, use cryptographic checksums for data in transit."},
            "164.312(d)": {"title": "Person or Entity Authentication", "owasp": ["A07", "A02"],
                           "desc": "Verify the identity of persons or entities seeking access to ePHI.",
                           "remediation": "Implement multi-factor authentication, enforce strong password policies, use certificate-based auth for system-to-system communication."},
            "164.312(e)": {"title": "Transmission Security", "owasp": ["A02", "A05"],
                           "desc": "Protect ePHI when transmitted over electronic networks.",
                           "remediation": "Enforce TLS 1.2+ for all data in transit, implement integrity controls, disable insecure protocols, use VPN for remote access."},
            "164.308(a)(1)": {"title": "Security Management Process - Risk Analysis", "owasp": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
                              "desc": "Conduct an accurate and thorough assessment of potential risks to ePHI.",
                              "remediation": "Conduct comprehensive risk assessments annually, document all identified risks, implement risk mitigation plans, track remediation progress."},
        },
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "subtitle": "Information Security Management System",
        "color": (30, 64, 175),
        "mappings": {
            "A.8.9": {"title": "Configuration Management", "owasp": ["A05", "A06"],
                      "desc": "Establish, document, implement, and review configurations including security settings.",
                      "remediation": "Define security baselines for all technologies, automate configuration checks, track deviations, review configs on change."},
            "A.8.24": {"title": "Use of Cryptography", "owasp": ["A02"],
                       "desc": "Define and implement rules for the effective use of cryptography.",
                       "remediation": "Define cryptographic policy, use approved algorithms (AES-256, RSA-2048+), manage keys via HSM/KMS, rotate keys regularly."},
            "A.8.25": {"title": "Secure Development Life Cycle", "owasp": ["A03", "A04"],
                       "desc": "Establish and apply rules for the secure development of software and systems.",
                       "remediation": "Integrate security into all SDLC phases, require threat modeling, conduct design reviews, implement SAST/DAST in CI."},
            "A.8.28": {"title": "Secure Coding", "owasp": ["A03", "A08"],
                       "desc": "Apply secure coding principles to software development.",
                       "remediation": "Follow OWASP Secure Coding Practices, require peer code review, use linters/SAST, train developers annually."},
            "A.8.29": {"title": "Security Testing in Development and Acceptance", "owasp": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
                       "desc": "Define and implement security testing processes throughout the development life cycle.",
                       "remediation": "Integrate DAST/SAST into CI/CD, conduct pen testing pre-release, define acceptance criteria for security, track defect resolution."},
        },
    },
    "nist": {
        "name": "NIST SP 800-53 Rev 5",
        "subtitle": "Security and Privacy Controls for Information Systems",
        "color": (30, 41, 59),
        "mappings": {
            "SA-11": {"title": "Developer Testing and Evaluation", "owasp": ["A03", "A04", "A08"],
                      "desc": "Require developers to create and implement a security assessment plan.",
                      "remediation": "Mandate SAST/DAST as part of build pipeline, require security-focused unit tests, conduct fuzz testing for critical inputs."},
            "SI-10": {"title": "Information Input Validation", "owasp": ["A03"],
                      "desc": "Check the validity of information inputs to the system.",
                      "remediation": "Validate all inputs at the server side using allowlists, reject malformed data, implement context-specific encoding for outputs."},
            "SC-8": {"title": "Transmission Confidentiality and Integrity", "owasp": ["A02"],
                     "desc": "Protect the confidentiality and integrity of transmitted information.",
                     "remediation": "Enforce TLS 1.2+ with strong cipher suites, implement HSTS, use certificate pinning for critical connections."},
            "AC-3": {"title": "Access Enforcement", "owasp": ["A01", "A07"],
                     "desc": "Enforce approved authorizations for logical access to information and system resources.",
                     "remediation": "Implement RBAC with least privilege, enforce authorization on every request server-side, audit access decisions."},
            "AU-2": {"title": "Event Logging", "owasp": ["A09"],
                     "desc": "Identify events that the system is capable of logging in support of the audit function.",
                     "remediation": "Log authentication events, privilege changes, data access, and failures; ship logs to centralized SIEM; retain per policy."},
            "CM-6": {"title": "Configuration Settings", "owasp": ["A05", "A06"],
                     "desc": "Establish and document configuration settings for system components.",
                     "remediation": "Apply CIS Benchmarks, scan for misconfigurations weekly, disable unnecessary services, remove default accounts."},
            "SC-5": {"title": "Denial-of-Service Protection", "owasp": ["A04"],
                     "desc": "Protect against or limit the effects of denial-of-service events.",
                     "remediation": "Implement rate limiting, use CDN/DDoS protection, validate resource consumption, limit request payload sizes."},
        },
    },
}


_PDF_UNICODE_FONT = None

def _init_pdf_fonts(pdf):
    """Register a Unicode TTF font if available, enabling full character support."""
    global _PDF_UNICODE_FONT
    if _PDF_UNICODE_FONT is False:
        return
    if _PDF_UNICODE_FONT:
        for style, path in _PDF_UNICODE_FONT.items():
            pdf.add_font("DJV", style, path, uni=True)
        return
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ]
    regular = None
    bold = None
    italic = None
    for c in candidates:
        if Path(c).exists():
            if "Bold" in c:
                bold = c
            elif "Oblique" in c or "Italic" in c:
                italic = c
            else:
                regular = c
    if regular:
        _PDF_UNICODE_FONT = {"": regular, "B": bold or regular, "I": italic or regular, "BI": bold or regular}
        for style, path in _PDF_UNICODE_FONT.items():
            pdf.add_font("DJV", style, path, uni=True)
    else:
        _PDF_UNICODE_FONT = False


def _safe_pdf(text):
    """Sanitize text for PDF output — handles Unicode gracefully."""
    if not text:
        return ""
    s = str(text)
    s = s.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "").replace("\ufeff", "")
    if _PDF_UNICODE_FONT:
        return s[:3500]
    s = s.replace("\u2014", " -- ").replace("\u2013", " - ")
    s = s.replace("\u2018", "'").replace("\u2019", "'")
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    s = s.replace("\u2026", "...").replace("\u00a0", " ")
    s = s.replace("\u2022", "*").replace("\u2192", "->").replace("\u2190", "<-")
    s = s.replace("\u2605", "*").replace("\u00b7", "-")
    s = s.replace("\u2713", "[PASS]").replace("\u2714", "[PASS]")
    s = s.replace("\u2717", "[FAIL]").replace("\u2718", "[FAIL]")
    s = s.replace("\u25cf", "*").replace("\u25cb", "o").replace("\u25a0", "#").replace("\u25a1", "[ ]")
    s = s.replace("\u2502", "|").replace("\u2500", "-").replace("\u253c", "+")
    s = s.replace("\u00e9", "e").replace("\u00e8", "e").replace("\u00ea", "e")
    import re
    s = re.sub(r'[\U00010000-\U0010FFFF]', '', s)
    return s.encode("latin-1", errors="replace").decode("latin-1")[:3500]


def _pdf_font(pdf, style="", size=10):
    """Set font — use Unicode DJV if available, else Helvetica."""
    family = "DJV" if _PDF_UNICODE_FONT else "Helvetica"
    pdf.set_font(family, style, size)


def _finding_sev(f: dict) -> str:
    """Resolve severity from triaged finding — triage stores it in final_severity/scanner_severity."""
    raw = (f.get("final_severity")
           or f.get("severity")
           or f.get("scanner_severity")
           or "Info")
    return raw if isinstance(raw, str) else str(raw)


_SEV_COLORS = {
    "Critical": (153, 27, 27),
    "High": (220, 38, 38),
    "Medium": (234, 88, 12),
    "Low": (22, 163, 74),
    "Info": (100, 116, 139),
    "Not Exploitable": (100, 116, 139),
}

_SEV_BG = {
    "Critical": (254, 226, 226),
    "High": (254, 226, 226),
    "Medium": (255, 237, 213),
    "Low": (220, 252, 231),
    "Info": (241, 245, 249),
    "Not Exploitable": (241, 245, 249),
}


def _pdf_severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        s = _finding_sev(f)
        counts[s] = counts.get(s, 0) + 1
    return counts


def _pdf_section_header(pdf, title: str, *, bg=(30, 41, 59), fg=(255, 255, 255)):
    """Draw a full-width colored section header bar."""
    pdf.set_fill_color(*bg)
    pdf.set_text_color(*fg)
    _pdf_font(pdf, "B", 11)
    pdf.cell(0, 9, _safe_pdf(f"  {title}"), ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)


def _pdf_kv_row(pdf, label: str, value: str, bold_val: bool = False):
    _pdf_font(pdf, "B", 9)
    pdf.cell(42, 6, _safe_pdf(label), ln=False)
    _pdf_font(pdf, "B" if bold_val else "", 9)
    pdf.cell(0, 6, _safe_pdf(value), ln=True)


def _pdf_severity_badge(pdf, sev: str, w: int = 24):
    color = _SEV_COLORS.get(sev, (100, 116, 139))
    bg = _SEV_BG.get(sev, (241, 245, 249))
    pdf.set_fill_color(*bg)
    pdf.set_text_color(*color)
    _pdf_font(pdf, "B", 8)
    pdf.cell(w, 5, _safe_pdf(sev), align="C", fill=True)
    pdf.set_text_color(0, 0, 0)


def _pdf_horiz_bar(pdf, counts: dict, total: int, bar_w: float = 150):
    """Draw a horizontal stacked severity bar chart."""
    if total <= 0:
        return
    x0 = pdf.get_x() + 10
    y0 = pdf.get_y()
    for sev_name in ("Critical", "High", "Medium", "Low", "Info"):
        cnt = counts.get(sev_name, 0)
        if cnt <= 0:
            continue
        w = max(cnt / total * bar_w, 4)
        color = _SEV_COLORS.get(sev_name, (100, 116, 139))
        pdf.set_fill_color(*color)
        pdf.rect(x0, y0, w, 6, "F")
        if w > 12:
            pdf.set_xy(x0, y0)
            pdf.set_text_color(255, 255, 255)
            _pdf_font(pdf, "B", 6)
            pdf.cell(w, 6, _safe_pdf(str(cnt)), align="C")
        x0 += w
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(10, y0 + 9)


def _pdf_control_row(pdf, status: str, req_id: str, title: str, count: int, desc: str = "", remediation: str = "", mapped: str = ""):
    """Draw a professional control assessment row with status, description, and remediation."""
    if pdf.get_y() > 250:
        pdf.add_page()
    is_fail = status == "FAIL"
    stripe_color = (220, 38, 38) if is_fail else (22, 163, 74)
    row_bg = (254, 242, 242) if is_fail else (240, 253, 244)

    pdf.set_fill_color(*row_bg)
    y_start = pdf.get_y()
    pdf.rect(10, y_start, 190, 8, "F")
    pdf.set_fill_color(*stripe_color)
    pdf.rect(10, y_start, 3, 8, "F")

    pdf.set_xy(15, y_start + 1)
    pdf.set_text_color(*stripe_color)
    _pdf_font(pdf, "B", 9)
    badge = "FAIL" if is_fail else "PASS"
    pdf.cell(14, 6, _safe_pdf(badge))
    pdf.set_text_color(30, 41, 59)
    _pdf_font(pdf, "B", 9)
    pdf.cell(0, 6, _safe_pdf(f"{req_id}: {title}"), ln=False)
    pdf.set_xy(160, y_start + 1)
    pdf.set_text_color(100, 116, 139)
    _pdf_font(pdf, "", 8)
    pdf.cell(40, 6, _safe_pdf(f"{count} finding{'s' if count != 1 else ''}"), ln=True, align="R")
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(y_start + 8)

    if desc:
        _pdf_font(pdf, "I", 7)
        pdf.set_text_color(100, 116, 139)
        pdf.set_x(16)
        pdf.multi_cell(180, 3.5, _safe_pdf(desc))
        pdf.set_text_color(0, 0, 0)

    if mapped:
        _pdf_font(pdf, "", 7)
        pdf.set_text_color(79, 70, 229)
        pdf.set_x(16)
        pdf.cell(0, 4, _safe_pdf(f"Maps to OWASP: {mapped}"), ln=True)
        pdf.set_text_color(0, 0, 0)

    return is_fail, remediation


def _pdf_page_header_footer(pdf, fw_name: str, target_url: str, color: tuple = (30, 41, 59)):
    """Set up page header and footer via FPDF2 overrides — called after pdf creation."""
    class _PDF(pdf.__class__):
        _hdr_fw = fw_name
        _hdr_target = target_url[:60]
        _hdr_color = color

        def header(self):
            if self.page_no() == 1:
                return
            self.set_fill_color(*self._hdr_color)
            self.rect(0, 0, 210, 10, "F")
            self.set_text_color(255, 255, 255)
            _pdf_font(self, "B", 7)
            self.set_xy(10, 2)
            self.cell(0, 6, _safe_pdf(f"{self._hdr_fw} Compliance Report"), ln=False)
            _pdf_font(self, "", 7)
            self.cell(0, 6, _safe_pdf(self._hdr_target), ln=True, align="R")
            self.set_text_color(0, 0, 0)
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_draw_color(200, 200, 200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.set_text_color(150, 150, 150)
            _pdf_font(self, "", 7)
            self.cell(95, 8, _safe_pdf("Agentic Web Scanner"), ln=False)
            self.cell(95, 8, _safe_pdf(f"Page {self.page_no()}/{{nb}}"), ln=True, align="R")
            self.set_text_color(0, 0, 0)

    pdf.__class__ = _PDF


@app.post("/api/results/{scan_id}/compliance/{framework}", tags=["Results"])
async def generate_compliance_report(scan_id: str, framework: str):
    """Generate a compliance-mapped report (PDF) for the given framework."""
    if framework not in _COMPLIANCE_FRAMEWORKS:
        return JSONResponse({"error": f"Unknown framework: {framework}. Supported: {', '.join(_COMPLIANCE_FRAMEWORKS)}"}, status_code=400)

    data = _load_raw_result_dict(scan_id)
    if not data:
        return JSONResponse({"error": "Scan results not found"}, status_code=404)

    try:
        findings = data.get("findings") or []
        test_log = data.get("summary", {}).get("test_log") or []
        classified = [triage_classify(f, test_log) for f in findings if isinstance(f, dict)]
        _apply_cvss_overrides_to_classified(classified, scan_id)
        _tgt = data.get("target", "")
        target_url = (_tgt if isinstance(_tgt, str) else _tgt.get("url", "") if isinstance(_tgt, dict) else str(_tgt)) or data.get("metadata", {}).get("target_url", "")
        model_key = data.get("model", "") or data.get("metadata", {}).get("model", "unknown")
        fw = _COMPLIANCE_FRAMEWORKS[framework]
        fw_name = fw["name"]
        fw_subtitle = fw.get("subtitle", "")
        fw_color = fw.get("color", (30, 41, 59))
        scan_date = data.get("metadata", {}).get("timestamp", "") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = data.get("metadata", {}).get("duration_seconds") or data.get("metadata", {}).get("scan_duration_seconds")
        dur_str = f"{int(duration)}s" if duration else "N/A"

        from fpdf import FPDF
        pdf = FPDF()
        _init_pdf_fonts(pdf)
        pdf.set_auto_page_break(auto=True, margin=22)
        _pdf_page_header_footer(pdf, fw_name, target_url, fw_color)
        pdf.alias_nb_pages()

        # ── COVER PAGE ──
        pdf.add_page()
        pdf.set_fill_color(*fw_color)
        pdf.rect(0, 0, 210, 80, "F")
        accent_light = tuple(min(255, c + 40) for c in fw_color)
        pdf.set_fill_color(*accent_light)
        pdf.rect(0, 72, 210, 8, "F")

        pdf.set_text_color(255, 255, 255)
        _pdf_font(pdf, "B", 28)
        pdf.set_y(18)
        pdf.cell(0, 14, _safe_pdf(fw_name), ln=True, align="C")
        _pdf_font(pdf, "", 12)
        if fw_subtitle:
            pdf.cell(0, 7, _safe_pdf(fw_subtitle), ln=True, align="C")
        pdf.ln(4)
        _pdf_font(pdf, "B", 14)
        pdf.cell(0, 8, _safe_pdf("Compliance Assessment Report"), ln=True, align="C")
        pdf.set_text_color(0, 0, 0)

        pdf.set_y(90)
        pdf.set_draw_color(*fw_color)
        pdf.set_line_width(0.5)

        _pdf_font(pdf, "B", 11)
        pdf.set_text_color(*fw_color)
        pdf.cell(0, 8, _safe_pdf("ASSESSMENT DETAILS"), ln=True)
        pdf.line(10, pdf.get_y(), 90, pdf.get_y())
        pdf.ln(4)
        pdf.set_text_color(0, 0, 0)
        _pdf_kv_row(pdf, "Target:", target_url[:100])
        _pdf_kv_row(pdf, "Scan ID:", scan_id)
        _pdf_kv_row(pdf, "Model:", model_key)
        _pdf_kv_row(pdf, "Scan Date:", scan_date)
        _pdf_kv_row(pdf, "Duration:", dur_str)
        _pdf_kv_row(pdf, "Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pdf.ln(8)

        # ── EXECUTIVE SUMMARY ──
        tp_findings = [f for f in classified if f.get("verdict") not in ("FALSE_POSITIVE", "NOT_A_FINDING")]
        tp_sev = _pdf_severity_counts(tp_findings)
        all_sev = _pdf_severity_counts(classified)

        _pdf_font(pdf, "B", 11)
        pdf.set_text_color(*fw_color)
        pdf.cell(0, 8, _safe_pdf("EXECUTIVE SUMMARY"), ln=True)
        pdf.line(10, pdf.get_y(), 90, pdf.get_y())
        pdf.ln(4)
        pdf.set_text_color(0, 0, 0)

        # Severity table
        _pdf_font(pdf, "B", 8)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(30, 6, _safe_pdf("Severity"), fill=True, align="C")
        pdf.cell(25, 6, _safe_pdf("Total"), fill=True, align="C")
        pdf.cell(30, 6, _safe_pdf("True Positive"), fill=True, align="C")
        pdf.cell(30, 6, _safe_pdf("False Positive"), fill=True, align="C")
        pdf.ln()
        for sev_name in ("Critical", "High", "Medium", "Low", "Info"):
            total_cnt = all_sev.get(sev_name, 0)
            tp_cnt = tp_sev.get(sev_name, 0)
            fp_cnt = total_cnt - tp_cnt
            if total_cnt == 0 and sev_name not in ("Critical", "High", "Medium"):
                continue
            color = _SEV_COLORS.get(sev_name, (0, 0, 0))
            bg = _SEV_BG.get(sev_name, (241, 245, 249))
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*color)
            _pdf_font(pdf, "B", 8)
            pdf.cell(30, 5, _safe_pdf(sev_name), fill=True, align="C")
            _pdf_font(pdf, "", 8)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(25, 5, _safe_pdf(str(total_cnt)), align="C")
            pdf.cell(30, 5, _safe_pdf(str(tp_cnt)), align="C")
            pdf.cell(30, 5, _safe_pdf(str(fp_cnt)), align="C")
            pdf.ln()
        pdf.ln(2)

        _pdf_font(pdf, "B", 8)
        pdf.cell(55, 5, _safe_pdf(f"Total: {len(classified)} findings"))
        pdf.cell(0, 5, _safe_pdf(f"True Positives: {len(tp_findings)}"), ln=True)
        pdf.ln(2)
        _pdf_horiz_bar(pdf, tp_sev, len(tp_findings) or 1)
        pdf.ln(2)

        # Severity legend
        _pdf_font(pdf, "", 7)
        pdf.set_text_color(100, 116, 139)
        legend = "  ".join(f"{s}: {tp_sev.get(s, 0)}" for s in ("Critical", "High", "Medium", "Low", "Info") if tp_sev.get(s, 0))
        pdf.cell(0, 4, _safe_pdf(legend), ln=True)
        pdf.set_text_color(0, 0, 0)

        # ── OWASP bucketing (used by all frameworks) ──
        owasp_findings: dict[str, list] = {}
        for f in classified:
            cat_raw = f.get("owasp") or f.get("owasp_category") or ""
            cat = (cat_raw if isinstance(cat_raw, str) else str(cat_raw))[:3].upper()
            if cat and cat in [f"A{i:02d}" for i in range(1, 11)]:
                owasp_findings.setdefault(cat, []).append(f)
            elif cat:
                owasp_findings.setdefault(cat, []).append(f)

        # ── CONTROL ASSESSMENT ──
        pdf.add_page()
        _pdf_section_header(pdf, f"{fw_name} -- Control Assessment", bg=fw_color)

        pass_count = 0
        fail_count = 0
        mapping_items = list(fw["mappings"].items())
        all_control_remediations: list[tuple[str, str, str]] = []

        if framework == "owasp":
            for cat_id, cat_info in mapping_items:
                matched = owasp_findings.get(cat_id, [])
                status = "FAIL" if matched else "PASS"
                if matched:
                    fail_count += 1
                else:
                    pass_count += 1
                is_fail, ctrl_rem = _pdf_control_row(
                    pdf, status, cat_id, cat_info["title"], len(matched),
                    desc=cat_info.get("desc", ""), remediation=cat_info.get("remediation", ""))

                _pdf_font(pdf, "", 7)
                for mf in matched[:5]:
                    sev = _finding_sev(mf)
                    ftitle = str(mf.get("title") or "Untitled")[:80]
                    verdict = str(mf.get("verdict") or "")
                    v_tag = f" [{verdict}]" if verdict and verdict != "TRUE_POSITIVE" else ""
                    color = _SEV_COLORS.get(sev, (100, 116, 139))
                    pdf.set_text_color(*color)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf(f"[{sev}] {ftitle}{v_tag}"), ln=True)
                    pdf.set_text_color(0, 0, 0)
                if len(matched) > 5:
                    _pdf_font(pdf, "I", 7)
                    pdf.set_text_color(100, 116, 139)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf(f"... and {len(matched) - 5} more"), ln=True)
                    pdf.set_text_color(0, 0, 0)
                if not matched:
                    pdf.set_text_color(22, 163, 74)
                    _pdf_font(pdf, "", 7)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf("No vulnerabilities detected for this category."), ln=True)
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(3)
                if is_fail and ctrl_rem:
                    all_control_remediations.append((cat_id, cat_info["title"], ctrl_rem))
        else:
            for req_id, req_info in mapping_items:
                related_owasp = req_info.get("owasp", [])
                matched = []
                seen_titles = set()
                for ocat in related_owasp:
                    for mf in owasp_findings.get(ocat, []):
                        t = mf.get("title", "")
                        if t not in seen_titles:
                            seen_titles.add(t)
                            matched.append(mf)
                status = "FAIL" if matched else "PASS"
                if matched:
                    fail_count += 1
                else:
                    pass_count += 1
                mapped_str = ", ".join(related_owasp) if related_owasp else ""
                is_fail, ctrl_rem = _pdf_control_row(
                    pdf, status, req_id, req_info["title"], len(matched),
                    desc=req_info.get("desc", ""), remediation=req_info.get("remediation", ""),
                    mapped=mapped_str)

                _pdf_font(pdf, "", 7)
                for mf in matched[:3]:
                    sev = _finding_sev(mf)
                    ftitle = str(mf.get("title") or "Untitled")[:80]
                    color = _SEV_COLORS.get(sev, (100, 116, 139))
                    pdf.set_text_color(*color)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf(f"[{sev}] {ftitle}"), ln=True)
                    pdf.set_text_color(0, 0, 0)
                if len(matched) > 3:
                    _pdf_font(pdf, "I", 7)
                    pdf.set_text_color(100, 116, 139)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf(f"... and {len(matched) - 3} more"), ln=True)
                    pdf.set_text_color(0, 0, 0)
                if not matched:
                    pdf.set_text_color(22, 163, 74)
                    _pdf_font(pdf, "", 7)
                    pdf.set_x(18)
                    pdf.cell(0, 4, _safe_pdf("No vulnerabilities mapped to this control."), ln=True)
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(3)
                if is_fail and ctrl_rem:
                    all_control_remediations.append((req_id, req_info["title"], ctrl_rem))

        # ── COMPLIANCE SCORE ──
        total_controls = pass_count + fail_count
        score_pct = round(pass_count / total_controls * 100) if total_controls else 0
        pdf.ln(4)
        score_bg = (220, 252, 231) if score_pct >= 80 else (255, 237, 213) if score_pct >= 50 else (254, 226, 226)
        score_fg = (22, 101, 52) if score_pct >= 80 else (154, 52, 18) if score_pct >= 50 else (153, 27, 27)
        pdf.set_fill_color(*score_bg)
        pdf.set_text_color(*score_fg)
        _pdf_font(pdf, "B", 12)
        pdf.cell(0, 10, _safe_pdf(f"  Compliance Score: {pass_count}/{total_controls} controls passed ({score_pct}%)"), ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)

        # Visual score bar
        pdf.ln(2)
        bar_x = 10
        bar_w = 190
        bar_y = pdf.get_y()
        pdf.set_fill_color(229, 231, 235)
        pdf.rect(bar_x, bar_y, bar_w, 5, "F")
        fill_w = bar_w * score_pct / 100
        pdf.set_fill_color(*score_fg)
        if fill_w > 0:
            pdf.rect(bar_x, bar_y, fill_w, 5, "F")
        pdf.set_y(bar_y + 8)

        # ── REMEDIATION ROADMAP ──
        if all_control_remediations:
            pdf.add_page()
            _pdf_section_header(pdf, "Remediation Roadmap", bg=fw_color)
            _pdf_font(pdf, "", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 5, _safe_pdf(
                "The following remediation actions are recommended for each failing control. "
                "Prioritize Critical and High severity findings first."))
            pdf.set_text_color(0, 0, 0)
            pdf.ln(4)

            for idx, (ctrl_id, ctrl_title, rem) in enumerate(all_control_remediations, 1):
                if pdf.get_y() > 255:
                    pdf.add_page()
                pdf.set_fill_color(241, 245, 249)
                _pdf_font(pdf, "B", 9)
                pdf.cell(0, 7, _safe_pdf(f"  {idx}. {ctrl_id}: {ctrl_title}"), ln=True, fill=True)
                _pdf_font(pdf, "", 8)
                pdf.set_x(14)
                pdf.multi_cell(182, 4, _safe_pdf(rem))
                pdf.ln(3)

        # ── DETAILED FINDINGS ──
        if classified:
            pdf.add_page()
            _pdf_section_header(pdf, "Detailed Findings", bg=fw_color)

            for i, f in enumerate(classified, 1):
                if pdf.get_y() > 245:
                    pdf.add_page()
                sev = _finding_sev(f)
                title = str(f.get("title") or "Untitled")[:100]
                verdict = str(f.get("verdict") or "")
                owasp_cat = str(f.get("owasp") or f.get("owasp_category") or "")
                url = str(f.get("url") or "")
                param = str(f.get("parameter") or "")
                payload = str(f.get("payload") or "")[:150]
                evidence = str(f.get("scanner_evidence") or f.get("evidence") or "")[:250]
                remediation = str(f.get("remediation") or f.get("dev_action") or "")[:250]
                cwe = f.get("cwe", "")
                cvss = f.get("cvss")
                reason = f.get("reason", "")

                color = _SEV_COLORS.get(sev, (100, 116, 139))
                bg = _SEV_BG.get(sev, (241, 245, 249))
                pdf.set_fill_color(*bg)
                _pdf_font(pdf, "B", 9)
                pdf.set_text_color(*color)
                pdf.cell(20, 7, _safe_pdf(sev), fill=True, align="C")
                pdf.set_text_color(30, 41, 59)
                pdf.cell(0, 7, _safe_pdf(f"  {i}. {title}"), ln=True)
                pdf.set_text_color(0, 0, 0)

                _pdf_font(pdf, "", 7)
                meta_parts = []
                if verdict:
                    meta_parts.append(f"Verdict: {verdict}")
                if owasp_cat:
                    meta_parts.append(f"OWASP: {owasp_cat}")
                if cwe:
                    meta_parts.append(f"CWE: {cwe}")
                if cvss:
                    meta_parts.append(f"CVSS: {cvss}")
                if meta_parts:
                    pdf.set_text_color(100, 116, 139)
                    pdf.set_x(14)
                    pdf.cell(0, 4, _safe_pdf(" | ".join(meta_parts)), ln=True)
                    pdf.set_text_color(0, 0, 0)

                if url:
                    _pdf_font(pdf, "", 7)
                    pdf.set_x(14)
                    pdf.cell(0, 4, _safe_pdf(f"URL: {url[:120]}"), ln=True)
                if param:
                    pdf.set_x(14)
                    pdf.cell(0, 4, _safe_pdf(f"Parameter: {param[:60]}"), ln=True)
                if payload:
                    pdf.set_text_color(180, 83, 9)
                    pdf.set_x(14)
                    pdf.cell(0, 4, _safe_pdf(f"Payload: {payload}"), ln=True)
                    pdf.set_text_color(0, 0, 0)
                if evidence:
                    _pdf_font(pdf, "I", 7)
                    pdf.set_x(14)
                    pdf.multi_cell(182, 3.5, _safe_pdf(f"Evidence: {evidence}"))
                    _pdf_font(pdf, "", 7)
                if reason:
                    pdf.set_text_color(100, 116, 139)
                    pdf.set_x(14)
                    pdf.multi_cell(182, 3.5, _safe_pdf(f"Triage: {reason[:200]}"))
                    pdf.set_text_color(0, 0, 0)
                if remediation:
                    pdf.set_text_color(5, 150, 105)
                    pdf.set_x(14)
                    pdf.multi_cell(182, 3.5, _safe_pdf(f"Remediation: {remediation}"))
                    pdf.set_text_color(0, 0, 0)

                pdf.set_draw_color(229, 231, 235)
                pdf.line(14, pdf.get_y() + 1, 196, pdf.get_y() + 1)
                pdf.ln(3)

        # ── ASSESSMENT SUMMARY & DISCLAIMER ──
        pdf.add_page()
        _pdf_section_header(pdf, "Assessment Summary", bg=fw_color)
        _pdf_font(pdf, "", 10)
        pdf.multi_cell(0, 5.5, _safe_pdf(
            f"This {fw_name} compliance assessment was performed against {target_url} "
            f"using AI-powered security scanning (model: {model_key}). "
            f"The scan identified {len(classified)} total findings across {total_controls} "
            f"compliance controls. {pass_count} control{'s' if pass_count != 1 else ''} "
            f"passed ({score_pct}% compliance rate) and {fail_count} "
            f"control{'s' if fail_count != 1 else ''} had associated findings requiring attention."
        ))
        pdf.ln(6)

        _pdf_font(pdf, "B", 10)
        pdf.set_text_color(*fw_color)
        pdf.cell(0, 7, _safe_pdf("METHODOLOGY"), ln=True)
        pdf.set_text_color(0, 0, 0)
        _pdf_font(pdf, "", 8)
        pdf.multi_cell(0, 4.5, _safe_pdf(
            "This assessment was conducted using an AI-powered agentic security scanner that combines "
            "passive reconnaissance, active vulnerability testing, and LLM-based analysis. The scanner "
            "autonomously identifies security weaknesses across OWASP Top 10 categories and maps findings "
            "to the applicable compliance framework controls. Each finding is classified with a severity "
            "rating, triaged for accuracy, and assigned a remediation recommendation."
        ))
        pdf.ln(6)

        pdf.set_fill_color(241, 245, 249)
        _pdf_font(pdf, "B", 9)
        pdf.cell(0, 7, _safe_pdf("  DISCLAIMER"), ln=True, fill=True)
        _pdf_font(pdf, "I", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.multi_cell(0, 4.5, _safe_pdf(
            "This automated assessment identifies potential compliance gaps based on technical "
            "vulnerability scanning. It does not constitute a formal compliance audit or certification. "
            "Organizations should engage qualified assessors (QSA for PCI DSS, independent auditors for "
            "SOC 2, etc.) for official compliance certifications. Findings should be validated by the "
            "security team before remediation actions are taken."
        ))
        pdf.set_text_color(0, 0, 0)

        out_name = f"{framework}_compliance_{scan_id}.pdf"
        out_path = REPORTS_DIR / out_name
        pdf.output(str(out_path))

        return FileResponse(
            str(out_path),
            filename=out_name,
            media_type="application/pdf",
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"error": f"Compliance report failed: {str(e)}"}, status_code=500)


_SCAN_ID_RE = re.compile(r"(scan_\d{8}_\d{6}_[0-9a-f]{6})")


def _extract_scan_id_from_filename(stem: str) -> str | None:
    """Try to pull a scan_YYYYMMDD_HHMMSS_hex6 ID from a report filename."""
    m = _SCAN_ID_RE.search(stem)
    if m:
        return m.group(1)
    return None


def _find_scan_for_report(filename: str) -> tuple[str, dict]:
    """Match a report file to its scan record. Returns (scan_id, scan_info)."""
    stem = Path(filename).stem
    sid = _extract_scan_id_from_filename(stem)
    if sid and sid in SCANS:
        return sid, SCANS[sid]
    for s_id, info in SCANS.items():
        rf = info.get("result_file", "")
        if rf and stem in rf:
            return s_id, info
    if sid:
        return sid, {}
    slug = stem.replace("scan_", "", 1).replace("report_", "")
    slug_norm = slug.replace("_", "-").replace(".", "-").lower()
    best_sid, best_time = "", ""
    for s_id, info in SCANS.items():
        model = (info.get("model", "") or "").lower().replace("/", "-").replace(".", "-").replace(":", "-")
        if slug_norm and slug_norm in model or model in slug_norm:
            started = info.get("started", "")
            if started > best_time:
                best_sid, best_time = s_id, started
    if best_sid:
        return best_sid, SCANS[best_sid]
    return stem, {}


@app.get("/api/reports", tags=["Results"])
async def list_reports():
    """List all generated PDF and Excel reports grouped by target."""
    reports = []
    try:
        files = sorted(REPORTS_DIR.iterdir(), reverse=True) if REPORTS_DIR.exists() else []
    except Exception:
        files = []
    for f in files:
        if f.suffix not in (".pdf", ".xlsx"):
            continue
        scan_id, scan_info = _find_scan_for_report(f.name)
        target = scan_info.get("target_url", "")
        if not target and scan_id:
            try:
                rd = _load_raw_result_dict(scan_id)
                if rd:
                    t = rd.get("target", "")
                    target = t.get("url", "") if isinstance(t, dict) else str(t)
                    if not target:
                        target = rd.get("metadata", {}).get("target_url", "") or ""
            except Exception:
                pass
        target = target or "Unknown Target"
        try:
            fstat = f.stat()
            fsize = fstat.st_size
            fmod = datetime.fromtimestamp(fstat.st_mtime).isoformat()
        except Exception:
            fsize = 0
            fmod = ""
        reports.append({
            "filename": f.name, "size": fsize,
            "modified": fmod,
            "type": "pdf" if f.suffix == ".pdf" else "xlsx",
            "url": f"/api/reports/{f.name}",
            "scan_id": scan_id, "target": target,
            "model": scan_info.get("model_name", scan_info.get("model", "")),
            "scanner": scan_info.get("scanner", "ai"),
            "findings_count": scan_info.get("findings_count", 0),
            "started": scan_info.get("started", ""),
        })
    return {"reports": reports}


@app.get("/api/reports/{filename}", tags=["Results"])
async def download_report(filename: str):
    fpath = REPORTS_DIR / filename
    if not fpath.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    media = "application/pdf" if filename.endswith(".pdf") else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(str(fpath), filename=filename, media_type=media)


@app.delete("/api/reports/{filename}", tags=["Results"])
async def delete_report_file(filename: str):
    """Delete a single report file."""
    fpath = REPORTS_DIR / filename
    if not fpath.exists():
        return JSONResponse({"error": "Not found"}, status_code=404)
    try:
        fpath.unlink()
    except Exception as e:
        return JSONResponse({"error": f"Failed to delete: {e}"}, status_code=500)
    return {"deleted": filename}


@app.delete("/api/reports", tags=["Results"])
async def delete_reports_for_target(target: str = ""):
    """Delete all reports (and optionally scan data) for a target URL."""
    if not target:
        return JSONResponse({"error": "target query param required"}, status_code=400)

    deleted_files = []
    deleted_scans = []

    if target == "orphan":
        known_ids = set(SCANS.keys())
        for f in list(REPORTS_DIR.glob("*")) if REPORTS_DIR.exists() else []:
            sid = f.stem.replace("report_", "").replace("excel_", "")
            if sid not in known_ids:
                try:
                    f.unlink()
                    deleted_files.append(f.name)
                except Exception:
                    pass
    else:
        ids_to_delete = [sid for sid, s in SCANS.items() if s.get("target_url", "") == target]
        target_del_cost = 0.0
        for sid in ids_to_delete:
            sc = SCANS.get(sid, {}).get("cost", 0) or 0
            target_del_cost += sc
            for f in list(REPORTS_DIR.glob(f"*{sid}*")):
                try:
                    f.unlink()
                    deleted_files.append(f.name)
                except Exception:
                    pass
            for f in list(RAW_DIR.glob(f"*{sid}*")):
                try:
                    f.unlink()
                except Exception:
                    pass
            SCANS.pop(sid, None)
            deleted_scans.append(sid)
        if target_del_cost > 0:
            try:
                scandb.add_deleted_cost(target_del_cost, len(ids_to_delete))
            except Exception:
                pass
        if ids_to_delete:
            try:
                scandb.delete_scans(ids_to_delete)
            except Exception:
                pass

    return {"deleted_files": deleted_files, "deleted_scans": deleted_scans}


@app.get("/api/results/{scan_id}/excel", tags=["Results"])
async def generate_excel(scan_id: str):
    """Generate and download an Excel report for a scan.

    Uses the same ``_get_results_inner`` pipeline as the UI so that the
    Summary, All Findings, AI vs Triage, and AI Raw sheets always reflect
    the same triage verdicts and CVSS overrides the user sees on-screen.
    """
    try:
        result = await _get_results_inner(scan_id)
    except Exception as e:
        return JSONResponse({"error": f"Failed to load scan data: {e}"}, status_code=500)
    if isinstance(result, JSONResponse):
        return result
    try:
        from scripts.excel_exporter import generate_excel
        triaged = result.get("triaged_findings", []) or []
        raw = result.get("ai_findings", []) or []
        meta = result.get("metadata", {}) or {}
        xlsx_path = generate_excel(scan_id, meta, triaged, raw, str(REPORTS_DIR))
        return FileResponse(
            str(xlsx_path),
            filename=os.path.basename(xlsx_path),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({"error": f"Excel export failed: {str(e)}"}, status_code=500)


@app.get("/api/results/{scan_id}/raw/ai", tags=["Results"])
async def download_raw_ai(scan_id: str):
    """Download the raw AI findings (pre-triage) as a standalone JSON file.

    Mirrors what the UI "AI Raw Findings" tab shows — AI agent output before
    triage, verification, or CVSS overrides are applied.
    """
    try:
        data = await _get_results_inner(scan_id)
    except Exception as e:
        return JSONResponse({"error": f"Failed to load results: {e}"}, status_code=500)
    if isinstance(data, JSONResponse):
        return data
    meta = data.get("metadata", {}) or {}
    ai_findings = data.get("ai_findings", []) or []
    output = {
        "scan_id": scan_id,
        "target": meta.get("target", ""),
        "model": meta.get("model", ""),
        "scan_mode": meta.get("scan_mode", ""),
        "count": len(ai_findings),
        "ai_findings": ai_findings,
    }
    blob = json.dumps(output, indent=2, default=str).encode("utf-8")
    return StreamingResponse(
        BytesIO(blob),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="ai_raw_findings_{scan_id}.json"'},
    )


@app.get("/api/results/{scan_id}/raw/triage", tags=["Results"])
async def download_ai_vs_triage(scan_id: str):
    """Download AI vs Triage comparison as a JSON file.

    For every finding, includes AI-reported severity alongside the triage
    verdict, verification status, CWE/CVSS, and triage reasoning — the same
    data shown in the "AI vs Triage" tab of the results view.
    """
    try:
        data = await _get_results_inner(scan_id)
    except Exception as e:
        return JSONResponse({"error": f"Failed to load results: {e}"}, status_code=500)
    if isinstance(data, JSONResponse):
        return data

    meta = data.get("metadata", {}) or {}
    coverage = data.get("coverage", {}) or {}
    triaged = data.get("triaged_findings", []) or []

    comparison = []
    for f in triaged:
        ai_sev = (f.get("ai_severity") or "").strip()
        triage_sev = (f.get("final_severity") or f.get("severity") or "").strip()
        comparison.append({
            "title": f.get("title", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "owasp_category": f.get("owasp_category", ""),
            "cwe": f.get("cwe", ""),
            "ai_severity": ai_sev,
            "triage_severity": triage_sev,
            "severity_changed": ai_sev.lower() != triage_sev.lower(),
            "verdict": f.get("verdict", ""),
            "confidence": f.get("confidence", ""),
            "confidence_score": f.get("confidence_score"),
            "verified": bool(f.get("verified", False)),
            "verification_method": f.get("verification_method", "none"),
            "verification_evidence": f.get("verification_evidence", ""),
            "triage_reason": f.get("reason", ""),
            "cvss": f.get("cvss"),
            "cvss_rationale": f.get("cvss_rationale", ""),
            "cvss_override": f.get("cvss_override"),
            "cvss_override_note": f.get("cvss_override_note", ""),
        })

    verdict_counts: dict[str, int] = {}
    for c in comparison:
        v = (c.get("verdict") or "UNKNOWN").upper()
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    output = {
        "scan_id": scan_id,
        "target": meta.get("target", ""),
        "model": meta.get("model", ""),
        "scan_mode": meta.get("scan_mode", ""),
        "count": len(comparison),
        "summary": {
            "total": len(comparison),
            "severity_changed": sum(1 for c in comparison if c.get("severity_changed")),
            "verified": sum(1 for c in comparison if c.get("verified")),
            "verdicts": verdict_counts,
            "verification": coverage.get("verification", {}),
        },
        "comparison": comparison,
    }
    blob = json.dumps(output, indent=2, default=str).encode("utf-8")
    return StreamingResponse(
        BytesIO(blob),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="ai_vs_triage_{scan_id}.json"'},
    )


@app.get("/api/results/{scan_id}/payloads", tags=["Results"])
async def download_payloads(scan_id: str):
    """Download all payloads tested per phase as a JSON file."""
    data = _load_raw_result_dict(scan_id)
    if not data:
        return JSONResponse({"error": "Not found"}, status_code=404)
    test_log = data.get("summary", {}).get("test_log", [])
    phase_log = data.get("summary", {}).get("phase_log", [])
    target = data.get("target", "")
    model = data.get("model", "")

    phases_map = {}
    for entry in test_log:
        if not isinstance(entry, dict):
            continue
        pid = entry.get("phase", "unknown")
        if pid not in phases_map:
            phases_map[pid] = {"phase_id": pid, "phase_name": "", "payloads": []}
        phases_map[pid]["payloads"].append({
            "tool": entry.get("tool", ""),
            "request": entry.get("request", {}),
            "response": entry.get("response_summary", {}),
        })

    for p in phase_log:
        if not isinstance(p, dict):
            continue
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

    blob = json.dumps(output, indent=2, default=str).encode("utf-8")
    return StreamingResponse(
        BytesIO(blob),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="payloads_{scan_id}.json"'},
    )


@app.get("/api/scan/{scan_id}/payloads-live", tags=["Scans"])
async def download_live_payloads(scan_id: str):
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
        "phases_completed": [{"name": p.get("name", ""), "tool_calls": p.get("tool_calls", 0), "findings": p.get("findings", 0)} for p in phases if isinstance(p, dict)],
        "activity_log": tests,
    }
    return JSONResponse(output)


def _extract_crawled(summary: dict, test_log: list) -> list[dict]:
    # Defensive: in-memory ``live_tests`` (line 1734) and on-disk ``summary.test_log``
    # are *expected* to be a list of dicts, but live agent telemetry has occasionally
    # produced string entries (e.g. raw stringified JSON or error messages). Guard at
    # both levels - non-dict ``t`` and non-dict ``t['request']`` - so the read path
    # never raises AttributeError and breaks the results UI.
    urls = set()
    crawled = []
    if not isinstance(test_log, list):
        return crawled
    for t in test_log:
        if not isinstance(t, dict):
            continue
        req = t.get("request", {})
        if not isinstance(req, dict):
            continue
        url = str(req.get("url", "") or req.get("endpoint", ""))
        method = str(req.get("method", "GET"))
        if url and url not in urls:
            urls.add(url)
            resp = t.get("response_summary") or t.get("response") or {}
            status = resp.get("status") or resp.get("status_code", "") if isinstance(resp, dict) else ""
            crawled.append({"url": url, "method": method, "status": str(status)})
    return crawled


def _parse_str_value(v):
    """Try to parse a stringified list/dict back to native Python."""
    if not isinstance(v, str):
        return v
    s = v.strip()
    if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
        try:
            return json.loads(s)
        except Exception:
            try:
                import ast
                return ast.literal_eval(s)
            except Exception:
                pass
    return v


def _extract_payloads_by_endpoint(test_log: list) -> list[dict]:
    from collections import defaultdict
    ep_map: dict[str, list] = defaultdict(list)
    if not isinstance(test_log, list):
        return []
    for t in test_log:
        if not isinstance(t, dict):
            continue
        req = t.get("request", {})
        if not isinstance(req, dict):
            continue
        tool = t.get("tool", "")
        raw_url = str(req.get("url", "") or req.get("endpoint", ""))
        url_base = raw_url.split("?")[0]
        method = str(req.get("method", "GET"))
        if not url_base:
            continue
        key = f"{method} {url_base}"
        resp = t.get("response_summary") or t.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        resp_status = resp.get("status") or resp.get("status_code", "")
        resp_anomaly = resp.get("anomaly", False)
        if isinstance(resp_anomaly, str):
            resp_anomaly = resp_anomaly.lower() in ("true", "yes")
        resp_reflected = resp.get("reflected", False)
        if isinstance(resp_reflected, str):
            resp_reflected = resp_reflected.lower() in ("true", "yes")
        resp_body = str(resp.get("body_snippet") or resp.get("body") or "")

        if tool == "fuzz_parameter":
            param_name = str(req.get("param_name", ""))
            param_loc = str(req.get("param_location", "query"))
            raw_payloads = _parse_str_value(req.get("payloads", []))
            if isinstance(raw_payloads, str):
                raw_payloads = [raw_payloads]
            if not isinstance(raw_payloads, list):
                raw_payloads = [str(raw_payloads)]
            per_payload_results = _parse_str_value(resp.get("results", []))
            if not isinstance(per_payload_results, list):
                per_payload_results = []
            if raw_payloads:
                for i, pl in enumerate(raw_payloads[:100]):
                    pr = per_payload_results[i] if i < len(per_payload_results) else {}
                    if not isinstance(pr, dict):
                        pr = {}
                    ep_map[key].append({
                        "tool": tool,
                        "method": method,
                        "full_url": str(req.get("endpoint") or req.get("url", "")),
                        "param": param_name,
                        "param_location": param_loc,
                        "payload": _truncate(str(pl), 200),
                        "status": pr.get("status", resp_status),
                        "anomaly": pr.get("anomaly", resp_anomaly),
                        "reflected": pr.get("reflected", resp_reflected),
                        "body_snippet": _truncate(str(pr.get("body_snippet", resp_body)), 120),
                    })
            else:
                ep_map[key].append({
                    "tool": tool, "method": method,
                    "full_url": raw_url, "param": param_name,
                    "param_location": param_loc, "payload": "",
                    "status": resp_status, "anomaly": resp_anomaly,
                    "reflected": resp_reflected, "body_snippet": _truncate(resp_body, 120),
                })
        elif tool == "inject_payload":
            ep_map[key].append({
                "tool": tool, "method": "DOM", "full_url": raw_url,
                "param": str(req.get("selector", "")),
                "payload": _truncate(str(req.get("payload", "")), 200),
                "status": resp_status, "anomaly": resp_anomaly,
                "reflected": resp_reflected,
                "body_snippet": _truncate(resp_body, 120),
            })
        else:
            body_str = str(req.get("body", ""))
            query = "?" + raw_url.split("?", 1)[1] if "?" in raw_url else ""
            payload_display = body_str if body_str and body_str != "None" else (query if query else "")
            ep_map[key].append({
                "tool": tool, "method": method, "full_url": raw_url,
                "payload": _truncate(payload_display, 200),
                "status": resp_status, "anomaly": resp_anomaly,
                "reflected": resp_reflected,
                "body_snippet": _truncate(resp_body, 120),
            })

    result = []
    for ep, payloads in sorted(ep_map.items()):
        anomaly_count = sum(1 for p in payloads if p.get("anomaly"))
        result.append({
            "endpoint": ep,
            "payload_count": len(payloads),
            "anomaly_count": anomaly_count,
            "payloads": payloads[:200],
        })
    return result


def _truncate(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
