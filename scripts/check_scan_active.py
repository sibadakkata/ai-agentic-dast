#!/usr/bin/env python3
"""
Pre-deployment safety check: ensures no scans are active before deploying.

Run inside the Docker container:
    docker exec dast-scanner python3 /tmp/check_scan_active.py

Exit codes:
    0 = no active scans, safe to deploy
    1 = active scan(s) detected, DO NOT deploy
    2 = API unreachable, parse error, auth failure, etc.

The /api/scans endpoint returns a PAGINATED response:
    {"items": [...], "total": N, "page": 1, ...}
Always access data["items"] — never iterate the top-level dict.

Uses DAST_AUTH_USER / DAST_AUTH_PASS (container env) for RBAC when both are set.
"""
import base64
import json
import os
import sys
import urllib.request

ACTIVE_STATUSES = ("running", "paused", "pausing", "starting")
# EC2: uvicorn on 127.0.0.1:8000 behind host nginx; legacy images used :80.
_BASE_URL_CANDIDATES = [
    u.strip()
    for u in (
        os.environ.get("DAST_HEALTH_URL", ""),
        "http://127.0.0.1:8000",
        "http://localhost:80",
    )
    if u.strip()
]

# Defaults documented for operators; auth is only sent when both vars are in the environment.
DAST_AUTH_USER = os.environ.get("DAST_AUTH_USER", "dast-admin")
DAST_AUTH_PASS = os.environ.get("DAST_AUTH_PASS", "changeme")
_HAS_AUTH_USER = "DAST_AUTH_USER" in os.environ
_HAS_AUTH_PASS = "DAST_AUTH_PASS" in os.environ
_USE_BASIC_AUTH = _HAS_AUTH_USER and _HAS_AUTH_PASS

if not _USE_BASIC_AUTH:
    if _HAS_AUTH_USER or _HAS_AUTH_PASS:
        print(
            "WARNING: Only one of DAST_AUTH_USER / DAST_AUTH_PASS is set; "
            "calling /api/scans without authentication."
        )
    else:
        print(
            "WARNING: DAST_AUTH_USER and DAST_AUTH_PASS not set; "
            "calling /api/scans without authentication (pre-RBAC images only)."
        )


def _request(url):
    req = urllib.request.Request(url)
    if _USE_BASIC_AUTH:
        creds = f"{DAST_AUTH_USER}:{DAST_AUTH_PASS}".encode("utf-8")
        token = base64.b64encode(creds).decode("ascii")
        req.add_header("Authorization", f"Basic {token}")
    return urllib.request.urlopen(req)


def _resolve_base_url():
    last_err = None
    for base in _BASE_URL_CANDIDATES:
        try:
            _request(f"{base}/health")
            return base.rstrip("/")
        except Exception as e:
            last_err = e
    print("ERROR: Cannot reach scanner health on any of:")
    for base in _BASE_URL_CANDIDATES:
        print(f"  {base}/health")
    if last_err:
        print(f"  Last error: {last_err}")
    print("  Is the container running?")
    sys.exit(2)


def get_scans(base_url, page=1, per_page=100):
    url = f"{base_url}/api/scans?page={page}&per_page={per_page}"
    data = json.load(_request(url))
    if not isinstance(data, dict) or "items" not in data:
        print(f"ERROR: Unexpected API response format: {type(data).__name__}")
        print(f"  Keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
        print('  Expected: {{"items": [...], "total": N}}')
        sys.exit(2)
    return data["items"], data.get("total", 0), data.get("total_pages", 1)


def main():
    base_url = _resolve_base_url()
    try:
        items, total, total_pages = get_scans(base_url, page=1)
    except Exception as e:
        print(f"ERROR: Cannot reach scanner API at {base_url}")
        print(f"  {e}")
        sys.exit(2)

    all_items = list(items)
    for page in range(2, total_pages + 1):
        more, _, _ = get_scans(base_url, page=page)
        all_items.extend(more)

    active = []
    for s in all_items:
        if not isinstance(s, dict):
            continue
        status = s.get("status", "")
        if status in ACTIVE_STATUSES:
            active.append(s)

    if active:
        print(f"Total scans in database: {total}")
        print(f"Active scans: {len(active)}")
        print()
        for s in active:
            sid = s.get("id", "?")
            target = s.get("target", "?")
            status = s.get("status", "?")
            phase = s.get("current_phase", "")
            phase_info = f"  phase: {phase}" if phase else ""
            print(f"  ACTIVE  {sid}  status={status}  target={target}{phase_info}")
        print()
        print("BLOCKED — scan(s) in progress. Do NOT deploy.")
        print("Wait for completion or ask the user to stop the scan.")
        sys.exit(1)
    else:
        print(f"Total scans: {total} | Active scans: 0 | SAFE TO DEPLOY")
        sys.exit(0)


if __name__ == "__main__":
    main()
