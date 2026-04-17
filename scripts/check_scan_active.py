#!/usr/bin/env python3
"""
Pre-deployment safety check: ensures no scans are active before deploying.

Run inside the Docker container:
    docker exec dast-scanner python3 /tmp/check_scan_active.py

Exit codes:
    0 = no active scans, safe to deploy
    1 = active scan(s) detected, DO NOT deploy

The /api/scans endpoint returns a PAGINATED response:
    {"items": [...], "total": N, "page": 1, ...}
Always access data["items"] — never iterate the top-level dict.
"""
import json
import sys
import urllib.request

ACTIVE_STATUSES = ("running", "paused", "pausing", "starting")
BASE_URL = "http://localhost:8080"


def get_scans(page=1, per_page=100):
    url = f"{BASE_URL}/api/scans?page={page}&per_page={per_page}"
    data = json.load(urllib.request.urlopen(url))
    if not isinstance(data, dict) or "items" not in data:
        print(f"ERROR: Unexpected API response format: {type(data).__name__}")
        print(f"  Keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
        print("  Expected: {{\"items\": [...], \"total\": N}}")
        sys.exit(2)
    return data["items"], data.get("total", 0), data.get("total_pages", 1)


def main():
    try:
        items, total, total_pages = get_scans(page=1)
    except Exception as e:
        print(f"ERROR: Cannot reach scanner API at {BASE_URL}")
        print(f"  {e}")
        print("  Is the container running? Is the app listening on port 8080?")
        sys.exit(2)

    all_items = list(items)
    for page in range(2, total_pages + 1):
        more, _, _ = get_scans(page=page)
        all_items.extend(more)

    active = []
    for s in all_items:
        if not isinstance(s, dict):
            continue
        status = s.get("status", "")
        if status in ACTIVE_STATUSES:
            active.append(s)

    print(f"Total scans in database: {total}")
    print(f"Active scans: {len(active)}")

    if active:
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
        print()
        print("SAFE TO DEPLOY")
        sys.exit(0)


if __name__ == "__main__":
    main()
