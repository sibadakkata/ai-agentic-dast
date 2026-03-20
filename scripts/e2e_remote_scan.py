#!/usr/bin/env python3
"""End-to-end check: start a scan on a deployed DAST instance against a public test app.

Use **only** targets you are allowed to scan. Defaults to OWASP Juice Shop demo (intentionally
vulnerable training app).

Environment
-----------
DAST_BASE_URL     Base URL of the running scanner (required), no trailing slash.
E2E_TARGET_URL    Target to scan (default: Juice Shop demo root).
E2E_MODEL         Model id for POST body (default: first model from GET /api/models).
E2E_MAX_WAIT_SEC  Max seconds to wait for terminal status (default: 1800).
DAST_AUTH_USER / DAST_AUTH_PASS — only if your deployment requires Basic auth on POST (usually not).

Modes
-----
  python scripts/e2e_remote_scan.py              # wait until completed | error | timeout
  python scripts/e2e_remote_scan.py --smoke      # only verify health + scan starts + running

Examples
--------
  export DAST_BASE_URL=https://your-scanner.example.com
  python scripts/e2e_remote_scan.py --smoke
  python scripts/e2e_remote_scan.py
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

# Public intentionally-vulnerable demo (OWASP). Override with E2E_TARGET_URL if needed.
_DEFAULT_TARGET = os.environ.get(
    "E2E_TARGET_URL",
    "https://juice-shop.herokuapp.com/",
)


def _headers_json(auth: tuple[str, str] | None) -> dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth and auth[0]:
        b = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        h["Authorization"] = f"Basic {b}"
    return h


def request_json(
    method: str,
    base: str,
    path: str,
    body: dict | None = None,
    auth: tuple[str, str] | None = None,
    timeout: float = 60.0,
) -> tuple[int, dict | list | None]:
    url = f"{base.rstrip('/')}{path}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=_headers_json(auth))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw.strip():
                return resp.status, None
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8")
            parsed = json.loads(err_body) if err_body.strip() else None
        except Exception:
            parsed = None
        return e.code, parsed  # type: ignore[return-value]


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E scan against deployed DAST")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("DAST_BASE_URL", "").strip(),
        help="Scanner base URL (or set DAST_BASE_URL)",
    )
    parser.add_argument("--target-url", default=_DEFAULT_TARGET, help="Target application URL")
    parser.add_argument("--smoke", action="store_true", help="Only verify scan starts (do not wait for completion)")
    parser.add_argument("--max-wait", type=int, default=int(os.environ.get("E2E_MAX_WAIT_SEC", "1800")))
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    if not base:
        print("ERROR: Set DAST_BASE_URL or pass --base-url", file=sys.stderr)
        return 2

    user = (os.environ.get("DAST_AUTH_USER") or "").strip()
    pw = (os.environ.get("DAST_AUTH_PASS") or "").strip()
    auth = (user, pw) if user else None

    print(f"E2E remote scan")
    print(f"  Scanner: {base}")
    print(f"  Target:  {args.target_url}")
    print(f"  Mode:    {'smoke' if args.smoke else 'full'}")

    st, health = request_json("GET", base, "/health", auth=None, timeout=30.0)
    if st != 200 or not isinstance(health, dict) or health.get("status") != "ok":
        print(f"FAIL: GET /health -> {st} {health}")
        return 1
    print(f"  [OK] GET /health")

    st, models = request_json("GET", base, "/api/models", auth=None, timeout=30.0)
    if st != 200 or not isinstance(models, list) or not models:
        print(f"FAIL: GET /api/models -> {st}")
        return 1
    model_id = (os.environ.get("E2E_MODEL") or "").strip() or str(models[0].get("id") or "")
    if not model_id:
        print("FAIL: no model id from /api/models")
        return 1
    print(f"  [OK] model={model_id!r}")

    payload = {
        "target_url": args.target_url,
        "model": model_id,
        "scan_mode": "website",
        "auth_type": "auto",
        "scan_scope": "url_only",
        "scan_intensity": "light",
        "focus_urls": [],
        "focus_areas": [],
        "exclude_urls": [],
        "username": "",
        "password": "",
    }
    st, start = request_json("POST", base, "/api/scan", body=payload, auth=auth, timeout=60.0)
    if st != 200 or not isinstance(start, dict) or not start.get("scan_id"):
        print(f"FAIL: POST /api/scan -> {st} {start}")
        return 1
    scan_id = start["scan_id"]
    print(f"  [OK] POST /api/scan -> {scan_id}")

    if args.smoke:
        time.sleep(3)
        st2, status = request_json("GET", base, f"/api/scan/{scan_id}", auth=auth, timeout=30.0)
        if st2 != 200 or not isinstance(status, dict):
            print(f"FAIL: GET /api/scan/{{id}} -> {st2} {status}")
            return 1
        s = status.get("status")
        print(f"  [OK] smoke: scan status after 3s = {s!r}")
        if s == "error":
            print(f"FAIL: scan errored: {status.get('error')!r}")
            return 1
        if s not in ("running", "completed", "paused"):
            print(f"WARN: expected running/completed/paused, got {s!r}")
        print("\nSmoke OK — scan started. Use without --smoke to wait for completion.")
        return 0

    deadline = time.monotonic() + max(60, args.max_wait)
    last = ""
    while time.monotonic() < deadline:
        st3, status = request_json("GET", base, f"/api/scan/{scan_id}", auth=auth, timeout=60.0)
        if st3 != 200 or not isinstance(status, dict):
            print(f"FAIL: poll scan -> {st3} {status}")
            return 1
        s = status.get("status") or ""
        if s != last:
            print(f"  ... status={s!r}")
            last = s
        if s in ("completed", "error", "cancelled"):
            if s == "completed":
                fc = status.get("findings_count")
                print(f"\nE2E OK — scan completed (findings_count={fc})")
                return 0
            err = status.get("error") or status.get("progress", [])
            print(f"\nFAIL — scan ended with status={s!r} error={err}")
            return 1
        time.sleep(10)

    print(f"\nFAIL — timeout after {args.max_wait}s (scan_id={scan_id})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
