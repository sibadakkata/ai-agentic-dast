#!/usr/bin/env python3
"""Regression checks: scan metadata + results in SQLite; API consistency."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "results" / "scanner.db"

FAIL = 0


def ok(name: str, cond: bool, detail: str = ""):
    global FAIL
    if cond:
        print(f"  [OK] {name}")
    else:
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))
        FAIL += 1


def check_db_schema():
    if not DB.exists():
        print("  (skip DB file checks — no results/scanner.db; normal on fresh clone)")
        return
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        ok("table scans", "scans" in tables)
        ok("table scan_results", "scan_results" in tables)
        ok("table app_kv", "app_kv" in tables)
        ok("table cost_ledger", "cost_ledger" in tables)

        n_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        n_res = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        print(f"  (counts) scans={n_scans} scan_results={n_res}")

        rows = conn.execute(
            "SELECT scan_id, result_file, status FROM scans WHERE result_file IS NOT NULL AND result_file != ''"
        ).fetchall()
        missing_payload = []
        for r in rows:
            sid = r["scan_id"]
            has = conn.execute(
                "SELECT 1 FROM scan_results WHERE scan_id = ?", (sid,)
            ).fetchone()
            if not has:
                missing_payload.append(sid)
        ok(
            "scan_results rows for scans with result_file",
            len(missing_payload) == 0,
            f"missing DB payload for: {missing_payload[:5]}{'...' if len(missing_payload) > 5 else ''}" if missing_payload else "",
        )
    finally:
        conn.close()


def check_api():
    base = os.environ.get("DAST_BASE_URL", "").rstrip("/")
    if not base:
        print("  (skip API checks — set DAST_BASE_URL)")
        return
    try:
        import base64
    except ImportError:
        return

    user = os.environ.get("DAST_AUTH_USER", "")
    pw = os.environ.get("DAST_AUTH_PASS", "")
    headers = {}
    if user:
        b = base64.b64encode(f"{user}:{pw}".encode()).decode()
        headers["Authorization"] = f"Basic {b}"

    def get(path: str):
        req = urllib.request.Request(f"{base}{path}", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())

    auth_pass_set = bool(os.environ.get("DAST_AUTH_PASS"))

    try:
        st, health = get("/health")
        ok("GET /health 200", st == 200 and health.get("status") == "ok")
    except Exception as e:
        ok("GET /health", False, str(e))
        return

    try:
        st, scans = get("/api/scans?page=1&per_page=5")
        ok("GET /api/scans 200", st == 200)
        ok("/api/scans has items", "items" in scans and "total" in scans)
    except Exception as e:
        ok("GET /api/scans", False, str(e))

    try:
        st, ui = get("/api/ui-settings")
        ok("GET /api/ui-settings 200", st == 200)
        ok("ui-settings is dict", isinstance(ui, dict))
    except urllib.error.HTTPError as e:
        if e.code == 401 and not auth_pass_set:
            print("  [SKIP] GET /api/ui-settings — HTTP 401 (set DAST_AUTH_USER + DAST_AUTH_PASS to test)")
        else:
            ok("GET /api/ui-settings", False, f"HTTP {e.code}")
    except Exception as e:
        ok("GET /api/ui-settings", False, str(e))


def main():
    api_only = "--api-only" in sys.argv or os.environ.get("REGRESSION_API_ONLY", "").strip() in ("1", "true", "yes")
    print("Regression: DB persistence & API" + (" (API-only mode)" if api_only else ""))
    if not api_only:
        check_db_schema()
    else:
        print("  (skip local DB — API-only mode)")
    check_api()
    if FAIL:
        print(f"\n{FAIL} check(s) failed.")
        sys.exit(1)
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
