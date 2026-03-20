#!/usr/bin/env python3
"""Smoke E2E against deployed DAST (EC2 or local). No scan start — read-only API checks.

  set DAST_BASE_URL=http://HOST:8080
  set DAST_AUTH_USER=...  DAST_AUTH_PASS=...   (required if API is protected)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("DAST_BASE_URL", "").rstrip("/")
USER = (os.environ.get("DAST_AUTH_USER") or "dast-admin").strip()
PASS = (os.environ.get("DAST_AUTH_PASS") or "changeme").strip()
_AUTH_FROM_ENV = os.environ.get("DAST_AUTH_PASS") is not None

FAIL = 0


def skip(name: str, detail: str = ""):
    print(f"  [SKIP] {name}" + (f" — {detail}" if detail else ""))


def ok(name: str, cond: bool, detail: str = ""):
    global FAIL
    if cond:
        print(f"  [OK] {name}")
    else:
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))
        FAIL += 1


def req(path: str, auth: bool = False):
    url = f"{BASE}{path}"
    r = urllib.request.Request(url)
    if auth and USER:
        import base64

        b = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        r.add_header("Authorization", f"Basic {b}")
    with urllib.request.urlopen(r, timeout=30) as resp:
        return resp.status, json.loads(resp.read().decode())


def req_raw(path: str, method: str = "GET"):
    """Return (status, bytes) for non-JSON responses (PDFs, Excel)."""
    url = f"{BASE}{path}"
    r = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(r, timeout=60) as resp:
        return resp.status, resp.read()


def main():
    if not BASE:
        print("ERROR: Set DAST_BASE_URL environment variable")
        sys.exit(2)

    print(f"E2E smoke @ {BASE}")

    # --- Core APIs ---
    try:
        st, h = req("/health", auth=False)
        ok("GET /health 200", st == 200)
        ok("health.status ok", h.get("status") == "ok")
    except Exception as e:
        ok("GET /health", False, str(e))
        print("Abort (server unreachable).")
        sys.exit(1)

    try:
        st, scans = req("/api/scans?page=1&per_page=2", auth=False)
        ok("GET /api/scans (no auth) 200", st == 200)
        ok("scans.items is list", isinstance(scans.get("items"), list))
        ok("scans has total_pages", "total_pages" in scans)
    except urllib.error.HTTPError as e:
        ok("GET /api/scans", False, f"HTTP {e.code}")
    except Exception as e:
        ok("GET /api/scans", False, str(e))

    try:
        st, ui = req("/api/ui-settings", auth=True)
        ok("GET /api/ui-settings 200", st == 200)
        ok("ui-settings dict", isinstance(ui, dict))
    except urllib.error.HTTPError as e:
        if e.code == 401 and not _AUTH_FROM_ENV:
            skip("GET /api/ui-settings", "HTTP 401 - set DAST_AUTH_PASS in env to test authenticated routes")
        else:
            ok("GET /api/ui-settings", False, f"HTTP {e.code}")
    except Exception as e:
        ok("GET /api/ui-settings", False, str(e))

    try:
        st, models = req("/api/models", auth=False)
        ok("GET /api/models 200", st == 200)
        ok("models list", isinstance(models, list) and len(models) > 0)
    except urllib.error.HTTPError as e:
        ok("GET /api/models", False, f"HTTP {e.code}")
    except Exception as e:
        ok("GET /api/models", False, str(e))

    # --- Dashboard ---
    try:
        st, dash = req("/api/dashboard", auth=False)
        ok("GET /api/dashboard 200", st == 200)
        ok("dashboard has total_scans", "total_scans" in dash)
        ok("dashboard has total_findings", "total_findings" in dash)
    except urllib.error.HTTPError as e:
        ok("GET /api/dashboard", False, f"HTTP {e.code}")
    except Exception as e:
        ok("GET /api/dashboard", False, str(e))

    # --- Report/Compliance tests (if completed scans with findings exist) ---
    completed_sid = None
    try:
        st, all_s = req("/api/scans?per_page=50", auth=False)
        if st == 200:
            for s in (all_s.get("items") or []):
                if s.get("status") == "completed" and (s.get("findings_count") or 0) > 0:
                    completed_sid = s["id"]
                    break
    except Exception:
        pass

    if completed_sid:
        print(f"  (testing reports with scan: {completed_sid})")

        for fw in ("owasp", "pci-dss", "soc2", "hipaa", "iso27001", "nist"):
            try:
                st, data = req_raw(f"/api/results/{completed_sid}/compliance/{fw}", method="POST")
                ok(f"Compliance {fw}: PDF ({len(data)} bytes)", st == 200 and len(data) > 500)
            except urllib.error.HTTPError as e:
                ok(f"Compliance {fw}", False, f"HTTP {e.code}")
            except Exception as e:
                ok(f"Compliance {fw}", False, str(e))

        try:
            url = f"{BASE}/api/results/{completed_sid}/report"
            r = urllib.request.Request(url, data=b'', method='POST')
            r.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(r, timeout=60) as resp:
                rd = json.loads(resp.read().decode())
            ok("PDF report generated", isinstance(rd, dict) and "pdf" in rd)
        except Exception as e:
            ok("PDF report", False, str(e))

        try:
            st, xls = req_raw(f"/api/results/{completed_sid}/excel")
            ok(f"Excel export ({len(xls)} bytes)", st == 200 and len(xls) > 100)
        except Exception as e:
            ok("Excel export", False, str(e))
    else:
        print("  (no completed scan with findings -- skipping report/compliance tests)")

    if FAIL:
        print(f"\n{FAIL} check(s) failed.")
        sys.exit(1)
    print("\nAll smoke checks passed.")


if __name__ == "__main__":
    main()
