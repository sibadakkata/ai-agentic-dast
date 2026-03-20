#!/usr/bin/env python3
"""Post-deploy regression: local static checks + live API checks against your DAST host.

Requires:
  - ``DAST_BASE_URL`` — base URL of the deployed app (no trailing slash required).

Optional (if your server protects ``/api/ui-settings`` with Basic auth):
  - ``DAST_AUTH_USER``, ``DAST_AUTH_PASS``

Does **not** deploy or SSH; run this from your laptop/CI after you have deployed.

Example (PowerShell)::

    $env:DAST_BASE_URL = "https://your-dast-host"
    $env:DAST_AUTH_USER = "dast-admin"
    $env:DAST_AUTH_PASS = "your-secret"
    python scripts/run_regression_ec2.py

With optional pytest (``tests/``)::

    python scripts/run_regression_ec2.py --pytest
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_step(title: str, argv: list[str]) -> int:
    print(f"\n{'='*60}\n{title}\n{'='*60}")
    r = subprocess.run(
        [sys.executable, *argv],
        cwd=str(ROOT),
        env=os.environ.copy(),
    )
    return r.returncode


def main() -> int:
    base = (os.environ.get("DAST_BASE_URL") or "").strip()
    if not base:
        print(
            "ERROR: Set DAST_BASE_URL to your deployed DAST base URL, e.g.\n"
            "  PowerShell:  $env:DAST_BASE_URL = 'https://your-host'\n"
            "  bash:        export DAST_BASE_URL=https://your-host",
            file=sys.stderr,
        )
        return 2

    failed = 0
    failed += run_step("1/4 Local regression (_regression_local.py)", ["_regression_local.py"])
    failed += run_step("2/4 E2E smoke (scripts/e2e_ec2_smoke.py)", ["scripts/e2e_ec2_smoke.py"])
    failed += run_step(
        "3/4 Remote API persistence checks (scripts/regression_persistence.py --api-only)",
        ["scripts/regression_persistence.py", "--api-only"],
    )

    if "--pytest" in sys.argv:
        failed += run_step("4/4 pytest tests/", ["-m", "pytest", "tests/", "-q", "--tb=short"])
    else:
        print("\n(Skip pytest — pass --pytest to run tests/ )")

    print(f"\n{'='*60}")
    if failed:
        print(f"REGRESSION FINISHED WITH FAILURES (exit codes sum / steps > 0)")
        return 1
    print("REGRESSION COMPLETE — all steps exited 0.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
