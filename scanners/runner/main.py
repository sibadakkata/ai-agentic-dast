#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, json, logging, os, sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scanner-runner")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scan-id", required=True)
    args = p.parse_args()
    if not os.environ.get("SCAN_JOB_JSON") or not os.environ.get("DATABASE_URL"):
        return 1
    os.environ["DUAL_WRITE_PG"] = "1"
    from web.scan_job import execute_scan_job
    asyncio.run(execute_scan_job(args.scan_id, json.loads(os.environ["SCAN_JOB_JSON"])))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
