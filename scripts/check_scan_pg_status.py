#!/usr/bin/env python3
import os, sys, psycopg
scan_id = sys.argv[1]
with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=10) as conn:
    row = conn.execute(
        "SELECT status, error, findings_count FROM scans WHERE scan_id = %s", (scan_id,)
    ).fetchone()
    n = conn.execute("SELECT COUNT(1) FROM findings WHERE scan_id = %s", (scan_id,)).fetchone()[0]
print(scan_id, row, "findings", n)
