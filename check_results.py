import sqlite3, json

conn = sqlite3.connect("/app/results/scanner.db")
conn.row_factory = sqlite3.Row
c = conn.cursor()

# Check which scans have results vs which don't
c.execute("SELECT scan_id, status, result_file FROM scans ORDER BY rowid DESC")
scans = c.fetchall()
print(f"Total scans: {len(scans)}")
print()

for s in scans:
    sid = s["scan_id"]
    status = s["status"]
    rf = s["result_file"]
    # Check scan_results
    c.execute("SELECT LENGTH(payload) FROM scan_results WHERE scan_id=?", (sid,))
    row = c.fetchone()
    result_size = row[0] if row else 0
    print(f"  {sid}  status={status}  result_file={rf}  db_result_bytes={result_size}")

conn.close()
