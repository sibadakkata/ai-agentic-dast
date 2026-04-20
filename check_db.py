import sqlite3
conn = sqlite3.connect("/app/results/scanner.db")
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print("Tables:", tables)
for t in tables:
    tname = t[0]
    c.execute(f"SELECT COUNT(*) FROM {tname}")
    print(f"  {tname}: {c.fetchone()[0]} rows")
# Check scans
c.execute("SELECT scan_id, status, result_file FROM scans ORDER BY rowid DESC LIMIT 10")
for row in c.fetchall():
    print(f"  scan={row[0]}, status={row[1]}, file={row[2]}")
conn.close()
