import sqlite3
conn = sqlite3.connect("/app/results/scanner.db")
print("Integrity:", conn.execute("PRAGMA integrity_check").fetchone())
print("WAL mode:", conn.execute("PRAGMA journal_mode").fetchone())
print("DB size:", conn.execute("SELECT page_count * page_size FROM pragma_page_count, pragma_page_size").fetchone())
conn.close()
