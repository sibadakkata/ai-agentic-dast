import time, json, sqlite3, sys
sys.path.insert(0, "/app")

DB = "/app/results/scanner.db"
SCAN_ID = "scan_20260320_045824_69eb37"

t0 = time.perf_counter()
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT payload FROM scan_results WHERE scan_id=?", (SCAN_ID,)).fetchone()
raw = row["payload"] if row else None
conn.close()
t_db = time.perf_counter() - t0
print(f"1. DB read:         {t_db*1000:7.1f}ms")

t0 = time.perf_counter()
data = json.loads(raw) if raw else {}
t_parse = time.perf_counter() - t0
print(f"2. JSON parse:      {t_parse*1000:7.1f}ms")

findings = data.get("findings") or []
test_log = data.get("summary", {}).get("test_log") or []
print(f"   findings={len(findings)}, test_log={len(test_log)}")

# Build index (new)
from collections import defaultdict
t0 = time.perf_counter()
idx = defaultdict(list)
for t in test_log:
    req = t.get("request", {})
    if not isinstance(req, dict):
        continue
    t_url = req.get("url", "") or req.get("endpoint", "")
    url_base = str(t_url).split("?")[0]
    t["_req_json_lower"] = json.dumps(req, default=str).lower()
    if url_base:
        idx[url_base].append(t)
    idx["__all__"].append(t)
_index = dict(idx)
t_index = time.perf_counter() - t0
print(f"3. Build index:     {t_index*1000:7.1f}ms")

from scripts.triage_engine import classify as triage_classify

# WITH index
t0 = time.perf_counter()
triaged = [triage_classify(f, test_log, _index=_index) for f in findings]
t_triage_idx = time.perf_counter() - t0
print(f"4. triage (indexed):{t_triage_idx*1000:7.1f}ms  (x{len(findings)})")

# WITHOUT index (old way)
t0 = time.perf_counter()
triaged2 = [triage_classify(f, test_log) for f in findings]
t_triage_old = time.perf_counter() - t0
print(f"5. triage (old):    {t_triage_old*1000:7.1f}ms  (x{len(findings)})")

speedup = t_triage_old / t_triage_idx if t_triage_idx > 0 else float('inf')
print(f"\nTriage speedup: {speedup:.1f}x ({t_triage_old*1000:.0f}ms -> {t_triage_idx*1000:.0f}ms)")
print(f"Total (indexed): {(t_db+t_parse+t_index+t_triage_idx)*1000:.0f}ms  vs  old: {(t_db+t_parse+t_triage_old)*1000:.0f}ms")
