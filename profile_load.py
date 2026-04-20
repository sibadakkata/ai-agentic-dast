import time, json, sqlite3

DB = "/app/results/scanner.db"
SCAN_ID = "scan_20260320_045824_69eb37"

# 1. Measure DB read
t0 = time.perf_counter()
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT payload FROM scan_results WHERE scan_id=?", (SCAN_ID,)).fetchone()
raw = row["payload"] if row else None
conn.close()
t_db = time.perf_counter() - t0
print(f"1. DB read:         {t_db*1000:7.1f}ms  ({len(raw) if raw else 0} bytes)")

# 2. Measure JSON parse
t0 = time.perf_counter()
data = json.loads(raw) if raw else {}
t_parse = time.perf_counter() - t0
print(f"2. JSON parse:      {t_parse*1000:7.1f}ms")

findings = data.get("findings") or []
test_log = data.get("summary", {}).get("test_log") or []
print(f"   findings={len(findings)}, test_log={len(test_log)}")

# 3. Measure triage_classify for all findings
import sys
sys.path.insert(0, "/app")
from scripts.triage_engine import classify as triage_classify

t0 = time.perf_counter()
triaged = [triage_classify(f, test_log) for f in findings]
t_triage = time.perf_counter() - t0
print(f"3. triage_classify: {t_triage*1000:7.1f}ms  (x{len(findings)} findings)")

# 3b. Profile individual triage calls
if findings:
    times = []
    for f in findings[:10]:
        t0 = time.perf_counter()
        triage_classify(f, test_log)
        times.append((time.perf_counter() - t0)*1000)
    avg = sum(times)/len(times)
    print(f"   avg per finding: {avg:.1f}ms (first 10)")

# 4. Measure _extract_crawled equivalent
t0 = time.perf_counter()
urls = set()
crawled = []
for t in test_log:
    req = t.get("request", {})
    url = str(req.get("url", "") or req.get("endpoint", ""))
    method = str(req.get("method", "GET"))
    if url and url not in urls:
        urls.add(url)
        resp = t.get("response_summary") or t.get("response") or {}
        status = resp.get("status") or resp.get("status_code", "") if isinstance(resp, dict) else ""
        crawled.append({"url": url, "method": method, "status": str(status)})
t_crawl = time.perf_counter() - t0
print(f"4. extract_crawled: {t_crawl*1000:7.1f}ms  ({len(crawled)} endpoints)")

# 5. Measure payloads_by_endpoint equivalent
from collections import defaultdict
t0 = time.perf_counter()
ep_map = defaultdict(list)
for t in test_log:
    req = t.get("request", {})
    if not isinstance(req, dict):
        continue
    raw_url = str(req.get("url", "") or req.get("endpoint", ""))
    url_base = raw_url.split("?")[0]
    method = str(req.get("method", "GET"))
    if url_base:
        ep_map[f"{method} {url_base}"].append(t)
t_payloads = time.perf_counter() - t0
print(f"5. payloads_by_ep:  {t_payloads*1000:7.1f}ms  ({len(ep_map)} groups)")

# 6. Measure final JSON serialization
response = {
    "metadata": {},
    "ai_findings": [{"title": f.get("title","")} for f in findings],
    "triaged_findings": triaged,
    "crawled_endpoints": crawled,
    "payloads_by_endpoint": list(ep_map.keys()),
}
t0 = time.perf_counter()
out = json.dumps(response, default=str)
t_serial = time.perf_counter() - t0
print(f"6. JSON serialize:  {t_serial*1000:7.1f}ms  ({len(out)} bytes)")

print(f"\nTOTAL (1-6):        {(t_db+t_parse+t_triage+t_crawl+t_payloads+t_serial)*1000:.0f}ms")
