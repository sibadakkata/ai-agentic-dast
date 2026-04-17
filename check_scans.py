import sys, json
data = json.load(sys.stdin)
for s in data.get("scans", []):
    url = s.get("target_url", "")
    if "13.59" in url or "vapi" in url.lower():
        print(f"{s['scan_id']}  |  {url[:70]}  |  {s.get('status','')}  |  findings: {s.get('findings_count',0)}")
