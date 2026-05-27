import json, urllib.request

scan_id = "scan_20260519_060550_f2e9d5"
try:
    resp = urllib.request.urlopen(f"http://localhost:80/api/scan/{scan_id}")
    data = json.loads(resp.read())
    progress = data.get("progress", [])
    for p in progress:
        if "cookie" in str(p).lower() or "auth" in str(p).lower():
            print(p)
    print(f"\nStatus: {data.get('status')}")
    print(f"Findings: {data.get('findings_count')}")
except Exception as e:
    print(f"Error: {e}")
