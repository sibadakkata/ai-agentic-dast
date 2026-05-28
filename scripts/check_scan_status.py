import requests, json, sys

API = "http://localhost:80"
scan_id = "scan_20260519_124449_d14300"

r = requests.get(f"{API}/api/scans", timeout=10)
data = r.json()
items = data.get("items", [])

for s in items:
    if s["id"] == scan_id:
        print(f"Status: {s.get('status')}")
        print(f"Progress: {s.get('progress', 'N/A')}")
        print(f"Findings: {s.get('findings_count', 0)}")
        print(f"Tests: {s.get('tests_count', 0)}")
        print(f"Phase: {s.get('current_phase', 'N/A')}")
        break
else:
    print("Scan not found")
    for s in items[-3:]:
        print(f"  {s['id']}: {s.get('status')}")
