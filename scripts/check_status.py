import urllib.request, json, sys
scan_id = sys.argv[1] if len(sys.argv) > 1 else "scan_20260521_012615_bdb5df"
r = urllib.request.urlopen(f"http://localhost:80/api/scan/{scan_id}")
d = json.loads(r.read())
print(f"Status: {d['status']}")
print(f"Findings: {d.get('findings_count', '?')}")
print(f"Phase: {d.get('current_phase', '?')}")
print(f"Duration: {d.get('duration', '?')}s")
progress = d.get("progress", [])
for p in progress[-5:]:
    print(f"  {p}")
