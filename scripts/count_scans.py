import json, urllib.request
resp = urllib.request.urlopen("http://localhost:80/api/scans?limit=500")
d = json.loads(resp.read())
items = d["items"]
print(f"Total scans: {d['total']}")
targets = set(s.get("target", "") for s in items)
print(f"Unique targets: {len(targets)}")
for t in sorted(targets):
    count = sum(1 for s in items if s.get("target") == t)
    print(f"  {count:3d} scans  {t}")
