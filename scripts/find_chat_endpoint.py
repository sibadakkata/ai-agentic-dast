import urllib.request, json, sys

scan_id = sys.argv[1] if len(sys.argv) > 1 else "scan_20260519_064240_f29624"
resp = urllib.request.urlopen(f"http://localhost:80/api/scan/{scan_id}")
data = json.loads(resp.read())
progress = data.get("progress", [])
for p in progress:
    s = str(p).lower()
    if "neoclaw" in s or "/chat" in s or "/message" in s or "/agent/" in s:
        print(p)
