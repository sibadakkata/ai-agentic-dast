import os, json, urllib.request, base64, sys
ACTIVE = ("running", "paused", "pausing", "starting")
u, p = os.environ["DAST_AUTH_USER"], os.environ["DAST_AUTH_PASS"]
auth = base64.b64encode(f"{u}:{p}".encode()).decode()
def get(page):
    req = urllib.request.Request(f"http://localhost:80/api/scans?page={page}&per_page=100")
    req.add_header("Authorization", f"Basic {auth}")
    return json.load(urllib.request.urlopen(req))
data = get(1)
items = list(data["items"])
for pg in range(2, data.get("total_pages", 1) + 1):
    items.extend(get(pg)["items"])
active = [s for s in items if isinstance(s, dict) and s.get("status") in ACTIVE]
print(f"Total scans in database: {data.get('total', 0)}")
print(f"Active scans: {len(active)}")
if active:
    for s in active:
        print(f"  ACTIVE  {s.get('id')}  status={s.get('status')}  target={s.get('target')}")
    print("BLOCKED")
    sys.exit(1)
print("SAFE TO DEPLOY")
sys.exit(0)
