import json, urllib.request

url = "http://localhost:80/api/results/scan_20260522_001730_12a408"
data = json.loads(urllib.request.urlopen(url).read())

af = data.get("ai_findings", [])
print("Total ai_findings:", len(af))

llm = []
for f in af:
    t = str(f.get("title", "")).lower()
    s = str(f.get("source", "")).lower()
    if "llm" in t or "garak" in s or s in ("llm-agent",):
        llm.append(f)

print("LLM findings:", len(llm))
for i, f in enumerate(llm[:5]):
    print(json.dumps(f, indent=2, default=str)[:1500])
    print("---")
