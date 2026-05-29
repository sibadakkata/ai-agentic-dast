import urllib.request, json, sys

body = json.dumps({
    "target_url": "https://ai.norton.com",
    "scan_type": "ai_agent",
    "focus_areas": ["LLM"],
    "llm_scan_depth": "standard",
    "scan_intensity": "standard",
}).encode()

req = urllib.request.Request(
    "http://localhost:80/api/scan",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
resp = urllib.request.urlopen(req)
print(resp.read().decode())
