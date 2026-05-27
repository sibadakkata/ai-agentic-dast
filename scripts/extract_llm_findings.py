#!/usr/bin/env python3
"""Extract LLM findings with request/response from the latest scan."""
import json, sys, base64, urllib.request

scan_id = sys.argv[1] if len(sys.argv) > 1 else None

if not scan_id:
    resp = urllib.request.urlopen("http://localhost:80/api/scans")
    scans = json.loads(resp.read())
    items = scans.get("items", scans) if isinstance(scans, dict) else scans
    if items:
        scan_id = items[0]["scan_id"]
    else:
        print("No scans found"); sys.exit(1)

print(f"Scan: {scan_id}\n")

try:
    resp = urllib.request.urlopen(f"http://localhost:80/api/results/{scan_id}?enc=b64")
    envelope = json.loads(resp.read())
    data = json.loads(base64.b64decode(envelope["data"]).decode())
except Exception as e:
    resp = urllib.request.urlopen(f"http://localhost:80/api/results/{scan_id}")
    data = json.loads(resp.read())

findings = data.get("findings", [])
llm = [f for f in findings if "LLM" in f.get("phase", "") or "llm" in f.get("tool", "")]

print(f"Total findings: {len(findings)}")
print(f"LLM findings: {len(llm)}\n")

by_source = {}
for f in llm:
    src = f.get("_finding_source", f.get("tool", "unknown")).split(".")[0]
    by_source.setdefault(src, []).append(f)

for src, items in by_source.items():
    print(f"=== Source: {src} ({len(items)} findings) ===\n")
    for i, f in enumerate(items[:5]):
        print(f"--- [{i+1}] {f.get('title', 'N/A')} ---")
        print(f"  Severity: {f.get('severity', 'N/A')}")
        print(f"  Category: {f.get('owasp_llm', f.get('owasp_category', 'N/A'))}")
        print(f"  CWE: {f.get('cwe', 'N/A')}")
        req = f.get("request", {})
        if req:
            print(f"  Request: {req.get('method', 'POST')} {req.get('url', 'N/A')}")
            body = req.get("body", "")
            if body:
                print(f"  Payload: {str(body)[:200]}")
        resp_s = f.get("response_summary", {})
        if resp_s:
            print(f"  Response status: {resp_s.get('status_code', 'N/A')}")
            print(f"  Response body: {str(resp_s.get('body', ''))[:300]}")
        print(f"  Evidence: {f.get('evidence', 'N/A')[:200]}")
        print()
    if len(items) > 5:
        print(f"  ... and {len(items) - 5} more\n")
