import requests, json, sys

base = "http://localhost:8080"
scan_id = "scan_20260320_045824_69eb37"

r = requests.get(f"{base}/api/results/{scan_id}")
print(f"Status: {r.status_code}")
print(f"Content-Type: {r.headers.get('content-type')}")
print(f"Content-Length: {len(r.content)}")

try:
    d = r.json()
    print(f"Valid JSON: True")
    print(f"Keys: {list(d.keys())}")
    print(f"ai_findings: {len(d.get('ai_findings', []))}")
    print(f"triaged_findings: {len(d.get('triaged_findings', []))}")
    print(f"crawled_endpoints: {len(d.get('crawled_endpoints', []))}")
    print(f"payloads_by_endpoint: {len(d.get('payloads_by_endpoint', []))}")
    print(f"phase_log: {len(d.get('phase_log', []))}")
    
    meta = d.get("metadata", {})
    print(f"Metadata keys: {list(meta.keys())}")
    print(f"Target: {meta.get('target_url', 'N/A')}")
    print(f"Status: {meta.get('status', 'N/A')}")
    
    sev = d.get("severity_breakdown", {})
    print(f"Severity: {sev}")
    
    # Check for problematic characters
    raw = r.text
    has_null = '\x00' in raw
    print(f"Contains null bytes: {has_null}")
    
    # Check for very long strings that might crash the browser
    max_str_len = 0
    for f in d.get("ai_findings", []):
        for v in f.values():
            if isinstance(v, str) and len(v) > max_str_len:
                max_str_len = len(v)
    print(f"Max string length in findings: {max_str_len}")
    
except json.JSONDecodeError as e:
    print(f"INVALID JSON: {e}")
except Exception as e:
    print(f"Error: {e}")
