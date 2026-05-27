#!/usr/bin/env python3
import requests, json, sys

API = "http://localhost:80"

payload = {
    "target_url": "https://ai.norton.com/",
    "scan_mode": "website",
    "scan_profile": "vulnerability_scan",
    "username": "siba.dakkata@gendigital.com",
    "password": "Avyan@500",
    "focus_areas": ["LLM"],
}

print(f"Launching Garak-focused scan against {payload['target_url']}...")
r = requests.post(f"{API}/api/scan", json=payload, timeout=30)
print(f"Status: {r.status_code}")
data = r.json()
print(json.dumps(data, indent=2))

if "scan_id" in data:
    print(f"\nScan ID: {data['scan_id']}")
    print(f"Monitor: docker logs -f dast-scanner 2>&1 | grep -i garak")
