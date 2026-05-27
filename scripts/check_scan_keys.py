#!/usr/bin/env python3
import requests, json
r = requests.get("http://localhost:80/api/scans", timeout=10)
d = r.json()
items = d.get("items", [])
if items:
    print("Keys:", list(items[0].keys()))
    print("ID field:", items[0].get("scan_id") or items[0].get("id") or "NOT FOUND")
    print("Status:", items[0].get("status"))
else:
    print("No scans")
