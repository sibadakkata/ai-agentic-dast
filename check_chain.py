#!/usr/bin/env python3
import sys, json
d = json.load(sys.stdin)
items = d.get("items", d if isinstance(d, list) else [])
active = [s for s in items if s.get("status") in ("running", "in_progress")]
print(len(active), "active scans")
