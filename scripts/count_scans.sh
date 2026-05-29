#!/bin/bash
curl -s http://localhost:80/api/scans | python3 -c 'import sys,json; d=json.load(sys.stdin); print(f"Total scans: {d[\"total\"]}"); items=d["items"]; targets=set(s.get("target","") for s in items); print(f"Unique targets: {len(targets)}"); [print(f"  {t}") for t in sorted(targets)]'
