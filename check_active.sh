#!/bin/bash
curl -s http://localhost:8080/api/scans | python3 -c "
import sys, json
data = json.load(sys.stdin)
scans = data.get('items', [])
active = [s for s in scans if s.get('status') in ('running', 'in_progress')]
print(f'{len(active)} active scan(s)')
for s in active:
    print(f'  {s[\"id\"]} — {s[\"target\"]} — {s[\"status\"]}')
"
