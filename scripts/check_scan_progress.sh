#!/bin/bash
SCAN_ID="${1:-scan_20260519_033435_b97b8b}"
curl -s "http://localhost:80/api/scan/$SCAN_ID" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('Status:', d.get('status'))
print('Phase:', d.get('current_phase'))
print('Findings:', len(d.get('live_findings', [])))
print('Tool calls:', d.get('live_tool_calls'))
print('Crawled:', len(d.get('live_crawled', [])))
print()
print('=== Last 15 progress entries ===')
for p in d.get('progress', [])[-15:]:
    print(' ', p)
"
