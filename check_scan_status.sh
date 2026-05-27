#!/bin/bash
SCAN_ID="scan_20260416_115114_0d39f1"
curl -s "http://localhost:80/api/scan/${SCAN_ID}/live" | python3 << 'PYEOF'
import sys, json
try:
    d = json.load(sys.stdin)
except:
    print("ERROR: Could not parse response")
    sys.exit(1)

status = d.get("status", "?")
phases = d.get("phases", [])
current = d.get("current_phase", "")
findings = d.get("findings", [])
tests = d.get("tests", [])

print(f"Status: {status}")
print(f"Current: {current}")
print(f"Phases completed: {len(phases)}")
print(f"Findings so far: {len(findings)}")
print(f"Tests so far: {len(tests)}")

print(f"\nPhases:")
for p in phases:
    print(f"  [{p.get('phase','?')}] {p.get('name','?')} — {p.get('tool_calls',0)} tests, {p.get('findings',0)} findings")
PYEOF
