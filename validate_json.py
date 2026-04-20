import requests, json, gzip, io

base = "http://localhost:8080"
scan_id = "scan_20260320_045824_69eb37"

# Fetch with gzip like a browser would
r = requests.get(f"{base}/api/results/{scan_id}", headers={"Accept-Encoding": "gzip"})
print(f"Status: {r.status_code}")
print(f"Content-Encoding: {r.headers.get('content-encoding', 'none')}")
print(f"Content-Length header: {r.headers.get('content-length', 'none')}")
print(f"Actual body size: {len(r.content)}")

# Check for NaN, Infinity, -Infinity (valid Python JSON, invalid JS JSON)
text = r.text
has_nan = False
has_inf = False
for bad in [': NaN', ':NaN', ': Infinity', ':Infinity', ': -Infinity', ':-Infinity']:
    if bad in text:
        pos = text.index(bad)
        context = text[max(0,pos-50):pos+50]
        print(f"FOUND '{bad}' at pos {pos}: ...{context}...")
        if 'NaN' in bad:
            has_nan = True
        else:
            has_inf = True

# Check for null bytes
if '\x00' in text:
    print("FOUND null bytes in response!")
    
# Check for control characters that break JSON
import re
ctrl = re.findall(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', text)
if ctrl:
    print(f"FOUND {len(ctrl)} control characters: {set(repr(c) for c in ctrl[:10])}")

# Validate JSON
try:
    data = json.loads(text)
    print(f"Python JSON parse: OK ({len(text)} chars)")
except json.JSONDecodeError as e:
    print(f"Python JSON parse FAILED: {e}")

# Check for very large string values or deeply nested objects
def check_depth(obj, depth=0, max_depth=0):
    if depth > max_depth:
        max_depth = depth
    if isinstance(obj, dict):
        for v in obj.values():
            max_depth = check_depth(v, depth+1, max_depth)
    elif isinstance(obj, list):
        for v in obj:
            max_depth = check_depth(v, depth+1, max_depth)
    return max_depth

d = json.loads(text)
depth = check_depth(d)
print(f"Max nesting depth: {depth}")

# Check total number of keys/values
def count_nodes(obj):
    count = 1
    if isinstance(obj, dict):
        for v in obj.values():
            count += count_nodes(v)
    elif isinstance(obj, list):
        for v in obj:
            count += count_nodes(v)
    return count

nodes = count_nodes(d)
print(f"Total JSON nodes: {nodes}")

# Simulate browser: try to parse with strict mode
import subprocess
result = subprocess.run(
    ["python3", "-c", f"import json; json.loads(open('/dev/stdin').read())"],
    input=text, capture_output=True, text=True
)
print(f"Strict parse exit: {result.returncode}")
if result.stderr:
    print(f"  stderr: {result.stderr[:200]}")
