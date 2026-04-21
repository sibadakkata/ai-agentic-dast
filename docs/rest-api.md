# REST API Reference

[← Back to README](../README.md)

The scanner exposes a full REST API — the same one the Web UI uses. Any CI/CD pipeline, script, or external tool can invoke scans programmatically.

- **Interactive docs**: `http://<host>:8080/docs` (Swagger UI) or `/redoc`
- **Auth**: HTTP Basic Auth on all `/api/*` endpoints
- **Health check**: `GET /health` (no auth — for load balancers)

## Setup

```bash
export DAST_URL="http://YOUR-EC2-HOST:8080"
export DAST_USER="dast-admin"
export DAST_PASS="YourPassword"
```

## Endpoints

### 1. List Available Models

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/models" | jq .
```

### 2. Start a Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "username": "user@example.com",
    "password": "secret",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_mode": "both",
    "auth_type": "auto"
  }' | jq .
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_url` | Yes | — | URL to scan |
| `model` | No | Haiku 4.5 | Model ID from `/api/models` |
| `scan_mode` | No | `both` | `website`, `api`, or `both` |
| `scan_profile` | No | `vulnerability_scan` | `vulnerability_scan` (full OWASP testing) or `crawl_only` (discovery + passive checks only — no attack payloads). `crawl_only` forces-clears `focus_areas` and ignores `scan_intensity` |
| `username` | No | — | Login credentials (User A) |
| `password` | No | — | Login credentials (User A) |
| `username_b` | No | — | Second user credentials for BOLA/BFLA testing |
| `password_b` | No | — | Second user credentials for BOLA/BFLA testing |
| `auth_type` | No | `auto` | `auto`, `form`, `sso`, `oauth`, `api_key`, `bearer` |
| `scan_scope` | No | `directory` | `url_only`, `directory`, or `full_site` |
| `scan_intensity` | No | `deep` | `light`, `standard`, or `deep` — payloads per input |
| `focus_urls` | No | `[]` | Specific URLs to prioritize during scanning |
| `focus_areas` | No | `[]` | Vulnerability types to focus on (e.g. `["xss", "sqli"]`) |
| `exclude_urls` | No | `[]` | URLs/paths the scanner must skip entirely |
| `extra_domains` | No | `[]` | Additional domains to include in scope |
| `api_imports` | No | `{}` | Map of import type to filename |

**Response**: `{"scan_id": "scan_20260304_143022_a1b2c3", "status": "started"}`

### 3. Upload API Spec (Postman / OpenAPI)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/upload" \
  -F "file=@my_collection.postman_collection.json" | jq .
```

Then reference in scan: `"api_imports": {"postman": "my_collection.postman_collection.json"}`

Supported import keys: `postman`, `postman_env`, `openapi`.

### 4. Poll Scan Status

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scan/{scan_id}" | jq .
```

Returns `status`: `running`, `paused`, `stopping`, `completed`, `cancelled`, or `error`.

### 5. Stop a Running Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/stop" | jq .
```

Transitions to `stopping`, then `cancelled`. Partial findings are saved.

### 6. Pause a Running Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/pause" | jq .
```

### 7. Resume a Paused Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/resume" | jq .
```

### 7b. Start a Crawl-Only Scan

Use this to verify the scanner can reach every part of your app before committing budget to a full vulnerability scan. No attack payloads are sent.

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_profile": "crawl_only",
    "scan_mode": "both",
    "scan_scope": "directory"
  }' | jq .
```

Results land in the normal `/api/results/{scan_id}` payload — inspect `crawled_endpoints`, `out_of_scope_urls`, and `coverage` (AI Agent Coverage). Scan metadata includes `scan_profile: "crawl_only"`.

### 8. Retry a Failed/Cancelled Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/retry" | jq .

# Override scan_mode or model
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/retry" \
  -H "Content-Type: application/json" \
  -d '{"scan_mode": "api"}' | jq .
```

### 9. Get Live Activity (While Running)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/scan/{scan_id}/live?since_test=0&since_finding=0" | jq .
```

### 10. Get Full Results (After Completion)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/results/{scan_id}" | jq .
```

Returns AI findings, triaged findings, crawled endpoints, payloads by endpoint, coverage stats, severity/OWASP breakdowns.

### 11. Download Raw JSON

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/results/{scan_id}/download" -o scan_result.json
```

### 12. Generate & Download PDF Report

```bash
# Generate
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/results/{scan_id}/report" | jq .

# Download
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/reports/{filename}" -o report.pdf
```

### 13. Download Payloads (by Phase)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/results/{scan_id}/payloads" -o payloads.json
```

### 14. List All Scans

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scans" | jq .
```

### 15. Delete a Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" -X DELETE "$DAST_URL/api/scan/{scan_id}" | jq .
```

### 16. Health Check (No Auth)

```bash
curl -s "$DAST_URL/health" | jq .
# {"status": "ok", "scans_running": 1, "total_scans": 5}
```

## Python Example (End-to-End)

```python
import requests, time

BASE = "http://YOUR-EC2-HOST:8080"
AUTH = ("dast-admin", "YourPassword")

# Start scan
resp = requests.post(f"{BASE}/api/scan", auth=AUTH, json={
    "target_url": "https://example.com",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_mode": "website",
})
scan_id = resp.json()["scan_id"]
print(f"Started: {scan_id}")

# Poll until done
while True:
    status = requests.get(f"{BASE}/api/scan/{scan_id}", auth=AUTH).json()
    print(f"Status: {status['status']} — {status.get('current_phase', '')}")
    if status["status"] != "running":
        break
    time.sleep(30)

# Get results
results = requests.get(f"{BASE}/api/results/{scan_id}", auth=AUTH).json()
print(f"Findings: {len(results['triaged_findings'])}")
for f in results["triaged_findings"]:
    print(f"  [{f['final_severity']}] {f['title']} — {f['verdict']}")

# Generate PDF
pdf = requests.post(f"{BASE}/api/results/{scan_id}/report", auth=AUTH).json()
report = requests.get(f"{BASE}{pdf['pdf']}", auth=AUTH)
with open("report.pdf", "wb") as fh:
    fh.write(report.content)
```
