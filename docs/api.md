# HTTP API guide

The scanner exposes a REST API for launching scans, polling progress, and fetching triaged results. The Web UI uses the same endpoints. Interactive schemas live at **`/docs`** (Swagger UI) and **`/openapi.json`** on your scanner host.

Production: `https://rt.ai.webscanner.gendigital.com`  
Local dev: `http://localhost:8080` (or `http://localhost:80` when `SCANNER_PORT` defaults to 80 in Docker Compose)

## Authentication

> **Audience:** This guide is for **API clients, CI pipelines, MCP, and operator automation** — not for human operators opening the Web UI. End users access the platform via **SSO (Microsoft Entra ID, SAML 2.0)**. See [SSO & RBAC](SSO_RBAC.md).

All `/api/*` routes accept **HTTP Basic Auth** using the server's `DAST_AUTH_USER` and `DAST_AUTH_PASS`. There is no separate API-key scheme in OpenAPI today. Production traffic sits behind **ALB + WAFv2**; unauthenticated API calls return **401**.

**Browser SSO sessions** do not apply to `curl` or most CI scripts — use Basic Auth for those. Advanced integrations may reuse the `dast_session` cookie from a browser after SSO login; that path is not documented in OpenAPI.

Set **automation** credentials for the examples below (not end-user SSO passwords):

```bash
export SCANNER_URL="https://rt.ai.webscanner.gendigital.com"
export SCANNER_USER="YOUR_USER"
export SCANNER_PASS="YOUR_SECRET"
```

## Quick launch

**Recommended:** typed body on `POST /api/v1/scans` (OpenAPI-documented, supports base64 imports).

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/v1/scans" \
  -d '{
    "target_url": "https://example.com",
    "scan_mode": "both",
    "ai_instructions": "Focus on authentication and IDOR. Do not test /payments."
  }'
```

**Legacy:** free-form JSON on `POST /api/scan` accepts the same fields as the UI launch form.

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/scan" \
  -d '{
    "target_url": "https://example.com",
    "scan_mode": "both"
  }'
```

Both return:

```json
{"scan_id": "scan_20260528_120000_abc123", "status": "started"}
```

---

## Endpoints

### POST /api/v1/scans

Start a scan with a typed JSON body. Prefer this for automation and MCP-aligned fields.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_url` | string | Yes | URL or API entry point to scan |
| `scan_mode` | string | No | `website`, `api`, or `both` (default `both`) |
| `model` | string | No | LLM id from `GET /api/models`; empty = default Haiku |
| `username`, `password` | string | No | Primary login (User A) |
| `auth_type` | string | No | `auto`, `none`, `form`, `sso`, `oauth`, `api_key`, `bearer` |
| `ai_instructions` | string | No | Operator guidance for the LLM agent (see below) |
| `api_imports` | object | No | Filenames from upload, or `postman_b64` / `openapi_b64` / `burp_b64` |
| `postman_collection_b64` | string | No | Shorthand: Postman JSON as base64 |
| `scan_profile` | string | No | `vulnerability_scan`, `multi_agent`, or `crawl_only` |
| `scan_intensity` | string | No | `light`, `standard`, `deep` |

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/v1/scans" \
  -d '{
    "target_url": "https://example.com",
    "scan_mode": "api",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "ai_instructions": "Use staging credentials only. Skip CORS checks."
  }'
```

### POST /api/scan

Legacy launch endpoint; same semantics as `/api/v1/scans` but accepts any JSON dict the UI uses (including fields not yet on the v1 model). MCP `start_scan` / `launch_scan` call this route.

### GET /api/scan/{scan_id}

Poll scan status and lightweight live findings.

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  "${SCANNER_URL}/api/scan/SCAN_ID"
```

Important response fields:

| Field | Description |
|-------|-------------|
| `status` | `running`, `paused`, `stopping`, `completed`, `cancelled`, `error` |
| `current_phase` | Human-readable phase label while running |
| `progress` | Array of log lines |
| `findings_count` | Live finding count |
| `cost`, `duration` | Spend and elapsed time |
| `error` | Present when `status` is `error` |

### GET /api/results/{scan_id}

Full triaged results after completion (also works while partial data exists).

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  "${SCANNER_URL}/api/results/SCAN_ID"
```

Top-level keys you typically need:

| Key | Description |
|-----|-------------|
| `metadata` | `target`, `model`, `cost_usd`, `duration_seconds` |
| `triaged_findings` | Post-triage list (`verdict`, `final_severity`, `reason`, …) |
| `ai_findings` | Raw AI output before triage |
| `severity_breakdown`, `owasp_breakdown` | Aggregates |
| `crawled_endpoints`, `payloads_by_endpoint` | Coverage and evidence |

Optional: `?enc=b64` returns `{"_b64": "..."}` with the full JSON base64-encoded.

### GET /api/scans

Paginated scan history. **Always read `items`**, not the top-level object.

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  "${SCANNER_URL}/api/scans?page=1&per_page=25&search=example"
```

Response shape:

```json
{
  "items": [
    {
      "id": "scan_20260528_120000_abc123",
      "target": "https://example.com",
      "status": "completed",
      "findings_count": 42,
      "cost": 12.34
    }
  ],
  "total": 100,
  "page": 1,
  "per_page": 25,
  "total_pages": 4
}
```

### POST /api/upload

Upload Postman, OpenAPI, or Burp exports to `imports/` for use in `api_imports`.

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -X POST "${SCANNER_URL}/api/upload" \
  -F "file=@my_collection.postman_collection.json"
```

Returns `{"filename": "my_collection.postman_collection.json", "size": 12345}`.

Reference in a launch body:

```json
"api_imports": {"postman": "my_collection.postman_collection.json"}
```

Or skip upload and pass inline base64 on `POST /api/v1/scans`:

```json
"postman_collection_b64": "BASE64_OF_JSON_FILE"
```

---

## Operator guidance (`ai_instructions`)

Optional free-text rules injected into the agent system prompt (focus areas, out-of-scope paths, credential usage).

- Max **8192 bytes** UTF-8; longer text is truncated.
- Markdown code fences (triple backticks) are stripped server-side.
- Available on `POST /api/scan`, `POST /api/v1/scans`, and MCP `launch_scan` / `start_scan`.

Examples:

- `Focus on auth and IDOR. Do not test /payments or /checkout.`
- `Use staging credentials only.`
- `Skip CORS checks.`

---

## Polling until complete

### Bash

```bash
SCAN_ID="scan_20260528_120000_abc123"
while true; do
  STATUS=$(curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
    "${SCANNER_URL}/api/scan/${SCAN_ID}" | python -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
  echo "status=$STATUS"
  case "$STATUS" in
    completed|cancelled|error) break ;;
  esac
  sleep 15
done
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  "${SCANNER_URL}/api/results/${SCAN_ID}" -o results.json
```

### Python

```python
import os, time, requests

base = os.environ["SCANNER_URL"]
auth = (os.environ["SCANNER_USER"], os.environ["SCANNER_PASS"])
scan_id = "scan_20260528_120000_abc123"

while True:
    r = requests.get(f"{base}/api/scan/{scan_id}", auth=auth, timeout=30)
    r.raise_for_status()
    status = r.json().get("status")
    print("status:", status)
    if status in ("completed", "cancelled", "error"):
        break
    time.sleep(15)

results = requests.get(f"{base}/api/results/{scan_id}", auth=auth, timeout=120)
results.raise_for_status()
data = results.json()
print("triaged findings:", len(data.get("triaged_findings", [])))
```

Terminal statuses: `completed`, `cancelled`, `error`. While running you may also see `paused` or `stopping`.

---

## Troubleshooting (common HTTP errors)

| Code | Meaning | What to do |
|------|---------|------------|
| **401** | Missing or wrong automation Basic Auth | Set `SCANNER_USER` / `SCANNER_PASS` to match server `DAST_AUTH_*` (API/scripts — not SSO) |
| **400** | Invalid JSON or launch validation | Check body against `/docs` schema; ensure `target_url` is present |
| **404** | Unknown `scan_id` | Confirm id from launch response; list scans with `GET /api/scans` |
| **500** | Server error loading results | Retry; check scan `error` field on `GET /api/scan/{id}` |

For SSO, deploy, and WAF issues see [SSO_RBAC.md](SSO_RBAC.md) and [troubleshooting.md](troubleshooting.md).

---

## See also

- [README](../README.md) — platform overview and local dev
- [MCP / OpenClaw guide](mcp.md) — Cursor and Claude Desktop integration
- [rest-api.md](rest-api.md) — extended reference (pause, retry, reports, crawl-only)
- [openclaw-skill/README.md](../openclaw-skill/README.md) — CLI skill for chat-style workflows
