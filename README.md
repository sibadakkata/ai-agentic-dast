# AI Agentic DAST Scanner

LLM-powered Dynamic Application Security Testing scanner that works against **any website, API, or SPA**.

## How It Works

A single LLM agent (Observe -> Think -> Act -> Analyze -> Plan loop) uses 27 tools to crawl targets, generate context-aware payloads, and test for OWASP Top 10 + business logic vulnerabilities. Findings are triaged offline by a 3-layer evidence-based engine (no LLM cost for triage).

## Quick Start (Web UI)

The fastest way to get started — no CLI needed.

```bash
pip install -r requirements.txt
playwright install chromium
uvicorn web.app:app --host 0.0.0.0 --port 8080
# Open http://localhost:8080
# Login: dast-admin / (set via DAST_AUTH_PASS env var)
```

Or with Docker:

```bash
docker build -t ai-dast-scanner .
docker run -d --name dast-scanner --network host \
  --restart unless-stopped \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -e DAST_AUTH_PASS=YourStrongPassword \
  -v $(pwd)/dast-data/results:/app/results \
  -v $(pwd)/dast-data/imports:/app/imports \
  ai-dast-scanner uvicorn web.app:app --host 0.0.0.0 --port 8080
```

## Supported Models (AWS Bedrock)

All models run through **AWS Bedrock** — no external API keys needed. Uses IAM role or AWS credentials.

| Model | Bedrock ID | Cost (in/out per 1M) | Tool Calling | DAST Quality | Recommendation |
|-------|-----------|---------------------|-------------|-------------|----------------|
| **Ministral 8B** | `bedrock/mistral.ministral-3-8b-instruct` | $0.15 / $0.15 | Good (agentic) | Fair | Cheapest model with tool calling — good for dev/testing |
| **Ministral 14B** | `bedrock/mistral.ministral-3-14b-instruct` | $0.20 / $0.20 | **Strong** (agentic) | Good | **Best value** — designed for agentic use, very cheap |
| Mistral Small | `bedrock/mistral.mistral-small-2402-v1:0` | $0.10 / $0.30 | Weak | Poor | Legacy — does not use tools reliably, text-only findings |
| **Claude Haiku 4.5** | `bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0` | $0.80 / $4 | **Excellent** | **Good** | **Production scans** — reliable tool use, best cost/quality |
| **Claude Sonnet 4.6** | `bedrock/us.anthropic.claude-sonnet-4-6` | $3 / $15 | **Excellent** | **Best** | Deep analysis — most findings, highest quality |

> **Why not other models?**
> - **Amazon Nova** (Micro/Lite/Pro): Content guardrails block security-testing prompts.
> - **Gemini**: Requires a separate Google API key (not available via Bedrock).
> - **Mistral Small**: Responds with hypothetical findings instead of using tools to test.
>
> Ministral 14B or Claude Haiku 4.5 is the minimum for meaningful DAST results.

### Bedrock Setup

Attach an IAM role to your EC2 instance with these permissions:
- `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream` on `arn:aws:bedrock:*:*:inference-profile/*`
- `aws-marketplace:ViewSubscriptions`, `aws-marketplace:Subscribe`

Then set:
```bash
export AWS_DEFAULT_REGION=us-east-1
```

### LiteLLM Proxy (Optional)

If your team has a LiteLLM proxy, you can route non-Bedrock models through it:

```bash
export LITELLM_BASE_URL=https://litellm.your-company.com/
export LITELLM_API_KEY=sk-xxxx
```

The router auto-selects the path: `bedrock/` prefixed models always go direct to Bedrock; others go through the proxy. You can add any LiteLLM-supported model to the UI by editing the `MODELS` list in `web/app.py`.

## Web UI Features

- **New Scan** — enter target URL, optional credentials, pick model and scan mode (web/API/both)
- **API Imports** — upload Postman Collection (v2.0/v2.1), Burp Proxy Export (XML), or Swagger/OpenAPI spec (2.0, 3.0, 3.1 in JSON/YAML)
- **Live Scan Progress** — real-time view of tool calls, payloads tested, responses, pages crawled, and findings detected as the scan runs
- **AI vs Triage** — side-by-side comparison of AI severity vs evidence-based triage verdict
- **Crawled Endpoints** — full list of discovered links and API endpoints
- **Payloads by Endpoint** — expandable view of every payload tested per endpoint
- **Phase Log** — chronological breakdown of each scan phase with tool call and finding counts
- **PDF Report** — generate with full evidence: curl commands, response data, CVE/CVSS scores
- **Download Payloads** — export all payloads tested (grouped by phase) as JSON
- **Raw JSON** — download full scan data for integration
- **Delete Scans** — delete individual scans or clear all history
- **Error Details** — view error messages and progress log for failed scans
- **Basic Auth** — password-protected (configurable via `DAST_AUTH_USER` / `DAST_AUTH_PASS` env vars)

## Docker Deployment (EC2)

### Recommended Setup

```bash
# Build the image
docker build -t ai-dast-scanner .

# Create persistent data directories
mkdir -p /home/ubuntu/dast-data/results /home/ubuntu/dast-data/imports

# Run with persistent volumes + auto-restart
docker run -d --name dast-scanner --network host \
  --restart unless-stopped \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -e DAST_AUTH_PASS=YourStrongPassword \
  -v /home/ubuntu/dast-data/results:/app/results \
  -v /home/ubuntu/dast-data/imports:/app/imports \
  ai-dast-scanner uvicorn web.app:app --host 0.0.0.0 --port 8080
```

### Data Persistence

All scan data is stored in Docker volumes mounted to the host. If the container crashes, stops, or is rebuilt:

| Data | Host Path | Survives Restart? |
|------|-----------|-------------------|
| Scan history & metadata | `dast-data/results/scans_meta.json` | Yes |
| Scan results (JSON) | `dast-data/results/raw/*.json` | Yes |
| PDF reports | `dast-data/results/reports/*.pdf` | Yes |
| Uploaded API specs | `dast-data/imports/` | Yes |
| CVE/NVD cache | `dast-data/results/cache/` | Yes |
| Live activity stream | In-memory only | No (progress log is saved) |

The `--restart unless-stopped` flag ensures the container auto-restarts on crash or EC2 reboot. Scans interrupted by a restart are marked as "error" with the full progress log preserved.

### EC2 Requirements

- **Instance:** t3.xlarge or larger (4 vCPU, 16 GB RAM)
- **OS:** Ubuntu 24.04 LTS (x86_64) — required for Playwright Chromium
- **Disk:** 100 GB
- **Security Group:** Allow inbound TCP on port 8080
- **IAM Role:** Bedrock invoke permissions (see Bedrock Setup above)

## CLI Usage

```bash
# Default scan (uses model from scanner_config.yaml)
python scripts/run_scan.py

# Override model
python scripts/run_scan.py --model "bedrock/us.anthropic.claude-sonnet-4-6"

# Scan specific target
python scripts/run_scan.py --target T1

# Dry run (test connectivity)
python scripts/run_scan.py --dry-run

# Generate PDF reports from existing results
python scripts/report_generator.py
python scripts/report_generator.py --file results/raw/scan_result.json
```

## REST API (External Integration)

The scanner exposes a full REST API — the same one the Web UI uses. Any CI/CD pipeline, script, or external tool can invoke scans programmatically.

- **Interactive API docs:** `http://<host>:8080/docs` (Swagger UI) or `/redoc`
- **Auth:** HTTP Basic Auth on all `/api/*` endpoints
- **Health check:** `GET /health` (no auth — for load balancers)

### Base URL & Auth

```bash
export DAST_URL="http://18.117.143.222:8080"
export DAST_USER="dast-admin"
export DAST_PASS="YourPassword"
```

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

**Parameters:**
| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_url` | Yes | — | URL to scan |
| `model` | No | Haiku 4.5 | Model ID from `/api/models` |
| `scan_mode` | No | `both` | `website`, `api`, or `both` |
| `username` | No | — | Login credentials (leave empty for unauthenticated) |
| `password` | No | — | Login credentials |
| `auth_type` | No | `auto` | `auto`, `form`, `sso`, `oauth`, `api_key`, `bearer` |
| `api_imports` | No | `{}` | Map of import type to filename (see Upload below) |

**Response:**
```json
{"scan_id": "scan_20260304_143022_a1b2c3", "status": "started"}
```

### 3. Upload API Spec (Postman / Burp / OpenAPI)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/upload" \
  -F "file=@my_collection.postman_collection.json" | jq .
```

Then reference the uploaded file when starting a scan:

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://api.example.com",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_mode": "api",
    "api_imports": {"postman": "my_collection.postman_collection.json"}
  }'
```

Supported import keys: `postman`, `postman_env`, `burp`, `openapi`.

### 4. Poll Scan Status

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scan/{scan_id}" | jq .
```

Returns `status`: `running`, `completed`, or `error`.

### 5. Get Live Activity (While Running)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/scan/{scan_id}/live?since_test=0&since_finding=0" | jq .
```

Returns real-time tool calls, findings, crawled URLs, and phase progress.

### 6. Get Full Results (After Completion)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/results/{scan_id}" | jq .
```

Returns AI findings, triaged findings, crawled endpoints, payloads by endpoint, coverage stats, and severity/OWASP breakdowns.

### 7. Download Raw JSON

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/results/{scan_id}/download" -o scan_result.json
```

### 8. Generate & Download PDF Report

```bash
# Generate
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/results/{scan_id}/report" | jq .
# Response: {"pdf": "/api/reports/report_filename.pdf"}

# Download
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/reports/{filename}" -o report.pdf
```

### 9. Download All Payloads (by Phase)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/results/{scan_id}/payloads" -o payloads.json
```

### 10. List All Scans

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scans" | jq .
```

### 11. Delete a Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" -X DELETE "$DAST_URL/api/scan/{scan_id}" | jq .
```

### 12. Health Check (No Auth)

```bash
curl -s "$DAST_URL/health" | jq .
# {"status": "ok", "scans_running": 1, "total_scans": 5}
```

### Python Example (End-to-End)

```python
import requests, time

BASE = "http://18.117.143.222:8080"
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
print("Report saved: report.pdf")
```

## Project Structure

```
config/
  scanner_config.yaml       # Default model + scan settings
  targets.env.example       # Template for CLI credentials
scanners/ai_agent/
  agent.py                  # Core agent loop + context management
  auth.py                   # Authentication (form/SSO/OAuth/MFA)
  llm_config.py             # LLM routing (Bedrock/LiteLLM) + cost tracking
  prompts.py                # System + phase prompts (15 website + 10 API phases)
  tools.py                  # 27 tools (browser, API, WebSocket, fuzzing)
  api_import.py             # Postman/Burp/OpenAPI parsers
scripts/
  run_scan.py               # CLI entry point
  report_generator.py       # PDF report generator with full evidence
  triage_engine.py          # 3-layer universal triage engine
  cve_lookup.py             # NVD + OSV.dev dynamic CVE/CVSS lookup
web/
  app.py                    # FastAPI backend (with Basic Auth)
  static/index.html         # Single-page web UI
tests/
  test_api_imports.py       # API import parser tests (Postman/Burp/OpenAPI)
results/
  raw/                      # Scan output JSON
  reports/                  # Generated PDF reports
  cache/                    # NVD/OSV API response cache
imports/                    # Uploaded API definitions (Postman/Burp/OpenAPI)
Dockerfile                  # Production container image
```

## Scan Capabilities

- **Websites**: Traditional multi-page sites, SPAs (React/Angular/Vue), authenticated flows
- **APIs**: REST, GraphQL, WebSocket — with Postman (v2.0/v2.1), OpenAPI (2.0/3.0/3.1), and Burp XML import support
- **Authentication**: Form login, SSO (SAML), OAuth 2.0/OIDC, MFA (TOTP), session refresh, or unauthenticated scanning
- **Payloads**: 100% LLM-generated per context — no static payload lists
- **Business Logic**: IDOR, nonce reuse, race conditions, payment flow abuse, privilege escalation

## Triage Engine

Offline, zero-cost classification of findings:

1. **Layer 1 — Deterministic Rules**: Auto-classify obvious FPs and confirmed TPs based on HTTP evidence
2. **Layer 2 — Confidence Scoring**: Score ambiguous findings (0-100) using response analysis
3. **Layer 3 — Human Queue**: Flag low-confidence findings for manual verification

## PDF Reports

Generated reports include:
- Executive summary with severity breakdown and scan metadata (duration, cost, tokens)
- Clickable summary table linking to detailed findings
- Per-finding details: CVE/CWE, CVSS score, triage verdict with reasoning
- Full test evidence: actual `curl` commands sent, application responses (status codes, body snippets)
- Steps to reproduce and developer remediation actions
