# AI Agentic Web Scanner

LLM-powered Dynamic Application Security Testing scanner that works against **any website, API, or SPA**.

## How It Works

The scanner is a **single LLM agent** running a continuous loop. In each iteration:

1. **Observe** — The agent reads the current phase instruction and all accumulated context (HTTP responses, page source, network logs, cookies, previous findings, fuzzing anomalies)
2. **Think** — The LLM reasons about what it has seen — what the application does, what attack surface exists, which vulnerabilities are plausible given the tech stack and response patterns
3. **Act** — The LLM calls one or more of 28 tools (navigate, inject_payload, fuzz_parameter, api_request, test_token_security, etc.) to interact with the target
4. **Analyze** — The tool results (HTTP status, response body, timing, reflection) are fed back to the LLM, which interprets whether the response indicates a vulnerability or normal behavior
5. **Plan** — Based on what it learned, the LLM decides the next action: go deeper on a promising vector, move to a different parameter, or conclude the phase

This loop runs for each scan phase (up to 25 steps per phase). The LLM decides when a phase is complete — it stops when it has exhausted the attack surface for that category.

Every finding is then **triaged offline** by a 3-layer evidence-based engine that costs $0 (no LLM calls) and produces a verdict: Confirmed, False Positive, or Needs Manual Verification.

### End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. AUTHENTICATION                                                  │
│     Auto-detect auth type (form, SSO, OAuth, API key, bearer)       │
│     Login → capture session → monitor token expiry → auto-refresh   │
├─────────────────────────────────────────────────────────────────────┤
│  2. API BASELINE (if Postman/OpenAPI imported)                      │
│     Execute every endpoint in order with original data              │
│     Chain variables (IDs, tokens) between requests automatically    │
│     Result: "known good" responses for comparison                   │
├─────────────────────────────────────────────────────────────────────┤
│  3. HYBRID BODY FUZZING (POST/PUT/PATCH endpoints)                  │
│     a) LLM plans payloads (1 call ~$0.001)                          │
│     b) Engine executes: field fuzzing + schema probes + injection   │
│     c) Smart detection: value echo, key diff, timing, reflection    │
│     d) LLM analyzes anomalies (1 call ~$0.002)                      │
│     Result: deterministic + LLM-identified API security issues      │
├─────────────────────────────────────────────────────────────────────┤
│  4. LLM DEEP SCAN (15 web phases + 10 API phases)                   │
│     Agent uses 28 tools to test OWASP Top 10 + business logic       │
│     Each phase: observe context → plan attacks → execute → analyze   │
│     Enriched with baseline data + fuzzing anomalies from steps 2-3  │
├─────────────────────────────────────────────────────────────────────┤
│  5. RUNTIME VERIFICATION                                            │
│     Replay confirmed payloads against live target                    │
│     Compare responses: match = CONFIRMED, mismatch = DISPROVED      │
├─────────────────────────────────────────────────────────────────────┤
│  6. TRIAGE ENGINE (offline, $0 cost)                                 │
│     Layer 1: Deterministic rules (auto-classify obvious TP/FP)      │
│     Layer 2: Confidence scoring (-10 to +10 from HTTP evidence)     │
│     Layer 3: NEEDS_VERIFICATION queue for humans                     │
│     + CVE/CVSS enrichment via NVD + OSV.dev                         │
├─────────────────────────────────────────────────────────────────────┤
│  7. REPORT                                                          │
│     PDF with three-stage evidence: AI Agent → Verification → Triage │
│     Curl commands, response snippets, CVE/CWE, remediation steps    │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start (EC2 Deployment)

The recommended path — clone the repo, configure, and deploy with one script.

```bash
# 1. Clone & upload to EC2
scp -i key.pem -r ./POC ubuntu@<EC2-IP>:~/ai-dast-scanner

# 2. SSH in and configure
ssh -i key.pem ubuntu@<EC2-IP>
cd ~/ai-dast-scanner
cp .env.example .env
nano .env  # Add your API keys (AWS Bedrock creds, auth password, etc.)

# 3. Deploy
bash deploy.sh
# → Builds Docker image, starts container, waits for health check
# → Web UI available at http://<EC2-IP>:8080
```

### Local Development (No Docker)

```bash
pip install -r requirements.txt
playwright install chromium
cp .env.example .env && nano .env
uvicorn web.app:app --host 0.0.0.0 --port 8080
# Open http://localhost:8080
```

## Supported Models (AWS Bedrock)

All models run through **AWS Bedrock** — no external API keys needed. Uses IAM role or AWS credentials.

| Model | Bedrock ID | Cost (in/out per 1M) | Tool Calling | Scan Quality | Recommendation |
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
> Ministral 14B or Claude Haiku 4.5 is the minimum for meaningful scan results.

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
- **API Imports** — upload Postman Collection (v2.0/v2.1) or Swagger/OpenAPI spec (2.0, 3.0, 3.1 in JSON/YAML)
- **Live Scan Progress** — real-time view of tool calls, payloads tested, responses, pages crawled, and findings detected as the scan runs
- **AI vs Triage** — side-by-side comparison of AI severity vs evidence-based triage verdict
- **Crawled Endpoints** — full list of discovered links and API endpoints
- **Payloads by Endpoint** — expandable view of every payload tested per endpoint
- **Phase Log** — chronological breakdown of each scan phase with tool call and finding counts
- **PDF Report** — generate with full evidence: curl commands, response data, CVE/CVSS scores
- **Download Payloads** — export all payloads tested (grouped by phase) as JSON
- **Raw JSON** — download full scan data for integration
- **Pause / Resume Scan** — pause a running scan to save cost, resume when ready (no lost progress)
- **Stop Scan** — cancel a running scan; partial findings are saved
- **Delete Scans** — stops running scans first, then permanently deletes scan record, results, and PDF reports
- **Bulk Actions** — select multiple scans via checkboxes for batch retry or delete
- **Retry Failed Scans** — one-click re-run button on errored or cancelled scans (in-place, same ID). Correctly infers scan mode for legacy scans
- **Scan Mode Badge** — each scan shows its mode (`api`, `website`, `both`) in the scan list and error view
- **Error Details** — view error messages, scan mode, and progress log for failed scans
- **Basic Auth** — password-protected (configurable via `DAST_AUTH_USER` / `DAST_AUTH_PASS` env vars)

## Docker Deployment (EC2)

### Recommended Setup (Docker Compose)

Use the included `deploy.sh` script which handles everything:

```bash
bash deploy.sh
```

This runs `docker compose build && docker compose up -d` using the provided `docker-compose.yml`. All configuration (API keys, auth credentials, port) is read from the `.env` file.

To customize, edit `.env` (copied from `.env.example`):

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...     # Optional (if using Anthropic directly)
AWS_ACCESS_KEY_ID=AKIA...        # For Bedrock models
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
DAST_AUTH_USER=dast-admin
DAST_AUTH_PASS=YourStrongPassword
```

### Data Persistence

All scan data is stored in Docker named volumes. If the container crashes, stops, or is rebuilt:

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
export DAST_URL="http://YOUR-EC2-HOST:8080"
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

### 3. Upload API Spec (Postman / OpenAPI)

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

Supported import keys: `postman`, `postman_env`, `openapi`.

### 4. Poll Scan Status

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scan/{scan_id}" | jq .
```

Returns `status`: `running`, `paused`, `stopping`, `completed`, `cancelled`, or `error`.

### 5. Stop a Running Scan

Stop a scan early to save LLM cost (e.g., if triggered accidentally). Partial findings are saved.

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/stop" | jq .
```

The scan transitions to `stopping`, then `cancelled` once the current step completes.

### 6. Pause a Running Scan

Pause a scan to save LLM cost temporarily. The agent blocks after the current step — no progress is lost.

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/pause" | jq .
# {"scan_id": "...", "status": "paused"}
```

### 7. Resume a Paused Scan

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/resume" | jq .
# {"scan_id": "...", "status": "running"}
```

### 8. Retry a Failed or Cancelled Scan

Re-run a scan that errored or was cancelled. Resets the same scan in-place (same ID) with the original target, model, credentials, and scan mode. For legacy scans without stored `scan_mode`, the mode is inferred from the target URL or result metadata.

```bash
# Basic retry (uses original parameters)
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/retry" | jq .

# Override scan_mode or model
curl -s -u "$DAST_USER:$DAST_PASS" \
  -X POST "$DAST_URL/api/scan/{scan_id}/retry" \
  -H "Content-Type: application/json" \
  -d '{"scan_mode": "api"}' | jq .
```

The scan status resets to `running` and a fresh scan begins. No duplicate entries are created.

### 9. Get Live Activity (While Running)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/scan/{scan_id}/live?since_test=0&since_finding=0" | jq .
```

Returns real-time tool calls, findings, crawled URLs, and phase progress.

### 10. Get Full Results (After Completion)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/results/{scan_id}" | jq .
```

Returns AI findings, triaged findings, crawled endpoints, payloads by endpoint, coverage stats, and severity/OWASP breakdowns.

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
# Response: {"pdf": "/api/reports/report_filename.pdf"}

# Download
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/reports/{filename}" -o report.pdf
```

### 13. Download All Payloads (by Phase)

```bash
curl -s -u "$DAST_USER:$DAST_PASS" \
  "$DAST_URL/api/results/{scan_id}/payloads" -o payloads.json
```

### 14. List All Scans

```bash
curl -s -u "$DAST_USER:$DAST_PASS" "$DAST_URL/api/scans" | jq .
```

### 15. Delete a Scan

Stops the scan if running/paused (no further LLM calls), then permanently deletes the scan record, result JSON, and PDF reports.

```bash
curl -s -u "$DAST_USER:$DAST_PASS" -X DELETE "$DAST_URL/api/scan/{scan_id}" | jq .
# {"deleted": ["stopped_running_scan", "scan_record", "aiagent_..._scan_....json", "report_....pdf"]}
```

### 16. Health Check (No Auth)

```bash
curl -s "$DAST_URL/health" | jq .
# {"status": "ok", "scans_running": 1, "total_scans": 5}
```

### Python Example (End-to-End)

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
print("Report saved: report.pdf")
```

## MCP Server (Model Context Protocol)

The scanner includes an MCP server that exposes all capabilities as tools for AI assistants like **Cursor**, **Claude Desktop**, or any MCP-compatible client.

### Setup for Cursor

1. Install the MCP dependency:
```bash
pip install mcp
```

2. Add to your Cursor MCP settings (`.cursor/mcp.json` or global settings):
```json
{
  "mcpServers": {
    "agentic-web-scanner": {
      "command": "python",
      "args": ["mcp_server.py"],
      "env": {
        "SCANNER_URL": "http://YOUR-EC2-HOST:8080",
        "SCANNER_USER": "dast-admin",
        "SCANNER_PASS": "YOUR_PASSWORD"
      }
    }
  }
}
```

3. Restart Cursor. The scanner tools will be available in Agent mode.

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `health_check` | Check if scanner is running |
| `list_models` | List available LLM models |
| `start_scan` | Start a new security scan (target URL, model, scan mode, credentials) |
| `stop_scan` | Stop a running scan to save cost (partial findings are saved) |
| `retry_scan` | Re-run a failed or cancelled scan in-place (same ID, infers scan mode for legacy scans) |
| `get_scan_status` | Poll scan progress (includes `scan_mode`) |
| `wait_for_scan` | Block until scan completes (with timeout) |
| `get_scan_results` | Get full triaged findings |
| `get_live_activity` | Real-time tool calls and findings for running scans |
| `get_findings_summary` | Human-readable severity summary |
| `query_findings` | Search findings across scans by target, keyword, severity, verdict (e.g., "SQL injection in NGP") |
| `get_scan_stats` | Aggregated statistics: severity/verdict/category breakdown, cost, duration, coverage |
| `generate_report` | Generate PDF report |
| `download_payloads` | Export all tested payloads by phase |
| `upload_api_spec` | Upload Postman/OpenAPI file |
| `list_scans` | List all scan history (includes `scan_mode` per scan) |
| `delete_scan` | Stop (if running) and permanently delete a scan, results, and reports |

### Standalone Mode

Run the MCP server directly (e.g., for the MCP Inspector):
```bash
SCANNER_URL=http://your-host:8080 SCANNER_PASS=secret python mcp_server.py --transport=streamable-http
```

## Project Structure

```
.env.example                # Environment template (copy to .env and fill in)
docker-compose.yml          # Docker Compose service definition
Dockerfile                  # Production container image
deploy.sh                   # One-command EC2 deployment script
requirements.txt            # Python dependencies
mcp_server.py               # MCP server (Model Context Protocol)
mcp_config.example.json     # Example Cursor MCP configuration
config/
  scanner_config.yaml       # Default model + scan settings
  targets.env.example       # Template for CLI credentials
scanners/ai_agent/
  agent.py                  # Core agent loop + context management
  auth.py                   # Authentication (form/SSO/OAuth/MFA)
  llm_config.py             # LLM routing (Bedrock/LiteLLM) + cost tracking
  prompts.py                # System + phase prompts (15 website + 10 API phases)
  tools.py                  # 28 tools (browser, API, WebSocket, token, fuzzing)
  api_import.py             # Postman/OpenAPI parsers
  baseline_executor.py      # API happy-path executor + variable auto-chaining
  body_fuzzer.py            # Hybrid body fuzzer (LLM-planned, deterministic execution)
scripts/
  run_scan.py               # CLI entry point
  report_generator.py       # PDF report generator with full evidence
  excel_exporter.py         # Excel report exporter (multi-sheet .xlsx)
  triage_engine.py          # 3-layer universal triage engine
  cve_lookup.py             # NVD + OSV.dev dynamic CVE/CVSS lookup
web/
  app.py                    # FastAPI backend (with Basic Auth)
  static/index.html         # Single-page web UI
tests/
  test_api_imports.py       # API import parser tests (Postman/OpenAPI)
results/                    # Created at runtime
  raw/                      # Scan output JSON
  reports/                  # Generated PDF reports
  cache/                    # NVD/OSV API response cache
imports/                    # Uploaded API definitions (Postman/OpenAPI)
```

## Scan Capabilities

- **Websites**: Traditional multi-page sites, SPAs (React/Angular/Vue), authenticated flows
- **APIs**: REST, GraphQL, WebSocket — with Postman (v2.0/v2.1) and OpenAPI (2.0/3.0/3.1) import support
- **Authentication**: Form login, SSO (SAML), OAuth 2.0/OIDC, MFA (TOTP), session refresh, or unauthenticated scanning
- **Payloads**: LLM-generated per context — the agent reasons about what it sees and crafts payloads accordingly
- **Business Logic**: IDOR, nonce reuse, race conditions, payment flow abuse, privilege escalation

---

## How API Scanning Works (Detailed Walkthrough)

This section walks through exactly what happens when you scan an API, using a realistic banking API as an example.

### Example: Scanning a Banking API

Suppose you have a Postman collection with these endpoints:

```
POST /api/auth/login          {"email": "user@bank.com", "password": "secret"}
GET  /api/accounts/me
POST /api/transfer            {"fromAccount": "ACC-001", "toAccount": "ACC-002", "amount": 500, "currency": "USD", "note": "rent"}
GET  /api/transactions?accountId=ACC-001&limit=50
PUT  /api/profile             {"name": "John", "email": "john@bank.com", "phone": "+1234567890"}
```

Here's what happens step by step:

### Step 1: Baseline Execution (Happy Path)

The engine runs every endpoint in order with the original data. This is deterministic (no LLM).

```
POST /api/auth/login → 200 {"token": "eyJhbGci...", "userId": "USR-42"}
  ↳ Auto-chains: Bearer token captured for subsequent requests
  ↳ Auto-chains: userId=USR-42 stored for variable substitution

GET /api/accounts/me → 200 {"id": "ACC-001", "balance": 5000, "name": "John Doe"}
  ↳ Auto-chains: accountId=ACC-001

POST /api/transfer → 200 {"transactionId": "TXN-99", "status": "completed"}
  ↳ Auto-chains: transactionId=TXN-99

GET /api/transactions?accountId=ACC-001 → 200 [{"id": "TXN-99", ...}]

PUT /api/profile → 200 {"name": "John", "email": "john@bank.com"}
```

**What this gives us**: A "known good" baseline — the exact response codes, body sizes, and JSON structures we expect when everything is normal. The fuzzer compares against this.

### Step 2: Field Classification

For every POST/PUT/PATCH endpoint, the engine extracts and classifies JSON body fields:

```
POST /api/transfer:
  fromAccount → auth_id (P1)     — account identifier, high IDOR risk
  toAccount   → auth_id (P1)     — account identifier, high IDOR risk
  amount      → financial (P1)   — monetary value, business logic risk
  currency    → enum (P2)        — constrained set, type confusion risk
  note        → freetext (P3)    — user input, XSS/injection risk

PUT /api/profile:
  name        → pii (P2)         — personal data
  email       → contact (P1)     — high-value, account takeover risk
  phone       → contact (P1)     — high-value
```

P1 = highest priority (tested first), P3 = lowest.

### Step 3: LLM Payload Planning (~$0.001 per endpoint)

One LLM call per endpoint. The LLM sees the field list, their types, and the API context, then decides what payloads to test:

```json
// LLM output for POST /api/transfer:
[
  {"field": "fromAccount", "payloads": ["ACC-002", "ACC-999", "' OR 1=1--", "0"]},
  {"field": "toAccount", "payloads": ["ACC-001", "{{fromAccount}}", "null"]},
  {"field": "amount", "payloads": [-1, 0, 0.001, 999999999, "abc"]},
  {"field": "currency", "payloads": ["", "XXX", "USD'; DROP TABLE--", null]},
  {"field": "note", "payloads": ["<script>alert(1)</script>", "A".repeat(10000)]}
]
```

The LLM understands that `fromAccount` + `toAccount` is a transfer pair (IDOR risk), that `amount` needs boundary testing (negative, zero, overflow), and that `currency` is an enum that should reject invalid values.

### Step 4: Deterministic Execution (Zero LLM Cost)

The engine runs every payload — mutating one field at a time while keeping the rest valid:

```
# Field fuzzing (LLM-planned payloads)
POST /api/transfer {"fromAccount":"ACC-002", "toAccount":"ACC-002", "amount":500, ...}  → 200 ✗ ANOMALY
POST /api/transfer {"fromAccount":"ACC-001", "toAccount":"ACC-001", "amount":-1, ...}   → 200 ✗ ANOMALY
POST /api/transfer {"fromAccount":"ACC-001", "toAccount":"ACC-002", "amount":0, ...}    → 200 ✗ ANOMALY

# JSON Schema Probes (auto-generated)
POST /api/transfer {+ "is_admin": true, + "role": "admin"}     → 200 ✗ ANOMALY (extra fields accepted)
POST /api/transfer {"amount": "not_a_number"}                   → 200 ✗ ANOMALY (wrong type accepted)
POST /api/transfer {missing "fromAccount"}                      → 400 ✓ OK (validation works)
POST /api/transfer {"amount": null}                             → 200 ✗ ANOMALY (null accepted)

# JSON Injection Probes (auto-generated)
POST /api/transfer {"amount": 500, "amount": -1}               → 200 ✗ ANOMALY (duplicate key)
POST /api/transfer {"__proto__": {"isAdmin": true}}             → 200 ✗ ANOMALY
POST /api/transfer {"fromAccount": {"$ne": ""}}                 → 200 ✗ ANOMALY (NoSQL operator)
```

**Anomaly detection** compares each response to the baseline:
- **Status change**: Got 200 but expected 400? That's an anomaly.
- **Value echo**: Did the server include `is_admin: true` in the response? Server accepted it.
- **Response key diff**: Did the response JSON grow new keys that weren't in the baseline?
- **Error strings**: Does the 500 response contain stack traces, SQL errors, or internal paths?
- **Timing**: Did the request take 5x longer? Potential time-based injection.
- **Reflection**: Is the payload echoed back in the response body?

### Step 5: LLM Anomaly Analysis (~$0.002 per endpoint)

All anomalous responses (not every response — only the ones that deviated from baseline) are batched into one LLM call. The LLM reads the anomalies and identifies real security issues:

```json
// LLM analysis output:
[
  {
    "title": "IDOR: Transfer from another user's account",
    "severity": "High",
    "type": "idor",
    "field": "fromAccount",
    "evidence": "Changing fromAccount to ACC-002 returned 200 with transactionId — server transferred from a different account without authorization check",
    "payload": "ACC-002",
    "explanation": "The API does not verify that the authenticated user owns the fromAccount. An attacker can drain any account."
  },
  {
    "title": "Negative transfer amount accepted",
    "severity": "High",
    "type": "biz_logic",
    "field": "amount",
    "evidence": "amount=-1 returned 200 with status:completed — negative transfer processed",
    "payload": -1,
    "explanation": "Negative amounts reverse money flow. Attacker sends amount=-1000 to themselves to effectively steal from the toAccount."
  },
  {
    "title": "Mass assignment: extra fields accepted",
    "severity": "Medium",
    "type": "mass_assignment",
    "field": "is_admin",
    "evidence": "Extra field is_admin:true was accepted (200 OK, no validation error)",
    "payload": "{\"is_admin\": true}",
    "explanation": "Server does not filter unknown fields. If persisted, attacker could escalate privileges."
  }
]
```

**Cost**: This single LLM call costs ~$0.002. Compare to testing each anomaly individually with the LLM ($0.05-0.10+).

### Step 6: LLM Deep Scan (10 API Phases)

The LLM agent now runs its full OWASP phase scan, but **enriched** with everything from steps 1-5. It already knows:
- Which endpoints exist and what they return
- Which fields have validation issues
- Which anomalies the fuzzer found
- Which API security issues the analysis identified

The 10 API phases, each with its own agent loop:

| # | Phase | What the Agent Does | Example Action |
|---|-------|---------------------|----------------|
| 1 | **Endpoint Discovery** | Maps all imported endpoints. Generates path wordlists from observed patterns and probes for undocumented endpoints using OPTIONS and common admin/debug paths. | `api_request("GET", "/api/admin")` → 200? Hidden admin endpoint found |
| 2 | **Authentication Testing** | Removes auth headers and checks if endpoints still respond. Tests token validation, token reuse across contexts, and JWT manipulation (alg:none, claim tampering). | `api_request("GET", "/api/accounts/me", headers={})` → 200 without auth = broken |
| 3 | **Authorization / BOLA** | For every object ID in path, query, or body, crafts IDOR payloads. Tests horizontal (same role, different user) and vertical (user→admin) privilege escalation. | `api_request("GET", "/api/accounts/ACC-002")` using User A's token → gets User B's data? |
| 4 | **Injection Testing** | Tests SQLi, NoSQLi, LDAP injection, XSS in JSON responses, and XXE in XML endpoints. Infers backend technology from error patterns and crafts targeted payloads. | `api_request("POST", "/api/search", body={"q": "' UNION SELECT * FROM users--"})` |
| 5 | **Mass Assignment** | Sends extra fields in POST/PUT that aren't in the schema (`role`, `is_admin`, `price`). Checks if unintended fields are persisted by reading the resource back. | `api_request("PUT", "/api/profile", body={"name": "John", "role": "admin"})` → `GET /api/profile` → role changed? |
| 6 | **Rate Limiting** | Sends rapid-fire requests to login, password reset, and transaction endpoints. Checks whether the API returns 429 or allows unlimited attempts. | 100x `POST /api/auth/login` with wrong password → no 429 = no rate limiting |
| 7 | **SSRF** | Identifies parameters that accept URLs (webhooks, callbacks, file imports, redirects). Probes for cloud metadata endpoints and internal services. | `api_request("POST", "/api/webhook", body={"url": "http://169.254.169.254/latest/meta-data/"})` |
| 8 | **GraphQL Testing** | If GraphQL is detected: tests introspection queries, query batching, deep nesting (DoS), and alias brute-force for enumeration. | `api_request("POST", "/graphql", body={"query": "{__schema{types{name fields{name}}}}"})` |
| 9 | **Excessive Data Exposure** | Compares API response fields to what the UI actually displays. Flags PII, secrets, internal IDs, or debug information that the frontend doesn't render. | Response to `GET /api/users/me` includes `ssn`, `internal_id`, `admin_notes` not shown in UI |
| 10 | **Business Logic** | Tests flow bypass (skipping required steps), parameter tampering (negative amounts, zero prices), race conditions (parallel requests on state-changing actions), and idempotency violations. | Two simultaneous `POST /api/transfer` with same nonce — does money transfer twice? |

### Step 7: Runtime Verification

After the LLM reports findings, the agent replays the exact payloads against the live target to verify they're real:

```
Finding: "SQL Injection in /api/search"
  Replay: POST /api/search {"q": "' OR 1=1--"}
  Response: 200 {"results": [...50 items...]}
  Baseline: 200 {"results": [...3 items...]}
  Verdict: CONFIRMED — response size dramatically different, query returned all records
```

```
Finding: "XSS in /api/profile name field"
  Replay: PUT /api/profile {"name": "<script>alert(1)</script>"}
  Response: 200 {"name": "&lt;script&gt;alert(1)&lt;/script&gt;"}
  Verdict: DISPROVED — output is HTML-encoded, XSS not executable
```

### Step 8: Triage Engine (Offline, $0)

Every finding — whether from the body fuzzer, the LLM phases, or runtime verification — goes through the triage engine. See the [Triage Engine](#triage-engine-detailed) section below.

---

## How Website Scanning Works

For websites (traditional or SPA), the flow is similar but uses browser automation instead of API calls.

### What the Agent Does

1. **Application mapping** — Opens the site in a real Chromium browser. For SPAs, clicks elements and intercepts `fetch`/`XHR`. For traditional sites, follows links BFS-style. Extracts forms, hidden inputs, localStorage, cookies.

2. **OWASP Top 10 + extended phases** (15 phases for websites):

| # | Phase | What the Agent Does | Example Action |
|---|-------|---------------------|----------------|
| 1 | **Application Mapping** | Opens a real Chromium browser. For SPAs: clicks elements, intercepts fetch/XHR, monitors route changes. For traditional sites: follows links BFS-style. Extracts every form, hidden input, JS endpoint, and storage data. | `navigate("https://app.com")` → `get_links()` → `get_forms()` → `get_local_storage()` |
| 2 | **Broken Access Control (A01)** | For every ID in paths, query params, or body, crafts IDOR payloads with adjacent/predictable IDs. Tests forced browsing to admin paths and HTTP method tampering (GET→POST). | Change `/users/42/profile` to `/users/43/profile` — does it return another user's data? |
| 3 | **Cryptographic Failures (A02)** | Checks TLS version and cipher support, inspects cookie flags (Secure, HttpOnly, SameSite), looks for sensitive data in URLs, localStorage, or unencrypted channels. | `get_cookies()` → finds `session_id` without `Secure` flag on HTTPS site |
| 4 | **SQL Injection (A03)** | Infers the database engine from error messages and response patterns. Crafts engine-specific payloads: error-based, blind boolean, blind time-based, UNION, stacked queries. | `fuzz_parameter(url, "id", ["1' OR 1=1--", "1' AND SLEEP(5)--"])` → checks for SQL errors or time delay |
| 5 | **Cross-Site Scripting (A03)** | Tests reflected, stored, and DOM-based XSS. Crafts polyglots, CSP bypass attempts, event handlers, SVG payloads based on where input is reflected and what sanitization exists. | `inject_payload("search", "<svg/onload=alert(1)>")` → checks if payload appears unencoded in response |
| 6 | **Command Injection (A03)** | Identifies inputs that might reach a shell (forms, headers, URL params). Crafts blind payloads using sleep/ping if output is not visible. | `fuzz_parameter(url, "filename", ["; sleep 5", "| cat /etc/passwd"])` → measures response timing |
| 7 | **Template Injection (A03)** | Detects template engine from error messages or markers. Once identified, crafts engine-specific SSTI payloads. | Sends `{{7*7}}` → response contains `49` → confirmed Jinja2 SSTI |
| 8 | **Insecure Design (A04)** | Tests business logic: price tampering, flow bypass (skipping checkout steps), race conditions on state-changing actions, rate limit abuse. | Submits order with `price: 0.01` or skips payment step entirely |
| 9 | **Security Misconfiguration (A05)** | Inspects response headers (CSP, X-Frame-Options, HSTS), tests CORS policy with cross-origin requests, checks for verbose error pages, directory listings, debug endpoints, and default credentials. | `api_request("OPTIONS", url, headers={"Origin": "https://evil.com"})` → checks `Access-Control-Allow-Origin` |
| 10 | **Vulnerable Components (A06)** | Fingerprints frameworks and JS libraries from response headers, page source, and script tags. Identifies versions and checks for known CVEs via NVD + OSV.dev. | `get_page_source()` → finds `jquery-3.3.1.min.js` → looks up CVE-2020-11022 |
| 11 | **Authentication Failures (A07)** | Tests session fixation, weak/predictable tokens, brute-force resistance, JWT manipulation (alg:none, key confusion, claim tampering), password reset flaws. | `test_token_security(token)` → decodes JWT → tries `alg:none` bypass → checks if server accepts it |
| 12 | **Integrity Failures (A08)** | Verifies Subresource Integrity (SRI) on external scripts, checks for untrusted CDN resources, tests client-side prototype pollution via `__proto__` and `constructor`. | Finds `<script src="https://cdn.example.com/lib.js">` without `integrity=` attribute |
| 13 | **Logging Failures (A09)** | Triggers security-relevant actions (failed logins, injection attempts) and checks whether the application leaks sensitive information in error responses. | Sends invalid input → response contains `java.sql.SQLException at com.app.db.Query:42` |
| 14 | **SSRF (A10)** | Identifies URL-accepting parameters (webhooks, file import, redirects). Crafts cloud metadata probes and redirect chain payloads. | `fuzz_parameter(url, "callback", ["http://169.254.169.254/latest/meta-data/"])` |
| 15 | **WebSocket Testing** | Connects to discovered WS endpoints. Injects payloads into messages, tests if WS connections require authentication, probes for message injection and authorization bypass. | `ws_connect("wss://app.com/ws")` → `ws_inject({"action": "getUser", "id": "OTHER_USER"})` |
| 16 | **Beyond OWASP** | Tests additional vectors: open redirect, CRLF injection, HTTP request smuggling, clickjacking, CSRF, and prototype pollution. | `fuzz_parameter(url, "redirect", ["https://evil.com"])` → checks if 302 redirects to attacker domain |

3. **The agent uses 28 tools** organized by capability:

| Category | Tools | What They Do |
|----------|-------|-------------|
| Browser | `navigate`, `click`, `fill`, `submit_form`, `screenshot` | Navigate pages, interact with elements, fill forms |
| Injection | `inject_payload` | Inject payloads directly into page DOM |
| Observation | `get_page_source`, `get_cookies`, `get_network_log`, `get_forms`, `get_links`, `get_local_storage` | Read page content, cookies, XHR traffic, storage |
| SPA | `wait_for_spa_route`, `intercept_requests`, `execute_js` | Handle React/Angular/Vue route changes, intercept fetch/XHR |
| WebSocket | `ws_connect`, `ws_send`, `ws_receive`, `ws_inject`, `ws_close` | Full WebSocket lifecycle testing |
| API | `api_request`, `api_request_raw`, `fuzz_parameter`, `replay_with_modification` | HTTP requests, parameter fuzzing, response comparison |
| Discovery | `get_api_endpoints` | List all imported/discovered API endpoints |
| Auth Testing | `test_auth_bypass`, `test_method_override`, `test_token_security` | Auth bypass, HTTP method override, JWT manipulation |

---

## Domain Scoping

The scanner restricts activity to the target domain and its subdomains. Gen Digital owned domains are auto-scoped (norton.com, avg.com, avast.com, avira.com, ccleaner.com, gendigital.com, lifelock.com, nortonlifelock.com, reputation.com). Third-party domains are excluded and listed in the UI. Additional domains can be explicitly included via the "Additional Domains" field in the scan form.

---

## Triage Engine (Detailed)

The triage engine classifies every finding **offline** (no LLM calls, $0 cost). It answers: "Is this finding real, and how severe is it?"

### Three Layers

```
Finding from AI agent
        │
        ▼
┌─────────────────────────────────────────┐
│  LAYER 0: Runtime Verification          │
│  If the payload was replayed live:       │
│    CONFIRMED  → TRUE_POSITIVE           │
│    DISPROVED  → FALSE_POSITIVE          │
│    INCONCLUSIVE → fall through          │
├─────────────────────────────────────────┤
│  LAYER 1: Deterministic Rules           │
│  Pattern-match title + HTTP evidence:    │
│    SQL error keywords in response?       │
│      → TRUE_POSITIVE (Critical)         │
│    All responses 301/302 redirects?      │
│      → FALSE_POSITIVE (not auth'd)      │
│    Zero evidence (no payload, no tests)? │
│      → FALSE_POSITIVE                   │
│    Missing HSTS header?                  │
│      → TRUE_POSITIVE (Low)              │
├─────────────────────────────────────────┤
│  LAYER 2: Confidence Scoring (-10..+10) │
│  Score from HTTP evidence signals:       │
│    +4: SQL error keywords in body       │
│    +3: payload reflected in response     │
│    +5: OS file content in response       │
│    -4: all responses are redirects       │
│    -3: all responses are 403            │
│    -5: zero evidence at all             │
│  Score ≥ 5 → TRUE_POSITIVE (Medium)     │
│  Score ≥ 3 → TRUE_POSITIVE (Low)        │
│  Score ≥ 0 → TRUE_POSITIVE (Low)        │
│  Score < 0 → FALSE_POSITIVE (Info)      │
└─────────────────────────────────────────┘
```

### Triage Examples

Here are concrete examples of how the engine classifies real findings:

#### Example 1: SQL Injection — CONFIRMED

```
AI Agent reports: "SQL Injection in /api/search"
  Payload: ' OR 1=1--
  Evidence: "mysql syntax error near '' at line 1"

Triage:
  Layer 0: Runtime replay returned same SQL error → CONFIRMED
  Layer 1: Title matches "sql injection" + SQL_ERROR_KEYWORDS found in response body
  Verdict: TRUE_POSITIVE
  Severity: Critical (CWE-89, CVSS 9.8)
  Dev Action: "URGENT: Use parameterized queries. Never concatenate user input into SQL."
```

#### Example 2: XSS — FALSE POSITIVE

```
AI Agent reports: "Reflected XSS in /api/profile"
  Payload: <script>alert(1)</script>
  Evidence: "payload reflected in response"

Triage:
  Layer 0: Runtime replay → response contains &lt;script&gt; (HTML-encoded) → DISPROVED
  Verdict: FALSE_POSITIVE
  Severity: Info
  Reason: "XSS payload sent but output is HTML-encoded. Not executable."
  Dev Action: "No action — output encoding is effective."
```

#### Example 3: IDOR — NEEDS MANUAL VERIFICATION

```
AI Agent reports: "IDOR in /api/accounts/{id}"
  Payload: Changed id from ACC-001 to ACC-002
  Response: 200 OK with account data

Triage:
  Layer 1: IDOR pattern detected, 200 response with PII keywords ("email", "name")
  Verdict: TRUE_POSITIVE
  Severity: Medium (needs two-account test for High)
  Steps: "1. Login as User A, note resource IDs
          2. Login as User B, try to access User A's resources
          3. If successful → upgrade to High"
  Dev Action: "Implement object-level authorization checks."
```

#### Example 4: Missing HSTS — TRUE POSITIVE (Low)

```
AI Agent reports: "Missing Strict-Transport-Security header"
  Evidence: "HSTS header not present in response"

Triage:
  Layer 1: Title matches "hsts" + "missing" pattern
  Verdict: TRUE_POSITIVE
  Severity: Low (CWE-319, CVSS 4.3)
  Reason: "HSTS absent. Requires active MITM to exploit. No exploit demonstrated."
  Dev Action: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
```

#### Example 5: Scanner Noise — FALSE POSITIVE

```
AI Agent reports: "Broken Access Control in /admin"
  Payload: GET /admin
  All test responses: [302, 302, 302] (redirects to login)

Triage:
  Layer 1: All responses are redirects → scanner wasn't authenticated
  Verdict: FALSE_POSITIVE
  Severity: Info
  Reason: "All 3 responses were [302] redirects. Scanner was not authenticated.
           Injection findings require authenticated access to be valid."
```

#### Example 6: Outdated Library with Real CVE

```
AI Agent reports: "Outdated jQuery 3.3.1"
  Evidence: "jQuery 3.3.1 found in page source"

Triage:
  Layer 1: Matches "jquery" → queries NVD + OSV.dev for jquery@3.3.1
  CVE lookup: CVE-2020-11022 (XSS via html(), CVSS 6.1), CVE-2020-11023 (XSS, CVSS 6.1)
  Verdict: TRUE_POSITIVE
  Severity: Medium (CVSS 6.1)
  Dev Action: "Upgrade jQuery to 3.5.0+ to fix CVE-2020-11022 and CVE-2020-11023."
```

### Severity Policy

The triage engine applies a consistent severity policy regardless of what the LLM reported:

| Severity | Criteria |
|----------|----------|
| **Critical** | Confirmed RCE, data exfiltration, or account takeover WITH proof in HTTP response |
| **High** | Confirmed exploit with demonstrated real impact (SQLi with DB errors, SSRF hitting metadata) |
| **Medium** | Known CVE with documented exploit path, or confirmed issue needing multi-account verification |
| **Low** | Config weakness, defense-in-depth, theoretical risk, recon aid (missing headers, weak cookies) |
| **Info** | Best practice observation, false positive, or scanner noise |

### What Gets CWE/CVSS

The engine maps findings to CWE IDs and CVSS scores automatically:

| Finding Type | CWE | CVSS | Example |
|-------------|-----|------|---------|
| SQL Injection (confirmed) | CWE-89 | 9.8 | SQL error in response |
| RCE / Command Injection | CWE-78 | 9.8 | OS output in response |
| SSRF (confirmed) | CWE-918 | 7.5 | Cloud metadata returned |
| Path Traversal (confirmed) | CWE-22 | 7.5 | /etc/passwd content |
| Auth Bypass | CWE-287 | 7.5 | Protected endpoint without auth |
| XSS (confirmed) | CWE-79 | 6.1 | Unencoded script in response |
| IDOR | CWE-639 | 6.5 | Other user's data returned |
| Missing SRI | CWE-353 | 6.1 | External scripts without integrity hash |
| CSRF | CWE-352 | 4.3 | No CSRF token on state-changing form |
| Missing HSTS | CWE-319 | 4.3 | Header absent |
| Missing CSP | CWE-693 | 4.7 | Header absent |
| Outdated library | Dynamic | Dynamic | NVD/OSV lookup for actual CVEs |

For outdated libraries, CVE/CVSS data is fetched live from **NVD** (National Vulnerability Database) and **OSV.dev** — no hardcoded CVE lists.

---

## PDF Reports

Generated reports include a three-stage evidence pipeline for each finding:

**Stage 1: AI Agent Scan** — What the LLM found, the exact curl command it sent, and the application's response.

**Stage 2: Runtime Verification** — Whether the payload was replayed and what the live response was. Color-coded: green (CONFIRMED), red (DISPROVED), yellow (INCONCLUSIVE).

**Stage 3: Triage Engine Decision** — Final verdict, severity, CWE/CVSS, reasoning, steps to reproduce, and developer remediation action.

Additional report sections:
- Executive summary with severity breakdown pie chart and scan metadata (duration, cost, tokens)
- Clickable summary table linking to per-finding details
- Confirmed vulnerabilities vs. needs-verification separation
- Full test evidence: actual curl commands, response status codes and body snippets

## Troubleshooting: Scan Errors & Model Issues

When a scan fails, the UI shows a red **Scan Error** banner with the error details. Here's every known failure mode, what causes it, and how to fix it.

### Content Filtered (Guardrails)

```
ContentFiltered: Model bedrock/... refuses security-testing prompts (content guardrails)
```

**Cause**: The model's built-in safety guardrails block security-testing prompts (SQL injection payloads, XSS vectors, etc.). The model sees the scan instructions as harmful content and refuses to cooperate.

**Affected models**:
| Model | Status |
|-------|--------|
| Amazon Nova Micro/Lite/Pro | Always blocked — Nova considers pen-test prompts unsafe |
| Amazon Titan | Always blocked |
| Claude Haiku 4.5 | Works — no content filtering for security testing |
| Claude Sonnet 4.6 | Works |
| Ministral 8B / 14B | Works |
| Mistral Small | Works but poor quality (doesn't use tools) |

**Fix**: Switch to **Claude Haiku 4.5** or **Ministral 14B**. These models allow security-testing tool calls without triggering guardrails.

### Context Window Exceeded

```
ContextWindowExceeded: prompt is too long / input is too long
```

**Cause**: The conversation history (system prompt + all phase messages + tool call results) exceeded the model's maximum token limit. This happens on long scans with many API endpoints or when target responses are very large.

**Auto-recovery**: The scanner automatically trims old phase history and retries. If trimming isn't enough, it skips the current phase and moves to the next one. The scan continues — you don't lose previous findings.

**If it keeps happening**:
- Use a model with a larger context window (Claude models support 200K tokens)
- Reduce the number of API endpoints by providing a more targeted Postman collection
- For websites with huge pages, the scanner already truncates responses to fit

### Malformed Message Sequence (Tool Call Pairing)

```
BadRequestError: Expected toolResult blocks at messages.X.content for the following Ids: tooluse_...
```

**Cause**: Bedrock's Claude API requires strict pairing — every assistant message with `tool_calls` must be immediately followed by `tool` result messages with matching IDs. This can happen when context trimming splits a tool-call group, or in rare edge cases with very long multi-tool exchanges.

**Auto-recovery**: Three layers of defense handle this automatically:
1. **Prevention** — `_repair_tool_pairs()` validates message pairing before every LLM call
2. **Detection** — The error is caught as `MalformedMessages` (not a generic crash)
3. **Recovery** — Messages are stripped back to the last safe point and retried. If retry fails, the phase is skipped (not the entire scan)

**If you see this in logs**: It means recovery worked. The scan continued. No action needed.

### Rate Limit / Throttling

```
429 Too Many Requests / rate limit exceeded
```

**Cause**: Too many concurrent requests to Bedrock. Each scan makes many LLM calls (one per agent step), and Bedrock has per-model request-per-minute limits.

**Auto-recovery**: The scanner retries with exponential backoff (2s → 4s → 8s), up to 3 retries.

**If it keeps happening**:
- Run fewer concurrent scans
- Request a Bedrock quota increase via AWS Service Quotas console
- Switch to a less popular model (Ministral models typically have higher limits than Claude)

### AWS Credentials / Access Denied

```
AccessDeniedException / ExpiredTokenException / UnrecognizedClientException
```

**Cause**: The EC2 instance's IAM role doesn't have Bedrock permissions, or the AWS region is wrong.

**Fix**:
1. Verify IAM role is attached to the EC2 instance
2. Check permissions: `bedrock:InvokeModel` on `arn:aws:bedrock:*:*:inference-profile/*`
3. Ensure `AWS_DEFAULT_REGION` is set (e.g. `us-east-1`)
4. For cross-region models, enable cross-region inference profiles in Bedrock console

### Model Not Available / Not Subscribed

```
ResourceNotFoundException / ModelNotAvailableException
```

**Cause**: The selected Bedrock model isn't enabled in your AWS account or isn't available in your region.

**Fix**:
1. Go to AWS Bedrock console → **Model access** → Request access for the model
2. Some models (Claude, Mistral) require clicking "Request access" and waiting for approval
3. Check that the model is available in your configured region

### Empty Response

```
Empty response from model at phase X step Y
```

**Cause**: The model returned an empty response (no content, no tool calls). This can happen when the model is confused by the conversation state or when it "gives up" on a phase.

**Auto-recovery**: The scanner breaks out of the current step loop and moves to the next phase. No findings are lost.

### Authentication Failure (Target App)

```
Auth failed / login unsuccessful
```

**Cause**: The scanner couldn't authenticate to the target application with the provided credentials. This affects authenticated scan coverage but doesn't crash the scan.

**Fix**:
- Verify the username/password are correct for the target app
- Check if the target has CAPTCHA, MFA, or IP-based rate limiting that blocks automated login
- For API scans, provide auth tokens directly in the headers field

### Quick Reference: Error → Action

| Error Pattern | Auto-Recovers? | Action Needed |
|---------------|----------------|---------------|
| `content_filtered` / `content filtered` | No — fatal | Switch model (use Claude Haiku or Ministral) |
| `prompt is too long` / `context window` | Yes — trims & retries | None (may skip a phase) |
| `Expected toolResult` / `tool_use_id` | Yes — repairs & retries | None (may skip a phase) |
| `rate limit` / `429` / `too many requests` | Yes — backoff & retries | Reduce concurrency or increase quota |
| `AccessDeniedException` | No — fatal | Fix IAM permissions |
| `ResourceNotFoundException` | No — fatal | Enable model in Bedrock console |
| `Empty response` | Yes — skips step | None |
| `Auth failed` | Partial — scans unauthenticated | Fix target credentials |
