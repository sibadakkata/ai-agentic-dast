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
# Login: dast-admin / Dk9xMvP2wLz7nQr8
```

Or with Docker:

```bash
docker build -t ai-dast-scanner .
docker run -d --name dast --network host \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/imports:/app/imports \
  ai-dast-scanner uvicorn web.app:app --host 0.0.0.0 --port 8080
```

## Supported Models

### Model Compatibility for DAST Scanning

Not all models work well for agentic DAST. The scanner requires strong **tool/function calling** to navigate, inject payloads, and analyze responses. Models that lack this capability will generate text-only findings without actually testing the target.

| Model | ID | Cost (in/out per 1M) | Provider | Tool Calling | DAST Quality | Notes |
|-------|-----|---------------------|----------|-------------|-------------|-------|
| Gemini 2.5 Flash Lite | `gemini/gemini-2.5-flash-lite` | $0.075 / $0.30 | Google AI | Yes | Fair | Cheapest option, basic scanning |
| Gemini 2.5 Flash | `gemini/gemini-2.5-flash` | $0.15 / $0.60 | Google AI | Yes | Good | Good balance of cost and quality |
| Mistral Small | `bedrock/mistral.mistral-small-2402-v1:0` | $0.10 / $0.30 | Bedrock | Basic | Poor | Does not use tools properly — text-only findings |
| **Claude Haiku 4.5** | `bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0` | $0.80 / $4 | Bedrock | **Strong** | **Good** | **Recommended** — actually probes targets |
| **Claude Sonnet 4.6** | `bedrock/us.anthropic.claude-sonnet-4-6` | $3 / $15 | Bedrock | **Strong** | **Best** | Deepest analysis, most findings |

> **Amazon Nova models** (Micro, Lite, Pro) are **not supported** — their content guardrails block security-testing prompts.

### AWS Bedrock (Recommended for deployment)

No API keys needed — uses IAM role or AWS credentials.

**Setup:** Attach an IAM role to your EC2 instance with these permissions:
- `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream` on `arn:aws:bedrock:*:*:inference-profile/*`
- `aws-marketplace:ViewSubscriptions`, `aws-marketplace:Subscribe`

Then set:
```bash
export AWS_DEFAULT_REGION=us-east-1
```

### Google AI (Gemini)

For Gemini models, set the API key directly:

```bash
export GOOGLE_API_KEY=your-api-key
```

### LiteLLM Proxy

Routes requests through a central LiteLLM proxy. Best for teams with an existing proxy deployment.

```bash
export LITELLM_BASE_URL=https://litellm.your-company.com/
export LITELLM_API_KEY=sk-xxxx
```

Models use their standard names (no `bedrock/` prefix):

```bash
python scripts/run_scan.py --model "claude-haiku-4-5-20251001"
```

### Direct API Keys

Call LLM providers directly without any proxy. Set the provider's API key as an environment variable.

| Provider | Env Variable | Example Model |
|----------|-------------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| Google | `GOOGLE_API_KEY` | `gemini/gemini-2.5-flash` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o` |

### Hybrid Routing

You can configure both Bedrock and LiteLLM at the same time. The router picks the right path automatically:
- Models with `bedrock/`, `vertex_ai/`, `sagemaker/`, `ollama/` prefix → direct (via LiteLLM library)
- All other models → LiteLLM proxy (if configured) or direct API

## Web UI Features

- **New Scan** — enter target URL, credentials, pick model and scan mode
- **API Imports** — upload Postman Collection, Burp Export, or Swagger/OpenAPI spec
- **AI vs Triage** — side-by-side comparison of AI severity vs evidence-based triage verdict
- **Crawled Endpoints** — full list of discovered links and API endpoints
- **Payloads by Endpoint** — expandable view of every payload tested per endpoint
- **PDF Report** — generate with full evidence: curl commands, response data, CVE/CVSS scores
- **Raw JSON** — download full scan data for integration
- **Delete Scans** — delete individual scans or clear all history
- **Basic Auth** — password-protected (configurable via `DAST_AUTH_USER` / `DAST_AUTH_PASS` env vars)

## Docker Deployment (EC2)

### With AWS Bedrock (IAM Role)

Attach an IAM role with Bedrock permissions to the EC2 instance, then:

```bash
docker build -t ai-dast-scanner .
docker run -d --name dast --network host \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v /home/ubuntu/ai-dast-scanner/results:/app/results \
  -v /home/ubuntu/ai-dast-scanner/imports:/app/imports \
  ai-dast-scanner uvicorn web.app:app --host 0.0.0.0 --port 8080
```

### With LiteLLM Proxy

```bash
docker run -d --name dast --network host \
  -e LITELLM_BASE_URL=https://litellm.your-company.com/ \
  -e LITELLM_API_KEY=sk-xxxx \
  -v /home/ubuntu/ai-dast-scanner/results:/app/results \
  -v /home/ubuntu/ai-dast-scanner/imports:/app/imports \
  ai-dast-scanner uvicorn web.app:app --host 0.0.0.0 --port 8080
```

### Custom Auth Password

```bash
docker run -d --name dast --network host \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -e DAST_AUTH_USER=admin \
  -e DAST_AUTH_PASS=YourStrongPassword \
  ...
```

### EC2 Requirements

- **Instance:** t3.xlarge or larger (4 vCPU, 16 GB RAM)
- **OS:** Ubuntu 24.04 LTS (x86_64) — required for Playwright Chromium
- **Disk:** 100 GB
- **Security Group:** Allow inbound TCP on port 8080

## CLI Usage

```bash
# Default scan using config model (Haiku)
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

## Project Structure

```
config/
  scanner_config.yaml       # Default model + scan settings
  targets.env.example       # Template for CLI credentials
scanners/ai_agent/
  agent.py                  # Core agent loop + context management
  auth.py                   # Authentication (form/SSO/OAuth/MFA)
  llm_config.py             # LLM routing (Bedrock/LiteLLM/Direct) + cost tracking
  prompts.py                # System + phase prompts (15 website + 8 API phases)
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
results/
  raw/                      # Scan output JSON
  reports/                  # Generated PDF reports
  cache/                    # NVD/OSV API response cache
imports/                    # Uploaded API definitions (Postman/Burp/OpenAPI)
Dockerfile                  # Production container image
```

## Scan Capabilities

- **Websites**: Traditional multi-page sites, SPAs (React/Angular/Vue), authenticated flows
- **APIs**: REST, GraphQL, WebSocket — with Postman/OpenAPI/Burp import support
- **Authentication**: Form login, SSO (SAML), OAuth 2.0/OIDC, MFA (TOTP), session refresh
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
