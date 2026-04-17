# AI Agentic Web Scanner

LLM-powered Dynamic Application Security Testing (DAST) scanner that works against **any website, API, or SPA**.

A single LLM agent drives a real Chromium browser and HTTP client through the OWASP Top 10, crafting context-aware payloads, interpreting responses, and reporting findings — all autonomously. The agent can chain multiple individual vulnerabilities into multi-step exploit sequences, similar to how a manual pentester escalates access.

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                          SCAN PIPELINE                                │
│                                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────────────────┐ │
│  │    Auth      │──▶│   Passive    │──▶│     LLM Deep Scan          │ │
│  │  (auto-     │   │   Recon      │   │  (25 web + 15 API phases)  │ │
│  │  detect)    │   │ (24 checks)  │   │                            │ │
│  └─────────────┘   └──────────────┘   └─────────────┬──────────────┘ │
│                                                      │                │
│                                        ┌─────────────▼──────────────┐ │
│                                        │  Attack Chain Analysis      │ │
│                                        │  (multi-step exploit chains)│ │
│                                        └─────────────┬──────────────┘ │
│                                                      │                │
│  ┌─────────────┐   ┌──────────────┐                  ▼                │
│  │   Report    │◀──│   Triage     │◀──┌──────────────────────────┐   │
│  │  (PDF/Excel │   │   Engine     │   │  Runtime Verification    │   │
│  │   /JSON)    │   │  ($0 cost)   │   │  (replay live payloads)  │   │
│  └─────────────┘   └──────────────┘   └──────────────────────────┘   │
│                                                                       │
│  Infrastructure: AWS Bedrock (Claude/Mistral) · Playwright · FastAPI  │
└───────────────────────────────────────────────────────────────────────┘
```

### How the LLM Agent Works

Each scan phase runs a continuous **Observe → Think → Act → Analyze → Plan** loop:

1. **Observe** — Agent reads current context: HTTP responses, page source, cookies, network logs, prior findings
2. **Think** — LLM reasons about attack surface, tech stack, and plausible vulnerabilities
3. **Act** — LLM calls tools (30 available: navigate, inject, fuzz, API request, token testing, exploit chaining, etc.)
4. **Analyze** — Tool results are interpreted: does the response indicate a vulnerability?
5. **Plan** — LLM decides next action: go deeper, try different parameter, or conclude phase

This loop runs up to 25 steps per phase. Every finding is then **triaged offline** by a deterministic 3-layer engine ($0 LLM cost).

## Key Features

| Feature | Description | Details |
|---------|-------------|---------|
| **Passive Reconnaissance** | 24 deterministic checks: source maps, DOM sinks, secrets, headers, CSP analysis, CORS, JWT, cookies, telemetry leakage, mixed content, clickjacking, and more | Runs before LLM phases, $0 cost |
| **Active Scanning** | 25 web phases + 15 API phases: full OWASP Top 10 + context-aware checks (path traversal, XXE, race conditions, file upload, host header, session mgmt, HTTP smuggling) | [Web Scanning](docs/web-scanning.md) · [API Scanning](docs/api-scanning.md) |
| **Triage Engine** | 3-layer evidence-based classification (TP/FP/Manual Review) with CWE/CVSS | [Triage Engine](docs/triage-engine.md) |
| **Authentication** | Auto-detect form, SSO/OIDC, OAuth, API key, bearer — with session refresh | Multi-step OIDC, self-healing sessions |
| **Two-User BOLA/BFLA** | Supply a second user (User B) to test horizontal privilege escalation and broken function-level auth | Automated IDOR testing across user contexts |
| **Impact Statements** | LLM-generated business impact for every finding, with passive recon fallback | Contextual risk descriptions in reports |
| **Scan Targeting** | Exclude URLs, focus on specific pages/areas, control scan intensity (light/standard/deep) | Fine-grained scan scope control |
| **API Import** | Postman (v2.0/v2.1), OpenAPI/Swagger (2.0, 3.0, 3.1) | Baseline execution + hybrid fuzzing |
| **Logout Protection** | 6-layer protection: URL patterns, selector blocking, href inspection, post-click recovery, LLM prompt rules, link filtering | Never accidentally destroys the session |
| **Web UI** | Real-time scan progress, AI vs Triage comparison, PDF reports, scan management | [Web UI Guide](docs/web-ui.md) |
| **REST API** | Full API for CI/CD integration — start, stop, pause, resume, results, reports | [API Reference](docs/rest-api.md) |
| **MCP Server** | Model Context Protocol integration for Cursor, Claude Desktop | [MCP Guide](docs/mcp-server.md) |
| **Reports** | Three-stage evidence: AI Agent → Runtime Verification → Triage verdict | PDF, Excel, JSON export |
| **Cost Control** | Pause/resume scans, stop early, per-scan cost tracking | Real-time cost display in UI |
| **Multi-Step Exploit Chaining** | Combines individual findings into attack chains (e.g. XSS + cookie theft → session hijack, SSRF → internal API → data exfiltration) | Cross-phase context, `chain_exploit` tool |
| **Findings Grouping** | Group findings by Issue Category, OWASP Top 10 code, Severity, PCI DSS requirement, or SANS/CWE Top 25 — with a "Group by" selector, collapsible sections, and per-group severity breakdown | All tabs: Live, Comparison, AI Raw Findings |
| **Evidence Summary** | When an LLM phase reports 0 findings but collected evidence, a single follow-up LLM call reviews the evidence to recover any missed vulnerabilities — lightweight replacement for the old retry loop | Reduces cost, removes duplicate payloads |
| **Deploy Safety** | Pre-deployment check detects active/paused scans and aborts `deploy.sh` before overwriting a running scanner | `scripts/check_scan_active.py`, integrated in `deploy.sh` |

## Quick Start

### EC2 Deployment (Recommended)

```bash
# 1. Upload to EC2
scp -i key.pem -r ./POC ubuntu@<EC2-IP>:~/ai-dast-scanner

# 2. Configure
ssh -i key.pem ubuntu@<EC2-IP>
cd ~/ai-dast-scanner
cp .env.example .env
nano .env   # Add AWS Bedrock creds, auth password

# 3. Deploy
bash deploy.sh
# Web UI at http://<EC2-IP>:8080
```

### Local Development

```bash
pip install -r requirements.txt
playwright install chromium
cp .env.example .env && nano .env
uvicorn web.app:app --host 0.0.0.0 --port 8080
```

> Full deployment guide: [docs/deployment.md](docs/deployment.md)

## Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. AUTHENTICATION                                                  │
│     Auto-detect auth type → login → capture session → auto-refresh  │
├─────────────────────────────────────────────────────────────────────┤
│  2. PASSIVE RECONNAISSANCE ($0) — 24 checks                         │
│     Source maps, sinks, secrets, headers, CSP, CORS, JWT, cookies  │
├─────────────────────────────────────────────────────────────────────┤
│  3. API BASELINE (if Postman/OpenAPI imported)                      │
│     Execute every endpoint → capture "known good" responses         │
├─────────────────────────────────────────────────────────────────────┤
│  4. HYBRID BODY FUZZING (POST/PUT/PATCH endpoints)                  │
│     LLM plans payloads ($0.001) → engine executes → LLM analyzes   │
├─────────────────────────────────────────────────────────────────────┤
│  5. LLM DEEP SCAN (25 web + 15 API phases)                         │
│     OWASP Top 10 + context-aware: race, upload, host header, etc.  │
├─────────────────────────────────────────────────────────────────────┤
│  5b. ATTACK CHAIN ANALYSIS                                          │
│     Combine findings into multi-step exploit chains                 │
├─────────────────────────────────────────────────────────────────────┤
│  6. RUNTIME VERIFICATION                                            │
│     Replay payloads against live target → CONFIRMED / DISPROVED     │
├─────────────────────────────────────────────────────────────────────┤
│  7. TRIAGE ENGINE ($0)                                              │
│     3-layer classification → CWE/CVSS enrichment → verdicts         │
├─────────────────────────────────────────────────────────────────────┤
│  8. REPORT                                                          │
│     PDF with three-stage evidence, curl commands, remediation steps │
└─────────────────────────────────────────────────────────────────────┘
```

## Supported Models (AWS Bedrock)

| Model | Cost (in/out per 1M) | Tool Calling | Recommendation |
|-------|---------------------|-------------|----------------|
| **Ministral 8B** | $0.15 / $0.15 | Good | Cheapest — good for dev/testing |
| **Ministral 14B** | $0.20 / $0.20 | **Strong** | **Best value** — designed for agentic use |
| **Claude Haiku 4.5** | $0.80 / $4 | **Excellent** | **Production scans** — reliable, best cost/quality |
| **Claude Sonnet 4.6** | $3 / $15 | **Excellent** | Deep analysis — most findings, highest quality |

> Ministral 14B or Claude Haiku 4.5 is the minimum for meaningful results. See [Deployment Guide](docs/deployment.md) for Bedrock setup and model details.

## Project Structure

```
├── README.md                    # This file
├── docs/                        # Detailed documentation
│   ├── architecture.md          #   AI agent architecture & design
│   ├── system-prompt-guide.md   #   ★ How the LLM system prompt & phases work
│   ├── scanner-internals.md     #   ★ E2E scan flow, evidence, retries, context mgmt
│   ├── contributing.md          #   ★ How to add phases, tools, optimize detection
│   ├── security-checks.md       #   Complete reference: all 65 check categories
│   ├── triage-engine.md         #   Triage engine deep dive
│   ├── api-scanning.md          #   How API scanning works (walkthrough)
│   ├── web-scanning.md          #   How website scanning works
│   ├── rest-api.md              #   REST API reference
│   ├── deployment.md            #   Docker, EC2, models, Bedrock setup
│   ├── web-ui.md                #   Web UI features & configuration
│   ├── mcp-server.md            #   MCP integration guide
│   └── troubleshooting.md       #   Error handling & debugging
├── scanners/ai_agent/           # Core scanner engine
│   ├── agent.py                 #   Agent loop & context management
│   ├── auth.py                  #   Authentication (form/SSO/OAuth)
│   ├── passive_recon.py         #   Deterministic passive checks
│   ├── llm_config.py            #   LLM routing & cost tracking
│   ├── prompts.py               #   System + phase prompts
│   ├── tools.py                 #   30 tools (browser, API, WebSocket, chaining)
│   ├── api_import.py            #   Postman/OpenAPI parsers
│   ├── baseline_executor.py     #   API baseline & variable chaining
│   └── body_fuzzer.py           #   Hybrid body fuzzer
├── scripts/
│   ├── triage_engine.py         #   3-layer triage engine
│   ├── cve_lookup.py            #   NVD + OSV.dev CVE lookup
│   ├── report_generator.py      #   PDF report generator
│   ├── excel_exporter.py        #   Excel report exporter
│   └── check_scan_active.py     #   Pre-deploy scan-active safety check
├── web/
│   ├── app.py                   #   FastAPI backend
│   ├── db.py                    #   SQLite persistence
│   └── static/index.html        #   Single-page web UI
├── mcp_server.py                # MCP server for Cursor/Claude Desktop
├── deploy.sh                    # One-command EC2 deployment
├── docker-compose.yml           # Docker Compose config
├── Dockerfile                   # Production container
└── requirements.txt             # Python dependencies
```

### Data storage (SQLite, not browser disk)

- **`results/scanner.db`** — source of truth: `scans` (metadata), `scan_results` (full findings + summary JSON), `app_kv` (UI prefs), `cost_ledger`. On startup, any scan with `result_file` on disk but no `scan_results` row is **back-filled** and `findings_count` is reconciled.
- **`results/raw/*.json`** — written when a scan finishes as **backup/export** only; API reads **DB first**, then legacy file once to populate DB.
- **Scan list** (`GET /api/scans`) — DB-backed only (no file-only orphan rows).
- **Payloads export** (`GET /api/results/{id}/payloads`) — generated in memory (no `payloads_*.json` cache file).
- **Other files (not scan DB):** `imports/*` (uploaded Postman/Burp/OpenAPI), `results/reports/*` (PDF/XLSX exports), `data/models_cache.json` (Bedrock model list cache), `results/cache/*` (CVE lookup caches). These do not drive scan history or findings in the UI.

**Regression (local code + UI strings):** `python _regression_local.py` (use a venv with `pip install -r requirements.txt` so agent/auth imports pass).

**After deploy (e.g. EC2) — hit the live API from your machine:**

```bash
export DAST_BASE_URL=https://your-dast-host
export DAST_AUTH_USER=dast-admin    # optional, if /api/ui-settings needs Basic auth
export DAST_AUTH_PASS=your-secret
python scripts/run_regression_ec2.py          # runs local regression + e2e smoke + API-only persistence checks
python scripts/run_regression_ec2.py --pytest # same, plus pytest tests/
```

**Piecemeal:** `python scripts/e2e_ec2_smoke.py` (read-only HTTP smoke). `python scripts/regression_persistence.py --api-only` skips local `results/scanner.db` and only checks the remote URL (set `DAST_BASE_URL`). Without `DAST_AUTH_PASS`, a **401** on `/api/ui-settings` is reported as **SKIP**, not failure.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | AI agent design, LLM loop, tool system, phase orchestration |
| [System Prompt Guide](docs/system-prompt-guide.md) | **How the LLM is instructed** — system prompt structure, phase prompts, payload methodology, finding format |
| [Scanner Internals](docs/scanner-internals.md) | **E2E scan flow** — tool execution, evidence buffer, evidence summary, context trimming, finding extraction |
| [Contributing & Extending](docs/contributing.md) | **How to add new phases, tools, and optimize detection** — step-by-step guide for team members |
| [Security Checks](docs/security-checks.md) | Complete reference of all 65 check categories — passive recon, web phases, API phases, CWE/OWASP coverage |
| [Triage Engine](docs/triage-engine.md) | How TP/FP classification works, confidence scoring, CVSS adjustment |
| [API Scanning](docs/api-scanning.md) | Step-by-step walkthrough with banking API example |
| [Web Scanning](docs/web-scanning.md) | Browser-based scanning, SPA handling, 25 OWASP + context-aware phases |
| [REST API](docs/rest-api.md) | Full API reference with curl examples and Python SDK |
| [Deployment](docs/deployment.md) | EC2 setup, Docker, Bedrock config, models, data persistence |
| [Web UI](docs/web-ui.md) | UI features, scan configuration, AI planner |
| [MCP Server](docs/mcp-server.md) | Cursor/Claude Desktop integration, available tools |
| [Troubleshooting](docs/troubleshooting.md) | Every error type, auto-recovery, and fixes |
