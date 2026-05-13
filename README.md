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
│  │  detect +   │   │ (29 checks + │   │  + enriched retry prompts  │ │
│  │  multi-id)  │   │  secrets)    │   │                            │ │
│  └─────────────┘   └──────────────┘   └─────────────┬──────────────┘ │
│                                                      │                │
│                                        ┌─────────────▼──────────────┐ │
│                                        │  Attack Chain Analysis      │ │
│                                        │  (multi-step exploit chains)│ │
│                                        └─────────────┬──────────────┘ │
│                                                      │                │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐     ▼          │
│  │   Report    │◀──│   Triage     │◀──│  CVSS        │◀──┌────────┐  │
│  │  (PDF/Excel │   │   Engine     │   │  Severity    │   │Runtime │  │
│  │   /JSON)    │   │  ($0 cost)   │   │  (severity.  │   │Verify  │  │
│  └─────────────┘   └──────────────┘   │   py, $0)    │   └────────┘  │
│                                        └──────────────┘               │
│                                                                       │
│  Infrastructure: AWS Bedrock (Claude/Mistral) · Playwright · FastAPI  │
└───────────────────────────────────────────────────────────────────────┘
```

### How the LLM Agent Works

Each scan phase runs a continuous **Observe → Think → Act → Analyze → Plan** loop:

1. **Observe** — Agent reads current context: HTTP responses, page source, cookies, network logs, prior findings
2. **Think** — LLM reasons about attack surface, tech stack, and plausible vulnerabilities
3. **Act** — LLM calls tools (31 available: navigate, inject, fuzz, API request, token testing, exploit chaining, etc.)
4. **Analyze** — Tool results are interpreted: does the response indicate a vulnerability?
5. **Plan** — LLM decides next action: go deeper, try different parameter, or conclude phase

This loop runs up to 50 steps per phase (20–50 depending on phase complexity). Every finding is then **triaged offline** by a deterministic 3-layer engine ($0 LLM cost).

## Key Features

| Feature | Description | Details |
|---------|-------------|---------|
| **Passive Reconnaissance** | 29 deterministic checks: source maps, DOM sinks, **hardcoded secret scanner** (17 TruffleHog-style patterns: AWS keys, Stripe, GitHub PATs, Slack, SendGrid, Google, JWT, master/service tokens, JSON key sweep — with masked evidence), headers, CSP analysis, CORS, JWT, cookies, telemetry leakage, mixed content, clickjacking, **TLS protocol/cipher audit** (deprecated TLS 1.0/1.1, Sweet32/3DES, RC4, EXPORT, NULL, anonymous DH — via `sslyze` fallback), **hybrid vulnerable JS library detection** (49-library regex catalog + heuristic CDN-path / filename / banner / package-meta extractors + global JS URL registry that aggregates URLs across auth, SPA crawl, and network listeners + live NVD/OSV.dev CVE enrichment), **subdomain takeover detection** (46-provider fingerprint DB, DNS CNAME chain resolution, Certificate Transparency enumeration, HTTP response fingerprinting — covers AWS S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Shopify, Fastly, and 38 more), **email/DNS security** (SPF/DKIM/DMARC/MX validation — detects missing or misconfigured email authentication), and more. Post-auth passive pass also scans authenticated DOM HTML for secrets | Runs before LLM phases, $0 cost |
| **Active Scanning** | 25 web phases + 15 API phases: full OWASP Top 10 + context-aware checks (path traversal, XXE, race conditions, file upload, host header, session mgmt, HTTP smuggling) | [Web Scanning](docs/web-scanning.md) · [API Scanning](docs/api-scanning.md) |
| **Crawl-Only Profile** | Acunetix-style crawl-only scan mode: discovers URLs, SPA routes, forms, APIs, and in-scope sub-domains **without** sending attack payloads. Still runs passive recon (TLS, headers, JS CVEs) and API baseline; **body fuzzing is now correctly skipped** (was previously leaking through). Use to verify coverage before a full scan | Dashboard "Scan Profile" dropdown, `scan_profile: "crawl_only"` via API |
| **SPA Sibling-Host Coverage** | Passively harvests in-scope HTTPS sub-domains from browser XHR/fetch/navigation traffic and `robots.txt`/`sitemap.xml`. After every phase, newly discovered hosts get a **passive re-audit** (TLS + security headers — Stage A). At the start of each OWASP phase, new hosts are **surfaced to the LLM** with directives to apply that phase's methodology against them (Stage B) | Works for React/Angular/Vue SPAs where sibling hosts only appear post-auth via network traffic |
| **Triage Engine** | 3-layer evidence-based classification (TP/FP/Manual Review) with CWE/CVSS, exploitation tiers (validated/informational), entropy-based secret filtering, SPA catch-all detection, deduplication by (host + CWE + parameter), and step-by-step triage narrative separating AI actions from engine validation | [Triage Engine](docs/triage-engine.md) |
| **Authentication** | Auto-detect form, SSO/OIDC, OAuth, API key, bearer — with session refresh. Multi-identity: User B, Admin, Tenant B (password, bearer, or API key) authenticated at scan start | Multi-step OIDC, self-healing sessions, fast-path static-token auth |
| **Multi-Identity Testing** | Supply up to 3 extra identities (User B, Admin, Tenant B) via UI or API. All identities are authenticated at scan start; their credentials are injected into **all 8 authorization-class phases** (not just BOLA). Supports username/password, bearer tokens, and API keys — including fast-path static-token auth | Cross-user BOLA, cross-role BFLA, cross-tenant access, session/key revocation, license generation |
| **Deterministic CVSS Severity** | AI Raw findings get a deterministic CVSS v3.1 score and severity bucket (`severity.py`) based on CWE profile + evidence keywords — independent of LLM mood. LLM's original severity preserved as `llm_severity` for comparison | XBOW-style pre-triage classification, UI shows CVSS column + LLM-vs-deterministic tooltip |
| **Impact Statements** | LLM-generated business impact for every finding, with passive recon fallback | Contextual risk descriptions in reports |
| **Scan Targeting** | Exclude URLs, focus on specific pages/areas, control scan intensity (light/standard/deep) | Fine-grained scan scope control |
| **API Import** | Postman (v2.0/v2.1), OpenAPI/Swagger (2.0, 3.0, 3.1) | Baseline execution + hybrid fuzzing |
| **Logout Protection** | 6-layer protection: URL patterns, selector blocking, href inspection, post-click recovery, LLM prompt rules, link filtering | Never accidentally destroys the session |
| **Web UI** | Real-time scan progress, AI vs Triage comparison, PDF reports, scan management | [Web UI Guide](docs/web-ui.md) |
| **REST API** | Full API for CI/CD integration — start, stop, pause, resume, results, reports | [API Reference](docs/rest-api.md) |
| **MCP Server** | Model Context Protocol integration for Cursor, Claude Desktop | [MCP Guide](docs/mcp-server.md) |
| **Reports** | Four-stage evidence: AI Agent → Runtime Verification → CVSS Severity → Triage verdict | PDF, Excel, JSON export |
| **Cost Control** | Pause/resume scans, stop early, per-scan cost tracking | Real-time cost display in UI |
| **Multi-Step Exploit Chaining** | Combines individual findings into attack chains (e.g. XSS + cookie theft → session hijack, SSRF → internal API → data exfiltration) | Cross-phase context, `chain_exploit` tool |
| **Findings Grouping** | Group findings by Issue Category, OWASP Top 10 code, Severity, PCI DSS requirement, or SANS/CWE Top 25 — with a "Group by" selector, collapsible sections, and per-group severity breakdown | All tabs: Live, Comparison, AI Raw Findings |
| **Hybrid Smart Retry** | For 20 high-impact phases the agent runs a second, tool-enabled pass with a phase-tailored retry prompt whenever the phase either finds 0 vulnerabilities **or** misses its core vulnerability class. Retry prompts include: **SQLi** (ORDER BY/GROUP BY column-injection, date_trunc/period parameter injection, export/report endpoint injection), **Injection** (14-engine SSTI payload sweep, YAML/Pickle/Java/PHP/.NET deserialization content-type sweep, verbose-error/stack-trace harness), **Access Control** (SaaS business-logic surface probing — /api/licenses, /api/sessions, /api/invoices, etc.; state-mutation invariants — cross-user session/key revocation, cross-tenant license generation, role-validation absence, org-switch impersonation), **Auth** (multi-role credential discovery, parameter-name permutation), **XSS/SSRF/File Upload** (existing) | `_ACTIVE_RETRY_PHASES`, `_PHASE_CORE_KEYWORDS`, `_RETRY_PROMPTS` in `agent.py` |
| **Finding Deduplication** | Two-tier dedup: (1) runtime dedup by `(title, url, parameter)` prevents double-counting across passes; (2) triage-level dedup by `(host, CWE, parameter)` merges equivalent findings keeping highest severity — reduces noise by ~40% on typical scans | `_finding_key`, `_dedupe_findings` in `web/app.py`; `deduplicate()` in `scripts/triage_engine.py` |
| **Model ID Resolution** | UI/API callers can pass a display name ("Claude Haiku 4.5 (recommended)"), a short alias ("haiku", "sonnet"), or the full litellm id — the backend normalises all three to a valid litellm model id, preventing "LLM Provider NOT provided" errors | `_resolve_model_id` in `web/app.py`, applied at `/api/scan`, `/api/scan/{id}/retry`, `/api/scan/{id}/rescan` |
| **Deploy Safety** | Pre-deployment check detects active/paused scans and aborts `deploy.sh` before overwriting a running scanner | `scripts/check_scan_active.py`, integrated in `deploy.sh` |
| **Parallel-Phase Failure Surfacing** | When phases run concurrently via `asyncio.gather`, worker exceptions used to be silently swallowed by `return_exceptions=True`, leaving missing phases with no trace. Now every worker is wrapped in a guard that logs the failure to `phase_log` with an `error` field and a `(FAILED)` suffix in the live UI, so a transient Bedrock 5xx, Playwright timeout, or LLM-context overflow no longer disappears a phase silently | `run_phases_parallel._guarded` in `agent.py`; UI shows `(FAILED)` + tooltip with error |
| **LLM Transient-Error Retry** | `LLMRouter.complete` retries up to 5× with 2 / 4 / 8 / 16 / 32 s exponential back-off (~62 s total) on transient signatures: connection failures (`All connection attempts failed`), 502 / 503 / 504, read timeouts, throttling. Tunable at runtime via `LLM_RETRY_DELAYS` env var. Terminal errors (`ContextWindowExceeded`, `ContentFiltered`, `MalformedMessages`) bubble immediately so a single bad message doesn't burn 6× cost | `LLMRouter.complete` in `llm_config.py` |
| **Partial-DB Cache Fallback** | The DB sometimes wrote a partial-checkpoint payload (`metadata.partial=True`) for a scan that later finished cleanly to disk, then served the stale partial blob to the API. The reader now prefers a complete on-disk result over a partial DB record and back-fills the DB on read so subsequent loads serve the full payload | `_load_raw_result_dict` in `web/app.py` |
| **Body-Fuzz Return-Shape Hardening** | `fuzz_body` early-exit paths (unparseable body, baseline failure) used to return a bare `[]` while the caller did `a, b = await fuzz_body(...)`, crashing phase 4 with `not enough values to unpack (expected 2, got 0)`. Now both early exits return `([], [])`; return type annotation corrected; 23-test scenario suite (`tests/test_scan_error_resilience.py`) audits every tuple-unpack contract in the scanner | `body_fuzzer.py`, `tests/test_body_fuzzer_return_shape.py`, `tests/test_scan_error_resilience.py` |
| **Subdomain Takeover Detection** | Detects dangling DNS records pointing to unclaimed third-party services. 46-provider fingerprint database covering AWS S3, CloudFront, Elastic Beanstalk, GitHub Pages, Heroku, Azure (Web Apps, Blob, Traffic Manager), Netlify, Shopify, Fastly, Vercel, Google Cloud Storage, Wix, Webflow, Render, Fly.io, and 30 more. Detection via: (1) DNS CNAME chain resolution with `dnspython`, (2) NXDOMAIN detection for abandoned service instances, (3) HTTP response fingerprint matching against known takeover strings, (4) Subdomain enumeration via Certificate Transparency (crt.sh) + 75-prefix DNS wordlist. Concurrent checking with configurable semaphore | `subdomain_takeover.py`, `subdomain_enum.py`, integrated in passive recon step 26 |
| **Email/DNS Security** | Validates email authentication configuration for the target domain: SPF record presence and enforcement level (+all/~all/-all, lookup count, multiple records), DMARC policy analysis (none/quarantine/reject, subdomain policy, pct, reporting URIs), DKIM selector probing (22 common selectors including google, selector1/2, mandrill, amazonses, sendgrid), MX record security (null MX, IP-based MX). Only flags findings when the domain actually handles email (MX-aware). Generates actionable remediation guidance per finding | `dns_security.py`, integrated in passive recon step 27 |
| **Active Baseline (Bug Bounty PoC Shape)** | Time-based blind SQLi probes use bug-bounty-researcher request patterns (`?payload?ninjeee=sectest` double-? shape) with realistic browser User-Agent headers to bypass WAF/bot-detection layers that block scanner-like traffic. Does NOT follow redirects so delay signals are measured at the vulnerable origin | `active_baseline.py`, `_PROBE_HEADERS` |
| **Exploitation Tiers** | Every finding is assigned `validated` (exploitation proven: runtime confirmed, payload reflected, SQL error returned) or `informational` (detected but not proven: pattern match, missing header, config check). Inspired by XBOW's "proof over probability" methodology | `_assign_exploitation_tier()` in `triage_engine.py` |
| **Entropy-Based Secret Filtering** | Hardcoded "secrets" detected in JS are validated via Shannon entropy calculation + framework constant detection (38 known patterns: `$$ROW_INTERNAL`, `__react_devtools`, `ng-version`, etc.). Low-entropy or known-constant values are auto-classified as FALSE_POSITIVE | `_shannon_entropy()`, `_is_fake_secret()` in `triage_engine.py` |
| **SPA Catch-All Detection** | Detects when SPAs (React/Angular/Vue) return the app shell for sensitive file paths (e.g., `/.git/HEAD` returns `index.html` with 200). Marks these as FALSE_POSITIVE instead of real file disclosure findings | Layer 0B in `triage_engine.py` |
| **Triage Narrative** | Every triaged finding includes a structured step-by-step breakdown: "What the AI Scanner Tested" (payloads, requests, observations) vs "How Triage Engine Validated" (HTTP codes checked, body analysis, pattern matching, severity adjustment, final verdict) | `_build_triage_narrative()` in `triage_engine.py`, rendered in UI finding detail modal |
| **Brute Force Validation (50-request threshold)** | Rate limiting findings require 50 consecutive unblocked requests (up from 5) to be reported. Prevents false positives from CDN/WAF soft limits that only trigger after higher volumes | Configured in `prompts.py` BRUTE FORCE + RATE LIMITING phases |
| **Secret Usage Validation** | When the AI discovers a potential API key/token, it must: (1) calculate entropy, (2) attempt to use the key for authentication, (3) only report if entropy is high AND key works or matches a known service pattern. Framework constants are explicitly excluded | `STEP 2B` in `prompts.py` |

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
│     Multi-identity: also authenticate User B, Admin, Tenant B       │
├─────────────────────────────────────────────────────────────────────┤
│  2. PASSIVE RECONNAISSANCE ($0) — 29 checks + hardcoded secrets     │
│     Source maps, sinks, headers, CSP, CORS, JWT, cookies,           │
│     TLS audit (sslyze), HYBRID vulnerable JS libraries (49-lib      │
│     catalog + heuristic CDN/filename/banner extractors + global     │
│     JS URL registry across auth/SPA/network — NVD/OSV.dev CVE),     │
│     hardcoded secret scanner (17 TruffleHog-style regex patterns    │
│     in JS bundles + authenticated HTML — AWS, Stripe, GitHub PATs,  │
│     Slack, Google, SendGrid, JWT, master/service tokens),           │
│     SUBDOMAIN TAKEOVER (46-provider CNAME fingerprints + CT enum    │
│     + DNS wordlist + HTTP response matching),                        │
│     EMAIL/DNS SECURITY (SPF/DKIM/DMARC/MX validation)               │
│     Runs on seed host AND passively-discovered in-scope sub-domains │
├─────────────────────────────────────────────────────────────────────┤
│  3. API BASELINE (if Postman/OpenAPI imported)                      │
│     Execute every endpoint → capture "known good" responses         │
├─────────────────────────────────────────────────────────────────────┤
│  4. HYBRID BODY FUZZING (POST/PUT/PATCH endpoints)                  │
│     LLM plans payloads ($0.001) → engine executes → LLM analyzes   │
├─────────────────────────────────────────────────────────────────────┤
│  5. LLM DEEP SCAN (25 web + 15 API phases)                         │
│     OWASP Top 10 + context-aware: race, upload, host header, etc.  │
│     After each phase: host-delta passive audit on new sub-domains   │
│     Before each phase: new in-scope sub-domains injected into prompt│
├─────────────────────────────────────────────────────────────────────┤
│  5b. ATTACK CHAIN ANALYSIS                                          │
│     Combine findings into multi-step exploit chains                 │
├─────────────────────────────────────────────────────────────────────┤
│  6. RUNTIME VERIFICATION                                            │
│     Replay payloads against live target → CONFIRMED / DISPROVED     │
├─────────────────────────────────────────────────────────────────────┤
│  6b. DETERMINISTIC CVSS SEVERITY ($0)                               │
│     severity.py: CWE profile matching → CVSS v3.1 score →          │
│     severity bucket. Evidence-adjusted (±0.5 for confirmed/weak).   │
│     LLM severity preserved as llm_severity for comparison           │
├─────────────────────────────────────────────────────────────────────┤
│  7. TRIAGE ENGINE ($0)                                              │
│     3-layer classification → CWE/CVSS enrichment → verdicts         │
│     + SPA catch-all detector + entropy/secret filter + dedup        │
│     + exploitation tier (validated/informational) + narrative        │
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
| **Claude Sonnet 4.5** | $3 / $15 | **Excellent** | Deep analysis — strong reasoning at Sonnet-tier cost |
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
│   ├── security-checks.md       #   Complete reference: all 69 check categories
│   ├── triage-engine.md         #   Triage engine deep dive
│   ├── api-scanning.md          #   How API scanning works (walkthrough)
│   ├── web-scanning.md          #   How website scanning works
│   ├── rest-api.md              #   REST API reference
│   ├── deployment.md            #   Docker, EC2, models, Bedrock setup
│   ├── web-ui.md                #   Web UI features & configuration
│   ├── mcp-server.md            #   MCP integration guide
│   └── troubleshooting.md       #   Error handling & debugging
├── scanners/ai_agent/           # Core scanner engine (21 modules)
│   ├── agent.py                 #   Agent loop, context mgmt, multi-identity, parallel phases
│   ├── auth.py                  #   Authentication (form/SSO/OAuth) + multi-identity (User B/Admin/Tenant B)
│   ├── severity.py              #   Deterministic CVSS v3.1 severity classifier (XBOW-style)
│   ├── passive_recon.py         #   Deterministic passive checks + hardcoded secret scanner + hybrid JS lib detection
│   ├── retry_prompts.py         #   Hybrid Smart Retry — phase-tailored re-prompt constants for 20 phases
│   ├── subdomain_takeover.py    #   Subdomain takeover detection (46-provider fingerprint DB + CNAME + HTTP matching)
│   ├── subdomain_enum.py        #   Subdomain enumeration (Certificate Transparency + DNS wordlist)
│   ├── dns_security.py          #   Email/DNS security checks (SPF/DKIM/DMARC/MX validation)
│   ├── js_registry.py           #   Global JS URL registry (auth + SPA + network listeners → unified set for CVE audit)
│   ├── spa_crawler.py           #   SPA-aware crawling (route extraction, XHR capture, sibling host discovery)
│   ├── llm_config.py            #   LLM routing, prompt caching, cost tracking, transient retry (5× backoff)
│   ├── prompts.py               #   System + phase prompts (multi-identity placeholders)
│   ├── tools.py                 #   31 tools (browser, API, WebSocket, chaining)
│   ├── active_baseline.py       #   Deterministic probes: SQLi, XSS, SSRF, cache poisoning, open redirect, sensitive paths
│   ├── api_import.py            #   Postman/OpenAPI/Burp XML parsers
│   ├── baseline_executor.py     #   API baseline & variable chaining
│   ├── body_fuzzer.py           #   Hybrid body fuzzer
│   ├── model_discovery.py       #   Bedrock model listing & alias resolution
│   ├── oob.py                   #   Out-of-band interaction helpers (SSRF/XXE callbacks)
│   ├── scan_state.py            #   Scan state persistence & crash recovery
│   └── workflow.py              #   Multi-step workflow / business-flow scanning
├── scripts/
│   ├── triage_engine.py         #   3-layer triage engine + exploitation tiers + entropy filter + dedup + narrative
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
- **Crash / error / pause resilience** — on every save, the transient `live_*` counters (cost, tokens, LLM calls, tool calls, findings_count, phases_completed) and structured summaries (per-phase breakdown, per-phase tool usage, last-500 crawled URLs, out-of-scope URLs) are promoted into the persisted `scans` row. Errored, stopped, paused, or container-killed scans therefore keep their last-known-good metrics and breakdowns in the DB — the UI's Phases / Crawled Pages / Out of Scope tabs stay populated. The only field not persisted is the detailed per-tool-call request/response log (`live_tests`), which can reach ~20 MB per scan and is still kept in-memory only; on graceful error it's written into `scan_results.payload.summary.test_log`.
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
| [Security Checks](docs/security-checks.md) | Complete reference of all 69 check categories — passive recon (inc. subdomain takeover, DNS security), web phases, API phases, CWE/OWASP coverage |
| [Triage Engine](docs/triage-engine.md) | How TP/FP classification works, confidence scoring, CVSS adjustment |
| [API Scanning](docs/api-scanning.md) | Step-by-step walkthrough with banking API example |
| [Web Scanning](docs/web-scanning.md) | Browser-based scanning, SPA handling, 25 OWASP + context-aware phases |
| [REST API](docs/rest-api.md) | Full API reference with curl examples and Python SDK |
| [Deployment](docs/deployment.md) | EC2 setup, Docker, Bedrock config, models, data persistence |
| [Web UI](docs/web-ui.md) | UI features, scan configuration, AI planner |
| [MCP Server](docs/mcp-server.md) | Cursor/Claude Desktop integration, available tools |
| [Troubleshooting](docs/troubleshooting.md) | Every error type, auto-recovery, and fixes |
