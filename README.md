# AI Agentic Web Scanner

LLM-powered Dynamic Application Security Testing (DAST) scanner that works against **any website, API, SPA, or LLM-powered application**.

A **multi-agent architecture** deploys 13 specialist agents in parallel — each an expert in its vulnerability class — coordinated by an orchestrator with shared context, inter-agent messaging, and an independent verifier that confirms findings and builds exploit chains. Covers the full **OWASP Web Top 10 (2021)**, **OWASP API Top 10 (2023)**, and **OWASP LLM Top 10 (2025)** — 32 OWASP categories total. Each agent drives a real Chromium browser and HTTP client, crafting context-aware payloads, interpreting responses, and reporting findings autonomously.

**Production architecture:** [Red Team AI Web Scanner (Confluence)](https://confluence.corp.nortonlifelock.com/spaces/CIP/pages/954017481/Red+Team+AI+Web+Scanner) · [Terraform / AWS](infra/terraform/README.md) · [Scalable platform design](docs/architecture/scalable-scanner-platform-proposal.md)

> ## Access model
>
> | Who | How |
> |-----|-----|
> | **End users (Red Team operators)** | **SSO** — Microsoft Entra ID, SAML 2.0 ([setup guide](docs/SSO_RBAC.md)) |
> | **API / CI / automation scripts** | HTTP Basic Auth (`DAST_AUTH_USER` / `DAST_AUTH_PASS`) |
>
> SSO is the canonical platform access path. Basic Auth exists for scripting and as an interim during the SSO/HTTPS rollout. **Do not share Basic Auth credentials with end users.**

## Production platform

Production runs a **control plane** (FastAPI UI on EC2) and **scan workers** (Fargate tasks), with durable state migrating to PostgreSQL while SQLite remains the default read path during rollout.

```text
Human operators ──► SSO (Entra SAML 2.0) ──┐
Automation / CI  ──► HTTP Basic Auth     ──┼──► rt.ai.webscanner.gendigital.com (CNAME)
                                             └── ALB + WAFv2 (us-east-2)
                                                     └── EC2 3.20.180.251 : Docker dast-scanner :80
                                                             ├── SCAN_LAUNCHER=fargate → ECS Fargate (1 task / scan)
                                                             ├── RDS PostgreSQL 16 Multi-AZ (dual-write)
                                                             └── ElastiCache Redis (live events → SSE)
```

| Layer | Details |
|-------|---------|
| **Public URL** | `https://rt.ai.webscanner.gendigital.com` — TLS on ALB; WAFv2 regional Web ACL (see [infra/terraform/README.md](infra/terraform/README.md)) |
| **UI host** | EC2 `3.20.180.251`, container `dast-scanner`, app port **80**, health check `GET /healthz` |
| **Database** | **RDS** PostgreSQL 16, `db.t4g.small`, Multi-AZ, encrypted, deletion protection. **SQLite** (`results/scanner.db`) is still the default **read** source; set `DUAL_WRITE_PG=1` + `DATABASE_URL` to mirror writes to Postgres (`web/db_pg.py`). Set `READ_FROM_PG=1` to serve reads from Postgres via `web/db_router.py` (falls back to SQLite on error). |
| **Scan workers** | Standalone image under `scanners/runner/`, pushed to **ECR** `dast-scanner-runner`. Production: `SCAN_LAUNCHER=fargate` (one Fargate task per scan). Dev: `docker compose` or `SCAN_LAUNCHER=local-docker`. |
| **Live progress** | **SSE** in the UI; with `LIVE_EVENTS_REDIS=1` and `REDIS_URL`, Fargate workers publish via Redis pub/sub (`web/live_events.py`). Polling fallback when Redis is off. |
| **Secrets** | RDS credentials in Secrets Manager **`dast/rds/master`**; EC2 and Fargate tasks read via IAM role. |
| **Backups** | Weekly Lambda (`infra/terraform/lambda/db_backup.py`) dumps RDS tables to S3 bucket `dast-scanner-db-backups-<account_id>`; lifecycle: Glacier at 90 days, delete at 180 days. |
| **Network** | VPC interface endpoints (Secrets Manager, ECR API/DKR, CloudWatch Logs) plus S3 gateway endpoint so Lambda/Fargate in private subnets avoid public egress for AWS APIs. |
| **IaC** | `infra/terraform/` — profile **`dast-poc`**, region **`us-east-2`**. Plan/apply only with explicit approval (see [Deployment protocol](.cursor/rules/deployment-protocol.mdc)). |

**Deploying application code** — new operators: [Install from scratch](#install-from-scratch); day-to-day: [Day-to-day code deploys](#day-to-day-code-deploys). Run `scripts/check_scan_active.py` before any container restart (**mandatory** — in-process scan state is lost on restart). Human operators must get explicit approval before touching EC2; see [.cursor/rules/deployment-protocol.mdc](.cursor/rules/deployment-protocol.mdc).

## Architecture (scanner engine)

### Multi-Agent Mode — `scan_profile: "multi_agent"`

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     MULTI-AGENT SCAN PIPELINE                            │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐ │
│  │  Auth    │─▶│ Passive  │─▶│  Active  │─▶│  ORCHESTRATOR            │ │
│  │ (Playw- │  │  Recon   │  │ Baseline │  │                          │ │
│  │  right)  │  │ (29 chk) │  │ (10+DOM) │  │  Phase 1: RECON AGENT   │ │
│  └──────────┘  └──────────┘  └──────────┘  │  (map attack surface)   │ │
│                                             │         │                │ │
│                                             │         ▼                │ │
│  ┌─────────────── SHARED CONTEXT BUS ─────────────────────────────┐  │ │
│  │ endpoints, params, tech stack, auth tokens, inter-agent msgs   │  │ │
│  └────────────────────────────────────────────────────────────────┘  │ │
│         │         │         │         │         │         │          │ │
│  ┌──────▼──┐┌─────▼───┐┌───▼─────┐┌──▼──────┐┌▼────────┐┌▼───────┐ │ │
│  │  XSS   ││  SQLi   ││  Auth   ││ Inject  ││  API    ││ SSRF   │ │ │
│  │ Agent  ││  Agent  ││  Agent  ││  Agent  ││  Agent  ││ Agent  │ │ │
│  └────────┘└─────────┘└─────────┘└─────────┘└─────────┘└────────┘ │ │
│  ┌────────┐┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌────────┐ │ │
│  │ Config ││  CSRF   ││ BizLogic││ Deser   ││ LLM/AI  ││Smuggle │ │ │
│  │ Agent  ││  Agent  ││  Agent  ││  Agent  ││  Agent  ││ Agent  │ │ │
│  └────────┘└─────────┘└─────────┘└─────────┘└─────────┘└────────┘ │ │
│  ┌────────┐      13 SPECIALISTS IN PARALLEL                       │ │
│  │SupplyC ││                                                      │ │
│  │ Agent  ││                                                      │ │
│  └────────┘│         │                                            │ │
│            │         ▼                                            │ │
│            │  Phase 3: VERIFIER AGENT                             │ │
│            │  (replay attacks, confirm, build exploit chains)     │ │
│            └──────────────────────────────────────────────────────┘ │
│                              │                                       │
│  ┌─────────────┐  ┌─────────▼────┐  ┌──────────────┐                │
│  │   Report    │◀─│   Triage     │◀─│  CVSS        │                │
│  │ (PDF/Excel) │  │   Engine     │  │  Severity    │                │
│  └─────────────┘  └──────────────┘  └──────────────┘                │
│                                                                      │
│  Infrastructure: AWS Bedrock (Claude/Mistral) · Playwright · FastAPI │
└──────────────────────────────────────────────────────────────────────────┘
```

### Standard Mode — `scan_profile: "vulnerability_scan"` (default)

```
┌───────────────────────────────────────────────────────────────────────┐
│                          SCAN PIPELINE                                │
│                                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────┐ │
│  │    Auth      │──▶│   Passive    │──▶│    Active    │──▶│  LLM    │ │
│  │  (auto-     │   │   Recon      │   │   Baseline   │   │  Deep   │ │
│  │  detect +   │   │ (29 checks + │   │  (10 probes  │   │  Scan   │ │
│  │  multi-id)  │   │  secrets)    │   │  + DOM XSS)  │   │ (40 ph) │ │
│  └─────────────┘   └──────────────┘   └──────────────┘   └────┬────┘ │
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
| **Multi-Agent Architecture** | 15 agents (13 specialists + recon + verifier) run in parallel, each with a deeply focused system prompt for its vulnerability class. Shared context bus enables inter-agent communication, dedup, and cross-agent findings. Verifier replays all findings and builds exploit chains. Covers **OWASP Web Top 10** (A01-A10), **API Top 10** (API1-API10), and **LLM Top 10** (LLM01-LLM10) — 32 OWASP categories. Agents: XSS, SQLi, Auth/IDOR, Injection (CMDI/SSTI/LFI/XXE/LDAP), API (GraphQL/WS/mass-assign), SSRF, Config/Crypto, CSRF, Business Logic/Race Conditions, Deserialization, LLM/AI Security, HTTP Smuggling, Supply Chain | `specialist_prompts.py`, `orchestrator.py`, `multi_agent_context.py` |
| **Passive Reconnaissance** | 29 deterministic checks: source maps (**+ deep scan: extracts secrets & hidden API endpoints from `.js.map` contents**), DOM sinks, **hardcoded secret scanner** (17 TruffleHog-style patterns), headers, CSP analysis, CORS, JWT, cookies, telemetry leakage, mixed content, clickjacking, **TLS protocol/cipher audit** (via `sslyze` fallback), **hybrid vulnerable JS library detection** (49-library catalog + NVD/OSV.dev CVE enrichment), **subdomain takeover detection** (46-provider fingerprint DB), **email/DNS security** (SPF/DKIM/DMARC/MX), **WAF/CDN fingerprinting** (15+ products: Cloudflare, Akamai, Fastly, Azure Front Door, Sucuri, Imperva Incapsula, Kong, Envoy, Varnish, ModSecurity, FortiWeb, Barracuda, F5 BIG-IP — via headers + response body signatures). Post-auth passive pass also scans authenticated DOM HTML for secrets | Runs before LLM phases, $0 cost |
| **Active Scanning** | 25 web phases + 15 API phases + LLM security phase + 10 deterministic active baseline probes: full OWASP Top 10 + context-aware checks (path traversal, XXE, race conditions, file upload, host header, session mgmt, HTTP smuggling, GraphQL introspection, OAuth/OIDC) | [Web Scanning](docs/web-scanning.md) · [API Scanning](docs/api-scanning.md) |
| **LLM Application Security** | Auto-detects chatbot/AI-powered features via DOM heuristics and network traffic analysis. Three-layer LLM testing: **(1) Baseline** — 37 deterministic probes covering OWASP LLM Top 10 (LLM01–LLM10). **(2) Garak (NVIDIA)** — 41 probe families covering jailbreaks (`dan.DanInTheWild`, `grandma.*`), toxicity/slurs (`lmrc.Profanity`, `lmrc.SlurUsage`), prompt injection (`promptinject.*`), API key extraction, encoding attacks, and more — prioritised by security impact (jailbreak → toxicity → info disclosure). **(3) LLM-Agent** — adaptive, context-aware payloads crafted by the AI agent (jailbreak roleplay, data exfiltration, SSRF via chatbot, multi-turn escalation, encoding tricks). Each source is labeled `[GARAK]`, `[BASELINE]`, or `[LLM-AGENT]` in findings. **Browser Bridge for Authenticated Chatbot Testing:** Garak and LLM-Agent probes interact with UI-based chatbots through a Playwright browser bridge (`browser_llm_bridge.py`). The bridge logs into the target, navigates to the chat UI, types prompts into the real input field, and captures responses via **stability-based container text diff** — monitoring DOM changes until the chatbot finishes responding. **Preflight validation** sends a "Hello" test (45s timeout, up to 3 attempts with backoff, re-auth between attempts); on failure you get a loud skip warning plus a visible **Scan Coverage** finding when LLM01 probes cannot run (browser → HTTP → skip). Empty / `NO_REPLY` Garak hits are suppressed so noise does not flood triage. LLM phase passes real `auth_headers` from the scan session (not `{}`). Garak and LLM-Agent findings are trusted by the triage engine — the exact payload and chatbot response are shown in the finding narrative. **Deep LLM Scan** option: standard mode (15 payloads/probe, ~8 min) vs deep (256/probe, ~30 min) — controlled independently from general scan intensity via `llm_scan_depth` or the UI checkbox. Force LLM phase with `focus_areas: ["LLM"]` | `llm_detect.py`, `llm_baseline.py`, `garak_runner.py`, `browser_llm_bridge.py`; Garak is optional (`pip install garak`) |
| **Crawl-Only Profile** | Acunetix-style crawl-only scan mode: discovers URLs, SPA routes, forms, APIs, and in-scope sub-domains **without** sending attack payloads. Still runs passive recon (TLS, headers, JS CVEs) and API baseline; **body fuzzing is now correctly skipped** (was previously leaking through). Use to verify coverage before a full scan | Dashboard "Scan Profile" dropdown, `scan_profile: "crawl_only"` via API |
| **SPA Crawling & Coverage** | **SPA route walker** extracts routes from Angular, React, Vue, Next.js, Nuxt, and Remix framework globals, then navigates each to capture XHRs via the network listener. **Post-auth SPA re-crawl** runs after authentication with reduced budget to discover auth-gated endpoints. **Crawl coverage metric** tracks total/unique paths and warns when coverage is low (<5 pages). Passively harvests in-scope HTTPS sub-domains from browser XHR/fetch/navigation traffic. After every phase, newly discovered hosts get a **passive re-audit** (TLS + security headers). **Parallel worker dedup** prevents redundant fuzz requests across concurrent workers via shared tested-endpoint set | `spa_crawler.py` route walker, `agent.py` post-auth re-crawl + coverage metric + parallel dedup |
| **WAF-Aware Fuzzing** | `fuzz_parameter` and `inject_payload` return a `waf_likely` flag when responses match WAF block signatures (Cloudflare, Sucuri, ModSecurity, Imperva, F5, etc.). WAF-blocked responses are excluded from anomaly counts, reducing false positives from WAF interference | `tools.py` `_detect_waf_block`, `_WAF_SIGNATURES` |
| **Triage Engine** | 3-layer evidence-based classification (TP/FP/Manual Review) with CWE/CVSS, exploitation tiers (validated/informational), entropy-based secret filtering, SPA catch-all detection, deduplication by (host + CWE + parameter), step-by-step triage narrative separating AI actions from engine validation, and **Garak LLM bypass** — Garak probe failures are trusted as TRUE_POSITIVE with the exact chatbot payload and response shown in the exploit evidence and narrative | [Triage Engine](docs/triage-engine.md) |
| **Platform Authentication** | **SSO (canonical):** SAML 2.0 via Microsoft Entra ID, invite/group-based onboarding, `admin` / `user` RBAC. **Automation only:** HTTP Basic Auth (`DAST_AUTH_*`) for API/scripts — not end-user login | [SSO & RBAC Guide](docs/SSO_RBAC.md) |
| **Scan Authentication** | Auto-detect form, SSO/OIDC, OAuth, API key, bearer — with session refresh. Multi-identity: User B, Admin, Tenant B (password, bearer, or API key) authenticated at scan start | Multi-step OIDC, self-healing sessions, fast-path static-token auth |
| **Multi-Identity Testing** | Supply up to 3 extra identities (User B, Admin, Tenant B) via UI or API. All identities are authenticated at scan start; their credentials are injected into **all 8 authorization-class phases** (not just BOLA). Supports username/password, bearer tokens, and API keys — including fast-path static-token auth | Cross-user BOLA, cross-role BFLA, cross-tenant access, session/key revocation, license generation |
| **Deterministic CVSS Severity** | AI Raw findings get a deterministic CVSS v3.1 score and severity bucket (`severity.py`) based on CWE profile + evidence keywords — independent of LLM mood. LLM's original severity preserved as `llm_severity` for comparison | Pre-triage classification, UI shows CVSS column + LLM-vs-deterministic tooltip |
| **Impact Statements** | LLM-generated business impact for every finding, with passive recon fallback | Contextual risk descriptions in reports |
| **Scan Targeting** | Exclude URLs, focus on specific pages/areas, control scan intensity (light/standard/deep) | Fine-grained scan scope control |
| **API Import** | Postman (v2.0/v2.1), OpenAPI/Swagger (2.0, 3.0, 3.1) | Baseline execution + hybrid fuzzing |
| **Logout Protection** | 6-layer protection: URL patterns, selector blocking, href inspection, post-click recovery, LLM prompt rules, link filtering | Never accidentally destroys the session |
| **Web UI** | Real-time scan progress, AI vs Triage comparison, PDF reports, scan management. **Cost Management** (FINANCE nav): KPI cards, spend-by-status chart, top-25 cost-per-scan table (dashboard LLM cost card removed). **Roles reference:** permission matrix on User Management; **Your Access** card on Settings (all roles) | [Web UI Guide](docs/web-ui.md) |
| **REST API** | Full API for CI/CD integration — start, stop, pause, resume, results, reports | [HTTP API guide](docs/api.md) |
| **MCP Server** | Model Context Protocol integration for Cursor, Claude Desktop | [MCP guide](docs/mcp.md) |
| **Reports** | Four-stage evidence: AI Agent → Runtime Verification → CVSS Severity → Triage verdict | PDF, Excel, JSON export |
| **Cost Control** | Pause/resume scans, stop early, per-scan cost tracking | Cost Management page (FINANCE); ledger still in `cost_ledger` table |
| **Multi-Step Exploit Chaining** | Combines individual findings into attack chains (e.g. XSS + cookie theft → session hijack, SSRF → internal API → data exfiltration) | Cross-phase context, `chain_exploit` tool |
| **Findings Grouping** | Group findings by Issue Category, OWASP Top 10 code, OWASP LLM Top 10, Severity, PCI DSS requirement, or SANS/CWE Top 25 — with a "Group by" selector, collapsible sections, and per-group severity breakdown | All tabs: Live, Comparison, AI Raw Findings |
| **Hybrid Smart Retry** | For 20 high-impact phases the agent runs a second, tool-enabled pass with a phase-tailored retry prompt whenever the phase either finds 0 vulnerabilities **or** misses its core vulnerability class. Retry prompts include: **SQLi** (ORDER BY/GROUP BY column-injection, date_trunc/period parameter injection, export/report endpoint injection), **Injection** (14-engine SSTI payload sweep, YAML/Pickle/Java/PHP/.NET deserialization content-type sweep, verbose-error/stack-trace harness), **Access Control** (SaaS business-logic surface probing — /api/licenses, /api/sessions, /api/invoices, etc.; state-mutation invariants — cross-user session/key revocation, cross-tenant license generation, role-validation absence, org-switch impersonation), **Auth** (multi-role credential discovery, parameter-name permutation), **XSS/SSRF/File Upload** (existing) | `_ACTIVE_RETRY_PHASES`, `_PHASE_CORE_KEYWORDS`, `_RETRY_PROMPTS` in `agent.py` |
| **Finding Deduplication** | Three-tier dedup: (1) multi-agent orchestrator dedup by `(host, vuln_type, path)` or `(host, title)` removes cross-agent duplicates before verification; (2) runtime dedup by `(title, url, parameter)` prevents double-counting across passes; (3) triage-level dedup by `(host, CWE, parameter)` merges equivalent findings keeping highest severity — reduces noise by ~40% on typical scans | `_deduplicate_findings` in `orchestrator.py`; `_finding_key`, `_dedupe_findings` in `web/app.py`; `deduplicate()` in `scripts/triage_engine.py` |
| **Model ID Resolution** | UI/API callers can pass a display name ("Claude Haiku 4.5 (recommended)"), a short alias ("haiku", "sonnet"), or the full litellm id — the backend normalises all three to a valid litellm model id, preventing "LLM Provider NOT provided" errors | `_resolve_model_id` in `web/app.py`, applied at `/api/scan`, `/api/scan/{id}/retry`, `/api/scan/{id}/rescan` |
| **Deploy Safety** | Pre-deployment check detects active/paused scans and aborts `deploy.sh` before overwriting a running scanner. `check_scan_active.py` uses operator **automation** Basic Auth (`DAST_AUTH_*` in-container) when calling `/api/scans` (falls back to unauthenticated on older images) | `scripts/check_scan_active.py`, integrated in `deploy.sh` |
| **Parallel-Phase Failure Surfacing** | When phases run concurrently via `asyncio.gather`, worker exceptions used to be silently swallowed by `return_exceptions=True`, leaving missing phases with no trace. Now every worker is wrapped in a guard that logs the failure to `phase_log` with an `error` field and a `(FAILED)` suffix in the live UI, so a transient Bedrock 5xx, Playwright timeout, or LLM-context overflow no longer disappears a phase silently | `run_phases_parallel._guarded` in `agent.py`; UI shows `(FAILED)` + tooltip with error |
| **LLM Transient-Error Retry** | `LLMRouter.complete` retries up to 5× with 2 / 4 / 8 / 16 / 32 s exponential back-off (~62 s total) on transient signatures: connection failures (`All connection attempts failed`), 502 / 503 / 504, read timeouts, throttling. Tunable at runtime via `LLM_RETRY_DELAYS` env var. Terminal errors (`ContextWindowExceeded`, `ContentFiltered`, `MalformedMessages`) bubble immediately so a single bad message doesn't burn 6× cost | `LLMRouter.complete` in `llm_config.py` |
| **Partial-DB Cache Fallback** | The DB sometimes wrote a partial-checkpoint payload (`metadata.partial=True`) for a scan that later finished cleanly to disk, then served the stale partial blob to the API. The reader now prefers a complete on-disk result over a partial DB record and back-fills the DB on read so subsequent loads serve the full payload | `_load_raw_result_dict` in `web/app.py` |
| **Body-Fuzz Return-Shape Hardening** | `fuzz_body` early-exit paths (unparseable body, baseline failure) used to return a bare `[]` while the caller did `a, b = await fuzz_body(...)`, crashing phase 4 with `not enough values to unpack (expected 2, got 0)`. Now both early exits return `([], [])`; return type annotation corrected; 23-test scenario suite (`tests/test_scan_error_resilience.py`) audits every tuple-unpack contract in the scanner | `body_fuzzer.py`, `tests/test_body_fuzzer_return_shape.py`, `tests/test_scan_error_resilience.py` |
| **Subdomain Takeover Detection** | Detects dangling DNS records pointing to unclaimed third-party services. 46-provider fingerprint database covering AWS S3, CloudFront, Elastic Beanstalk, GitHub Pages, Heroku, Azure (Web Apps, Blob, Traffic Manager), Netlify, Shopify, Fastly, Vercel, Google Cloud Storage, Wix, Webflow, Render, Fly.io, and 30 more. Detection via: (1) DNS CNAME chain resolution with `dnspython`, (2) NXDOMAIN detection for abandoned service instances, (3) HTTP response fingerprint matching against known takeover strings, (4) Subdomain enumeration via Certificate Transparency (crt.sh) + 75-prefix DNS wordlist. Concurrent checking with configurable semaphore | `subdomain_takeover.py`, `subdomain_enum.py`, integrated in passive recon step 26 |
| **Email/DNS Security** | Validates email authentication configuration for the target domain: SPF record presence and enforcement level (+all/~all/-all, lookup count, multiple records), DMARC policy analysis (none/quarantine/reject, subdomain policy, pct, reporting URIs), DKIM selector probing (22 common selectors including google, selector1/2, mandrill, amazonses, sendgrid), MX record security (null MX, IP-based MX). Only flags findings when the domain actually handles email (MX-aware). Generates actionable remediation guidance per finding | `dns_security.py`, integrated in passive recon step 27 |
| **Active Baseline (10 Probes + DOM XSS)** | Deterministic active probes ($0 LLM cost): bare-root SQLi (time-based blind), cache poisoning (unkeyed header reflection), **reflected XSS** (dynamic param discovery + 4-layer detection: direct reflection, cross-endpoint fallback, propagation-aware multi-page test, HTML attribute context breakout), **Playwright DOM XSS probe** (browser-verified: injects payloads into URL params, navigates pages, clicks links, listens for `alert()` dialogs — replicates manual pentester workflow), SSRF bypass (cloud metadata + IP encoding), open redirect, sensitive path disclosure, Salesforce misconfiguration, **GraphQL introspection** (8 common paths, mutation exposure), **HTTP request smuggling** (CL-TE + TE-CL timing desync), **OAuth/OIDC** (PKCE enforcement, implicit flow, redirect_uri validation). All use realistic browser UA to bypass WAF | `active_baseline.py` |
| **Exploitation Tiers** | Every finding is assigned `validated` (exploitation proven: runtime confirmed, payload reflected, SQL error returned, Garak/LLM-Agent probe with real chatbot response) or `informational` (detected but not proven: pattern match, missing header, config check). Garak and LLM-Agent findings are always `validated` — the chatbot's verbatim response is captured and shown. Follows "proof over probability" methodology | `_assign_exploitation_tier()`, `_assign_exploitation_tier_garak()` in `triage_engine.py` |
| **Entropy-Based Secret Filtering** | Hardcoded "secrets" detected in JS are validated via Shannon entropy calculation + framework constant detection (38 known patterns: `$$ROW_INTERNAL`, `__react_devtools`, `ng-version`, etc.). Low-entropy or known-constant values are auto-classified as FALSE_POSITIVE | `_shannon_entropy()`, `_is_fake_secret()` in `triage_engine.py` |
| **SPA Catch-All Detection** | Detects when SPAs (React/Angular/Vue) return the app shell for sensitive file paths (e.g., `/.git/HEAD` returns `index.html` with 200). Marks these as FALSE_POSITIVE instead of real file disclosure findings | Layer 0B in `triage_engine.py` |
| **Triage Narrative** | Every triaged finding includes a structured step-by-step breakdown: "What the AI Scanner Tested" (payloads, requests, observations) vs "How Triage Engine Validated" (HTTP codes checked, body analysis, pattern matching, severity adjustment, final verdict). **Garak and LLM-Agent findings** show the exact probe name, detector, payload sent, and the chatbot's verbatim response — making it clear what the LLM actually said | `_build_triage_narrative()` in `triage_engine.py`, rendered in UI finding detail modal |
| **Brute Force Validation (50-request threshold)** | Rate limiting findings require 50 consecutive unblocked requests (up from 5) to be reported. Prevents false positives from CDN/WAF soft limits that only trigger after higher volumes | Configured in `prompts.py` BRUTE FORCE + RATE LIMITING phases |
| **Secret Usage Validation** | When the AI discovers a potential API key/token, it must: (1) calculate entropy, (2) attempt to use the key for authentication, (3) only report if entropy is high AND key works or matches a known service pattern. Framework constants are explicitly excluded | `STEP 2B` in `prompts.py` |

## Quick Start

### Production UI

The hosted scanner is at **`https://rt.ai.webscanner.gendigital.com`** (ALB + WAF in front of the EC2 UI container). **Sign in via SSO** (Microsoft Entra ID) — see [docs/SSO_RBAC.md](docs/SSO_RBAC.md). HTTP Basic Auth is for API/automation only, not the operator UI path.

### Local development

```bash
pip install -r requirements.txt
playwright install chromium
cp .env.example .env && nano .env   # local dev: SSO_ENABLED=false; set DAST_AUTH_* for API/script auth only
uvicorn web.app:app --host 0.0.0.0 --port 80
# Or: docker compose up --build
```

Optional Postgres dual-write locally: set `DATABASE_URL`, `DUAL_WRITE_PG=1` in `.env` (see [db/README.md](db/README.md)).

## Install from scratch

End-to-end path for a **new operator** provisioning AWS infrastructure and bringing up the UI + Fargate scan workers. Depth on Terraform variables, WAF, and backups: [infra/terraform/README.md](infra/terraform/README.md). Bedrock, `.env`, and SSO: [docs/deployment.md](docs/deployment.md).

### Prerequisites

| Item | Value |
|------|--------|
| **AWS account** | `168551359048` |
| **Region** | `us-east-2` |
| **AWS CLI profile** | `dast-poc` — verify: `aws sts get-caller-identity --profile dast-poc` |
| **Terraform** | `>= 1.6` (repo pins in `infra/terraform/versions.tf`; team standard **1.9.8** on Windows — add install dir to `PATH`, e.g. `C:\terraform\terraform_1.9.8`) |
| **SSH key** | `C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem` (outside repo; never commit) |
| **EC2 UI** (after Step 1) | `ubuntu@3.20.180.251`, container `dast-scanner`, app root `~/ai-dast-scanner` |
| **Git** | Clone `master` at a known SHA (e.g. `9d8cd59`): `https://github.com/sibadakkata/ai-agentic-dast.git` or `https://git.int.avast.com/red-team/ai-agentic-dast.git` |

**Approval gates:** Do **not** run `terraform apply` without explicit review/approval ([deployment protocol](.cursor/rules/deployment-protocol.mdc)). Do **not** `scp` / restart production EC2 without operator sign-off.

### Step 1: Provision infrastructure with Terraform

From a workstation with AWS credentials:

```powershell
cd C:\Projects\Pen-Test\Acunetix\POC\infra\terraform
Copy-Item terraform.tfvars.example terraform.tfvars   # if first time
# Edit terraform.tfvars — required: ec2_security_group_id, ec2_private_ip (see infra/terraform/README.md)
terraform init
terraform fmt -recursive
terraform validate
terraform plan -var-file=terraform.tfvars -out=tfplan
# STOP — review tfplan with a second operator; apply only after explicit approval:
terraform apply tfplan
```

**Terraform creates (among other things):** RDS PostgreSQL, ALB + WAF, ECS cluster + Fargate task definition, ECR repo `dast-scanner-runner`, ElastiCache Redis, Secrets Manager `dast/rds/master`, backup Lambda → S3, VPC interface endpoints (Secrets Manager, ECR API/DKR, CloudWatch Logs). It does **not** deploy application Python/HTML or Docker images for the UI — that is Step 3.

Note the ALB DNS from outputs: `terraform output alb_dns_name` (or use `https://rt.ai.webscanner.gendigital.com` when DNS is wired).

### Step 2: First-time EC2 setup

`terraform apply` assumes an **existing** UI EC2 instance (security group + private IP in `terraform.tfvars`). On the instance (Ubuntu 24.04+, Docker installed, port 80 open):

```bash
ssh -i /path/to/siba-dast-agentic-poc.pem ubuntu@3.20.180.251
git clone https://git.int.avast.com/red-team/ai-agentic-dast.git ~/ai-dast-scanner
cd ~/ai-dast-scanner
git checkout 9d8cd59   # or current master
cp .env.example .env
nano .env              # Bedrock/AWS, DAST_AUTH_*, DATABASE_URL, DUAL_WRITE_PG, SCAN_LAUNCHER=fargate, ECS_* — see docs/deployment.md
```

Attach/confirm the EC2 instance IAM role includes Bedrock invoke, Secrets Manager read for `dast/rds/master`, and ECS `RunTask` (Terraform `ec2_iam.tf` when `ec2_iam_role_name` is set).

### Step 3: First application boot (UI container)

On the EC2 host (interactive shell — see [Common deploy failures](docs/deployment.md#common-deploy-failures) if `deploy.sh` is run via `nohup`):

```bash
cd ~/ai-dast-scanner
bash deploy.sh
# First run: Docker image build ~5–15 min (Playwright + deps)
```

Smoke from your laptop (replace host with ALB DNS or public IP):

```bash
curl -sf http://<ALB-DNS>/healthz && echo OK
# Or production URL:
curl -sf https://rt.ai.webscanner.gendigital.com/healthz && echo OK
```

### Step 4: Push Fargate runner image to ECR

Build on **EC2** (recommended). Building on Windows and copying sources risks UTF-16 corruption in `.py` files if edited with certain tools — see [.cursor/rules/file-encoding.mdc](.cursor/rules/file-encoding.mdc).

**Prerequisites on the EC2 instance role:**

- IAM: `ecr:GetAuthorizationToken` plus `ecr:BatchCheckLayerAvailability`, `ecr:CompleteLayerUpload`, `ecr:InitiateLayerUpload`, `ecr:PutImage`, `ecr:UploadLayerPart` on repository `dast-scanner-runner`
- Network: VPC interface endpoints for **ECR API** and **ECR DKR** (Terraform `vpc_endpoints_ecs.tf`) **or** outbound HTTPS to `*.ecr.us-east-2.amazonaws.com` and `*.dkr.ecr.us-east-2.amazonaws.com`

Without both, `docker push` fails with `ConnectTimeoutError` to `api.ecr.us-east-2.amazonaws.com` (see [docs/deployment.md](docs/deployment.md)).

On EC2:

```bash
cd ~/ai-dast-scanner
export AWS_REGION=us-east-2
ECR_URL=$(terraform -chdir=infra/terraform output -raw ecr_scanner_runner_url)
# e.g. 168551359048.dkr.ecr.us-east-2.amazonaws.com/dast-scanner-runner
TAG=v9d8cd59   # match git SHA or release tag

aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin 168551359048.dkr.ecr.us-east-2.amazonaws.com

docker build -f scanners/runner/Dockerfile -t dast-scanner-runner:"$TAG" .
docker tag dast-scanner-runner:"$TAG" "$ECR_URL:$TAG"
docker push "$ECR_URL:$TAG"
```

Bump the image tag in the ECS task definition via Terraform or `aws ecs register-task-definition` so `RunTask` pulls the new digest. Worker details: [scanners/runner/README.md](scanners/runner/README.md).

### Step 5: Verify

1. Open `https://rt.ai.webscanner.gendigital.com` (or ALB URL); **Sign in with Microsoft** (SSO per [docs/SSO_RBAC.md](docs/SSO_RBAC.md)). Use `DAST_AUTH_*` only for automation curls, not as the operator login path.
2. Start a smoke scan against OWASP Juice Shop (or `python scripts/e2e_remote_scan.py --smoke` from your laptop — [docs/deployment.md](docs/deployment.md)).
3. Confirm a Fargate task appears: ECS console → cluster `dast-scanner` → Tasks, or CloudWatch log group `/ecs/dast-scanner-runner`.

---

## Day-to-day code deploys

**UI host:** `3.20.180.251` · **Container:** `dast-scanner` · **SSH key:** `C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem`

### Canonical flow (EC2)

On the host after `git pull` in `~/ai-dast-scanner`:

```bash
bash deploy.sh
```

`deploy.sh` compares `HEAD` to `.last_deployed_sha`, runs `scripts/deploy/classify_changes.py`, and **hot-patches** changed `web/` / `scanners/` / `scripts/` files by default. It rebuilds the **UI image** only when root `Dockerfile`, `requirements*.txt`, or compose files change. **Runner image rebuilds** happen only when `scanners/runner/**`, files under `scanners/` / `web/` / `scripts/` / `config/` (runner `COPY` tree), or shared dependency files change — then follow the ECR push steps below (or `scripts/ec2_build_push_runner.py build-host`).

First-time / dependency rebuild: `bash deploy.sh --full`.

`deploy.sh` runs `scripts/checks/check_no_null_bytes.py --all` automatically before any hot-patch or image rebuild (refuses deploy on UTF-16 / null-byte files). Docker image builds also fail at `COPY` time if bad encoding is baked in.

**MANDATORY before any pattern that restarts the container:** `scripts/check_scan_active.py` must exit **0** (no active/paused scan). In-process scan state is lost on restart; pause-deploy-resume does **not** work. The script is usually already in the container at `/tmp/check_scan_active.py`; refresh if needed:

```powershell
scp -i "C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem" `
  "C:\Projects\Pen-Test\Acunetix\POC\scripts\check_scan_active.py" `
  ubuntu@3.20.180.251:/tmp/
ssh -i "C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem" ubuntu@3.20.180.251 `
  "docker cp /tmp/check_scan_active.py dast-scanner:/tmp/ && docker exec dast-scanner python3 /tmp/check_scan_active.py"
```

Only proceed when output includes **SAFE TO DEPLOY**. See [.cursor/rules/deployment-protocol.mdc](.cursor/rules/deployment-protocol.mdc) for approval rules.

### A. Hot-patch a few files (~30 sec)

Use when `requirements.txt`, `Dockerfile`, and Playwright/OS packages are **unchanged**.

```powershell
$pem = "C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem"
$sshTarget = "ubuntu@3.20.180.251"
$f = "web/app.py"
scp -i $pem "C:\Projects\Pen-Test\Acunetix\POC\$($f -replace '/','\')" "${sshTarget}:/tmp/_deploy.tmp"
ssh -i $pem $sshTarget "docker exec dast-scanner python3 /tmp/check_scan_active.py && docker cp /tmp/_deploy.tmp dast-scanner:/app/$f && docker restart dast-scanner"
```

### B. Hot-patch many files or a whole folder (~10 sec)

```powershell
$pem = "C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem"
$sshTarget = "ubuntu@3.20.180.251"
ssh -i $pem $sshTarget "docker exec dast-scanner python3 /tmp/check_scan_active.py"
tar -cf - -C "C:\Projects\Pen-Test\Acunetix\POC" web | ssh -i $pem $sshTarget "docker exec -i dast-scanner tar -xf - -C /app"
ssh -i $pem $sshTarget "docker restart dast-scanner"
```

Replace `web` with `scanners/ai_agent`, `web/static`, etc. Only hot-patch files that are **committed in git** (or already on the host tree); otherwise the next `bash deploy.sh` rebuild clobbers uncommitted `docker cp` changes.

### C. Full rebuild — `bash deploy.sh` (5–15 min)

On EC2, from `~/ai-dast-scanner` in an **interactive** shell:

```bash
docker exec dast-scanner python3 /tmp/check_scan_active.py   # MUST exit 0
bash deploy.sh
```

Use when you changed **`requirements.txt`**, root **`Dockerfile`**, Playwright/browser deps, or system packages in the image. `deploy.sh` already runs the scan-active check if the container is up.

### D. Fargate runner image rebuild

Rebuild and push to ECR (Step 4 above). ECS picks up the new image on the next `RunTask`; no UI container restart required unless you also changed the control plane.

### When to use what

| What changed | Deploy path | Typical time |
|--------------|-------------|--------------|
| Routine code on EC2 after `git pull` | **`bash deploy.sh`** (auto hot-patch / rebuild) | ~10–60 s |
| One or a few files from laptop | **A** — `scp` + `docker cp` + `docker restart` | ~30 s |
| Many files or a directory from laptop | **B** — `tar` pipe into `docker exec … tar` | ~10 s |
| `requirements.txt`, root `Dockerfile`, Playwright/OS packages | **`bash deploy.sh --full`** on EC2 | 5–15 min |
| `scanners/runner/Dockerfile` or runner-only paths | **D** — `docker build` + `docker push` to ECR (see classify output) | 3–10 min |
| `.env` / environment variables only | Edit `~/ai-dast-scanner/.env` on host, then `docker restart dast-scanner` (after scan check) | ~30 s |
| RDS, ALB, WAF, ECS task definition, IAM, security groups, VPC, empty ECR repo, S3, Lambda | **Terraform** `plan` + `apply` | minutes |

---

## Infra vs application: what tool does what

| Layer | Tool | Notes |
|-------|------|-------|
| RDS, ALB, WAF, ECS task def, IAM, SG, VPC, ECR repo, S3, Lambda | **Terraform** | Declarative; drift-detected |
| Fargate runner image | **docker build** + **docker push** to ECR | Image bytes, not infra |
| Fargate task def image tag bump | **Terraform** OR **aws CLI** | Tag change = infra config |
| EC2 UI code (`.py` / templates / static) | **docker cp** + **docker restart** | Hot-patch into running container |
| EC2 UI image rebuild (deps changed) | **`bash deploy.sh`** on host | Full image rebuild |
| `.env` / env vars | Edit `~/ai-dast-scanner/.env` + **docker restart** | No `scp`/build |

**Terraform does NOT deploy application code.** Use the [code-deploy patterns](#day-to-day-code-deploys) above for that.

> More detail: [docs/deployment.md](docs/deployment.md) · [infra/terraform/README.md](infra/terraform/README.md)

## Authentication

**Human operators** sign in via **SAML 2.0** (Microsoft Entra ID) with invite- or group-based onboarding and two roles: **`admin`** (Red Team Admin) and **`user`** (Red Team Member). This is the production-grade, canonical access path.

**HTTP Basic Auth** (`DAST_AUTH_USER` / `DAST_AUTH_PASS`) is for **API clients, CI, deploy scripts, and MCP** — not for distributing credentials to Red Team operators. While `SSO_ENABLED=false` during rollout, a local username/password form may still appear on `/login`; treat it as **interim/emergency** only until SSO and HTTPS are live.

See **[docs/SSO_RBAC.md](docs/SSO_RBAC.md)** for Entra app registration, full environment variable reference, bootstrapping the first admin (`INITIAL_ADMIN_EMAILS`), invites, group RBAC, and troubleshooting — do not duplicate that guide here.

### Roles & permissions

| Capability | admin | user |
|------------|-------|------|
| Start scans, view own scans/reports | Yes | Yes |
| View all scans, delete scans/reports | Yes | No |
| User management, write UI settings | Yes | No |
| Settings (read), Cost Management, Insights | Yes | Yes |

The in-app **Roles & Permissions** matrix on **User Management** and the **Your Access** card on **Settings** stay in sync with this table.

### Environment variables (platform auth)

| Variable | When | Purpose |
|----------|------|---------|
| `SSO_ENABLED` | Always | `true` = SAML (production); `false` = interim local form on `/login` (dev/rollout only) |
| `DAST_AUTH_USER` / `DAST_AUTH_PASS` | Automation / API | HTTP Basic Auth for scripts, MCP, `check_scan_active.py` — **not** end-user platform login |
| `INITIAL_ADMIN_EMAILS` | First SSO bootstrap | Comma-separated emails granted `admin` on first SAML login (set in deploy env only, not git) |
| `SAML_IDP_METADATA_URL`, `SAML_SP_ENTITY_ID`, `SAML_SP_ACS_URL` | SSO on | Entra ID SP configuration |
| `SAML_SP_CERT_PATH`, `SAML_SP_KEY_PATH` | Optional | SP signing cert/key (PEM paths) |
| `DAST_SESSION_SECRET`, `PUBLIC_BASE_URL` | Production | Session cookies; invite link base URL |

All SAML and IdP variables are documented in [docs/SSO_RBAC.md](docs/SSO_RBAC.md).

## Choosing a Scan Profile

The scanner offers three scan profiles. Select from the **Scan Profile** dropdown in the UI or set `scan_profile` via the API.

| Profile | Best for | How it works | Strengths | Limitations |
|---------|----------|-------------|-----------|-------------|
| **Vulnerability Scan** (default) | Production apps, thorough audits, bug bounty | Single LLM agent runs 25 web + 15 API phases sequentially/parallel. Each phase has a battle-tested prompt targeting a specific vuln class. Includes smart retry, attack chain analysis, and runtime verification. | Highest finding count. Mature prompts tuned over hundreds of scans. Deep per-phase context. Runtime verification confirms exploitability. | Sequential phases = longer scan time. Single agent can't cross-pollinate findings between vuln classes mid-phase. |
| **Multi-Agent** | Broad coverage, OWASP compliance, parallel specialist analysis | 13 specialist agents run in parallel, each with an isolated browser + HTTP client. A recon agent maps the surface first, then specialists (XSS, SQLi, Auth, SSRF, etc.) test simultaneously. Inter-agent deduplication removes duplicate findings across agents. A verifier confirms findings and builds exploit chains. | Full OWASP Web/API/LLM Top 10 coverage (32 categories). Parallel = faster wall-clock time (2x vs standard). Lower cost per finding. Each agent is a domain expert with action-oriented prompts. Agents share context (endpoints, params, findings) in real time. Built-in dedup reduces noise. | Each agent has a step budget (200 max). Newer architecture -- may need further tuning for specific target types. |
| **Crawl Only** | Reconnaissance, attack surface mapping | Discovers URLs, forms, APIs, and parameters without sending any attack payloads. | Zero risk to target. Fast. Good for scoping before a full scan. | No vulnerability testing -- findings are informational only. |

### When to use which?

- **"I want broad coverage fast"** -- use **Multi-Agent**. 13 specialists test in parallel, covering all OWASP categories simultaneously. Typically 2x faster and lower cost than standard mode with comparable or higher finding counts.
- **"I want deep per-phase testing"** -- use **Vulnerability Scan** (default). Single-agent sequential phases with smart retry and runtime verification. Best for targets that need deep context across phases.
- **"I want to compare"** -- run both profiles on the same target (one at a time recommended for heavy targets) and compare findings in the UI.
- **"I just want to map the surface"** -- use **Crawl Only**. No payloads, no risk.

> **Note:** Both Vulnerability Scan and Multi-Agent share the same foundation: authentication, passive recon (29 checks), and active baseline probes (SQLi, XSS, DOM XSS, SSRF, smuggling, etc.) always run first regardless of profile. The difference is what happens after baseline.

---

## Scan Pipeline

### Multi-Agent Mode

Select **"Multi-Agent"** in the Scan Profile dropdown or set `scan_profile: "multi_agent"` via API.

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. AUTH + PASSIVE RECON + ACTIVE BASELINE (same as standard mode)  │
├─────────────────────────────────────────────────────────────────────┤
│  2. ORCHESTRATOR deploys 15 agents:                                 │
│     Phase 1: RECON AGENT (sequential) — maps full attack surface    │
│     Phase 2: 13 SPECIALISTS (parallel) — each focused on its class  │
│       ┌─────┬─────┬──────┬────────┬─────┬──────┬────────┐          │
│       │ XSS │ SQLi│ Auth │Inject  │ API │ SSRF │ Config │          │
│       ├─────┼─────┼──────┼────────┼─────┼──────┼────────┤          │
│       │CSRF │BizLo│Deser │ LLM/AI │Smug │Supply│        │          │
│       └─────┴─────┴──────┴────────┴─────┴──────┴────────┘          │
│     Phase 3: VERIFIER AGENT (sequential) — confirms + chains        │
├─────────────────────────────────────────────────────────────────────┤
│  3. TRIAGE + CVSS + REPORT (same as standard mode)                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Shared Context Bus:** All agents read/write to `SharedScanContext` — discovered endpoints, params, tech stack, auth tokens, findings from other agents, and inter-agent messages. Thread-safe via `asyncio.Lock`.

**OWASP Coverage (32 categories):**
- **Web Top 10 (2021):** A01 (Auth/CSRF), A02 (Crypto), A03 (XSS/SQLi/Injection), A04 (Design/BizLogic), A05 (Config/Smuggling), A06 (Supply Chain), A07 (Auth), A08 (Deserialization), A09 (Logging), A10 (SSRF)
- **API Top 10 (2023):** API1-API3 (Auth/BOLA/BOPLA), API4 (Rate Limit), API5 (BFLA), API6 (BizFlow), API7 (SSRF), API8 (Config), API9 (Inventory), API10 (Unsafe Consumption)
- **LLM Top 10 (2025):** LLM01-LLM10 (Prompt Injection, Info Disclosure, Supply Chain, Poisoning, Output Handling, Excessive Agency, Prompt Leakage, Embeddings, Misinformation, Unbounded Consumption)

### Standard Mode (default)

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. AUTHENTICATION                                                  │
│     Auto-detect auth type → login → capture session → auto-refresh  │
│     Multi-identity: also authenticate User B, Admin, Tenant B       │
├─────────────────────────────────────────────────────────────────────┤
│  2. PASSIVE RECONNAISSANCE ($0) — 29 checks + hardcoded secrets     │
│     Source maps (+ deep scan: secrets & API endpoints from .map),  │
│     DOM sinks, headers, CSP, CORS, JWT, cookies,                    │
│     TLS audit (sslyze), HYBRID vulnerable JS libraries,             │
│     hardcoded secret scanner (17 TruffleHog-style patterns),        │
│     SUBDOMAIN TAKEOVER (46-provider CNAME fingerprints),            │
│     EMAIL/DNS SECURITY (SPF/DKIM/DMARC/MX),                        │
│     WAF/CDN FINGERPRINTING (15+ products via headers + body sigs)   │
│     Runs on seed host AND passively-discovered in-scope sub-domains │
├─────────────────────────────────────────────────────────────────────┤
│  3. API BASELINE (if Postman/OpenAPI imported)                      │
│     Execute every endpoint → capture "known good" responses         │
├─────────────────────────────────────────────────────────────────────┤
│  4. HYBRID BODY FUZZING (POST/PUT/PATCH endpoints)                  │
│     LLM plans payloads ($0.001) → engine executes → LLM analyzes   │
├─────────────────────────────────────────────────────────────────────┤
│  4b. ACTIVE BASELINE ($0) — 10 probes + Playwright DOM XSS         │
│     SQLi (time-based), reflected XSS (4-layer: direct, cross-      │
│     endpoint, propagation-aware, attribute context breakout),       │
│     DOM XSS (Playwright: navigate, click links, detect alert()),   │
│     SSRF bypass, cache poisoning, open redirect, sensitive paths,   │
│     Salesforce, GraphQL introspection, HTTP smuggling, OAuth/OIDC   │
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
├── docs/                        # Detailed documentation (see docs/README.md)
│   ├── architecture.md          #   AI agent architecture & design
│   ├── architecture/            #   Platform rollout (Fargate, PG, Redis)
│   ├── system-prompt-guide.md   #   ★ How the LLM system prompt & phases work
│   ├── scanner-internals.md     #   ★ E2E scan flow, evidence, retries, context mgmt
│   ├── contributing.md          #   ★ How to add phases, tools, optimize detection
│   ├── security-checks.md       #   Complete reference: all 69 check categories
│   ├── triage-engine.md         #   Triage engine deep dive
│   ├── api-scanning.md          #   How API scanning works (walkthrough)
│   ├── web-scanning.md          #   How website scanning works
│   ├── api.md                   #   HTTP API guide (curl, polling)
│   ├── mcp.md                   #   MCP / OpenClaw client wiring
│   ├── rest-api.md              #   Extended API reference (redirects to api.md)
│   ├── deployment.md            #   Docker, EC2, models, Bedrock setup
│   ├── web-ui.md                #   Web UI features & configuration
│   ├── mcp-server.md            #   MCP guide (redirects to mcp.md)
│   └── troubleshooting.md       #   Error handling & debugging
├── scanners/                    # Scanner packages (see scanners/README.md)
│   ├── runner/                  # Fargate/local worker entrypoint (ECR image)
│   ├── auth/                    # Platform SAML helpers
│   ├── users/                   # User/invite models
│   └── ai_agent/                # Core scanner engine (25+ modules)
│       ├── agent.py             #   Agent loop, context mgmt, multi-identity, parallel phases
│       ├── auth.py              #   Target auth (form/SSO/OAuth) + multi-identity
│       ├── tools.py             #   31 agent tools (browser, API, fuzz, WAF detection)
│       ├── llm_config.py        #   LiteLLM / Bedrock routing, retries, cost
│       ├── orchestrator.py      #   Multi-agent orchestrator
│       └── ...                  #   passive_recon, active_baseline, garak, etc.
├── scripts/                     # Ops, triage, reports (see scripts/README.md)
│   ├── triage_engine.py         #   3-layer triage engine + exploitation tiers + entropy filter + dedup + narrative
│   ├── cve_lookup.py            #   NVD + OSV.dev CVE lookup
│   ├── report_generator.py      #   PDF report generator
│   ├── excel_exporter.py        #   Excel report exporter
│   └── check_scan_active.py     #   Pre-deploy scan-active safety check (RBAC Basic Auth)
├── web/                         # FastAPI UI + API (see web/README.md)
│   ├── app.py                   #   FastAPI backend, SSE, scan launcher
│   ├── db.py                    #   SQLite persistence (default reads)
│   ├── db_pg.py                 #   PostgreSQL dual-write / read helpers
│   ├── db_router.py             #   READ_FROM_PG routing
│   ├── scan_launcher.py         #   Fargate / local-docker worker launch
│   ├── live_events.py           #   Redis pub/sub for SSE
│   └── static/index.html        #   Single-page web UI
├── migrations/                  # PostgreSQL DDL (see migrations/README.md)
├── infra/terraform/             # AWS production stack
├── mcp_server.py                # MCP server for Cursor/Claude Desktop
├── deploy.sh                    # One-command EC2 deployment
├── docker-compose.yml           # Docker Compose config
├── Dockerfile                   # Production container
└── requirements.txt             # Python dependencies
```

### Data storage

**SQLite (default reads):** `results/scanner.db` — `scans`, `scan_results`, `app_kv`, `cost_ledger`, `users`, `invites`. On startup, legacy `results/raw/*.json` files are back-filled into the DB when missing. See [db/README.md](db/README.md).

**PostgreSQL (production rollout):** RDS instance `dast-scanner` receives **dual-writes** when `DUAL_WRITE_PG=1` and `DATABASE_URL` are set (`web/db_pg.py`). Schema in `migrations/0001_init.sql`. Enable **`READ_FROM_PG=1`** to prefer Postgres for API reads (with SQLite fallback). Fargate workers use `RUNNER_PG_ONLY=1` in the runner image.

- **Crash / error / pause resilience** — on every save, transient `live_*` counters and phase/crawl summaries are promoted into the `scans` row so stopped or errored scans keep metrics in the DB. The detailed per-tool-call log (`live_tests`, up to ~20 MB) stays in-memory during the scan; on graceful completion/error it is written to `scan_results.payload.summary.test_log`.
- **`results/raw/*.json`** — backup/export when a scan finishes; API reads **DB first**, then legacy file once to populate DB.
- **Scan list** (`GET /api/scans`) — paginated `{"items": [...], "total": N}` from DB (see `web/db_router.py` when `READ_FROM_PG=1`).
- **Payloads export** (`GET /api/results/{id}/payloads`) — generated in memory (no on-disk cache).
- **Other files:** `imports/*`, `results/reports/*`, `data/models_cache.json`, `results/cache/*` — not the scan history source of truth.

**Regression (local code + UI strings):** `python _regression_local.py` (use a venv with `pip install -r requirements.txt` so agent/auth imports pass).

**After deploy (e.g. EC2) — hit the live API from your machine:**

```bash
export DAST_BASE_URL=https://your-dast-host
export DAST_AUTH_USER=dast-admin    # automation Basic Auth (scripts/CI) — not operator SSO login
export DAST_AUTH_PASS=your-secret   # same vars used by scripts/check_scan_active.py in-container
python scripts/run_regression_ec2.py          # runs local regression + e2e smoke + API-only persistence checks
python scripts/run_regression_ec2.py --pytest # same, plus pytest tests/
```

**Piecemeal:** `python scripts/e2e_ec2_smoke.py` (read-only HTTP smoke). `python scripts/regression_persistence.py --api-only` skips local `results/scanner.db` and only checks the remote URL (set `DAST_BASE_URL`). Without `DAST_AUTH_PASS`, a **401** on `/api/ui-settings` is reported as **SKIP**, not failure.

## Using the API

The scanner exposes a REST API for **automation** (CI, scripts, MCP). Calls use **HTTP Basic Auth** (`DAST_AUTH_*`). Browser operators use **SSO** instead — see [docs/SSO_RBAC.md](docs/SSO_RBAC.md). You may also call `/api/*` with a session cookie from an SSO login when building browser-based tools.

```bash
# API / automation — not the operator sign-in path
curl -s -u "YOUR_USER:YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -X POST "https://rt.ai.webscanner.gendigital.com/api/v1/scans" \
  -d '{"target_url": "https://example.com", "scan_mode": "both"}'
```

- **Full API reference:** [docs/api.md](docs/api.md) (endpoints, polling, `ai_instructions`, troubleshooting)
- **Interactive docs:** Swagger at `/docs` on your scanner host ([production](https://rt.ai.webscanner.gendigital.com/docs))
- **MCP / OpenClaw:** [docs/mcp.md](docs/mcp.md) and [openclaw-skill/README.md](openclaw-skill/README.md)
- **Local dev:** see [Quick Start](#quick-start) above

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | AI agent design, LLM loop, tool system, phase orchestration |
| [Platform rollout](docs/architecture/scalable-scanner-platform-proposal.md) | Fargate workers, Postgres, Redis, SSE — target production design |
| [Terraform](infra/terraform/README.md) | RDS, ALB, WAF, ECS, ECR, Redis, backups, VPC endpoints |
| [System Prompt Guide](docs/system-prompt-guide.md) | **How the LLM is instructed** — system prompt structure, phase prompts, payload methodology, finding format |
| [Scanner Internals](docs/scanner-internals.md) | **E2E scan flow** — tool execution, evidence buffer, evidence summary, context trimming, finding extraction |
| [Contributing & Extending](docs/contributing.md) | **How to add new phases, tools, and optimize detection** — step-by-step guide for team members |
| [Security Checks](docs/security-checks.md) | Complete reference of all 69 check categories — passive recon (inc. subdomain takeover, DNS security), web phases, API phases, CWE/OWASP coverage |
| [Triage Engine](docs/triage-engine.md) | How TP/FP classification works, confidence scoring, CVSS adjustment |
| [API Scanning](docs/api-scanning.md) | Step-by-step walkthrough with banking API example |
| [Web Scanning](docs/web-scanning.md) | Browser-based scanning, SPA handling, 25 OWASP + context-aware phases |
| [HTTP API](docs/api.md) | Launch, poll, results — curl examples and polling patterns |
| [REST API (extended)](docs/rest-api.md) | Pause, retry, reports, crawl-only, and more endpoints |
| [Deployment](docs/deployment.md) | EC2 setup, Docker, Bedrock config, models, data persistence |
| [SSO & RBAC](docs/SSO_RBAC.md) | Entra ID SAML, invites, roles, env vars, troubleshooting |
| [Web UI](docs/web-ui.md) | UI features, scan configuration, AI planner |
| [MCP / OpenClaw](docs/mcp.md) | Cursor/Claude Desktop MCP wiring and tool reference |
| [Troubleshooting](docs/troubleshooting.md) | Every error type, auto-recovery, and fixes |
