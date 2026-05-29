# Web UI Guide

[← Back to README](../README.md)

The scanner includes a single-page web UI for managing scans, viewing results, and generating reports.

## Features

| Feature | Description |
|---------|-------------|
| **New Scan** | Enter target URL, optional credentials, pick model and scan mode |
| **Model selection mode** | **Manual model** (default) — existing model dropdown unchanged. **Auto (scanner picks best model)** — disables the dropdown and uses tiered Bedrock models per phase (Haiku → Sonnet → Opus). Yellow info banner warns that cost may be 3–10× higher than Haiku-only |
| **Budget cap** | Optional USD cap on LLM spend for the scan; live estimate from `POST /api/scans/estimate` shown under the field. Blank cap defaults to ~2× the expected estimate at launch |
| **Budget approval** | When spend hits the cap, the scan **pauses** (same mechanism as manual Pause). Owner (or admin) sees a yellow banner in the live scan view to raise the cap and resume, or stop the scan |
| **AI Scan Planner** | Type natural-language instruction → LLM generates structured scan plan → review and confirm |
| **Scan Profile** | `Vulnerability Scan` (default, full OWASP testing) or `Crawl Only` (discovery + passive checks, no attack payloads). A `CRAWL` badge appears next to crawl-only scans in the scan list and a "Profile: Crawl Only" stat in the scan detail header |
| **Vulnerability Focus** | Select specific vuln types (XSS, SQLi, CMDI, etc.) or "Full Scan" for all. Disabled in `Crawl Only` mode |
| **Scan Intensity** | Light (3-5 payloads), Standard (8-15), or Deep (20-40+) per input. Disabled in `Crawl Only` mode |
| **Scan Scope** | "This URL Only", "URL + Sub-paths" (default), or "Full Site Crawl" |
| **API Imports** | Upload Postman Collection or OpenAPI/Swagger spec |
| **Live Progress** | Real-time tool calls, payloads, responses, and findings as the scan runs |
| **AI vs Triage** | Side-by-side comparison of AI severity vs evidence-based triage verdict |
| **Findings Grouping (Group by)** | All findings tabs (Live, Comparison, AI Raw) support five grouping modes selectable via a "Group by" toolbar: **Issue Category** (default — inferred vulnerability type like SQL Injection, XSS, etc.), **OWASP** (A01–A10 codes), **Severity** (Critical/High/Medium/Low/Info), **PCI DSS** (v4.0 requirements 3–11), and **SANS 25** (CWE Top 25). Each group is collapsible with a finding count and severity chip breakdown |
| **Crawled Endpoints** | Full list of discovered links and API endpoints |
| **Payloads by Endpoint** | Expandable view of every payload tested per endpoint |
| **Phase Log** | Chronological breakdown of each scan phase with tool call and finding counts |
| **Impact Statements** | LLM-generated business impact for each finding, with fallback from passive recon map |
| **PDF Report** | Generate with full evidence: curl commands, response data, CVE/CVSS |
| **Excel Report** | Export findings as XLSX with severity, CWE, CVSS, and evidence columns |
| **Download Payloads** | Export all payloads tested per endpoint with request/response detail as JSON |
| **Raw JSON** | Download full scan data for integration |
| **Pause / Resume** | Pause to save cost, resume with no lost progress |
| **Stop Scan** | Cancel — partial findings are saved |
| **Delete Scans** | Stops running scans first, then permanently deletes everything |
| **Bulk Actions** | Multi-select via checkboxes for batch retry or delete |
| **Retry Failed** | One-click re-run for errored/cancelled scans (same ID) |
| **Scan Mode Badge** | Each scan shows its mode (`api`, `website`, `both`) |
| **Error Details** | View error messages, scan mode, and progress log for failed scans |
| **Platform access** | **SSO** (Entra SAML) for operators; HTTP Basic Auth for automation/API only |
| **Cost Tracking** | Real-time and cumulative LLM cost display per scan and across all scans |

### Model selection and budget (screenshot placeholder)

> _Screenshot: New Scan form showing Selection mode radio, budget cap field, and cost estimate helper text._

When **Auto** is selected, expand **Models used by phase** in the live scan header after phases start to see which model ran for each phase id.

### When you'll see the approval banner

<!-- SCREENSHOT: Budget approval banner with cap, spend, and three actions -->

The **Budget cap (USD)** field on the launch form is the **only** way to set or change a cap (SSO session). Leave blank for the server default (**$30** for Auto mode). API, MCP, and OpenClaw automation always use that default for Auto mode.

During a live scan, if LLM spend reaches `budget_cap_usd`, the scan **pauses** and a yellow **budget approval** banner appears above the progress log (only for the scan owner or an admin, SSO session):

| Control | Action |
|---------|--------|
| **Increase budget and resume** | Enter a new cap (defaults to ~2× current spend) and approve — calls `POST /api/scans/{id}/budget/approve` |
| **Stop scan** | Ends the scan at the gate — `POST /api/scans/{id}/budget/stop` |
| **Models used by phase** | Expandable breakdown of phase id → model (auto mode audit) |

Others see a note that only the scan owner can approve. Full flow: [intelligent-model-selection.md](intelligent-model-selection.md#the-approval-gate).

## Scan Configuration

| Setting | Options | Default | Notes |
|---------|---------|---------|-------|
| **Scan Mode** | `website`, `api`, `both` | `both` | What to test |
| **Scan Profile** | `vulnerability_scan`, `crawl_only` | `vulnerability_scan` | `crawl_only` skips every OWASP attack phase and the attack-chain stage. Still runs passive recon (TLS, headers, JS CVEs), API baseline, and a broad crawl of URLs/SPA routes/forms/APIs/sibling sub-domains. Selecting it disables Vulnerability Focus and Scan Intensity. Results appear in the normal Crawled Endpoints / Out of Scope / AI Agent Coverage tabs |
| **Scan Scope** | `url_only`, `directory`, `full_site` | `directory` | How far to crawl |
| **Vulnerability Focus** | `Full Scan`, or specific types | Full Scan | Limits phases to selected types. Ignored in Crawl Only mode |
| **Scan Intensity** | `light`, `standard`, `deep` | `deep` | Payloads per input. Ignored in Crawl Only mode |
| **Focus URLs** | List of URLs | (empty) | Specific pages to prioritize |
| **Exclude URLs** | List of URLs/paths | (empty) | URLs the scanner must skip entirely |
| **Additional Domains** | List of domains | (empty) | Extra domains (beyond the target's registrable domain) treated as in-scope for crawl, sibling-host passive checks, and LLM recursion |
| **Second User (User B)** | Username + password | (empty) | Enables two-user BOLA/BFLA testing |

### Auto-Deep Rule

When you select specific vulnerability types (e.g. XSS + SQLi), the scanner automatically forces **Deep** intensity for maximum coverage.

### Crawl-Only Profile

Use **Crawl Only** to verify the scanner can actually reach every part of your app before committing budget to a full vulnerability scan. In this mode:

- A single `crawl_only` phase replaces all 25 web / 15 API OWASP phases
- No attack payloads are sent (no injection, no auth-bypass, no BOLA/BFLA, no SSRF probes)
- Passive recon (TLS audit, security headers, JS library CVEs) still runs — on the seed host **and** every passively-discovered in-scope HTTPS sub-domain
- API baseline requests still execute against imported Postman/OpenAPI specs (informational, not fuzzed)
- The LLM is instructed to enumerate broadly: click links/buttons, fill forms with dummy data, walk SPA routes, inspect the network log for new in-scope hostnames and recurse into them (capped)
- Coverage lands in the normal **Crawled Endpoints**, **Out of Scope**, and **AI Agent Coverage** tabs; the scan list shows a `CRAWL` badge

### Sibling Sub-Domain Coverage

The scanner automatically extends both passive and active coverage to in-scope sub-domains that appear during the scan (typical for SPAs where hosts like `api.example.com` or `cdn-int.example.com` only surface after authentication via XHR/fetch):

- **Passive harvest** — hostnames are collected from the landing page DOM, `robots.txt`, `sitemap.xml`, and live browser network traffic
- **Stage A (post-phase)** — after every phase, any newly discovered in-scope HTTPS host gets a passive re-audit (TLS protocol/cipher + security headers), capped at 10 new hosts per phase
- **Stage B (pre-phase)** — before the next phase prompt, new in-scope hosts (capped at 8 per phase) are surfaced to the LLM with an explicit directive to navigate to them and apply the current phase's testing methodology
- Scope is computed from the target's registrable domain (eTLD+1 via `tldextract`) plus any **Additional Domains** you configure

### Manual vs AI Planner

- **Manual form** — Configure all settings directly. "Full Scan" with Deep intensity by default.
- **AI Planner** — Type a natural-language instruction (e.g. "quick XSS scan on example.com/login"). The LLM parses it into a structured plan. Review and confirm.

### Business Logic Recorder

Available in both Manual and AI modes:

- **Record a workflow** — Record browser interactions (login → add to cart → checkout) that the scanner replays and tests
- **Describe a flow** — Write a natural language description of the business flow for the AI to follow
- **Use saved workflows** — Select a previously recorded workflow from the dropdown

## Authentication

**Red Team operators** sign in via **Microsoft Entra ID (SAML 2.0)** — **Sign in with Microsoft** on `/login`. See [SSO & RBAC](SSO_RBAC.md).

**HTTP Basic Auth** (`DAST_AUTH_USER` / `DAST_AUTH_PASS` in `.env`) is for **API clients, CI, MCP, and deploy scripts** — not for distributing credentials to end users. While `SSO_ENABLED=false` during rollout, an interim username/password form may appear; that is temporary until SSO is live.
