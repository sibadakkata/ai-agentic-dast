# Web UI Guide

[← Back to README](../README.md)

The scanner includes a single-page web UI for managing scans, viewing results, and generating reports.

## Features

| Feature | Description |
|---------|-------------|
| **New Scan** | Enter target URL, optional credentials, pick model and scan mode |
| **AI Scan Planner** | Type natural-language instruction → LLM generates structured scan plan → review and confirm |
| **Vulnerability Focus** | Select specific vuln types (XSS, SQLi, CMDI, etc.) or "Full Scan" for all |
| **Scan Intensity** | Light (3-5 payloads), Standard (8-15), or Deep (20-40+) per input |
| **Scan Scope** | "This URL Only", "URL + Sub-paths" (default), or "Full Site Crawl" |
| **API Imports** | Upload Postman Collection or OpenAPI/Swagger spec |
| **Live Progress** | Real-time tool calls, payloads, responses, and findings as the scan runs |
| **AI vs Triage** | Side-by-side comparison of AI severity vs evidence-based triage verdict |
| **Crawled Endpoints** | Full list of discovered links and API endpoints |
| **Payloads by Endpoint** | Expandable view of every payload tested per endpoint |
| **Phase Log** | Chronological breakdown of each scan phase with tool call and finding counts |
| **PDF Report** | Generate with full evidence: curl commands, response data, CVE/CVSS |
| **Download Payloads** | Export all payloads tested (by phase) as JSON |
| **Raw JSON** | Download full scan data for integration |
| **Pause / Resume** | Pause to save cost, resume with no lost progress |
| **Stop Scan** | Cancel — partial findings are saved |
| **Delete Scans** | Stops running scans first, then permanently deletes everything |
| **Bulk Actions** | Multi-select via checkboxes for batch retry or delete |
| **Retry Failed** | One-click re-run for errored/cancelled scans (same ID) |
| **Scan Mode Badge** | Each scan shows its mode (`api`, `website`, `both`) |
| **Error Details** | View error messages, scan mode, and progress log for failed scans |
| **Basic Auth** | Password-protected (configurable via env vars) |
| **Cost Tracking** | Real-time and cumulative LLM cost display per scan and across all scans |

## Scan Configuration

| Setting | Options | Default | Notes |
|---------|---------|---------|-------|
| **Scan Mode** | `website`, `api`, `both` | `both` | What to test |
| **Scan Scope** | `url_only`, `directory`, `full_site` | `directory` | How far to crawl |
| **Vulnerability Focus** | `Full Scan`, or specific types | Full Scan | Limits phases to selected types |
| **Scan Intensity** | `light`, `standard`, `deep` | `deep` | Payloads per input |
| **Focus URLs** | List of URLs | (empty) | Specific pages to prioritize |

### Auto-Deep Rule

When you select specific vulnerability types (e.g. XSS + SQLi), the scanner automatically forces **Deep** intensity for maximum coverage.

### Manual vs AI Planner

- **Manual form** — Configure all settings directly. "Full Scan" with Deep intensity by default.
- **AI Planner** — Type a natural-language instruction (e.g. "quick XSS scan on example.com/login"). The LLM parses it into a structured plan. Review and confirm.

## Authentication

The Web UI is protected with HTTP Basic Auth:

```bash
DAST_AUTH_USER=dast-admin
DAST_AUTH_PASS=YourStrongPassword
```

Set these in your `.env` file before deploying.
