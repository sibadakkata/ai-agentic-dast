# MCP and OpenClaw integration

The repo ships **`mcp_server.py`**, a thin [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes scanner operations as tools. Each tool calls the same HTTP API as `web/app.py` (`POST /api/scan`, `GET /api/scan/{id}`, etc.) using `httpx` and **HTTP Basic Auth** (`SCANNER_USER` / `SCANNER_PASS` — automation only; human operators use **SSO**, not Basic Auth, for the Web UI).

Use MCP when an AI assistant (Cursor, Claude Desktop) should start scans, poll status, or summarize findings from chat. Use the [HTTP API guide](api.md) directly for CI/CD scripts.

## Prerequisites

```bash
pip install mcp httpx
```

Environment variables (read at process start):

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_URL` | `http://localhost:80` | Scanner base URL (no trailing slash) |
| `SCANNER_USER` | `dast-admin` | Basic Auth username |
| `SCANNER_PASS` | *(empty)* | Basic Auth password (**required** in production) |

Production example:

```bash
export SCANNER_URL="https://rt.ai.webscanner.gendigital.com"
export SCANNER_USER="YOUR_USER"
export SCANNER_PASS="YOUR_SECRET"
```

---

## Installation by client

### Cursor

Add to project `.cursor/mcp.json` (paths relative to repo root):

```json
{
  "mcpServers": {
    "agentic-web-scanner": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "C:/Projects/Pen-Test/Acunetix/POC",
      "env": {
        "SCANNER_URL": "https://rt.ai.webscanner.gendigital.com",
        "SCANNER_USER": "YOUR_USER",
        "SCANNER_PASS": "YOUR_SECRET"
      }
    }
  }
}
```

Restart Cursor. In Agent mode, ask the model to call `health_check` then `launch_scan`.

### Claude Desktop

**Windows** — `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS / Linux** — `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "agentic-web-scanner": {
      "command": "python",
      "args": ["C:/Projects/Pen-Test/Acunetix/POC/mcp_server.py"],
      "env": {
        "SCANNER_URL": "https://rt.ai.webscanner.gendigital.com",
        "SCANNER_USER": "YOUR_USER",
        "SCANNER_PASS": "YOUR_SECRET"
      }
    }
  }
}
```

Use absolute paths to `mcp_server.py` on your machine.

### Generic stdio

Any MCP client that spawns a subprocess:

```bash
cd /path/to/POC
SCANNER_URL=https://rt.ai.webscanner.gendigital.com \
SCANNER_USER=YOUR_USER \
SCANNER_PASS=YOUR_SECRET \
python mcp_server.py
```

Optional SSE transport for remote debugging:

```bash
python mcp_server.py --transport sse --port 3001
```

---

## Tool reference

Unless noted, tools return JSON dicts from the API, or an `{"error": "...", "message": "..."}` object on connection/auth failures.

### health_check

| | |
|---|---|
| **HTTP** | `GET /health` |
| **Args** | *(none)* |

```json
{"name": "health_check", "arguments": {}}
```

### list_models

| | |
|---|---|
| **HTTP** | `GET /api/models` |
| **Args** | *(none)* |

### start_scan / launch_scan

`launch_scan` is an alias of `start_scan` (same implementation).

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target_url` | string | Yes | URL to scan |
| `scan_mode` | string | No | `website`, `api`, or `both` (default `both`) |
| `model` | string | No | LLM model id; empty = server default |
| `username` | string | No | Login username |
| `password` | string | No | Login password |
| `auth_type` | string | No | `auto`, `form`, `sso`, `oauth`, `api_key`, `bearer` |
| `extra_domains` | string | No | Comma-separated extra in-scope hosts |
| `postman_file` | string | No | Filename from `upload_api_spec` |
| `ai_instructions` | string | No | Operator guidance (see below) |
| `model_policy` | string | No | `manual` (default) or `auto` — per-phase Haiku/Sonnet/Opus |

> **Budget:** MCP cannot set `budget_cap_usd`. Auto-mode scans use the server default (**$30**). Custom caps require the Web UI (SSO).

| | |
|---|---|
| **HTTP** | `POST /api/scan` |
| **Returns** | `{"scan_id": "...", "status": "started"}` |

**Auto mode example:**

```json
{
  "name": "start_scan",
  "arguments": {
    "target_url": "https://staging.example.com",
    "scan_mode": "both",
    "model_policy": "auto"
  }
}
```

Typed launches with more fields (base64 imports, `scan_profile`) are available via [HTTP `POST /api/v1/scans`](api.md) — MCP forwards `model_policy` only.

Guide: [intelligent-model-selection.md](intelligent-model-selection.md)

### estimate_scan_cost

| | |
|---|---|
| **HTTP** | `POST /api/scans/estimate` |

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_mode` | string | No | `website`, `api`, `both` |
| `scan_intensity` | string | No | `light`, `standard`, `deep` |
| `llm_scan_depth` | string | No | `standard`, `deep` |
| `model_policy` | string | No | `manual` or `auto` |
| `manual_model` | string | No | Model id when policy is `manual` |

### get_scan_budget

| | |
|---|---|
| **HTTP** | `GET /api/scans/{scan_id}/budget` |

Returns `cap_usd`, `total_usd`, `status`, `model_choices`, `model_policy`, `approval_requires_sso`, `default_cap_usd`. Budget approval must be done in the Web UI (SSO); MCP tools for approve/stop were removed.

### get_scan_status

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_id` | string | Yes | Scan id from `start_scan` |

| | |
|---|---|
| **HTTP** | `GET /api/scan/{scan_id}` |

### stop_scan

| | |
|---|---|
| **HTTP** | `POST /api/scan/{scan_id}/stop` |

### retry_scan

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_id` | string | Yes | Failed/cancelled scan |
| `force_restart` | bool | No | Restart from phase 0 |

| | |
|---|---|
| **HTTP** | `POST /api/scan/{scan_id}/retry` |

### rescan

| | |
|---|---|
| **HTTP** | `POST /api/scan/{scan_id}/rescan` (new scan id) |

### wait_for_scan

Polls until terminal status or timeout.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `scan_id` | string | Yes | Scan id |
| `poll_interval` | int | No | Seconds between polls (default 15) |
| `timeout` | int | No | Max wait seconds (default 3600) |

| | |
|---|---|
| **HTTP** | Repeated `GET /api/scan/{scan_id}` |

### get_scan_results

| | |
|---|---|
| **HTTP** | `GET /api/results/{scan_id}` |

### get_live_activity

| | |
|---|---|
| **HTTP** | `GET /api/scan/{scan_id}/live` |

### list_scans

| | |
|---|---|
| **HTTP** | `GET /api/scans?per_page=100` (unwraps `items`) |

### generate_report

| | |
|---|---|
| **HTTP** | `POST /api/results/{scan_id}/report` |

### download_payloads

| | |
|---|---|
| **HTTP** | `GET /api/results/{scan_id}/payloads` |

### upload_api_spec

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `file_path` | string | Yes | Local path to Postman/OpenAPI file |

| | |
|---|---|
| **HTTP** | `POST /api/upload` (multipart) |

### delete_scan

| | |
|---|---|
| **HTTP** | `DELETE /api/scan/{scan_id}` |

### get_findings_summary

| | |
|---|---|
| **HTTP** | `GET /api/results/{scan_id}` (formatted text) |
| **Returns** | Markdown string |

### query_findings

Search triaged findings across completed scans.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target` | string | No | Substring match on target URL |
| `keyword` | string | No | Substring match on title |
| `severity` | string | No | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `verdict` | string | No | e.g. `TRUE_POSITIVE`, `FALSE_POSITIVE` |
| `scan_id` | string | No | Limit to one scan |

### get_scan_stats

Aggregated cost, duration, and severity breakdown (optional `scan_id` or `target` filter).

---

## Operator guidance (`ai_instructions`)

Pass natural-language rules on `launch_scan` / `start_scan` when the agent should respect scope or focus:

- Focus on auth and IDOR; do not test `/payments`.
- Use staging credentials only.
- Skip CORS checks.

Rules are forwarded to `POST /api/scan` and sanitized server-side: **8192-byte** UTF-8 cap, markdown fences removed. Details: [api.md#operator-guidance-ai_instructions](api.md#operator-guidance-ai_instructions).

---

## MCP server vs OpenClaw skill

| Component | Path | Role |
|-----------|------|------|
| **MCP server** | `mcp_server.py` | Stdio/SSE tools for Cursor, Claude Desktop, any MCP host |
| **OpenClaw skill** | `openclaw-skill/SKILL.md` | Skill bundle for [OpenClaw](https://github.com/openclaw/openclaw) chat (`http` + `shell` tools, not MCP) |
| **CLI helper** | `openclaw-skill/test_skill.py` | Standalone script (`list`, `scan`, `results`, …) without OpenClaw |

The skill teaches an OpenClaw agent which REST endpoints to call; MCP wraps those calls as named tools. For skill install and CLI examples see [openclaw-skill/README.md](../openclaw-skill/README.md).

### MCP resources and prompts

**Resources:** `scanner://health`, `scanner://models`, `scanner://scans`  
**Prompts:** `scan_website`, `scan_api` — canned instructions for the host model

---

## See also

- [HTTP API guide](api.md) — curl launch, polling, pagination
- [README](../README.md) — architecture and deployment
- [openclaw-skill/README.md](../openclaw-skill/README.md) — OpenClaw install and `test_skill.py`
- [SSO_RBAC.md](SSO_RBAC.md) — credentials for production
