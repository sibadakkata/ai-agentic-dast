# MCP Server (Model Context Protocol)

[← Back to README](../README.md)

> **Quick start:** For Cursor/Claude wiring, tool tables, and `ai_instructions`, see **[mcp.md](mcp.md)**. This page is kept for backward-compatible links.

The scanner includes an MCP server that exposes all capabilities as tools for AI assistants like **Cursor**, **Claude Desktop**, or any MCP-compatible client.

## Setup for Cursor

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
        "SCANNER_URL": "http://YOUR-EC2-HOST",
        "SCANNER_USER": "dast-admin",
        "SCANNER_PASS": "YOUR_PASSWORD"
      }
    }
  }
}
```

3. Restart Cursor. The scanner tools will be available in Agent mode.

## Available Tools

| Tool | Description |
|------|-------------|
| `health_check` | Check if scanner is running |
| `list_models` | List available LLM models |
| `start_scan` | Start a new security scan |
| `stop_scan` | Stop a running scan (saves partial findings) |
| `retry_scan` | Re-run a failed/cancelled scan in-place |
| `get_scan_status` | Poll scan progress |
| `wait_for_scan` | Block until scan completes (with timeout) |
| `get_scan_results` | Get full triaged findings |
| `get_live_activity` | Real-time tool calls and findings for running scans |
| `get_findings_summary` | Human-readable severity summary |
| `query_findings` | Search findings across scans by target, keyword, severity, verdict |
| `get_scan_stats` | Aggregated statistics: severity/verdict breakdown, cost, duration |
| `generate_report` | Generate PDF report |
| `download_payloads` | Export all tested payloads by phase |
| `upload_api_spec` | Upload Postman/OpenAPI file |
| `list_scans` | List all scan history |
| `delete_scan` | Stop (if running) and permanently delete a scan |

## Standalone Mode

Run the MCP server directly (e.g., for the MCP Inspector):

```bash
SCANNER_URL=http://your-host SCANNER_PASS=secret python mcp_server.py --transport=streamable-http
```
