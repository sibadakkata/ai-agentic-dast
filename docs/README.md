# Documentation

[<- Back to README](../README.md)

## API / UI

| Doc | Description |
|-----|-------------|
| [api.md](api.md) | **HTTP API** — auth, launch, poll, results, uploads, troubleshooting |
| [mcp.md](mcp.md) | **MCP / OpenClaw** — Cursor and Claude Desktop wiring, tool reference |
| [rest-api.md](rest-api.md) | Extended API reference (pause, retry, reports, SDK notes) |
| [../openclaw-skill/README.md](../openclaw-skill/README.md) | OpenClaw skill bundle and `test_skill.py` CLI |

See also [architecture.md](architecture.md), [deployment.md](deployment.md), [SSO_RBAC.md](SSO_RBAC.md).

**Intelligent model selection & budget gate:** [web-ui.md](web-ui.md) (UI), [scanner-internals.md](scanner-internals.md) (engine), [rest-api.md](rest-api.md) / [api.md](api.md) (`POST /api/scans/estimate`, budget approve/stop).
