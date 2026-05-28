# Web (FastAPI UI + API)

[<- Back to README](../README.md)

FastAPI on port **80** in container **dast-scanner** on EC2. Production: **https://rt.ai.webscanner.gendigital.com**.

## HTTP API

| Endpoint | Description |
|----------|-------------|
| GET /docs | Swagger UI (/openapi.json, /redoc) |
| POST /api/scan | Start scan (JSON, same fields as UI) |
| POST /api/v1/scans | Typed JSON + base64 imports |
| GET /api/scan/{id} | Status |
| GET /api/scans | Paginated list (items, total) |
| GET /api/results/{id} | Triaged findings |

Examples: [Using the API](../README.md#using-the-api). MCP: [openclaw-skill](../openclaw-skill/README.md).

## Key modules

app.py, scan_models.py, db.py, db_pg.py, scan_launcher.py, static/index.html.

## Deploy

Run scripts/check_scan_active.py before container restart.
