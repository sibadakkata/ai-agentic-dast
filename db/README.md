# Database Schema

[← Back to README](../README.md)

## Overview

The scanner persists state in **SQLite** on the UI host (`results/scanner.db`) and, in production, **mirrors writes to Amazon RDS PostgreSQL** while reads gradually migrate behind a feature flag.

| Store | Role | Code |
|-------|------|------|
| **SQLite** | Default **read** path; always created on UI host | `web/db.py`, `db/schema.sql` |
| **PostgreSQL** | Dual-write target; optional read source | `web/db_pg.py`, `web/db_router.py`, `migrations/` |

### Feature flags (UI / API container)

| Variable | Default | Effect |
|----------|---------|--------|
| `DATABASE_URL` | unset | Postgres connection string (from Secrets Manager in prod) |
| `DUAL_WRITE_PG` | `0` | When `1`, mirror writes to Postgres (`web/db_pg.py`) |
| `READ_FROM_PG` | `0` | When `1`, prefer Postgres reads via `web/db_router.py`; fall back to SQLite on error |

Fargate workers (`scanners/runner/`) set `DUAL_WRITE_PG=1` and `RUNNER_PG_ONLY=1` in the runner image Dockerfile.

RDS is provisioned by [infra/terraform](../infra/terraform/README.md) (PostgreSQL 16, Multi-AZ, encrypted). Credentials live in Secrets Manager **`dast/rds/master`**.

## Files

| File | Purpose |
|------|---------|
| `schema.sql` | Canonical SQLite DDL — keep in sync with `web/db.py` `init()` |
| `../migrations/0001_init.sql` | PostgreSQL schema (normalized tables + `live_events` for SSE) |

## Tables (SQLite / mirrored to PG)

| Table | Description |
|-------|-------------|
| `scans` | One row per scan — metadata, status, cost, and a `data` JSON blob with the full scan info dict |
| `cost_ledger` | Singleton row tracking cumulative spend (including deleted scans); surfaced in the UI **Cost Management** page |
| `scan_results` | Full result JSON per scan — source of truth for the results API |
| `app_kv` | Key/value store for UI preferences (column visibility, theme, etc.) |
| `users` | Platform accounts (`email`, `role` = `admin` \| `user`, SAML/local login metadata) |
| `invites` | Pending invite tokens for SSO onboarding (7-day expiry; see [SSO & RBAC](../docs/SSO_RBAC.md)) |

### `scans.data` — what's in the JSON blob

Beyond the explicit columns (`target_url`, `model`, `status`, `cost`, `findings_count`, `error`, …), the `data` JSON blob contains the snapshotted `live_*` state so it survives error / stop / pause / container-kill:

| Key | Source | Notes |
|-----|--------|-------|
| `total_tokens`, `llm_calls`, `total_tool_calls` | promoted from `live_tokens` / `live_llm_calls` / `live_tool_calls` | max() on every save so a clean finalization never regresses |
| `phases_completed`, `phases` | promoted from `len(live_phases)` / `live_phases` | full per-phase list with tool-call + finding counts |
| `phase_tools` | promoted from `live_phase_tools` | `{phase_name: {tool_name: count}}` |
| `crawled_urls`, `pages_crawled` | promoted from `live_crawled` (capped at last 500) | bounds blob size |
| `out_of_scope_urls` | promoted from `live_out_of_scope` | blocked third-party URLs |
| `progress` | in-memory append-only | user-facing log lines |

Persistence logic lives in `_snapshot_live_metrics` → `_clean_scan_for_db` in `web/app.py` and runs on every `_save_scan` call.

The `live_tests` detailed tool-call log (up to ~20 MB) is **not** in `scans.data` during the run — it is written to `scan_results.payload.summary.test_log` on graceful completion/error.

## Runtime directory layout

```
results/
├── scanner.db          # SQLite database (auto-created)
├── raw/                # Legacy per-scan JSON files (optional, back-filled into DB)
├── reports/            # Generated PDF/Excel reports
└── cache/              # Temporary cache files
```

## Backups

Weekly Lambda ([`infra/terraform/lambda/db_backup.py`](../infra/terraform/lambda/db_backup.py)) exports RDS tables to S3. Restore procedure: [infra/terraform/README.md](../infra/terraform/README.md#weekly-db-backup-to-s3).

## Fresh EC2 deployment

1. Build and start the UI container — SQLite is created automatically on first request.
2. No manual SQL migration needed for SQLite; `web/db.py` `init()` runs `CREATE TABLE IF NOT EXISTS` for all tables.
3. For Postgres, apply `migrations/0001_init.sql` to RDS once (or via your migration process).
4. Legacy JSON installs: place `scans_meta.json` and/or `cost_ledger.json` in `results/` — auto-migrated into SQLite on startup and renamed to `.bak`.
