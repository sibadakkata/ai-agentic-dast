# Database Schema

## Overview

The scanner uses **SQLite** (`results/scanner.db`) for all persistent state.
The schema is applied automatically on first startup by `web/db.py` `init()`.

## Files

| File | Purpose |
|------|---------|
| `schema.sql` | Canonical DDL — keep in sync with `web/db.py` `init()` |

## Tables

| Table | Description |
|-------|-------------|
| `scans` | One row per scan — metadata, status, cost, and a `data` JSON blob with the full scan info dict |
| `cost_ledger` | Singleton row tracking cumulative spend (including deleted scans) |
| `scan_results` | Full result JSON per scan — source of truth for the results API |
| `app_kv` | Key/value store for UI preferences (column visibility, theme, etc.) |

## Runtime directory layout

```
results/
├── scanner.db          # SQLite database (auto-created)
├── raw/                # Legacy per-scan JSON files (optional, back-filled into DB)
├── reports/            # Generated PDF/Excel reports
└── cache/              # Temporary cache files
```

## Fresh EC2 deployment

1. Build and start the container — the DB is created automatically on first request.
2. No manual SQL migration needed; `web/db.py` `init()` runs `CREATE TABLE IF NOT EXISTS` for all tables.
3. If migrating from an older JSON-based install, place `scans_meta.json` and/or `cost_ledger.json` in `results/` — they will be auto-migrated into SQLite on startup and renamed to `.bak`.
