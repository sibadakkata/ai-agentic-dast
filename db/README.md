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

Persistence logic lives in `_snapshot_live_metrics` → `_clean_scan_for_db` in `web/app.py` and runs on every `_save_scan` call (every 10 tool calls, every 5 findings, each phase boundary, and a 30 s autosave tick).

The `live_tests` detailed tool-call log (up to ~20 MB) is **not** included here — it is written to `scan_results.payload.summary.test_log` only on graceful completion/error/stop.

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
