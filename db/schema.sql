-- Agentic Web Scanner – SQLite schema
-- Applied automatically by web/db.py init() on first startup.
-- Keep this file in sync with db.py when making schema changes.
--
-- Database location (at runtime): results/scanner.db
-- Journal mode: WAL  (set per-connection via PRAGMA)
-- Busy timeout:  5 s  (set per-connection via PRAGMA)

-- ─── Scan metadata ───────────────────────────────────────────────────
-- One row per scan.  The `data` column holds the full scan info dict
-- as JSON (progress log, live findings, auth state, etc.).
-- Indexed columns are used for list/filter queries in the UI.

CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    target_url     TEXT,
    model          TEXT,
    model_name     TEXT,
    status         TEXT,          -- running | completed | cancelled | error | paused | stopping
    scan_mode      TEXT,          -- full | api | passive | recon_only
    started        TEXT,          -- ISO-8601 timestamp
    duration       REAL,          -- seconds
    cost           REAL,          -- USD
    findings_count INTEGER,
    result_file    TEXT,          -- filename in results/raw/
    error          TEXT,
    data           TEXT           -- full JSON blob
);

CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started);


-- ─── Cost ledger ─────────────────────────────────────────────────────
-- Singleton row (id = 1) tracking cumulative spend across all scans,
-- including scans that have been deleted from the UI.

CREATE TABLE IF NOT EXISTS cost_ledger (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    all_time_cost       REAL    DEFAULT 0,
    deleted_scans_cost  REAL    DEFAULT 0,
    deleted_scans_count INTEGER DEFAULT 0
);

INSERT OR IGNORE INTO cost_ledger
    (id, all_time_cost, deleted_scans_cost, deleted_scans_count)
    VALUES (1, 0, 0, 0);


-- ─── Full scan results ──────────────────────────────────────────────
-- The complete raw result document (findings, summary, test_log, etc.)
-- stored as a JSON string.  This is the source of truth for the
-- /api/results/<scan_id> endpoint.  Legacy results/raw/*.json files
-- are back-filled into this table on startup.

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL         -- full result JSON
);


-- ─── App-wide key/value store ───────────────────────────────────────
-- Used for UI preferences (column visibility, theme, etc.)
-- that persist across sessions without browser localStorage.

CREATE TABLE IF NOT EXISTS app_kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);


-- ─── Platform users (SSO / RBAC) ────────────────────────────────────
-- Accounts created on SAML login or invite acceptance.
-- Mirrors web/db.py init() — introduced in SSO/RBAC merge.

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT,
    role            TEXT NOT NULL,          -- admin | user
    created_at      TEXT NOT NULL,          -- ISO-8601 timestamp
    last_login_at   TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


-- ─── Pending invites (SSO onboarding) ─────────────────────────────────
-- Token-based invites; consumed on first SAML login for that email.

CREATE TABLE IF NOT EXISTS invites (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    role                TEXT NOT NULL,      -- admin | user
    token               TEXT NOT NULL UNIQUE,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,      -- ISO-8601 timestamp
    expires_at          TEXT NOT NULL,
    used_at             TEXT,
    used_by_user_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token);
