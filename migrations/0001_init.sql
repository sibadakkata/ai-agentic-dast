-- PostgreSQL schema for DAST Scanner (Phase 0)
-- Mirrors SQLite tables in web/db.py plus normalized tables for future workers/SSE.

-- ─── Schema version ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    migration   TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── Users (mirrors SQLite users) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT,
    role            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    last_login_at   TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ─── Targets (future; optional FK from scans) ─────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    label       TEXT,
    owner_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_targets_owner ON targets(owner_id);

-- ─── Sessions (platform auth; future persistence) ─────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ─── Scan metadata (mirrors SQLite scans + owner_user_id) ─────────────
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_id       TEXT REFERENCES targets(id) ON DELETE SET NULL,
    target_url      TEXT,
    model           TEXT,
    model_name      TEXT,
    status          TEXT,
    scan_mode       TEXT,
    started         TIMESTAMPTZ,
    duration        DOUBLE PRECISION,
    cost            DOUBLE PRECISION,
    findings_count  INTEGER,
    result_file     TEXT,
    error           TEXT,
    data            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started);
CREATE INDEX IF NOT EXISTS idx_scans_user_status ON scans(user_id, status);

-- ─── Full scan results (mirrors SQLite scan_results) ──────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id     TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    payload     JSONB NOT NULL
);

-- ─── Normalized findings (extracted from payloads / live stream) ──────
CREATE TYPE finding_severity AS ENUM (
    'critical', 'high', 'medium', 'low', 'info', 'unknown'
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    title           TEXT,
    severity        finding_severity NOT NULL DEFAULT 'unknown',
    vulnerability   TEXT,
    url             TEXT,
    parameter       TEXT,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

-- ─── Phase execution log ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS phase_logs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    phase_name      TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL,
    log_text        TEXT
);

CREATE INDEX IF NOT EXISTS idx_phase_logs_scan_started ON phase_logs(scan_id, started_at);

-- ─── Live events (SSE / worker telemetry) ─────────────────────────────
CREATE TABLE IF NOT EXISTS live_events (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_live_events_scan_created ON live_events(scan_id, created_at);

-- ─── Cost ledger (mirrors SQLite singleton) ───────────────────────────
CREATE TABLE IF NOT EXISTS cost_ledger (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    all_time_cost       DOUBLE PRECISION DEFAULT 0,
    deleted_scans_cost  DOUBLE PRECISION DEFAULT 0,
    deleted_scans_count INTEGER DEFAULT 0
);

INSERT INTO cost_ledger (id, all_time_cost, deleted_scans_cost, deleted_scans_count)
VALUES (1, 0, 0, 0)
ON CONFLICT (id) DO NOTHING;

-- ─── App key/value (mirrors SQLite app_kv) ────────────────────────────
CREATE TABLE IF NOT EXISTS app_kv (
    k   TEXT PRIMARY KEY,
    v   TEXT NOT NULL
);

-- ─── Invites (mirrors SQLite invites) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS invites (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    role                TEXT NOT NULL,
    token               TEXT NOT NULL UNIQUE,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    used_by_user_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token);

-- ─── Seed schema version ──────────────────────────────────────────────
INSERT INTO schema_version (version, migration, applied_at)
VALUES (1, '0001_init', now())
ON CONFLICT (version) DO NOTHING;
