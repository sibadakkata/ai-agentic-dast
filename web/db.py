"""SQLite persistence for scan metadata, full result payloads, UI prefs, and cost.

Scan list and metadata live in ``scans``; full result JSON (findings + summary)
is stored in ``scan_results`` and is the **source of truth** for the API.
Legacy ``results/raw/*.json`` files are optional; reads fall back to disk and
back-fill the DB.  PDF reports remain on disk.

UI column preferences (no browser localStorage) use ``app_kv``.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "results" / "scanner.db"

_lock = threading.Lock()

_COL_FIELDS = (
    "target_url", "model", "model_name", "status", "scan_mode",
    "started", "duration", "cost", "findings_count", "result_file", "error",
)

_UPSERT_SQL = """
    INSERT INTO scans (scan_id, target_url, model, model_name, status,
                       scan_mode, started, duration, cost, findings_count,
                       result_file, error, data)
    VALUES (:scan_id, :target_url, :model, :model_name, :status,
            :scan_mode, :started, :duration, :cost, :findings_count,
            :result_file, :error, :data)
    ON CONFLICT(scan_id) DO UPDATE SET
        target_url=excluded.target_url, model=excluded.model,
        model_name=excluded.model_name, status=excluded.status,
        scan_mode=excluded.scan_mode, started=excluded.started,
        duration=excluded.duration, cost=excluded.cost,
        findings_count=excluded.findings_count,
        result_file=excluded.result_file, error=excluded.error,
        data=excluded.data
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def _scan_to_row(scan_id: str, info: dict) -> dict:
    row = {k: info.get(k) for k in _COL_FIELDS}
    row["scan_id"] = scan_id
    row["data"] = json.dumps(info, default=str)
    return row


# ── Initialisation ───────────────────────────────────────────────────

def init():
    """Create tables and indexes.  Safe to call multiple times."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = _connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id        TEXT PRIMARY KEY,
                    target_url     TEXT,
                    model          TEXT,
                    model_name     TEXT,
                    status         TEXT,
                    scan_mode      TEXT,
                    started        TEXT,
                    duration       REAL,
                    cost           REAL,
                    findings_count INTEGER,
                    result_file    TEXT,
                    error          TEXT,
                    data           TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started);

                CREATE TABLE IF NOT EXISTS cost_ledger (
                    id                  INTEGER PRIMARY KEY CHECK (id = 1),
                    all_time_cost       REAL    DEFAULT 0,
                    deleted_scans_cost  REAL    DEFAULT 0,
                    deleted_scans_count INTEGER DEFAULT 0
                );
                INSERT OR IGNORE INTO cost_ledger
                    (id, all_time_cost, deleted_scans_cost, deleted_scans_count)
                    VALUES (1, 0, 0, 0);

                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    payload   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_kv (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id              TEXT PRIMARY KEY,
                    email           TEXT NOT NULL UNIQUE,
                    name            TEXT,
                    role            TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    last_login_at   TEXT,
                    is_active       INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

                CREATE TABLE IF NOT EXISTS invites (
                    id                  TEXT PRIMARY KEY,
                    email               TEXT NOT NULL,
                    role                TEXT NOT NULL,
                    token               TEXT NOT NULL UNIQUE,
                    created_by          TEXT NOT NULL,
                    created_at          TEXT NOT NULL,
                    expires_at          TEXT NOT NULL,
                    used_at             TEXT,
                    used_by_user_id     TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email);
                CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token);
            """)
            conn.commit()
            logger.info("SQLite DB initialised at %s", DB_PATH)
        finally:
            conn.close()


# ── Scan CRUD ────────────────────────────────────────────────────────

def upsert_scan(scan_id: str, info: dict):
    """Insert or update a single scan record."""
    row = _scan_to_row(scan_id, info)
    with _lock:
        conn = _connect()
        try:
            conn.execute(_UPSERT_SQL, row)
            conn.commit()
        finally:
            conn.close()


def upsert_all(scans: dict[str, dict]):
    """Bulk upsert every scan in one transaction."""
    if not scans:
        return
    rows = [_scan_to_row(sid, info) for sid, info in scans.items()]
    with _lock:
        conn = _connect()
        try:
            conn.executemany(_UPSERT_SQL, rows)
            conn.commit()
        finally:
            conn.close()


def load_all_scans() -> dict[str, dict]:
    """Return ``{scan_id: info_dict}`` for every persisted scan."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT scan_id, data FROM scans").fetchall()
    finally:
        conn.close()
    result: dict[str, dict] = {}
    for row in rows:
        try:
            result[row["scan_id"]] = json.loads(row["data"])
        except (json.JSONDecodeError, TypeError):
            pass
    return result


def delete_scan(scan_id: str):
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()


def delete_scans(scan_ids: list[str]):
    if not scan_ids:
        return
    with _lock:
        conn = _connect()
        try:
            placeholders = ",".join("?" for _ in scan_ids)
            conn.execute(
                f"DELETE FROM scans WHERE scan_id IN ({placeholders})", scan_ids
            )
            conn.execute(
                f"DELETE FROM scan_results WHERE scan_id IN ({placeholders})", scan_ids
            )
            conn.commit()
        finally:
            conn.close()


def delete_all_scans():
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM scan_results")
            conn.commit()
        finally:
            conn.close()


def scan_count() -> int:
    conn = _connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        conn.close()


# ── Cost Ledger ──────────────────────────────────────────────────────

def get_cost_ledger() -> dict:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT all_time_cost, deleted_scans_cost, deleted_scans_count "
            "FROM cost_ledger WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()
    if row:
        return {
            "all_time_cost": row["all_time_cost"] or 0,
            "deleted_scans_cost": row["deleted_scans_cost"] or 0,
            "deleted_scans_count": row["deleted_scans_count"] or 0,
        }
    return {"all_time_cost": 0, "deleted_scans_cost": 0, "deleted_scans_count": 0}


def add_all_time_cost(cost: float):
    """Atomically increment the all-time cost counter."""
    if not cost:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE cost_ledger SET all_time_cost = all_time_cost + ? WHERE id = 1",
                (round(cost, 6),),
            )
            conn.commit()
        finally:
            conn.close()


def add_deleted_cost(cost: float, count: int = 1):
    """Atomically increment the deleted-scans counters."""
    if not cost and not count:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE cost_ledger "
                "SET deleted_scans_cost = deleted_scans_cost + ?, "
                "    deleted_scans_count = deleted_scans_count + ? "
                "WHERE id = 1",
                (round(cost, 6), count),
            )
            conn.commit()
        finally:
            conn.close()


def set_cost_ledger(all_time: float, deleted_cost: float = 0, deleted_count: int = 0):
    """Set absolute values (used during migration from JSON)."""
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE cost_ledger "
                "SET all_time_cost = ?, deleted_scans_cost = ?, deleted_scans_count = ? "
                "WHERE id = 1",
                (round(all_time, 6), round(deleted_cost, 6), deleted_count),
            )
            conn.commit()
        finally:
            conn.close()


# ── Migration from JSON ──────────────────────────────────────────────

def migrate_from_json(scans_meta_file: Path, cost_ledger_file: Path) -> bool:
    """One-time migration from the old JSON files into SQLite.

    Only runs when the scans table is empty and at least one JSON file exists.
    The JSON files are kept on disk (renamed to .bak) for safety.
    """
    if scan_count() > 0:
        return False

    migrated = False

    if scans_meta_file.exists():
        try:
            data = json.loads(scans_meta_file.read_text(encoding="utf-8"))
            if data:
                upsert_all(data)
                bak = scans_meta_file.with_suffix(".json.bak")
                scans_meta_file.rename(bak)
                logger.info("Migrated %d scans from JSON → SQLite (backup: %s)", len(data), bak)
                migrated = True
        except Exception:
            logger.exception("Failed to migrate scans_meta.json")

    if cost_ledger_file.exists():
        try:
            ledger = json.loads(cost_ledger_file.read_text(encoding="utf-8"))
            set_cost_ledger(
                ledger.get("all_time_cost", 0),
                ledger.get("deleted_scans_cost", 0),
                ledger.get("deleted_scans_count", 0),
            )
            bak = cost_ledger_file.with_suffix(".json.bak")
            cost_ledger_file.rename(bak)
            logger.info("Migrated cost_ledger from JSON → SQLite (backup: %s)", bak)
            migrated = True
        except Exception:
            logger.exception("Failed to migrate cost_ledger.json")

    return migrated


# ── Full scan result JSON (findings + metadata) ─────────────────────────

def save_scan_result(scan_id: str, payload_json: str):
    """Store the complete raw result document for *scan_id*."""
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO scan_results (scan_id, payload) VALUES (?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET payload = excluded.payload
                """,
                (scan_id, payload_json),
            )
            conn.commit()
        finally:
            conn.close()


def get_scan_result(scan_id: str) -> str | None:
    """Return raw JSON string or None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload FROM scan_results WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    finally:
        conn.close()
    if row and row["payload"]:
        return row["payload"]
    return None


def list_findings(scan_id: str) -> list[dict]:
    """Findings from scan_results JSON (pre-normalized PG rows)."""
    raw = get_scan_result(scan_id)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    findings = data.get("findings") if isinstance(data, dict) else None
    return findings if isinstance(findings, list) else []


# ── App-wide key/value (UI preferences, etc.) ───────────────────────────

def app_kv_get(key: str) -> str | None:
    conn = _connect()
    try:
        row = conn.execute("SELECT v FROM app_kv WHERE k = ?", (key,)).fetchone()
    finally:
        conn.close()
    return row["v"] if row else None


def app_kv_set(key: str, value: str):
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO app_kv (k, v) VALUES (?, ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v
                """,
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()


# ── Users ────────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    return dict(row)


def users_insert(row: dict):
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO users (id, email, name, role, created_at, last_login_at, is_active)
                VALUES (:id, :email, :name, :role, :created_at, :last_login_at, :is_active)
                """,
                row,
            )
            conn.commit()
        finally:
            conn.close()


def users_get_by_id(user_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row)


def users_get_by_email(email: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row)


def users_list_all(*, include_inactive: bool = False) -> list[dict]:
    conn = _connect()
    try:
        if include_inactive:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM users WHERE is_active = 1 ORDER BY created_at DESC"
            ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def users_update(user_id: str, updates: dict):
    if not updates:
        return
    cols = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [user_id]
    with _lock:
        conn = _connect()
        try:
            conn.execute(f"UPDATE users SET {cols} WHERE id = ?", vals)
            conn.commit()
        finally:
            conn.close()


def users_delete(user_id: str) -> bool:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


# ── Invites ──────────────────────────────────────────────────────────────

def invites_insert(row: dict):
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO invites (
                    id, email, role, token, created_by, created_at,
                    expires_at, used_at, used_by_user_id
                ) VALUES (
                    :id, :email, :role, :token, :created_by, :created_at,
                    :expires_at, :used_at, :used_by_user_id
                )
                """,
                row,
            )
            conn.commit()
        finally:
            conn.close()


def invites_get_by_id(invite_id: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row)


def invites_get_pending_by_email(email: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT * FROM invites
            WHERE email = ? AND used_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (email.lower().strip(),),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_dict(row)


def invites_list_pending() -> list[dict]:
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT * FROM invites
            WHERE used_at IS NULL
            ORDER BY created_at DESC
            """
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def invites_update(invite_id: str, updates: dict):
    if not updates:
        return
    cols = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [invite_id]
    with _lock:
        conn = _connect()
        try:
            conn.execute(f"UPDATE invites SET {cols} WHERE id = ?", vals)
            conn.commit()
        finally:
            conn.close()


def invites_delete(invite_id: str) -> bool:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM invites WHERE id = ?", (invite_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
