"""SQLite persistence for scan metadata and cost tracking.

Replaces the previous flat-JSON approach (scans_meta.json, cost_ledger.json)
with a single scanner.db file using WAL mode for safe concurrent access.

Data that stays as files (too large for SQLite rows):
  - results/raw/*.json   — full scan results with findings
  - results/reports/*.pdf — generated PDF reports
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
            conn.commit()
        finally:
            conn.close()


def delete_all_scans():
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scans")
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
