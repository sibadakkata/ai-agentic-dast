"""PostgreSQL adapter (Phase 0 / Gate 6).

Writes mirror ``web/db.py`` when ``DUAL_WRITE_PG=1`` and ``DATABASE_URL`` is set.
Write helpers are best-effort: failures log WARNING and never propagate.

Reads are implemented for ``READ_FROM_PG=1`` (via ``web/db_router``); read helpers
raise on failure so the router can fall back to SQLite.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Any, Callable
logger = logging.getLogger(__name__)

_pool = None
_pool_lock = threading.Lock()
_enabled: bool | None = None

_COL_FIELDS = (
    "target_url", "model", "model_name", "status", "scan_mode",
    "started", "duration", "cost", "findings_count", "result_file", "error",
)

_TRANSIENT_SQLSTATES = frozenset({
    "08000", "08001", "08003", "08006", "40001", "40P01", "55P03", "57P01",
})


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


def _dual_write_flag() -> bool:
    return os.environ.get("DUAL_WRITE_PG", "0").strip() == "1"


def dual_write_enabled() -> bool:
    """True when PG dual-write is configured and active."""
    global _enabled
    if _enabled is not None:
        return _enabled
    _enabled = bool(_dual_write_flag() and _database_url())
    return _enabled


def is_configured() -> bool:
    """True when DATABASE_URL is set (may still be disabled via DUAL_WRITE_PG)."""
    return bool(_database_url())


def _sanitize_json_obj(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _sanitize_json_obj(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_json_obj(v) for v in value]
    return value


def _json_dumps_safe(obj: Any) -> str:
    return json.dumps(_sanitize_json_obj(obj), default=str)


def _parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return None


def _is_transient(exc: Exception) -> bool:
    try:
        from psycopg import OperationalError, InterfaceError
    except ImportError:
        OperationalError = InterfaceError = ()  # type: ignore
    if isinstance(exc, (OperationalError, InterfaceError)):
        return True
    sqlstate = getattr(exc, "sqlstate", None) or getattr(
        getattr(exc, "__cause__", None), "sqlstate", None
    )
    if sqlstate in _TRANSIENT_SQLSTATES:
        return True
    return "connection" in str(exc).lower()


def _retry_write(fn: Callable[[], None], *, op: str) -> None:
    if not dual_write_enabled():
        return
    delays = (0.5, 1.0, 2.0)
    last_err: Exception | None = None
    for attempt in range(len(delays) + 1):
        try:
            fn()
            return
        except Exception as exc:
            last_err = exc
            if attempt < len(delays) and _is_transient(exc):
                time.sleep(delays[attempt])
                continue
            break
    scan_hint = ""
    if "(" in op and ")" in op:
        scan_hint = f" scan_id={op.split('(')[1].split(')')[0]}"
    logger.warning("Postgres dual-write %s failed%s: %s", op, scan_hint, last_err)


def _get_pool():
    global _pool
    if _pool is not None:
        return _pool
    url = _database_url()
    if not url:
        return None
    with _pool_lock:
        if _pool is not None:
            return _pool
        try:
            from psycopg_pool import ConnectionPool
        except ImportError:
            logger.warning("psycopg_pool not installed; Postgres dual-write disabled")
            return None
        conninfo = url
        if "connect_timeout=" not in conninfo:
            sep = "&" if "?" in conninfo else "?"
            conninfo = f"{conninfo}{sep}connect_timeout=3"
        _pool = ConnectionPool(
            conninfo=conninfo,
            min_size=1,
            max_size=5,
            kwargs={"autocommit": False},
            timeout=5,
            open=True,
        )
        return _pool


def _with_conn(fn: Callable):
    pool = _get_pool()
    if pool is None:
        return
    with pool.connection() as conn:
        fn(conn)
        conn.commit()


def health_check() -> dict[str, str]:
    """Return ``{status, error}`` for admin/ops (ok | disabled | degraded)."""
    url = _database_url()
    if not url:
        return {"status": "disabled", "error": ""}
    if not _dual_write_flag():
        return {"status": "disabled", "error": ""}
    try:
        import psycopg

        conninfo = url
        if "connect_timeout=" not in conninfo:
            sep = "&" if "?" in conninfo else "?"
            conninfo = f"{conninfo}{sep}connect_timeout=3"
        with psycopg.connect(conninfo) as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "error": ""}
    except Exception as exc:
        return {"status": "degraded", "error": str(exc)}


def _scan_row(scan_id: str, info: dict) -> dict:
    row = {k: info.get(k) for k in _COL_FIELDS}
    row["scan_id"] = scan_id
    row["user_id"] = info.get("owner_user_id")
    row["started"] = _parse_ts(row.get("started"))
    data = dict(info)
    row["data"] = _json_dumps_safe(data)
    return row


def upsert_scan(scan_id: str, info: dict):
    def _do(conn):
        row = _scan_row(scan_id, info)
        conn.execute(
            """
            INSERT INTO scans (
                scan_id, user_id, target_url, model, model_name, status,
                scan_mode, started, duration, cost, findings_count,
                result_file, error, data
            ) VALUES (
                %(scan_id)s, %(user_id)s, %(target_url)s, %(model)s, %(model_name)s,
                %(status)s, %(scan_mode)s, %(started)s, %(duration)s, %(cost)s,
                %(findings_count)s, %(result_file)s, %(error)s, %(data)s::jsonb
            )
            ON CONFLICT (scan_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                target_url = EXCLUDED.target_url,
                model = EXCLUDED.model,
                model_name = EXCLUDED.model_name,
                status = EXCLUDED.status,
                scan_mode = EXCLUDED.scan_mode,
                started = EXCLUDED.started,
                duration = EXCLUDED.duration,
                cost = EXCLUDED.cost,
                findings_count = EXCLUDED.findings_count,
                result_file = EXCLUDED.result_file,
                error = EXCLUDED.error,
                data = EXCLUDED.data
            """,
            row,
        )

    _retry_write(lambda: _with_conn(_do), op=f"upsert_scan({scan_id})")


def upsert_all(scans: dict[str, dict]):
    if not scans:
        return

    def _do(conn):
        for scan_id, info in scans.items():
            row = _scan_row(scan_id, info)
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, user_id, target_url, model, model_name, status,
                    scan_mode, started, duration, cost, findings_count,
                    result_file, error, data
                ) VALUES (
                    %(scan_id)s, %(user_id)s, %(target_url)s, %(model)s,
                    %(model_name)s, %(status)s, %(scan_mode)s, %(started)s,
                    %(duration)s, %(cost)s, %(findings_count)s, %(result_file)s,
                    %(error)s, %(data)s::jsonb
                )
                ON CONFLICT (scan_id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    target_url = EXCLUDED.target_url,
                    model = EXCLUDED.model,
                    model_name = EXCLUDED.model_name,
                    status = EXCLUDED.status,
                    scan_mode = EXCLUDED.scan_mode,
                    started = EXCLUDED.started,
                    duration = EXCLUDED.duration,
                    cost = EXCLUDED.cost,
                    findings_count = EXCLUDED.findings_count,
                    result_file = EXCLUDED.result_file,
                    error = EXCLUDED.error,
                    data = EXCLUDED.data
                """,
                row,
            )

    _retry_write(lambda: _with_conn(_do), op="upsert_all")


def save_scan_result(scan_id: str, payload_json: str):
    def _do(conn):
        conn.execute(
            """
            INSERT INTO scan_results (scan_id, payload)
            VALUES (%s, %s::jsonb)
            ON CONFLICT (scan_id) DO UPDATE SET payload = EXCLUDED.payload
            """,
            (scan_id, payload_json),
        )

    _retry_write(lambda: _with_conn(_do), op=f"save_scan_result({scan_id})")


def delete_scan(scan_id: str):
    def _do(conn):
        conn.execute("DELETE FROM scan_results WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))

    _retry_write(lambda: _with_conn(_do), op=f"delete_scan({scan_id})")


def delete_scans(scan_ids: list[str]):
    if not scan_ids:
        return

    def _do(conn):
        conn.execute("DELETE FROM scan_results WHERE scan_id = ANY(%s)", (scan_ids,))
        conn.execute("DELETE FROM scans WHERE scan_id = ANY(%s)", (scan_ids,))

    _retry_write(lambda: _with_conn(_do), op="delete_scans")


def delete_all_scans():
    def _do(conn):
        conn.execute("DELETE FROM scan_results")
        conn.execute("DELETE FROM scans")

    _retry_write(lambda: _with_conn(_do), op="delete_all_scans")


def add_all_time_cost(cost: float):
    if not cost:
        return

    def _do(conn):
        conn.execute(
            "UPDATE cost_ledger SET all_time_cost = all_time_cost + %s WHERE id = 1",
            (round(cost, 6),),
        )

    _retry_write(lambda: _with_conn(_do), op="add_all_time_cost")


def add_deleted_cost(cost: float, count: int = 1):
    if not cost and not count:
        return

    def _do(conn):
        conn.execute(
            """
            UPDATE cost_ledger
            SET deleted_scans_cost = deleted_scans_cost + %s,
                deleted_scans_count = deleted_scans_count + %s
            WHERE id = 1
            """,
            (round(cost, 6), count),
        )

    _retry_write(lambda: _with_conn(_do), op="add_deleted_cost")


def set_cost_ledger(all_time: float, deleted_cost: float = 0, deleted_count: int = 0):
    def _do(conn):
        conn.execute(
            """
            UPDATE cost_ledger
            SET all_time_cost = %s,
                deleted_scans_cost = %s,
                deleted_scans_count = %s
            WHERE id = 1
            """,
            (round(all_time, 6), round(deleted_cost, 6), deleted_count),
        )

    _retry_write(lambda: _with_conn(_do), op="set_cost_ledger")


def app_kv_set(key: str, value: str):
    def _do(conn):
        conn.execute(
            """
            INSERT INTO app_kv (k, v) VALUES (%s, %s)
            ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v
            """,
            (key, value),
        )

    _retry_write(lambda: _with_conn(_do), op=f"app_kv_set({key})")


def users_insert(row: dict):
    def _do(conn):
        conn.execute(
            """
            INSERT INTO users (id, email, name, role, created_at, last_login_at, is_active)
            VALUES (
                %(id)s, %(email)s, %(name)s, %(role)s,
                %(created_at)s::timestamptz, %(last_login_at)s::timestamptz,
                %(is_active)s
            )
            ON CONFLICT (id) DO NOTHING
            """,
            {
                **row,
                "email": str(row.get("email", "")).lower().strip(),
                "is_active": bool(int(row.get("is_active", 1))),
            },
        )

    _retry_write(lambda: _with_conn(_do), op="users_insert")


def users_update(user_id: str, updates: dict):
    if not updates:
        return
    allowed = {"email", "name", "role", "created_at", "last_login_at", "is_active"}
    filtered = {k: v for k, v in updates.items() if k in allowed}
    if not filtered:
        return
    if "is_active" in filtered:
        filtered["is_active"] = bool(int(filtered["is_active"]))
    cols = ", ".join(f"{k} = %({k})s" for k in filtered)
    filtered["id"] = user_id

    def _do(conn):
        conn.execute(f"UPDATE users SET {cols} WHERE id = %(id)s", filtered)

    _retry_write(lambda: _with_conn(_do), op="users_update")


def users_delete(user_id: str):
    def _do(conn):
        conn.execute("DELETE FROM users WHERE id = %s", (user_id,))

    _retry_write(lambda: _with_conn(_do), op="users_delete")


def invites_insert(row: dict):
    def _do(conn):
        conn.execute(
            """
            INSERT INTO invites (
                id, email, role, token, created_by, created_at,
                expires_at, used_at, used_by_user_id
            ) VALUES (
                %(id)s, %(email)s, %(role)s, %(token)s, %(created_by)s,
                %(created_at)s::timestamptz, %(expires_at)s::timestamptz,
                %(used_at)s::timestamptz, %(used_by_user_id)s
            )
            ON CONFLICT (id) DO NOTHING
            """,
            row,
        )

    _retry_write(lambda: _with_conn(_do), op="invites_insert")


def invites_update(invite_id: str, updates: dict):
    if not updates:
        return
    allowed = {
        "email", "role", "token", "created_by", "created_at",
        "expires_at", "used_at", "used_by_user_id",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed}
    if not filtered:
        return
    cols = ", ".join(f"{k} = %({k})s" for k in filtered)
    filtered["id"] = invite_id

    def _do(conn):
        conn.execute(f"UPDATE invites SET {cols} WHERE id = %(id)s", filtered)

    _retry_write(lambda: _with_conn(_do), op="invites_update")


def invites_delete(invite_id: str):
    def _do(conn):
        conn.execute("DELETE FROM invites WHERE id = %s", (invite_id,))

    _retry_write(lambda: _with_conn(_do), op="invites_delete")


def save_live_event(scan_id: str, event_type: str, payload: dict):
    def _do(conn):
        conn.execute(
            """
            INSERT INTO live_events (scan_id, event_type, payload)
            VALUES (%s, %s, %s::jsonb)
            """,
            (scan_id, event_type, _json_dumps_safe(payload)),
        )

    _retry_write(lambda: _with_conn(_do), op=f"save_live_event({scan_id})")


def save_finding(scan_id: str, finding: dict, *, finding_id: str | None = None):
    import uuid as _uuid

    fid = finding_id or finding.get("id") or str(_uuid.uuid4())
    sev = (finding.get("severity") or "unknown").lower()
    if sev not in ("critical", "high", "medium", "low", "info", "unknown"):
        sev = "unknown"

    def _do(conn):
        conn.execute(
            """
            INSERT INTO findings (
                id, scan_id, title, severity, vulnerability, url, parameter, evidence
            ) VALUES (
                %s, %s, %s, %s::finding_severity, %s, %s, %s, %s::jsonb
            )
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                evidence = EXCLUDED.evidence
            """,
            (
                fid,
                scan_id,
                finding.get("title"),
                sev,
                finding.get("vulnerability") or finding.get("type"),
                finding.get("url"),
                finding.get("parameter"),
                _json_dumps_safe(finding),
            ),
        )

    _retry_write(lambda: _with_conn(_do), op=f"save_finding({scan_id})")


def save_phase_log(
    scan_id: str,
    phase_name: str,
    *,
    log_id: str | None = None,
    started_at: Any = None,
    completed_at: Any = None,
    status: str = "running",
    log_text: str | None = None,
):
    import uuid as _uuid

    pid = log_id or str(_uuid.uuid4())
    started = _parse_ts(started_at) or datetime.utcnow()
    completed = _parse_ts(completed_at)

    def _do(conn):
        conn.execute(
            """
            INSERT INTO phase_logs (
                id, scan_id, phase_name, started_at, completed_at, status, log_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                status = EXCLUDED.status,
                log_text = EXCLUDED.log_text
            """,
            (pid, scan_id, phase_name, started, completed, status, log_text),
        )

    _retry_write(lambda: _with_conn(_do), op=f"save_phase_log({scan_id})")


# ── Read path (Gate 6; used when READ_FROM_PG=1 via db_router) ─────────────


def _with_read_conn(fn: Callable[[Any], Any]) -> Any:
    """Run *fn(conn)* and return its result. Raises if PG is not configured."""
    pool = _get_pool()
    if pool is None:
        raise RuntimeError("Postgres read: DATABASE_URL not configured or pool unavailable")
    with pool.connection() as conn:
        return fn(conn)


def _row_data_to_dict(data: Any) -> dict:
    if data is None:
        return {}
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _payload_to_json_str(payload: Any) -> str | None:
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload if payload else None
    return json.dumps(payload, default=str)


def load_all_scans() -> dict[str, dict]:
    """Return ``{scan_id: info_dict}`` — same shape as ``web.db.load_all_scans``."""

    def _do(conn):
        rows = conn.execute("SELECT scan_id, data FROM scans").fetchall()
        result: dict[str, dict] = {}
        for scan_id, data in rows:
            parsed = _row_data_to_dict(data)
            if parsed:
                result[scan_id] = parsed
        return result

    return _with_read_conn(_do)


def scan_count() -> int:
    def _do(conn):
        row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        return int(row[0]) if row else 0

    return _with_read_conn(_do)


def get_scan_result(scan_id: str) -> str | None:
    def _do(conn):
        row = conn.execute(
            "SELECT payload FROM scan_results WHERE scan_id = %s", (scan_id,)
        ).fetchone()
        if not row:
            return None
        return _payload_to_json_str(row[0])

    return _with_read_conn(_do)


def get_cost_ledger() -> dict:
    def _do(conn):
        row = conn.execute(
            "SELECT all_time_cost, deleted_scans_cost, deleted_scans_count "
            "FROM cost_ledger WHERE id = 1"
        ).fetchone()
        if row:
            return {
                "all_time_cost": row[0] or 0,
                "deleted_scans_cost": row[1] or 0,
                "deleted_scans_count": row[2] or 0,
            }
        return {"all_time_cost": 0, "deleted_scans_cost": 0, "deleted_scans_count": 0}

    return _with_read_conn(_do)


def app_kv_get(key: str) -> str | None:
    def _do(conn):
        row = conn.execute("SELECT v FROM app_kv WHERE k = %s", (key,)).fetchone()
        if not row:
            return None
        val = row[0]
        return str(val) if val is not None else None

    return _with_read_conn(_do)
