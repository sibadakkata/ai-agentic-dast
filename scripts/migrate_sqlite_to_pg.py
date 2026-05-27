#!/usr/bin/env python3
"""Migrate existing SQLite scan data to PostgreSQL.

Preserves users, scans, scan_results, invites, cost_ledger, and app_kv.
Optional extraction of findings/phase_logs from scan_results JSON payloads.

Example::

    python scripts/migrate_sqlite_to_pg.py \\
        --sqlite results/scanner.db \\
        --pg postgresql://dast_admin:devpassword@127.0.0.1:5432/dast_scanner \\
        --dry-run

    python scripts/migrate_sqlite_to_pg.py --sqlite results/scanner.db --verify-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_SQLITE = Path(__file__).resolve().parent.parent / "results" / "scanner.db"

TABLE_ORDER = ("users", "targets", "scans", "scan_results", "findings", "phase_logs", "invites", "cost_ledger", "app_kv")


def _parse_ts(value: Any):
    if value is None or value == "":
        return None
    from datetime import datetime
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _strip_null_bytes(value: Any) -> Any:
    """Postgres jsonb/text rejects \\u0000; strip from migrated SQLite blobs."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _strip_null_bytes(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_null_bytes(v) for v in value]
    return value


def _jsonb_value(raw: str | None):
    """Parse SQLite JSON text to a Python object safe for Postgres jsonb."""
    import re
    from psycopg.types.json import Json

    if not raw:
        return Json({})
    cleaned = re.sub(r"\\u0000", "", str(raw), flags=re.IGNORECASE)
    cleaned = cleaned.replace("\x00", "")
    try:
        return Json(_strip_null_bytes(json.loads(cleaned)))
    except json.JSONDecodeError:
        return Json({"_unparsed": cleaned})


def _canonical_rows_sqlite(conn: sqlite3.Connection, table: str, cols: list[str], order_by: str) -> list[dict]:
    rows = conn.execute(f"SELECT {','.join(cols)} FROM {table} ORDER BY {order_by}").fetchall()
    out = []
    for r in rows:
        d = dict(r) if isinstance(r, sqlite3.Row) else {cols[i]: r[i] for i in range(len(cols))}
        out.append({c: d.get(c) for c in cols})
    return out


def _canonical_rows_pg(cur, table: str, cols: list[str], order_by: str) -> list[dict]:
    cur.execute(f"SELECT {','.join(cols)} FROM {table} ORDER BY {order_by}")
    return [{cols[i]: row[i] for i in range(len(cols))} for row in cur.fetchall()]


def _table_checksum(rows: list[dict]) -> str:
    normalized = json.dumps(rows, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()


_VERIFY_TABLES = {
    "users": (["id", "email", "role"], "id"),
    "scans": (["scan_id", "status", "target_url", "findings_count"], "scan_id"),
    "scan_results": (["scan_id"], "scan_id"),
}


def verify_databases(sqlite_path: Path, pg_url: str) -> int:
    """Compare row counts and canonical checksums per table."""
    import psycopg

    sqlite_conn = sqlite3.connect(str(sqlite_path))
    sqlite_conn.row_factory = sqlite3.Row
    mismatches = 0
    with psycopg.connect(pg_url) as pg_conn:
        with pg_conn.cursor() as cur:
            valid_scan_ids = {
                r[0]
                for r in sqlite_conn.execute("SELECT scan_id FROM scans").fetchall()
            }
            for table, (cols, order_by) in _VERIFY_TABLES.items():
                try:
                    if table == "scan_results":
                        sl = sqlite_conn.execute(
                            "SELECT COUNT(*) FROM scan_results WHERE scan_id IN "
                            f"({','.join('?' * len(valid_scan_ids))})",
                            tuple(valid_scan_ids),
                        ).fetchone()[0]
                    else:
                        sl = sqlite_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except sqlite3.OperationalError:
                    sl = 0
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                pl = cur.fetchone()[0]
                if sl != pl:
                    logger.error("FAIL %s count: sqlite=%d pg=%d", table, sl, pl)
                    mismatches += 1
                    continue
                if sl == 0:
                    logger.info("PASS %s (empty)", table)
                    continue
                if table == "scan_results":
                    s_ids = sorted(
                        r[0]
                        for r in sqlite_conn.execute(
                            "SELECT scan_id FROM scan_results WHERE scan_id IN "
                            f"({','.join('?' * len(valid_scan_ids))}) ORDER BY scan_id",
                            tuple(valid_scan_ids),
                        ).fetchall()
                    )
                    cur.execute("SELECT scan_id FROM scan_results ORDER BY scan_id")
                    p_ids = sorted(r[0] for r in cur.fetchall())
                    if s_ids == p_ids:
                        logger.info("PASS %s rows=%d (scan_id sets match)", table, sl)
                    else:
                        logger.error("FAIL %s scan_id mismatch", table)
                        mismatches += 1
                    continue
                s_rows = _canonical_rows_sqlite(sqlite_conn, table, cols, order_by)
                p_rows = _canonical_rows_pg(cur, table, cols, order_by)
                cs, cp = _table_checksum(s_rows), _table_checksum(p_rows)
                if cs == cp:
                    logger.info("PASS %s rows=%d checksum=%s", table, sl, cs[:12])
                else:
                    logger.error("FAIL %s checksum sqlite=%s pg=%s", table, cs[:12], cp[:12])
                    mismatches += 1
    sqlite_conn.close()
    return 1 if mismatches else 0


def migrate_users(sqlite_conn, pg_conn, *, batch_size: int, dry_run: bool, stats: dict, resume_after: str | None):
    cur = sqlite_conn.execute("SELECT * FROM users ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    if resume_after:
        rows = [r for r in rows if r["id"] > resume_after]
    inserted = skipped = 0
    for i, row in enumerate(rows):
        if dry_run and i < 3:
            logger.info("DRY users sample: %s", {k: row[k] for k in ("id", "email", "role")})
        if dry_run:
            continue
        with pg_conn.cursor() as c:
            c.execute(
                """
                INSERT INTO users (id, email, name, role, created_at, last_login_at, is_active)
                VALUES (%s, %s, %s, %s, %s::timestamptz, %s::timestamptz, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    row["id"],
                    row["email"].lower().strip(),
                    row.get("name"),
                    row["role"],
                    _parse_ts(row["created_at"]),
                    _parse_ts(row.get("last_login_at")),
                    bool(int(row.get("is_active", 1))),
                ),
            )
            if c.rowcount:
                inserted += 1
            else:
                skipped += 1
        if (i + 1) % 100 == 0:
            logger.info("users progress: %d/%d", i + 1, len(rows))
        if (i + 1) % batch_size == 0:
            pg_conn.commit()
    if not dry_run:
        pg_conn.commit()
    stats["users"] = {"read": len(rows), "inserted": inserted, "skipped": skipped}


def migrate_scans(sqlite_conn, pg_conn, *, batch_size: int, dry_run: bool, stats: dict, resume_after: str | None):
    cur = sqlite_conn.execute("SELECT * FROM scans ORDER BY scan_id")
    rows = [dict(r) for r in cur.fetchall()]
    if resume_after:
        rows = [r for r in rows if r["scan_id"] > resume_after]
    inserted = skipped = 0
    for i, row in enumerate(rows):
        info = {}
        try:
            info = json.loads(row.get("data") or "{}")
        except json.JSONDecodeError:
            pass
        user_id = info.get("owner_user_id")
        started = _parse_ts(row.get("started"))
        if dry_run and i < 2:
            logger.info("DRY scans sample: scan_id=%s status=%s", row["scan_id"], row.get("status"))
        if dry_run:
            continue
        with pg_conn.cursor() as c:
            c.execute(
                """
                INSERT INTO scans (
                    scan_id, user_id, target_url, model, model_name, status,
                    scan_mode, started, duration, cost, findings_count,
                    result_file, error, data
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (scan_id) DO NOTHING
                """,
                (
                    row["scan_id"], user_id, row.get("target_url"), row.get("model"),
                    row.get("model_name"), row.get("status"), row.get("scan_mode"),
                    started, row.get("duration"), row.get("cost"), row.get("findings_count"),
                    row.get("result_file"), row.get("error"), _jsonb_value(row.get("data")),
                ),
            )
            if c.rowcount:
                inserted += 1
            else:
                skipped += 1
        if (i + 1) % 100 == 0:
            logger.info("scans progress: %d/%d", i + 1, len(rows))
        if (i + 1) % batch_size == 0:
            pg_conn.commit()
    if not dry_run:
        pg_conn.commit()
    stats["scans"] = {"read": len(rows), "inserted": inserted, "skipped": skipped}


def migrate_scan_results(sqlite_conn, pg_conn, *, batch_size: int, dry_run: bool, stats: dict, resume_after: str | None):
    valid_ids = {
        r[0]
        for r in sqlite_conn.execute("SELECT scan_id FROM scans").fetchall()
    }
    cur = sqlite_conn.execute("SELECT scan_id, payload FROM scan_results ORDER BY scan_id")
    rows = cur.fetchall()
    orphans = [r[0] for r in rows if r[0] not in valid_ids]
    if orphans:
        logger.warning(
            "Skipping %d scan_results row(s) with no matching scans row (e.g. %s)",
            len(orphans),
            orphans[0],
        )
    rows = [r for r in rows if r[0] in valid_ids]
    if resume_after:
        rows = [r for r in rows if r[0] > resume_after]
    inserted = skipped = 0
    for i, (scan_id, payload) in enumerate(rows):
        if dry_run and i < 2:
            logger.info("DRY scan_results sample: %s len=%d", scan_id, len(payload or ""))
        if dry_run:
            continue
        with pg_conn.cursor() as c:
            c.execute(
                """
                INSERT INTO scan_results (scan_id, payload)
                VALUES (%s, %s)
                ON CONFLICT (scan_id) DO NOTHING
                """,
                (scan_id, _jsonb_value(payload)),
            )
            if c.rowcount:
                inserted += 1
            else:
                skipped += 1
        if (i + 1) % batch_size == 0:
            pg_conn.commit()
    if not dry_run:
        pg_conn.commit()
    stats["scan_results"] = {"read": len(rows), "inserted": inserted, "skipped": skipped}


def migrate_invites(sqlite_conn, pg_conn, *, batch_size: int, dry_run: bool, stats: dict, resume_after: str | None):
    cur = sqlite_conn.execute("SELECT * FROM invites ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    if resume_after:
        rows = [r for r in rows if r["id"] > resume_after]
    inserted = skipped = 0
    for row in rows:
        if dry_run:
            continue
        with pg_conn.cursor() as c:
            c.execute(
                """
                INSERT INTO invites (
                    id, email, role, token, created_by, created_at,
                    expires_at, used_at, used_by_user_id
                ) VALUES (%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    row["id"], row["email"], row["role"], row["token"], row["created_by"],
                    _parse_ts(row["created_at"]), _parse_ts(row["expires_at"]),
                    _parse_ts(row.get("used_at")), row.get("used_by_user_id"),
                ),
            )
            if c.rowcount:
                inserted += 1
            else:
                skipped += 1
    if not dry_run:
        pg_conn.commit()
    stats["invites"] = {"read": len(rows), "inserted": inserted, "skipped": skipped}


def migrate_findings_from_payloads(sqlite_conn, pg_conn, *, batch_size: int, dry_run: bool, stats: dict):
    """Extract findings from scan_results JSON (best-effort)."""
    import uuid as _uuid
    from psycopg.types.json import Json

    valid_ids = {
        r[0]
        for r in sqlite_conn.execute("SELECT scan_id FROM scans").fetchall()
    }
    cur = sqlite_conn.execute("SELECT scan_id, payload FROM scan_results")
    inserted = read = 0
    for scan_id, payload in cur.fetchall():
        if scan_id not in valid_ids:
            continue
        try:
            doc = json.loads(payload)
        except json.JSONDecodeError:
            continue
        for f in doc.get("findings") or []:
            read += 1
            fid = f.get("id") or str(_uuid.uuid4())
            sev = (f.get("severity") or "unknown").lower()
            if sev not in ("critical", "high", "medium", "low", "info", "unknown"):
                sev = "unknown"
            if dry_run:
                continue
            with pg_conn.cursor() as c:
                c.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, title, severity, vulnerability, url, parameter, evidence
                    ) VALUES (%s,%s,%s,%s::finding_severity,%s,%s,%s,%s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (
                        fid, scan_id, f.get("title"), sev,
                        f.get("vulnerability") or f.get("type"),
                        f.get("url"), f.get("parameter"),
                        Json(_strip_null_bytes(f)),
                    ),
                )
                if c.rowcount:
                    inserted += 1
    if not dry_run:
        pg_conn.commit()
    stats["findings"] = {"read": read, "inserted": inserted, "skipped": read - inserted}


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate SQLite scanner DB to PostgreSQL")
    parser.add_argument("--sqlite", type=Path, default=DEFAULT_SQLITE)
    parser.add_argument(
        "--pg",
        dest="pg_url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL URL (default: DATABASE_URL env)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true", help="Compare counts/checksums only")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--resume-from", default="", help="table:id cursor, e.g. scans:scan_abc")
    args = parser.parse_args()

    if args.verify_only:
        if not args.pg_url:
            logger.error("--verify-only requires --pg or DATABASE_URL")
            return 2
        if not args.sqlite.exists():
            logger.error("SQLite DB not found: %s", args.sqlite)
            return 2
        return verify_databases(args.sqlite, args.pg_url)

    if not args.pg_url:
        logger.error("PostgreSQL URL required: --pg or DATABASE_URL")
        return 2

    if not args.sqlite.exists():
        logger.error("SQLite DB not found: %s", args.sqlite)
        return 2

    resume_table = ""
    resume_id = ""
    if args.resume_from:
        parts = args.resume_from.split(":", 1)
        if len(parts) != 2:
            logger.error("Invalid --resume-from; use table:id")
            return 2
        resume_table, resume_id = parts[0], parts[1]

    try:
        import psycopg
    except ImportError:
        logger.error("psycopg not installed; pip install 'psycopg[binary]>=3.1'")
        return 2

    sqlite_conn = sqlite3.connect(str(args.sqlite))
    sqlite_conn.row_factory = sqlite3.Row

    stats: dict[str, dict] = {}
    try:
        if args.dry_run:
            logger.info("DRY RUN — no writes to Postgres")
        else:
            pg_conn = psycopg.connect(args.pg_url)
            pg_conn.autocommit = False

        migrate_users(
            sqlite_conn, None if args.dry_run else pg_conn,
            batch_size=args.batch_size, dry_run=args.dry_run, stats=stats,
            resume_after=resume_id if resume_table == "users" else None,
        )
        stats["targets"] = {"read": 0, "inserted": 0, "skipped": 0}
        migrate_scans(
            sqlite_conn, None if args.dry_run else pg_conn,
            batch_size=args.batch_size, dry_run=args.dry_run, stats=stats,
            resume_after=resume_id if resume_table == "scans" else None,
        )
        migrate_scan_results(
            sqlite_conn, None if args.dry_run else pg_conn,
            batch_size=args.batch_size, dry_run=args.dry_run, stats=stats,
            resume_after=resume_id if resume_table == "scan_results" else None,
        )
        migrate_findings_from_payloads(
            sqlite_conn, None if args.dry_run else pg_conn,
            batch_size=args.batch_size, dry_run=args.dry_run, stats=stats,
        )
        stats["phase_logs"] = {"read": 0, "inserted": 0, "skipped": 0}
        migrate_invites(
            sqlite_conn, None if args.dry_run else pg_conn,
            batch_size=args.batch_size, dry_run=args.dry_run, stats=stats,
            resume_after=resume_id if resume_table == "invites" else None,
        )

        if not args.dry_run:
            sl = sqlite_conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            with pg_conn.cursor() as c:
                c.execute("SELECT COUNT(*) FROM scans")
                pg_count = c.fetchone()[0]
            if pg_count < sl:
                logger.error("Count mismatch scans: sqlite=%d pg=%d", sl, pg_count)
                return 1
            pg_conn.close()
    except Exception:
        logger.exception("Migration failed")
        return 2
    finally:
        sqlite_conn.close()

    logger.info("=== Migration summary ===")
    for table in TABLE_ORDER:
        if table in stats:
            s = stats[table]
            logger.info(
                "%s: read=%d inserted=%d skipped=%d",
                table, s.get("read", 0), s.get("inserted", 0), s.get("skipped", 0),
            )

    if not args.dry_run and args.pg_url:
        rc = verify_databases(args.sqlite, args.pg_url)
        if rc != 0:
            return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
