"""Postgres read path routing (Gate 6)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from web import db as scandb
from web import db_pg as pgdb
from web import db_router


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(scandb, "DB_PATH", db_file)
    scandb.init()
    yield db_file


@pytest.fixture
def reset_pg(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DUAL_WRITE_PG", raising=False)
    pgdb._enabled = None
    pgdb._pool = None
    yield
    pgdb._enabled = None
    pgdb._pool = None


@pytest.fixture
def pg_url():
    url = os.environ.get("TEST_PG_URL", "").strip()
    if not url:
        pytest.skip("TEST_PG_URL not set")
    return url


@pytest.fixture
def pg_schema(pg_url):
    import psycopg

    mig = Path(__file__).resolve().parent.parent / "migrations" / "0001_init.sql"
    sql = mig.read_text(encoding="utf-8")
    with psycopg.connect(pg_url, connect_timeout=3) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute(sql)
        conn.commit()
    yield


def test_flag_off_uses_sqlite(sqlite_db, monkeypatch):
    monkeypatch.setenv("READ_FROM_PG", "0")
    db_router.READ_FROM_PG = False

    with mock.patch.object(scandb, "load_all_scans", return_value={"a": {}}) as mock_sql:
        with mock.patch.object(pgdb, "load_all_scans") as mock_pg:
            out = db_router.load_all_scans()
    assert out == {"a": {}}
    mock_sql.assert_called_once()
    mock_pg.assert_not_called()


def test_flag_on_uses_pg(sqlite_db, reset_pg, monkeypatch):
    monkeypatch.setenv("READ_FROM_PG", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1:5432/x")
    db_router.READ_FROM_PG = True

    with mock.patch.object(pgdb, "load_all_scans", return_value={"pg": {}}) as mock_pg:
        with mock.patch.object(scandb, "load_all_scans") as mock_sql:
            out = db_router.load_all_scans()
    assert out == {"pg": {}}
    mock_pg.assert_called_once()
    mock_sql.assert_not_called()


def test_flag_on_pg_failure_falls_back(sqlite_db, reset_pg, monkeypatch, caplog):
    monkeypatch.setenv("READ_FROM_PG", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1:5432/x")
    db_router.READ_FROM_PG = True

    with mock.patch.object(pgdb, "scan_count", side_effect=RuntimeError("pg down")):
        with mock.patch.object(scandb, "scan_count", return_value=3) as mock_sql:
            with caplog.at_level("WARNING"):
                n = db_router.scan_count()
    assert n == 3
    mock_sql.assert_called_once()
    assert any("PG read failed" in r.message for r in caplog.records)


@pytest.mark.requires_postgres
def test_read_parity_load_scans_and_results(
    sqlite_db, pg_url, pg_schema, reset_pg, monkeypatch
):
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    pgdb._pool = None

    scan_id = "parity_scan"
    info = {
        "status": "complete",
        "target_url": "http://example.com",
        "started": "2026-01-01T00:00:00+00:00",
        "findings_count": 1,
    }
    scandb.upsert_scan(scan_id, info)
    pgdb.upsert_scan(scan_id, info)

    payload = {
        "findings": [{"title": "XSS", "severity": "high"}],
        "summary": {"total_findings": 1},
    }
    payload_json = json.dumps(payload)
    scandb.save_scan_result(scan_id, payload_json)
    pgdb.save_scan_result(scan_id, payload_json)

    sqlite_scans = scandb.load_all_scans()
    pg_scans = pgdb.load_all_scans()
    assert scan_id in sqlite_scans
    assert scan_id in pg_scans
    assert sqlite_scans[scan_id]["status"] == pg_scans[scan_id]["status"]
    assert sqlite_scans[scan_id]["target_url"] == pg_scans[scan_id]["target_url"]

    assert scandb.get_scan_result(scan_id) == pgdb.get_scan_result(scan_id)
    assert scandb.scan_count() == pgdb.scan_count()


@pytest.mark.requires_postgres
def test_read_parity_cost_ledger_and_app_kv(
    sqlite_db, pg_url, pg_schema, reset_pg, monkeypatch
):
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    pgdb._pool = None

    scandb.set_cost_ledger(12.5, 3.0, 2)
    pgdb.set_cost_ledger(12.5, 3.0, 2)
    assert scandb.get_cost_ledger() == pgdb.get_cost_ledger()

    scandb.app_kv_set("scanColVisibility", '{"a":1}')
    pgdb.app_kv_set("scanColVisibility", '{"a":1}')
    assert scandb.app_kv_get("scanColVisibility") == pgdb.app_kv_get("scanColVisibility")