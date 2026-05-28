"""Postgres dual-write behaviour (Phase 0)."""
from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from web import db as scandb
from web import db_pg as pgdb


@pytest.fixture
def sqlite_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(scandb, "DB_PATH", db_file)
    scandb.init()
    yield db_file


@pytest.fixture
def reset_pg(monkeypatch):
    """Reset module-level PG state between tests."""
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


def test_dual_write_disabled_pool_not_called(sqlite_db, reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1:5432/x")
    monkeypatch.setenv("DUAL_WRITE_PG", "0")
    pgdb._enabled = None

    with mock.patch("web.db_pg._get_pool") as mock_pool:
        scandb.upsert_scan("s1", {"status": "running", "target_url": "http://x"})
        pgdb.upsert_scan("s1", {"status": "running", "target_url": "http://x"})
        mock_pool.assert_not_called()


@pytest.mark.requires_postgres
def test_dual_write_enabled_writes_both(sqlite_db, pg_url, pg_schema, reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    pgdb._pool = None

    info = {
        "status": "complete",
        "target_url": "http://example.com",
        "started": "2026-01-01T00:00:00+00:00",
    }
    scandb.upsert_scan("s2", info)
    pgdb.upsert_scan("s2", info)

    assert "s2" in scandb.load_all_scans()

    import psycopg

    with psycopg.connect(pg_url, connect_timeout=3) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE scan_id = %s", ("s2",)
        ).fetchone()[0]
    assert n == 1


def test_pg_failure_sqlite_still_ok(sqlite_db, reset_pg, monkeypatch, caplog):
    monkeypatch.setenv("DATABASE_URL", "postgresql://bad:bad@127.0.0.1:59999/nodb")
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    pgdb._pool = None

    with caplog.at_level("WARNING"):
        scandb.upsert_scan("s3", {"status": "running"})
        pgdb.upsert_scan("s3", {"status": "running"})

    assert "s3" in scandb.load_all_scans()
    assert any("Postgres dual-write" in r.message for r in caplog.records)


def test_mirror_helper_swallows_pg_errors(sqlite_db, reset_pg, monkeypatch):
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1:1/x")
    pgdb._enabled = None

    with mock.patch.object(pgdb, "upsert_scan", side_effect=RuntimeError("boom")):
        scandb.upsert_scan("s4", {"status": "ok"})
    assert "s4" in scandb.load_all_scans()


def test_health_check_disabled_no_url(reset_pg, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DUAL_WRITE_PG", "0")
    pgdb._enabled = None
    h = pgdb.health_check()
    assert h["status"] == "disabled"
    assert h["error"] == ""


def test_health_check_disabled_url_set(reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@127.0.0.1:5432/db")
    monkeypatch.setenv("DUAL_WRITE_PG", "0")
    pgdb._enabled = None
    assert pgdb.health_check()["status"] == "disabled"


@pytest.mark.requires_postgres
def test_health_check_ok(pg_url, pg_schema, reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    h = pgdb.health_check()
    assert h["status"] == "ok"
    assert h["error"] == ""


def test_health_check_degraded_bad_url(reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://bad:bad@127.0.0.1:59999/nodb")
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    h = pgdb.health_check()
    assert h["status"] == "degraded"
    assert h["error"]


@pytest.mark.requires_postgres
def test_save_finding_dual_write(pg_url, pg_schema, reset_pg, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    pgdb._enabled = None
    pgdb._pool = None

    scan_id = "s_findings"
    pgdb.upsert_scan(scan_id, {"status": "running", "target_url": "http://example.com"})
    finding = {
        "id": "f-test-1",
        "title": "SQL Injection",
        "severity": "High",
        "url": "http://example.com/api",
        "parameter": "id",
        "vulnerability": "SQLi",
    }
    pgdb.save_finding(scan_id, finding)

    import psycopg

    with psycopg.connect(pg_url, connect_timeout=3) as conn:
        row = conn.execute(
            """
            SELECT title, severity::text, url, parameter
            FROM findings WHERE scan_id = %s AND id = %s
            """,
            (scan_id, "f-test-1"),
        ).fetchone()
    assert row == ("SQL Injection", "high", "http://example.com/api", "id")


def test_mirror_save_finding_swallows_pg_errors(reset_pg, monkeypatch):
    from web.app import _mirror_to_pg

    monkeypatch.setenv("DUAL_WRITE_PG", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1:1/x")
    pgdb._enabled = None

    with mock.patch.object(pgdb, "save_finding", side_effect=RuntimeError("boom")):
        _mirror_to_pg(
            "save_finding",
            "s5",
            {"title": "x", "severity": "low", "url": "http://a", "parameter": "q"},
        )
