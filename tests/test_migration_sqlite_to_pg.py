"""SQLite to Postgres migration script tests."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MIGRATE = ROOT / "scripts" / "migrate_sqlite_to_pg.py"


@pytest.fixture
def pg_url():
    url = os.environ.get("TEST_PG_URL", "").strip()
    if not url:
        pytest.skip("TEST_PG_URL not set")
    return url


@pytest.fixture
def pg_schema(pg_url):
    import psycopg

    mig_sql = (ROOT / "migrations" / "0001_init.sql").read_text(encoding="utf-8")
    with psycopg.connect(pg_url) as conn:
        conn.execute("DROP SCHEMA public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute(mig_sql)
        conn.commit()
    yield


@pytest.fixture
def seeded_sqlite(tmp_path):
    db = tmp_path / "scanner.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE TABLE scans (
            scan_id TEXT PRIMARY KEY, target_url TEXT, model TEXT, model_name TEXT,
            status TEXT, scan_mode TEXT, started TEXT, duration REAL, cost REAL,
            findings_count INTEGER, result_file TEXT, error TEXT, data TEXT
        );
        CREATE TABLE users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT,
            created_at TEXT, last_login_at TEXT, is_active INTEGER
        );
        CREATE TABLE scan_results (scan_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        """
    )
    conn.execute(
        "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
        ("u1", "a@b.com", "A", "admin", "2026-01-01T00:00:00+00:00", None, 1),
    )
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "scan_1",
            "http://t",
            "m",
            "M",
            "complete",
            "web",
            "2026-01-01T00:00:00+00:00",
            1.0,
            0.1,
            1,
            None,
            None,
            json.dumps({"owner_user_id": "u1"}),
        ),
    )
    conn.execute(
        "INSERT INTO scan_results VALUES (?,?)",
        (
            "scan_1",
            json.dumps({"findings": [{"title": "xss", "severity": "high", "id": "f1"}]}),
        ),
    )
    conn.commit()
    conn.close()
    return db


def _run_migrate(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(MIGRATE), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env or os.environ,
    )


@pytest.mark.requires_postgres
def test_migration_dry_run(seeded_sqlite, pg_url, pg_schema):
    r = _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url, "--dry-run")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "DRY RUN" in r.stdout

    import psycopg

    with psycopg.connect(pg_url) as conn:
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert n == 0


@pytest.mark.requires_postgres
def test_migration_row_counts(seeded_sqlite, pg_url, pg_schema):
    r = _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url)
    assert r.returncode == 0, r.stderr + r.stdout

    import psycopg

    with psycopg.connect(pg_url) as conn:
        users = conn.execute("SELECT email FROM users WHERE id = %s", ("u1",)).fetchone()
        scans = conn.execute(
            "SELECT status FROM scans WHERE scan_id = %s", ("scan_1",)
        ).fetchone()
        findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = %s", ("scan_1",)
        ).fetchone()[0]

    assert users[0] == "a@b.com"
    assert scans[0] == "complete"
    assert findings >= 1


@pytest.mark.requires_postgres
def test_migration_verify_only(seeded_sqlite, pg_url, pg_schema):
    _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url)
    r = _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url, "--verify-only")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "PASS" in r.stdout


@pytest.mark.requires_postgres
def test_migration_idempotent(seeded_sqlite, pg_url, pg_schema):
    _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url)
    r2 = _run_migrate("--sqlite", str(seeded_sqlite), "--pg", pg_url)
    assert r2.returncode == 0, r2.stderr + r2.stdout

    import psycopg

    with psycopg.connect(pg_url) as conn:
        n_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        n_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    assert n_users == 1
    assert n_scans == 1
