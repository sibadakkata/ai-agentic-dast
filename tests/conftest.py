from __future__ import annotations

import os

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "requires_postgres: needs TEST_PG_URL")


def _postgres_reachable(url: str) -> bool:
    try:
        import psycopg

        with psycopg.connect(url, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    pg_url = os.environ.get("TEST_PG_URL", "").strip()
    if pg_url and _postgres_reachable(pg_url):
        return
    reason = (
        "Postgres not reachable at TEST_PG_URL (start: docker compose up -d postgres)"
        if pg_url
        else "TEST_PG_URL not set"
    )
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if "requires_postgres" in item.keywords:
            item.add_marker(skip)
