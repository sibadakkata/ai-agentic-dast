"""Route DB reads to Postgres or SQLite based on READ_FROM_PG.

When READ_FROM_PG=1, tries web.db_pg first; on any failure logs a warning
and falls back to web.db (SQLite). Default READ_FROM_PG=0 preserves
existing SQLite-only behaviour.
"""
from __future__ import annotations

import logging
import os

from web import db as sqlite_db
from web import db_pg as pg_db

log = logging.getLogger(__name__)

READ_FROM_PG = os.environ.get("READ_FROM_PG", "0").strip() == "1"

_READ_OPS = frozenset({
    "load_all_scans",
    "scan_count",
    "get_scan_result",
    "get_cost_ledger",
    "app_kv_get",
})


def _route_read(op_name: str, *args, **kwargs):
    if op_name not in _READ_OPS:
        raise ValueError(f"unknown read op: {op_name}")
    if not READ_FROM_PG:
        return getattr(sqlite_db, op_name)(*args, **kwargs)
    try:
        return getattr(pg_db, op_name)(*args, **kwargs)
    except Exception as exc:
        log.warning(
            "PG read failed for %s, falling back to SQLite: %s", op_name, exc
        )
        return getattr(sqlite_db, op_name)(*args, **kwargs)


def load_all_scans(*args, **kwargs):
    return _route_read("load_all_scans", *args, **kwargs)


def scan_count(*args, **kwargs):
    return _route_read("scan_count", *args, **kwargs)


def get_scan_result(*args, **kwargs):
    return _route_read("get_scan_result", *args, **kwargs)


def get_cost_ledger(*args, **kwargs):
    return _route_read("get_cost_ledger", *args, **kwargs)


def app_kv_get(*args, **kwargs):
    return _route_read("app_kv_get", *args, **kwargs)