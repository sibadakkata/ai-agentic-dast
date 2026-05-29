"""Scan-create budget lockdown: SSO vs Basic Auth."""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

import scanners.ai_agent.budget as _budget_mod

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("DAST_AUTH_USER", "test-user")
os.environ.setdefault("DAST_AUTH_PASS", "test-pass")
os.environ.setdefault("SSO_ENABLED", "false")


@pytest.fixture(autouse=True)
def _pin_default_budget(monkeypatch):
    monkeypatch.delenv("AUTO_MODE_DEFAULT_BUDGET_USD", raising=False)
    importlib.reload(_budget_mod)
    yield
    importlib.reload(_budget_mod)


def _default_cap() -> float:
    return _budget_mod.get_default_budget_usd()


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr("web.db.DB_PATH", tmp_path / "scanner.db")
    import web.db as scandb

    scandb.init()
    yield scandb


@pytest.fixture
def scan_client(fresh_db, monkeypatch):
    from fastapi.testclient import TestClient
    from web import app as app_module

    monkeypatch.setattr(app_module, "SCANS", {})
    monkeypatch.setattr(app_module, "_use_external_scanner", lambda: False)

    class _NoThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            return None

    monkeypatch.setattr(app_module.threading, "Thread", _NoThread)
    client = TestClient(app_module.app)
    client.auth = ("test-user", "test-pass")
    return client, app_module


def _session(client, uid):
    from scanners.auth.session import create_session_token

    client.cookies.set("dast_session", create_session_token(uid))


class TestScanCreateBudgetLockdown:
    def test_auto_sso_custom_cap(self, scan_client):
        c, app = scan_client
        from scanners.users.repository import UserRepository

        user = UserRepository().create_user("owner@example.com", role="user")
        _session(c, user.id)
        resp = c.post(
            "/api/scan",
            json={
                "target_url": "https://example.com",
                "model_policy": "auto",
                "budget_cap_usd": 5.0,
            },
        )
        assert resp.status_code == 200, resp.text
        assert app.SCANS[resp.json()["scan_id"]]["budget_cap_usd"] == 5.0

    def test_auto_sso_no_cap_default_30(self, scan_client):
        c, app = scan_client
        from scanners.users.repository import UserRepository

        user = UserRepository().create_user("owner2@example.com", role="user")
        _session(c, user.id)
        resp = c.post(
            "/api/scan",
            json={"target_url": "https://example.com", "model_policy": "auto"},
        )
        assert resp.status_code == 200
        assert app.SCANS[resp.json()["scan_id"]]["budget_cap_usd"] == _default_cap()

    def test_auto_basic_auth_cap_ignored(self, scan_client):
        c, app = scan_client
        resp = c.post(
            "/api/scan",
            json={
                "target_url": "https://example.com",
                "model_policy": "auto",
                "budget_cap_usd": 5.0,
            },
            auth=c.auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert app.SCANS[data["scan_id"]]["budget_cap_usd"] == _default_cap()
        assert data.get("budget_override_ignored") is True

    def test_manual_basic_auth_cap_passthrough(self, scan_client):
        c, app = scan_client
        resp = c.post(
            "/api/scan",
            json={
                "target_url": "https://example.com",
                "model_policy": "manual",
                "budget_cap_usd": 5.0,
            },
            auth=c.auth,
        )
        assert resp.status_code == 200
        assert app.SCANS[resp.json()["scan_id"]]["budget_cap_usd"] == 5.0
