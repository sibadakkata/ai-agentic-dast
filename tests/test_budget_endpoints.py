"""API tests for scan budget approval endpoints."""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("DAST_AUTH_USER", "test-user")
os.environ.setdefault("DAST_AUTH_PASS", "test-pass")
os.environ.setdefault("SSO_ENABLED", "false")


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr("web.db.DB_PATH", tmp_path / "scanner.db")
    import web.db as scandb

    scandb.init()
    yield scandb


@pytest.fixture
def client(fresh_db, monkeypatch):
    from fastapi.testclient import TestClient
    from web import app as app_module

    import scanners.ai_agent.budget as budget_mod

    monkeypatch.setattr(budget_mod, "AUTO_MODE_DEFAULT_BUDGET_USD", 30.0)
    monkeypatch.setattr(app_module, "AUTO_MODE_DEFAULT_BUDGET_USD", 30.0)
    monkeypatch.setattr(app_module, "SCANS", {})
    monkeypatch.setattr(app_module, "CANCEL_FLAGS", {})
    monkeypatch.setattr(app_module, "PAUSE_FLAGS", {})
    return TestClient(app_module.app), app_module


@pytest.fixture
def repo(fresh_db):
    from scanners.users.repository import UserRepository

    return UserRepository()


def _session(client, uid):
    from scanners.auth.session import create_session_token

    client.cookies.set("dast_session", create_session_token(uid))


def _seed_scan(app_module, scan_id, owner_id, *, cap=1.0, total=1.5):
    pause = threading.Event()
    pause.set()
    app_module.SCANS[scan_id] = {
        "owner_user_id": owner_id,
        "budget_cap_usd": cap,
        "budget_total_usd": total,
        "budget_status": "awaiting_approval",
        "model_policy": "manual",
        "model_choices": {},
        "status": "paused",
        "progress": [],
    }
    app_module.PAUSE_FLAGS[scan_id] = pause
    app_module.CANCEL_FLAGS[scan_id] = threading.Event()
    return pause


class TestBudgetEndpoints:
    def test_owner_can_approve(self, client, repo):
        c, app = client
        owner = repo.create_user("owner@example.com", role="user")
        _session(c, owner.id)
        sid = "scan_budget_1"
        pause = _seed_scan(app, sid, owner.id)
        resp = c.post(f"/api/scans/{sid}/budget/approve", json={"new_cap_usd": 5.0})
        assert resp.status_code == 200
        assert app.SCANS[sid]["budget_status"] == "approved"
        assert app.SCANS[sid]["budget_cap_usd"] == 5.0
        assert not pause.is_set()

    def test_non_owner_forbidden(self, client, repo):
        c, app = client
        owner = repo.create_user("owner@example.com", role="user")
        other = repo.create_user("other@example.com", role="user")
        sid = "scan_budget_2"
        _seed_scan(app, sid, owner.id)
        _session(c, other.id)
        resp = c.post(f"/api/scans/{sid}/budget/approve", json={"new_cap_usd": 5.0})
        assert resp.status_code == 403

    def test_admin_can_approve_any(self, client, repo):
        c, app = client
        owner = repo.create_user("owner@example.com", role="user")
        admin = repo.create_user("admin@example.com", role="admin")
        sid = "scan_budget_3"
        pause = _seed_scan(app, sid, owner.id)
        _session(c, admin.id)
        resp = c.post(f"/api/scans/{sid}/budget/approve", json={"new_cap_usd": 10.0})
        assert resp.status_code == 200
        assert not pause.is_set()

    def test_stop_sets_cancel(self, client, repo):
        c, app = client
        owner = repo.create_user("owner@example.com", role="user")
        sid = "scan_budget_4"
        _seed_scan(app, sid, owner.id)
        cancel = app.CANCEL_FLAGS[sid]
        _session(c, owner.id)
        resp = c.post(f"/api/scans/{sid}/budget/stop", json={})
        assert resp.status_code == 200
        assert app.SCANS[sid]["budget_status"] == "stopped_by_budget"
        assert cancel.is_set()

    def test_get_budget_readable_by_owner(self, client, repo):
        c, app = client
        owner = repo.create_user("owner@example.com", role="user")
        sid = "scan_budget_5"
        _seed_scan(app, sid, owner.id, cap=2.0, total=1.0)
        _session(c, owner.id)
        resp = c.get(f"/api/scans/{sid}/budget")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cap_usd"] == 2.0
        assert data["owner_user_id"] == owner.id
