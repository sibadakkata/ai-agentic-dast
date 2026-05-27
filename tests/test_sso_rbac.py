"""SSO, invites, and RBAC tests."""
from __future__ import annotations

import os
import sys
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

    monkeypatch.setattr(app_module, "SCANS", {})
    return TestClient(app_module.app)


def _session(client, uid):
    from scanners.auth.session import create_session_token

    client.cookies.set("dast_session", create_session_token(uid))


@pytest.fixture
def repo(fresh_db):
    from scanners.users.repository import UserRepository

    return UserRepository()


class TestAccessResolution:
    def test_initial_admin(self, repo, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "admin@example.com")
        from scanners.auth.access import resolve_email_access

        r = resolve_email_access("admin@example.com", "Admin", repo)
        assert r.allowed and r.user.role == "admin"

    def test_unknown_denied(self, repo, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "")
        from scanners.auth.access import resolve_email_access

        assert not resolve_email_access("x@example.com", "X", repo).allowed

    def test_invite_accept(self, repo, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "")
        a = repo.create_user("admin@example.com", role="admin")
        repo.create_invite("user@example.com", "user", a.id)
        from scanners.auth.access import resolve_email_access

        r = resolve_email_access("user@example.com", "U", repo)
        assert r.allowed and r.user.role == "user"


class TestInviteRepository:
    def test_expire_revoke(self, repo):
        a = repo.create_user("admin@example.com", role="admin")
        inv = repo.create_invite("n@example.com", "user", a.id, expires_days=-1)
        assert not repo.is_invite_valid(inv)
        inv2 = repo.create_invite("o@example.com", "user", a.id)
        assert repo.revoke_invite(inv2.id)


class TestSamlAcs:
    def test_admin_callback(self, client, repo, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "admin@example.com")
        monkeypatch.setattr("scanners.auth.saml.sso_enabled", lambda: True)
        monkeypatch.setattr(
            "scanners.auth.saml.process_acs",
            lambda r, p: {"ok": True, "email": "admin@example.com", "name": "A"},
        )
        resp = client.post("/sso/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
        assert resp.status_code == 302 and resp.headers["location"] == "/"
        assert repo.get_user_by_email("admin@example.com").role == "admin"

    def test_denied_callback(self, client, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "")
        monkeypatch.setattr("scanners.auth.saml.sso_enabled", lambda: True)
        monkeypatch.setattr(
            "scanners.auth.saml.process_acs",
            lambda r, p: {"ok": True, "email": "u@example.com", "name": "U"},
        )
        resp = client.post("/sso/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
        assert resp.status_code == 302 and "denied" in resp.headers["location"]


class TestRbacEndpoints:
    def test_member_no_users(self, client, repo):
        repo.create_user("admin@example.com", role="admin")
        m = repo.create_user("user@example.com", role="user")
        _session(client, m.id)
        assert client.get("/api/users").status_code == 403

    def test_admin_users(self, client, repo):
        a = repo.create_user("admin@example.com", role="admin")
        _session(client, a.id)
        assert client.get("/api/users").status_code == 200

    def test_member_no_delete(self, client, repo):
        from web import app as app_module

        m = repo.create_user("user@example.com", role="user")
        app_module.SCANS["s1"] = {
            "target_url": "http://t/",
            "status": "completed",
            "owner_user_id": m.id,
        }
        _session(client, m.id)
        assert client.delete("/api/scan/s1").status_code == 403

    def test_admin_delete(self, client, repo):
        from web import app as app_module

        a = repo.create_user("admin@example.com", role="admin")
        app_module.SCANS["s2"] = {
            "target_url": "http://t/",
            "status": "completed",
            "owner_user_id": a.id,
        }
        _session(client, a.id)
        assert client.delete("/api/scan/s2").status_code == 200

    def test_scan_filter(self, client, repo):
        from web import app as app_module

        a = repo.create_user("admin@example.com", role="admin")
        m = repo.create_user("user@example.com", role="user")
        app_module.SCANS["sa"] = {
            "target_url": "http://a/",
            "status": "completed",
            "started": "2026-01-02",
            "owner_user_id": a.id,
        }
        app_module.SCANS["sb"] = {
            "target_url": "http://b/",
            "status": "completed",
            "started": "2026-01-01",
            "owner_user_id": m.id,
        }
        _session(client, m.id)
        ids = {i["id"] for i in client.get("/api/scans").json()["items"]}
        assert ids == {"sb"}
