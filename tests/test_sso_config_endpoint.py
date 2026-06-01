"""Tests for GET /api/sso/config (admin-only IdP handoff snapshot)."""
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


class TestSsoConfigEndpoint:
    def test_unauthenticated_401(self, client):
        assert client.get("/api/sso/config").status_code == 401

    def test_member_forbidden(self, client, repo):
        m = repo.create_user("user@example.com", role="user")
        _session(client, m.id)
        assert client.get("/api/sso/config").status_code == 403

    def test_admin_ok_shape(self, client, repo, monkeypatch):
        monkeypatch.setenv("SSO_USER_GROUP_IDS", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        monkeypatch.setenv("SAML_SP_ENTITY_ID", "https://rt.ai.webscanner.gendigital.com/")
        monkeypatch.setenv("SAML_SP_ACS_URL", "https://rt.ai.webscanner.gendigital.com/sso/acs")
        monkeypatch.setenv("SAML_IDP_METADATA_URL", "https://idp.example.com/metadata")
        a = repo.create_user("admin@example.com", role="admin")
        _session(client, a.id)
        r = client.get("/api/sso/config")
        assert r.status_code == 200
        data = r.json()
        assert data["enabled"] is False
        assert data["entity_id"] == "https://rt.ai.webscanner.gendigital.com/"
        assert data["acs_url"].endswith("/sso/acs")
        assert data["admin_group_auto_provision"] is False
        assert data["user_group_ids"] == {"configured": True, "count": 1}
        assert "aaaaaaaa" not in str(data)
        assert data["idp_metadata_source"] == "url"
        assert len(data["expected_attributes"]) == 3
        for attr in data["expected_attributes"]:
            assert "claim_names" in attr
            assert "purpose" in attr