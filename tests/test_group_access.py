"""Tests for Entra group → role / access mapping."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ADMIN_GID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
USER_GID = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
OTHER_GID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr("web.db.DB_PATH", tmp_path / "scanner.db")
    import web.db as scandb

    scandb.init()
    yield scandb


@pytest.fixture
def repo(fresh_db):
    from scanners.users.repository import UserRepository

    return UserRepository()


@pytest.fixture
def group_env(monkeypatch):
    monkeypatch.setenv("SSO_ADMIN_GROUP_IDS", ADMIN_GID)
    monkeypatch.setenv("SSO_USER_GROUP_IDS", USER_GID)
    monkeypatch.delenv("INITIAL_ADMIN_EMAILS", raising=False)


class TestResolveRoleFromGroups:
    def test_admin_group_does_not_grant_admin(self, group_env):
        from scanners.auth.groups import resolve_role_from_groups

        assert resolve_role_from_groups([ADMIN_GID]) is None

    def test_user_group(self, group_env):
        from scanners.auth.groups import resolve_role_from_groups

        assert resolve_role_from_groups([USER_GID]) == "user"

    def test_user_group_wins_when_both_configured(self, group_env):
        from scanners.auth.groups import resolve_role_from_groups

        assert resolve_role_from_groups([ADMIN_GID, USER_GID]) == "user"

    def test_unknown_group(self, group_env):
        from scanners.auth.groups import resolve_role_from_groups

        assert resolve_role_from_groups([OTHER_GID]) is None

    def test_empty_groups(self, group_env):
        from scanners.auth.groups import resolve_role_from_groups

        assert resolve_role_from_groups([]) is None


class TestResolveEmailAccessGroups:
    def test_group_grants_user_without_invite(self, repo, group_env):
        from scanners.auth.access import resolve_email_access

        r = resolve_email_access("new@corp.com", "New", repo, groups=[USER_GID])
        assert r.allowed
        assert r.user is not None
        assert r.user.role == "user"
        assert r.source == "group"

    def test_no_group_no_invite_denied(self, repo, group_env):
        from scanners.auth.access import resolve_email_access

        r = resolve_email_access("new@corp.com", "New", repo, groups=[])
        assert not r.allowed
        assert r.reason == "not_in_required_group"

    def test_bootstrap_still_works(self, repo, group_env, monkeypatch):
        monkeypatch.setenv("INITIAL_ADMIN_EMAILS", "bootstrap@corp.com")
        from scanners.auth.access import resolve_email_access

        r = resolve_email_access(
            "bootstrap@corp.com",
            "Boot",
            repo,
            groups=None,
        )
        assert r.allowed
        assert r.user.role == "admin"
        assert r.source == "bootstrap"

    def test_existing_admin_not_demoted_by_user_group(self, repo, group_env):
        from scanners.auth.access import resolve_email_access

        repo.create_user("existing@corp.com", role="admin")
        r = resolve_email_access("existing@corp.com", "Ex", repo, groups=[USER_GID])
        assert r.allowed
        assert r.user.role == "admin"
        assert r.source == "existing"
