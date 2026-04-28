"""Unit tests for multi-identity credential parsing in ScanTarget + load_targets_from_dict."""
from __future__ import annotations

from scanners.ai_agent.auth import ScanTarget, load_targets_from_dict


def test_load_targets_from_dict_with_admin_and_tenant_b() -> None:
    t = {
        "id": "T1",
        "url": "https://app.example.com",
        "scan_mode": "both",
        "auth": {"type": "auto", "username": "alice", "password": "secret"},
        "credentials_b": {"username": "bob", "password": "bob123"},
        "credentials_admin": {"username": "root", "password": "admin123"},
        "credentials_tenant_b": {"bearer_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZW5hbnRCIn0.FAKE"},
    }
    target = load_targets_from_dict(t)
    assert isinstance(target, ScanTarget)
    assert target.credentials["username"] == "alice"
    assert target.credentials_b == {"username": "bob", "password": "bob123"}
    assert target.credentials_admin == {"username": "root", "password": "admin123"}
    assert "bearer_token" in target.credentials_tenant_b
    assert target.credentials_tenant_b["bearer_token"].startswith("eyJ")


def test_load_targets_from_dict_no_extra_identities() -> None:
    t = {
        "url": "https://app.example.com",
        "scan_mode": "both",
        "auth": {"type": "auto", "username": "u", "password": "p"},
    }
    target = load_targets_from_dict(t)
    assert target.credentials_b is None
    assert target.credentials_admin is None
    assert target.credentials_tenant_b is None


def test_load_targets_from_dict_empty_creds_ignored() -> None:
    t = {
        "url": "https://app.example.com",
        "scan_mode": "both",
        "auth": {"type": "auto"},
        "credentials_admin": {"username": "", "password": ""},
        "credentials_tenant_b": {},
    }
    target = load_targets_from_dict(t)
    assert target.credentials_admin is None
    assert target.credentials_tenant_b is None


def test_load_targets_from_dict_api_key_identity() -> None:
    t = {
        "url": "https://api.example.com",
        "scan_mode": "api",
        "auth": {"type": "auto"},
        "credentials_admin": {"api_key": "sk_test_12345678"},
    }
    target = load_targets_from_dict(t)
    assert target.credentials_admin is not None
    assert target.credentials_admin["api_key"] == "sk_test_12345678"
    assert "username" not in target.credentials_admin
