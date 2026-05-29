"""Tests for scan launch API and ai_instructions handling."""
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

from web.scan_models import AI_INSTRUCTIONS_MAX_BYTES, sanitize_ai_instructions


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
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

    monkeypatch.setattr(app_module.threading, "Thread", _NoThread)
    client = TestClient(app_module.app)
    client.auth = ("test-user", "test-pass")
    return client, app_module


class TestSanitizeAiInstructions:
    def test_strips_fences(self):
        raw = "focus IDOR\n```python\nprint(1)\n```\nend"
        out = sanitize_ai_instructions(raw)
        assert "```" not in (out or "")
        assert "focus IDOR" in (out or "")

    def test_truncates_over_cap(self):
        big = "x" * (AI_INSTRUCTIONS_MAX_BYTES + 4000)
        out = sanitize_ai_instructions(big)
        assert out is not None
        assert len(out.encode("utf-8")) <= AI_INSTRUCTIONS_MAX_BYTES

    def test_empty_returns_none(self):
        assert sanitize_ai_instructions("   ") is None


class TestScanLaunchApi:
    def test_post_with_ai_instructions_stored(self, scan_client):
        client, app_module = scan_client
        resp = client.post(
            "/api/scan",
            json={
                "target_url": "https://example.com",
                "ai_instructions": "Focus on authentication and IDOR only.",
            },
            auth=client.auth,
        )
        assert resp.status_code == 200, resp.text
        scan_id = resp.json()["scan_id"]
        assert app_module.SCANS[scan_id]["ai_instructions"] == (
            "Focus on authentication and IDOR only."
        )

    def test_post_without_ai_instructions_backward_compat(self, scan_client):
        client, app_module = scan_client
        resp = client.post(
            "/api/scan",
            json={"target_url": "https://example.com"},
            auth=client.auth,
        )
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]
        assert app_module.SCANS[scan_id].get("ai_instructions") is None

    def test_system_prompt_includes_operator_instructions(self):
        from scanners.ai_agent.auth import ScanTarget
        from scanners.ai_agent.prompts import build_system_prompt

        target = ScanTarget(
            id="t1",
            url="https://example.com",
            scan_mode="both",
            credentials={},
            auth_config={"type": "none"},
            ai_instructions="Do not test /payments",
        )
        prompt = build_system_prompt(target, None)
        assert "OPERATOR INSTRUCTIONS" in prompt
        assert "Do not test /payments" in prompt

    def test_v1_scans_endpoint_accepts_typed_body(self, scan_client):
        client, app_module = scan_client
        resp = client.post(
            "/api/v1/scans",
            json={
                "target_url": "https://example.com",
                "scan_mode": "both",
                "ai_instructions": "Use staging credentials only.",
            },
            auth=client.auth,
        )
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]
        assert "staging" in (app_module.SCANS[scan_id].get("ai_instructions") or "")
