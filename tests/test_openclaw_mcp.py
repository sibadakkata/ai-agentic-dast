"""MCP launch_scan forwards ai_instructions to the HTTP API."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_launch_scan_forwards_ai_instructions():
    import mcp_server

    captured = {}

    def fake_request(method, path, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["json"] = kwargs.get("json")
        return {"scan_id": "scan_test", "status": "started"}

    with patch.object(mcp_server, "_request", side_effect=fake_request):
        out = mcp_server.launch_scan(
            target_url="https://example.com",
            ai_instructions="Focus on auth; skip /admin",
        )

    assert out["scan_id"] == "scan_test"
    assert captured["path"] == "/api/scan"
    assert captured["json"]["ai_instructions"] == "Focus on auth; skip /admin"


def test_start_scan_omits_empty_ai_instructions():
    import mcp_server

    captured = {}

    def fake_request(method, path, **kwargs):
        captured["json"] = kwargs.get("json")
        return {"scan_id": "s1", "status": "started"}

    with patch.object(mcp_server, "_request", side_effect=fake_request):
        mcp_server.start_scan(target_url="https://example.com")

    assert "ai_instructions" not in captured["json"]
