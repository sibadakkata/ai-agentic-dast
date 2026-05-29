"""OpenAPI schema smoke tests."""
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
def openapi_client(tmp_path, monkeypatch):
    monkeypatch.setattr("web.db.DB_PATH", tmp_path / "scanner.db")
    import web.db as scandb

    scandb.init()
    from fastapi.testclient import TestClient
    from web import app as app_module

    return TestClient(app_module.app)


def test_openapi_metadata(openapi_client):
    spec = openapi_client.get("/openapi.json").json()
    assert spec["info"]["title"] == "AI DAST Scanner API"
    assert spec["info"]["version"] == "1.0.0"
    servers = {s["url"] for s in spec.get("servers", [])}
    assert "https://rt.ai.webscanner.gendigital.com" in servers


def test_v1_scans_has_ai_instructions(openapi_client):
    spec = openapi_client.get("/openapi.json").json()
    post = spec["paths"]["/api/v1/scans"]["post"]
    schema = post["requestBody"]["content"]["application/json"]["schema"]
    props = schema.get("properties") or {}
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        props = spec["components"]["schemas"][ref].get("properties", {})
    assert "ai_instructions" in props
