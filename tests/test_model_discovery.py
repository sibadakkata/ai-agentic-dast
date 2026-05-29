"""Tests for Bedrock model discovery (inference profiles + overlay)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent import model_discovery as md


def test_friendly_name_opus_47():
    assert md._friendly_name("us.anthropic.claude-opus-4-7") == "Claude Opus 4.7"


def test_collect_candidates_prefers_inference_profile():
    raw = [
        {
            "modelId": "anthropic.claude-opus-4-7",
            "modelLifecycle": {"status": "ACTIVE"},
            "outputModalities": ["TEXT"],
        },
        {
            "modelId": "google.gemma-3-4b-it",
            "modelLifecycle": {"status": "ACTIVE"},
            "outputModalities": ["TEXT"],
        },
    ]
    profiles = ["us.anthropic.claude-opus-4-7"]
    candidates = md._collect_candidates(raw, profiles)
    assert "us.anthropic.claude-opus-4-7" in candidates
    assert "anthropic.claude-opus-4-7" not in candidates
    assert "google.gemma-3-4b-it" in candidates


def test_apply_overlay_recommended_and_premium():
    entry = {
        "id": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "name": "Claude Haiku 4 5",
        "recommended": False,
    }
    out = md._apply_overlay(entry)
    assert out["recommended"] is True
    assert "(recommended)" in out["name"]

    opus = md._apply_overlay({
        "id": "bedrock/us.anthropic.claude-opus-4-7",
        "name": "Claude Opus 4.7",
        "high_cost": False,
    })
    assert opus["high_cost"] is True
    assert "premium" in opus["name"].lower()


def test_bedrock_region_defaults_us_east_2(monkeypatch):
    monkeypatch.delenv("BEDROCK_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    assert md._bedrock_region() == "us-east-2"


def test_bedrock_region_explicit_override(monkeypatch):
    monkeypatch.setenv("BEDROCK_REGION", "us-west-2")
    assert md._bedrock_region() == "us-west-2"


def test_discover_keeps_cache_when_all_canaries_fail(monkeypatch, tmp_path):
    cache_path = tmp_path / "models_cache.json"
    monkeypatch.setattr(md, "CACHE_FILE", cache_path)
    cache_path.write_text(
        '{"models":[{"id":"bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0","name":"Haiku"}],'
        '"last_checked":"2026-01-01T00:00:00+00:00","tested":1,"passed":1,"failed":[]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        md,
        "list_bedrock_models",
        lambda: [
            {
                "modelId": "google.gemma-3-4b-it",
                "modelLifecycle": {"status": "ACTIVE"},
                "outputModalities": ["TEXT"],
            }
        ],
    )
    monkeypatch.setattr(md, "list_bedrock_inference_profiles", lambda: [])
    monkeypatch.setattr(md, "canary_test", lambda _lid, timeout=15.0: (False, "fail"))

    out = md.discover_models()
    assert len(out.get("models", [])) == 1
    assert out["models"][0]["name"] == "Haiku"
