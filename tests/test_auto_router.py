"""Tests for intelligent per-phase model selection."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent.auto_router import ModelSelector, ModelTier, tier_for_phase


def _sample_models():
    return [
        {
            "id": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
            "input_cost_per_m": 0.8,
            "output_cost_per_m": 4.0,
        },
        {
            "id": "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "input_cost_per_m": 3.0,
            "output_cost_per_m": 15.0,
        },
        {
            "id": "bedrock/us.anthropic.claude-opus-4-5-20251101-v1:0",
            "input_cost_per_m": 15.0,
            "output_cost_per_m": 75.0,
        },
    ]


def test_manual_policy_returns_manual_model():
    models = _sample_models()
    sel = ModelSelector(models, policy="manual", manual_model=models[0]["id"])
    assert sel.select("web_a03_xss") == models[0]["id"]
    assert sel.select("web_a01") == models[0]["id"]


def test_tier_mapping_recon_is_cheap():
    assert tier_for_phase("web_recon") == ModelTier.CHEAP
    assert tier_for_phase("api_recon") == ModelTier.CHEAP


def test_tier_mapping_authz_is_premium():
    assert tier_for_phase("web_a01") == ModelTier.PREMIUM
    assert tier_for_phase("api_authz") == ModelTier.PREMIUM


def test_auto_selects_haiku_for_recon():
    models = _sample_models()
    sel = ModelSelector(models, policy="auto", manual_model=models[0]["id"])
    picked = sel.select("web_recon")
    assert "haiku" in picked.lower()


def test_auto_selects_opus_or_sonnet_for_idor():
    models = _sample_models()
    sel = ModelSelector(models, policy="auto", manual_model=models[0]["id"])
    picked = sel.select("web_a01")
    assert "opus" in picked.lower() or "sonnet" in picked.lower()


def test_premium_fallback_when_opus_missing():
    models = [m for m in _sample_models() if "opus" not in m["id"]]
    sel = ModelSelector(models, policy="auto", manual_model=models[0]["id"])
    picked = sel.select("web_a01")
    assert picked in {m["id"] for m in models}
