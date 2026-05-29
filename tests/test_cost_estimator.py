"""Tests for rough scan cost estimation."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent.budget import estimate_scan_cost


def _models():
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


def test_estimate_ordering():
    est = estimate_scan_cost(
        "both", "deep", "standard", "manual",
        _models()[0]["id"], _models(),
    )
    assert est["low_usd"] <= est["expected_usd"] <= est["high_usd"]


def test_auto_estimate_gte_manual_haiku():
    models = _models()
    manual = estimate_scan_cost(
        "both", "deep", "standard", "manual", models[0]["id"], models,
    )
    auto = estimate_scan_cost(
        "both", "deep", "standard", "auto", None, models,
    )
    assert auto["expected_usd"] >= manual["expected_usd"]


def test_manual_uses_named_model_pricing():
    models = _models()
    haiku = estimate_scan_cost(
        "both", "standard", "standard", "manual", models[0]["id"], models,
    )
    opus = estimate_scan_cost(
        "both", "standard", "standard", "manual", models[2]["id"], models,
    )
    assert opus["expected_usd"] > haiku["expected_usd"]
