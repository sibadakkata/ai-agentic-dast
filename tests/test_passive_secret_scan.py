"""Unit tests for ``scan_for_hardcoded_secrets`` in passive recon."""
from __future__ import annotations

import pytest

from scanners.ai_agent.passive_recon import scan_for_hardcoded_secrets


def test_stripe_live_detected_and_evidence_masked() -> None:
    # Avoid ``apiKey`` substring so the generic API-key regex does not claim the Stripe value.
    body = 'stripePublishable = "sk_live_1234567890abcdefghijklmnop"'
    hits = scan_for_hardcoded_secrets(body, source_url="https://app.example/config.js", source_label="unit")
    assert hits
    titles = " ".join(h["title"] for h in hits)
    assert "Stripe live" in titles
    ev = next(h["evidence"] for h in hits if "Stripe live" in h["title"])
    assert "sk_live_1234567890abcdefghijklmnop" not in ev
    assert "Masked" in ev or "\u2026" in ev or "..." in ev


def test_github_classic_pat() -> None:
    # GitHub classic PAT is ``ghp_`` + exactly 36 alphanumeric characters.
    tail = "abcdefghijklmnopqrstuvwxyz0123456789"  # len 36
    blob = f'const x = "ghp_{tail}"'
    hits = scan_for_hardcoded_secrets(blob, source_label="unit")
    assert any("GitHub personal" in h["title"] for h in hits)


def test_master_key_assignment_critical() -> None:
    blob = "const MASTER_KEY = 'supersecretvalue123456789012'"
    hits = scan_for_hardcoded_secrets(blob, source_label="unit")
    crit = [h for h in hits if "Master" in h["title"] or "Service" in h["title"]]
    assert crit
    assert crit[0]["severity"] == "Critical"


def test_placeholder_api_key_ignored() -> None:
    blob = 'apiKey: "your-api-key-placeholder-here-not-real-secret-at-all"'
    hits = scan_for_hardcoded_secrets(blob, source_label="unit")
    assert not hits


def test_sensitive_json_key_masked() -> None:
    blob = '{"access_token": "not-a-real-jwt-but-long-secret-value-here-xyz"}'
    hits = scan_for_hardcoded_secrets(blob, source_label="JSON")
    assert any("Sensitive JSON key" in h["title"] for h in hits)
    h = next(x for x in hits if "Sensitive JSON key" in x["title"])
    assert "not-a-real-jwt-but-long-secret-value-here-xyz" not in h["evidence"]


@pytest.mark.parametrize("empty", ("", " ", "short"))
def test_empty_or_tiny_input(empty: str) -> None:
    assert scan_for_hardcoded_secrets(empty) == []
