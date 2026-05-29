"""Unit tests for effective_budget_cap_usd."""
from __future__ import annotations
import sys
from pathlib import Path
import pytest
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

@pytest.fixture
def budget_mod(monkeypatch):
    monkeypatch.delenv("AUTO_MODE_DEFAULT_BUDGET_USD", raising=False)
    import scanners.ai_agent.budget as budget

    return budget

class TestEffectiveBudgetCapUsd:
    def test_auto_sso_no_cap_uses_default(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("auto", None, caller_is_sso=True) == 30.0
    def test_auto_sso_custom_cap(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("auto", 5.0, caller_is_sso=True) == 5.0
    def test_auto_sso_zero_cap_uses_default(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("auto", 0, caller_is_sso=True) == 30.0
    def test_auto_sso_negative_cap_uses_default(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("auto", -1.0, caller_is_sso=True) == 30.0
    def test_auto_non_sso_ignores_cap(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("auto", 5.0, caller_is_sso=False) == 30.0
    def test_manual_passthrough(self, budget_mod):
        assert budget_mod.effective_budget_cap_usd("manual", 5.0, caller_is_sso=False) == 5.0
    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("AUTO_MODE_DEFAULT_BUDGET_USD", "50")
        import scanners.ai_agent.budget as budget

        assert budget.effective_budget_cap_usd("auto", None, caller_is_sso=False) == 50.0
