"""Scan budget guard and rough cost estimation."""
from __future__ import annotations

import math
from typing import Any, Callable

_TIER_PHASE_COUNTS = {"cheap": 12, "balanced": 28, "premium": 6}
_TOKENS_PER_PHASE_K = {"cheap": 8.0, "balanced": 45.0, "premium": 120.0}
_INTENSITY_MULT = {"light": 0.6, "standard": 1.0, "deep": 1.35}
_DEPTH_MULT = {"standard": 1.0, "deep": 1.25}
_MODE_MULT = {"website": 1.0, "api": 0.85, "both": 1.15}


def _price_per_token(model: dict) -> tuple[float, float]:
    inp = float(model.get("input_cost_per_m") or 1.0) / 1_000_000.0
    out = float(model.get("output_cost_per_m") or 3.0) / 1_000_000.0
    return inp, out


def _model_by_tier(models: list[dict]) -> dict[str, dict]:
    from .auto_router import ModelTier, _pick_for_tier

    return {
        "cheap": next(
            (m for m in models if m.get("id") == _pick_for_tier(models, ModelTier.CHEAP)),
            models[0],
        ),
        "balanced": next(
            (m for m in models if m.get("id") == _pick_for_tier(models, ModelTier.BALANCED)),
            models[0],
        ),
        "premium": next(
            (m for m in models if m.get("id") == _pick_for_tier(models, ModelTier.PREMIUM)),
            models[-1],
        ),
    }


def estimate_scan_cost(
    scan_mode: str,
    scan_intensity: str,
    llm_scan_depth: str,
    model_policy: str,
    manual_model: str | None,
    models: list[dict],
) -> dict[str, Any]:
    """Return low / expected / high USD estimates (not a billing quote)."""
    models = list(models or [])
    if not models:
        return {
            "low_usd": 0.0,
            "expected_usd": 0.0,
            "high_usd": 0.0,
            "assumptions": ["No models in cache — estimates unavailable."],
            "per_phase": [],
            "recommended_budget_usd": 0.0,
        }

    intensity = (scan_intensity or "deep").lower()
    depth = (llm_scan_depth or "standard").lower()
    mode = (scan_mode or "both").lower()
    mult = (
        _INTENSITY_MULT.get(intensity, 1.0)
        * _DEPTH_MULT.get(depth, 1.0)
        * _MODE_MULT.get(mode, 1.0)
    )

    assumptions = [
        "Rough heuristic based on average tokens per phase tier; not a quote.",
        f"Intensity={intensity}, depth={depth}, mode={mode} multiplier={mult:.2f}.",
    ]
    per_phase: list[dict] = []
    policy = (model_policy or "manual").lower()

    if policy == "manual":
        mid = next((m for m in models if m.get("id") == manual_model), models[0])
        inp, out = _price_per_token(mid)
        phases = sum(_TIER_PHASE_COUNTS.values())
        tok_k = sum(_TIER_PHASE_COUNTS[t] * _TOKENS_PER_PHASE_K[t] for t in _TIER_PHASE_COUNTS)
        expected = tok_k * 1000 * (inp * 0.55 + out * 0.45) * mult
        low = expected * 0.55
        high = expected * 1.8
        per_phase.append({
            "tier": "manual",
            "model_id": mid.get("id"),
            "phases": phases,
            "expected_usd": round(expected, 4),
        })
    else:
        tier_models = _model_by_tier(models)
        expected = 0.0
        for tier, count in _TIER_PHASE_COUNTS.items():
            m = tier_models[tier]
            inp, out = _price_per_token(m)
            tok = count * _TOKENS_PER_PHASE_K[tier] * 1000 * mult
            tier_cost = tok * (inp * 0.55 + out * 0.45)
            expected += tier_cost
            per_phase.append({
                "tier": tier,
                "model_id": m.get("id"),
                "phases": count,
                "expected_usd": round(tier_cost, 4),
            })
        assumptions.append(
            "Auto policy distributes phases across cheap/balanced/premium tiers."
        )
        low = expected * 0.5
        high = expected * 2.2

    return {
        "low_usd": round(low, 2),
        "expected_usd": round(expected, 2),
        "high_usd": round(high, 2),
        "assumptions": assumptions,
        "per_phase": per_phase,
        "recommended_budget_usd": round(math.ceil(expected * 2 * 10) / 10, 2),
    }


class BudgetGuard:
    """Tracks cumulative LLM spend and pauses the scan when cap is exceeded."""

    def __init__(
        self,
        scan_id: str,
        cap_usd: float | None,
        owner_user_id: str | None,
        scans: dict,
        pause_flag,
        *,
        owner_label: str = "scan owner",
        on_exceeded: Callable[[], None] | None = None,
    ):
        self.scan_id = scan_id
        self._cap = cap_usd
        self.owner_user_id = owner_user_id
        self._scans = scans
        self._pause_flag = pause_flag
        self._owner_label = owner_label
        self._on_exceeded = on_exceeded
        self._total = 0.0
        self._exceeded = False

    @property
    def current_total_usd(self) -> float:
        return round(self._total, 4)

    @property
    def cap_usd(self) -> float | None:
        return self._cap

    def is_exceeded(self) -> bool:
        if self._cap is None:
            return False
        return self._total >= self._cap

    def record(self, cost_usd: float) -> None:
        if cost_usd is None or cost_usd <= 0:
            return
        self._total += float(cost_usd)
        scan = self._scans.get(self.scan_id)
        if scan is not None:
            scan["budget_total_usd"] = round(self._total, 4)
            if self._cap is not None:
                scan.setdefault("budget_status", "ok")
        if self._cap is None:
            return
        if self._total >= self._cap:
            self._handle_exceeded()

    def _handle_exceeded(self) -> None:
        if self._exceeded:
            return
        self._exceeded = True
        scan = self._scans.get(self.scan_id)
        if scan is None:
            return
        cap = self._cap
        scan["budget_status"] = "awaiting_approval"
        msg = f"⏸ Budget cap ${cap:.2f} reached — awaiting approval from {self._owner_label}"
        scan.setdefault("progress", []).append(msg)
        if self._pause_flag is not None and hasattr(self._pause_flag, "set"):
            self._pause_flag.set()
        if self._on_exceeded:
            self._on_exceeded()
