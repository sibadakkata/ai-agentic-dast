"""Intelligent per-phase LLM selection for agentic scans."""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ModelTier(str, Enum):
    CHEAP = "cheap"
    BALANCED = "balanced"
    PREMIUM = "premium"


_PHASE_TIER: dict[str, ModelTier] = {}

_CHEAP_IDS = frozenset({
    "web_recon", "api_recon", "crawl_only", "passive_recon",
    "subdomain_enum", "dns_enum", "js_registry",
})

_BALANCED_IDS = frozenset({
    "web_a02", "web_a03_sqli", "web_a03_xss", "web_a03_cmdi", "web_a03_ssti",
    "web_a03_path_traversal", "web_a03_xxe", "web_a04", "web_a05", "web_a06",
    "web_a07", "web_a08", "web_a09", "web_a10", "web_websocket", "web_extras",
    "web_host_header", "web_timing_enum", "web_file_upload", "api_auth",
    "api_injection", "api_mass_assign", "api_rate_limit", "api_ssrf",
    "api_graphql", "api_data_exposure", "api_content_type", "api_method_override",
})

_PREMIUM_IDS = frozenset({
    "web_a01", "web_bfla", "web_session_mgmt", "web_password_reset",
    "api_authz", "api_bfla", "api_business_logic", "web_race_condition",
    "api_race_condition", "web_business_logic", "attack_chain_analysis",
    "chain_credential_theft", "chain_data_exfil", "chain_rce",
    "chain_access_escalation", "web_llm_security",
})

_PREMIUM_SUBSTRINGS = (
    "idor", "authz", "business_logic", "business-logic", "multi_tenant",
    "multi-tenant", "bfla", "session_mgmt", "access_control",
)

_SONNET_MARKERS = ("sonnet", "claude-sonnet")
_OPUS_MARKERS = ("opus",)
_HAIKU_MARKERS = ("haiku",)


def _register_tiers() -> None:
    for pid in _CHEAP_IDS:
        _PHASE_TIER[pid] = ModelTier.CHEAP
    for pid in _BALANCED_IDS:
        _PHASE_TIER[pid] = ModelTier.BALANCED
    for pid in _PREMIUM_IDS:
        _PHASE_TIER[pid] = ModelTier.PREMIUM


_register_tiers()


def tier_for_phase(phase_id: str, hint: dict[str, Any] | None = None) -> ModelTier:
    hint = hint or {}
    if hint.get("retry") or hint.get("tier") == "premium":
        return ModelTier.PREMIUM
    if hint.get("large_context") or hint.get("synthesis"):
        return ModelTier.PREMIUM
    if phase_id in _PHASE_TIER:
        return _PHASE_TIER[phase_id]
    pid_lower = phase_id.lower()
    for sub in _PREMIUM_SUBSTRINGS:
        if sub in pid_lower:
            return ModelTier.PREMIUM
    if pid_lower.startswith("chain_"):
        return ModelTier.PREMIUM
    if any(x in pid_lower for x in ("recon", "crawl", "passive", "dns", "subdomain", "js_")):
        return ModelTier.CHEAP
    return ModelTier.BALANCED


def _model_sort_key(m: dict) -> tuple:
    return (
        m.get("input_cost_per_m") or float("inf"),
        m.get("output_cost_per_m") or float("inf"),
        m.get("id") or "",
    )


def _id_text(model_id: str) -> str:
    return (model_id or "").lower()


def _matches_tier(model: dict, tier: ModelTier) -> bool:
    text = _id_text(model.get("id", ""))
    if tier == ModelTier.CHEAP:
        return any(m in text for m in _HAIKU_MARKERS) or "haiku" in text
    if tier == ModelTier.PREMIUM:
        return any(m in text for m in _OPUS_MARKERS) or (
            any(m in text for m in _SONNET_MARKERS)
            and ("4-5" in text or "4.5" in text or "4-6" in text)
        )
    if any(m in text for m in _OPUS_MARKERS):
        return False
    return any(m in text for m in _SONNET_MARKERS) or "sonnet" in text


def _pick_for_tier(models: list[dict], tier: ModelTier) -> str | None:
    if not models:
        return None
    ranked = sorted(models, key=_model_sort_key)
    if tier == ModelTier.CHEAP:
        for m in ranked:
            if _matches_tier(m, ModelTier.CHEAP):
                return m["id"]
        return ranked[0]["id"]
    if tier == ModelTier.PREMIUM:
        opus = [m for m in models if any(x in _id_text(m.get("id", "")) for x in _OPUS_MARKERS)]
        if opus:
            return sorted(opus, key=lambda x: -(_id_text(x.get("id", "")).count("4-6")))[0]["id"]
        sonnet = [m for m in models if _matches_tier(m, ModelTier.BALANCED)]
        if sonnet:
            return sorted(sonnet, key=_model_sort_key)[-1]["id"]
        return ranked[-1]["id"]
    balanced = [m for m in models if _matches_tier(m, ModelTier.BALANCED)]
    if balanced:
        return balanced[len(balanced) // 2]["id"]
    for m in ranked:
        if not any(x in _id_text(m.get("id", "")) for x in _HAIKU_MARKERS):
            return m["id"]
    return ranked[0]["id"]


class ModelSelector:
    """Pick concrete Bedrock model ids per scan phase."""

    def __init__(
        self,
        models: list[dict],
        policy: str = "auto",
        manual_model: str | None = None,
    ):
        self.models = list(models or [])
        self.policy = (policy or "auto").strip().lower()
        self.manual_model = manual_model
        self._cache: dict[tuple, str] = {}

    def select(self, phase: str, *, hint: dict | None = None) -> str:
        if self.policy == "manual":
            return self.manual_model or (self.models[0]["id"] if self.models else "")
        cache_key = (phase, tuple(sorted((hint or {}).items())))
        if cache_key in self._cache:
            return self._cache[cache_key]
        tier = tier_for_phase(phase, hint)
        chosen = _pick_for_tier(self.models, tier)
        if not chosen:
            chosen = self.manual_model or ""
        if chosen and not any(m.get("id") == chosen for m in self.models):
            logger.warning(
                "ModelSelector: %s not in discovered list; falling back one tier from %s",
                chosen,
                tier.value,
            )
            fallback_order = {
                ModelTier.PREMIUM: (ModelTier.BALANCED, ModelTier.CHEAP),
                ModelTier.BALANCED: (ModelTier.CHEAP,),
                ModelTier.CHEAP: (),
            }
            for fb in fallback_order.get(tier, ()):
                chosen = _pick_for_tier(self.models, fb)
                if chosen and any(m.get("id") == chosen for m in self.models):
                    break
            else:
                chosen = self.models[0]["id"] if self.models else chosen
        self._cache[cache_key] = chosen
        return chosen
