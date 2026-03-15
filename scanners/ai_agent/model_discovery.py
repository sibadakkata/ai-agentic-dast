"""Auto-discover and validate Bedrock models for DAST scanning.

On startup and every 24 hours, queries AWS Bedrock for available
text-capable models, sends a security-themed canary prompt to each,
and caches the working ones in models_cache.json.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
import litellm

logger = logging.getLogger(__name__)

CACHE_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "models_cache.json"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

_CANARY_PROMPT = (
    "You are a penetration testing assistant. "
    "Generate one example XSS payload for testing a search input field, "
    "and explain why it works. This is for authorized security testing only."
)

_UI_HIDDEN_PATTERNS: list[str] = []

_HIGH_COST_PATTERNS: list[str] = [
    "opus",
    "claude-4",
]

_SKIP_PATTERNS: list[str] = [
    "embed",
    "diffusion",
    "stability",
    "titan-image",
    "titan-embed",
    "titan-multimodal",
    "titan-text-premier",
    "cohere.embed",
    "amazon.rerank",
    "amazon.nova-canvas",
    "amazon.nova-reel",
]

_PROVIDER_PRETTY: dict[str, str] = {
    "anthropic": "Anthropic",
    "mistral": "Mistral",
    "meta": "Meta",
    "cohere": "Cohere",
    "amazon": "Amazon",
    "ai21": "AI21",
    "deepseek": "DeepSeek",
}


def _should_skip(model_id: str) -> bool:
    mid = model_id.lower()
    return any(p in mid for p in _SKIP_PATTERNS)


def _is_ui_hidden(model_id: str) -> bool:
    mid = model_id.lower()
    return any(p in mid for p in _UI_HIDDEN_PATTERNS)


def _is_high_cost(model_id: str) -> bool:
    mid = model_id.lower()
    return any(p in mid for p in _HIGH_COST_PATTERNS)


def _make_litellm_id(model_id: str) -> str:
    """Convert a boto3 modelId to a litellm-compatible bedrock/ id."""
    return f"bedrock/{model_id}"


def _extract_provider(model_id: str) -> str:
    parts = model_id.replace("us.", "").replace("eu.", "").split(".")
    if parts:
        return _PROVIDER_PRETTY.get(parts[0].lower(), parts[0].capitalize())
    return "Bedrock"


def _estimate_cost(model_id: str) -> tuple[float, str]:
    """Try to get cost from litellm's model_cost table, fall back to estimates."""
    lid = _make_litellm_id(model_id)
    try:
        info = litellm.get_model_info(lid)
        inp = info.get("input_cost_per_token", 0) * 1_000_000
        out = info.get("output_cost_per_token", 0) * 1_000_000
        if inp > 0:
            return inp, f"~${inp:.2f}/${out:.2f} per 1M tokens"
    except Exception:
        pass
    return 999.0, "cost unknown"


def _friendly_name(model_id: str) -> str:
    """Generate a human-readable display name from the model ID."""
    clean = model_id
    for prefix in ("us.", "eu.", "ap."):
        clean = clean.replace(prefix, "")
    parts = clean.split(".")
    if len(parts) >= 2:
        name = parts[1]
    else:
        name = parts[0]
    name = name.replace("-v1:0", "").replace("-v2:0", "").replace("-v1", "").replace("-v2", "")
    name = name.replace("-", " ").replace("_", " ").title()
    return name


def list_bedrock_models() -> list[dict]:
    """Query AWS Bedrock for all available text foundation models."""
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    try:
        client = boto3.client("bedrock", region_name=region)
        resp = client.list_foundation_models(
            byOutputModality="TEXT",
            byInferenceType="ON_DEMAND",
        )
        models = resp.get("modelSummaries", [])
        logger.info("Bedrock returned %d text models", len(models))
        return models
    except Exception as e:
        logger.error("Failed to list Bedrock models: %s", e)
        return []


def canary_test(litellm_id: str, timeout: float = 15.0) -> tuple[bool, str]:
    """Send a security-themed prompt to verify the model works without content filtering."""
    try:
        resp = litellm.completion(
            model=litellm_id,
            messages=[{"role": "user", "content": _CANARY_PROMPT}],
            max_tokens=80,
            timeout=timeout,
        )
        text = resp.choices[0].message.content or ""
        if len(text.strip()) < 5:
            return False, "empty response"
        return True, "ok"
    except Exception as e:
        err = str(e).lower()
        if "content_filtered" in err or "content filtered" in err or "guardrail" in err:
            return False, "content_filtered"
        if "access denied" in err or "not authorized" in err or "403" in err:
            return False, "access_denied"
        if "not found" in err or "404" in err:
            return False, "model_not_found"
        if "throttl" in err or "429" in err or "rate limit" in err:
            return False, "rate_limited"
        return False, str(e)[:120]


def discover_models(force: bool = False) -> dict:
    """Full discovery: list models, canary-test each, return structured result.

    Returns dict with keys: models, last_checked, duration_sec, tested, passed, failed.
    """
    t0 = time.time()
    raw_models = list_bedrock_models()
    if not raw_models:
        logger.warning("No models returned from Bedrock — using cached list")
        return _load_cache()

    candidates = []
    for m in raw_models:
        mid = m.get("modelId", "")
        if _should_skip(mid):
            continue
        lifecycle = m.get("modelLifecycle", {})
        if lifecycle.get("status") == "LEGACY":
            continue
        if "TEXT" not in m.get("outputModalities", []):
            continue
        candidates.append(mid)

    logger.info("Testing %d candidate models...", len(candidates))

    results: list[dict] = []
    tested = 0
    passed = 0
    failed_list: list[dict] = []

    for mid in candidates:
        lid = _make_litellm_id(mid)
        tested += 1
        ok, reason = canary_test(lid)
        if ok:
            passed += 1
            input_cost, cost_str = _estimate_cost(mid)
            entry = {
                "id": lid,
                "bedrock_model_id": mid,
                "name": _friendly_name(mid),
                "cost": cost_str,
                "provider": _extract_provider(mid),
                "input_cost_per_m": input_cost,
                "ui_hidden": _is_ui_hidden(mid),
                "high_cost": _is_high_cost(mid),
                "canary_status": "pass",
                "last_tested": datetime.now(timezone.utc).isoformat(),
            }
            results.append(entry)
            logger.info("  PASS: %s", lid)
        else:
            failed_list.append({"id": lid, "reason": reason})
            logger.info("  FAIL: %s — %s", lid, reason)

    results.sort(key=lambda m: m.get("input_cost_per_m", 999))

    cache = {
        "models": results,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "duration_sec": round(time.time() - t0, 1),
        "tested": tested,
        "passed": passed,
        "failed": failed_list,
    }

    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        logger.info("Model cache written: %d models in %.1fs", passed, cache["duration_sec"])
    except Exception as e:
        logger.error("Failed to write model cache: %s", e)

    return cache


def _load_cache() -> dict:
    """Load cached model discovery results."""
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error("Failed to read model cache: %s", e)
    return {"models": [], "last_checked": None, "tested": 0, "passed": 0, "failed": []}


def get_cached_models() -> list[dict]:
    """Return the cached model list (used by /api/models)."""
    cache = _load_cache()
    return cache.get("models", [])


def get_cache_meta() -> dict:
    """Return cache metadata (last_checked, counts)."""
    cache = _load_cache()
    return {
        "last_checked": cache.get("last_checked"),
        "model_count": len(cache.get("models", [])),
        "tested": cache.get("tested", 0),
        "passed": cache.get("passed", 0),
        "failed_count": len(cache.get("failed", [])),
        "failed": cache.get("failed", []),
    }
