"""Auto-discover and validate Bedrock models for DAST scanning.

On startup and on a configurable interval (default 24h), queries AWS Bedrock
``list_foundation_models`` and ``list_inference_profiles``, canary-tests each
candidate, and caches working models in ``data/models_cache.json``.

Many Anthropic models (e.g. Opus 4.7) are only invocable via cross-region
inference profile IDs (``us.anthropic.*``), not bare foundation model IDs.
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
    "amazon.titan",
    "amazon.nova",
    "amazon.rerank",
    "cohere.",
    "ai21.",
    "ministral",
    "mistral.",
]

_PROVIDER_PRETTY: dict[str, str] = {
    "anthropic": "Anthropic",
    "mistral": "Mistral",
    "meta": "Meta",
    "cohere": "Cohere",
    "amazon": "Amazon",
    "ai21": "AI21",
    "deepseek": "DeepSeek",
    "google": "Google",
    "nvidia": "Nvidia",
}

# Curated display names / cost hints (new Bedrock models still appear after canary pass).
_MODEL_OVERLAY: dict[str, dict] = {
    "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0": {
        "name": "Claude Haiku 4.5 (recommended)",
        "cost": "~$0.80/$4 per 1M tokens",
        "input_cost_per_m": 0.80,
        "recommended": True,
    },
    "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0": {
        "name": "Claude Sonnet 4.5",
        "cost": "~$3/$15 per 1M tokens",
        "input_cost_per_m": 3.0,
    },
    "bedrock/us.anthropic.claude-sonnet-4-6": {
        "name": "Claude Sonnet 4.6 (best quality)",
        "cost": "~$3/$15 per 1M tokens",
        "input_cost_per_m": 3.0,
    },
    "bedrock/us.anthropic.claude-opus-4-6-v1": {
        "name": "Claude Opus 4.6 (premium)",
        "cost": "~$15/$75 per 1M tokens",
        "input_cost_per_m": 15.0,
        "high_cost": True,
    },
    "bedrock/us.anthropic.claude-opus-4-7": {
        "name": "Claude Opus 4.7 (premium)",
        "cost": "~$15/$75 per 1M tokens",
        "input_cost_per_m": 15.0,
        "high_cost": True,
    },
    "bedrock/global.anthropic.claude-opus-4-7": {
        "name": "Claude Opus 4.7 Global (premium)",
        "high_cost": True,
        "ui_hidden": True,
    },
    "bedrock/us.anthropic.claude-opus-4-8": {
        "name": "Claude Opus 4.8 (preview · premium)",
        "cost": "~$15/$75 per 1M tokens",
        "input_cost_per_m": 15.0,
        "high_cost": True,
    },
}

_FRIENDLY_ALIASES: dict[str, str] = {
    "claude-opus-4-7": "Claude Opus 4.7",
    "claude-opus-4-8": "Claude Opus 4.8",
    "claude-opus-4-6": "Claude Opus 4.6",
    "claude-opus-4-5": "Claude Opus 4.5",
    "claude-sonnet-4-6": "Claude Sonnet 4.6",
    "claude-sonnet-4-5": "Claude Sonnet 4.5",
    "claude-haiku-4-5": "Claude Haiku 4.5",
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


def _bedrock_region() -> str:
    """Bedrock control-plane region for model discovery (defaults to us-east-2)."""
    explicit = os.environ.get("BEDROCK_REGION", "").strip()
    if explicit:
        return explicit
    # Do not inherit AWS_DEFAULT_REGION — EC2 often sets us-east-1 while Bedrock catalog is us-east-2.
    return "us-east-2"


def _friendly_name(model_id: str) -> str:
    """Generate a human-readable display name from the model ID."""
    clean = model_id
    for prefix in ("us.", "eu.", "ap.", "global."):
        clean = clean.replace(prefix, "")
    parts = clean.split(".")
    if len(parts) >= 2:
        name = parts[1]
    else:
        name = parts[0]
    name = name.replace("-v1:0", "").replace("-v2:0", "").replace("-v1", "").replace("-v2", "")
    low = name.lower()
    for key, pretty in _FRIENDLY_ALIASES.items():
        if key in low:
            return pretty
    return name.replace("-", " ").replace("_", " ").title()


def _apply_overlay(entry: dict) -> dict:
    overlay = _MODEL_OVERLAY.get(entry.get("id", ""), {})
    if overlay:
        entry.update(overlay)
    return entry


def list_bedrock_inference_profiles() -> list[str]:
    """Return active Bedrock inference profile IDs (cross-region Anthropic, etc.)."""
    region = _bedrock_region()
    try:
        client = boto3.client("bedrock", region_name=region)
        ids: list[str] = []
        token: str | None = None
        while True:
            kwargs: dict = {"maxResults": 100}
            if token:
                kwargs["nextToken"] = token
            resp = client.list_inference_profiles(**kwargs)
            for prof in resp.get("inferenceProfileSummaries", []):
                if prof.get("status") != "ACTIVE":
                    continue
                pid = prof.get("inferenceProfileId", "")
                if pid and not _should_skip(pid):
                    ids.append(pid)
            token = resp.get("nextToken")
            if not token:
                break
        logger.info("Bedrock returned %d active inference profiles", len(ids))
        return ids
    except Exception as e:
        logger.error("Failed to list Bedrock inference profiles: %s", e)
        return []


def _collect_candidates(raw_models: list[dict], profile_ids: list[str]) -> list[str]:
    """Merge inference profiles + on-demand foundation models without duplicate tests."""
    profile_set = set(profile_ids)
    candidates: list[str] = []
    seen: set[str] = set()

    for pid in profile_ids:
        if pid not in seen:
            seen.add(pid)
            candidates.append(pid)

    for m in raw_models:
        mid = m.get("modelId", "")
        if not mid or _should_skip(mid):
            continue
        lifecycle = m.get("modelLifecycle", {})
        if lifecycle.get("status") == "LEGACY":
            continue
        if "TEXT" not in m.get("outputModalities", []):
            continue
        prefixed = []
        if not mid.startswith(("us.", "global.", "eu.", "ap.")):
            prefixed.append(f"us.{mid}")
            if mid.startswith("anthropic."):
                prefixed.append(f"global.{mid}")
        if any(p in profile_set for p in prefixed):
            continue
        if mid not in seen:
            seen.add(mid)
            candidates.append(mid)

    return candidates


def list_bedrock_models() -> list[dict]:
    """Query AWS Bedrock for all available text foundation models."""
    region = _bedrock_region()
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
    profile_ids = list_bedrock_inference_profiles()
    if not raw_models and not profile_ids:
        logger.warning("No models returned from Bedrock — using cached list")
        return _load_cache()

    candidates = _collect_candidates(raw_models, profile_ids)

    logger.info(
        "Testing %d candidate models (%d profiles, %d foundation)...",
        len(candidates),
        len(profile_ids),
        len(raw_models),
    )

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
            entry = _apply_overlay({
                "id": lid,
                "bedrock_model_id": mid,
                "name": _friendly_name(mid),
                "cost": cost_str,
                "provider": _extract_provider(mid),
                "input_cost_per_m": input_cost,
                "ui_hidden": _is_ui_hidden(mid),
                "high_cost": _is_high_cost(mid),
                "recommended": False,
                "canary_status": "pass",
                "last_tested": datetime.now(timezone.utc).isoformat(),
            })
            results.append(entry)
            logger.info("  PASS: %s", lid)
        else:
            failed_list.append({"id": lid, "reason": reason})
            logger.info("  FAIL: %s — %s", lid, reason)

    results.sort(key=lambda m: m.get("input_cost_per_m", 999))

    if not results:
        prev = _load_cache()
        if prev.get("models"):
            logger.warning(
                "Discovery passed 0/%d models; keeping previous cache (%d models)",
                tested,
                len(prev["models"]),
            )
            return prev

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


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = discover_models()
    print(
        f"passed {out.get('passed')}/{out.get('tested')} "
        f"last_checked={out.get('last_checked')} "
        f"cache={CACHE_FILE}",
        file=sys.stderr,
    )
    for m in out.get("models", []):
        print(f"  {m.get('id')}  {m.get('name')}")
    sys.exit(0 if out.get("passed") else 1)
