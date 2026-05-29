from __future__ import annotations

import copy
import logging
import os
import time
from dataclasses import dataclass

import litellm
from openai import OpenAI

logger = logging.getLogger(__name__)


class ContextWindowExceeded(Exception):
    pass


class ContentFiltered(Exception):
    """Raised when the model's guardrails block the request (e.g. Amazon Nova)."""
    pass


class MalformedMessages(Exception):
    """Raised when the provider rejects the message array (e.g. orphaned tool calls)."""
    pass

MODELS = [
    "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
]

# ── Transient-error retry budget ──────────────────────────────────────
# Sleep durations (seconds) BETWEEN retry attempts. Total attempts =
# len(_DEFAULT_RETRY_DELAYS) + 1 (initial call).
#
# Default: 5 retries with 2 / 4 / 8 / 16 / 32 s back-off = 62 s total
# back-off. Sized to absorb the regional capacity blips observed in
# production (Bedrock "Bedrock is unable to process your request" 503s
# typically clear in 30-60 s).
#
# Operators can tune at runtime without redeploying via the
# ``LLM_RETRY_DELAYS`` env var (comma-separated integers), e.g.
# ``LLM_RETRY_DELAYS=2,4,8,16,32,60`` for 6 retries / ~2 min total.
_DEFAULT_RETRY_DELAYS: tuple[int, ...] = (2, 4, 8, 16, 32)


def _get_retry_delays() -> list[int]:
    """Resolve retry back-off delays from env or fall back to defaults.

    Falls back to ``_DEFAULT_RETRY_DELAYS`` on any parse error so a
    fat-fingered env var never disables retries entirely.
    """
    raw = os.environ.get("LLM_RETRY_DELAYS", "").strip()
    if not raw:
        return list(_DEFAULT_RETRY_DELAYS)
    try:
        parsed = [int(x.strip()) for x in raw.split(",") if x.strip()]
    except ValueError:
        logger.warning(
            "Invalid LLM_RETRY_DELAYS=%r (expected comma-separated ints); "
            "falling back to default %s",
            raw, list(_DEFAULT_RETRY_DELAYS),
        )
        return list(_DEFAULT_RETRY_DELAYS)
    if not parsed:
        return list(_DEFAULT_RETRY_DELAYS)
    if any(d < 0 for d in parsed):
        logger.warning(
            "LLM_RETRY_DELAYS=%r contains negative values; "
            "falling back to default %s",
            raw, list(_DEFAULT_RETRY_DELAYS),
        )
        return list(_DEFAULT_RETRY_DELAYS)
    return parsed

_BEDROCK_ANTHROPIC_CACHE_MODELS = (
    "anthropic.claude-haiku-4-5",
    "anthropic.claude-sonnet-4",
    "anthropic.claude-opus-4",
    "anthropic.claude-3-7-sonnet",
    "anthropic.claude-3-5-sonnet",
)


def _supports_bedrock_cache(model: str) -> bool:
    """Check if a bedrock/ model supports prompt caching."""
    if not model.startswith("bedrock/"):
        return False
    model_id = model.split("/", 1)[1]
    if model_id.startswith("us."):
        model_id = model_id[3:]
    return any(model_id.startswith(prefix) for prefix in _BEDROCK_ANTHROPIC_CACHE_MODELS)


def _inject_cache_control(messages: list[dict], tools: list[dict] | None, model: str):
    """Add cache_control breakpoints to the system message and last tool definition.

    Bedrock Anthropic requires the system message content to be in content-block
    format (list of dicts) for cache_control to apply.  We place one cache
    checkpoint on the system message (the static prompt that repeats every call)
    and one on the last tool definition (tool schema is also identical every call).

    Returns (messages, tools) — may be shallow-copied to avoid mutating originals.
    """
    if not _supports_bedrock_cache(model):
        return messages, tools

    has_1h_ttl = any(k in model for k in ("haiku-4-5", "sonnet-4-5", "sonnet-4.5", "opus-4-5", "opus-4.5", "sonnet-4-6", "opus-4-6", "haiku-4.5"))
    ttl_value = "1h" if has_1h_ttl else None

    cache_marker: dict = {"type": "ephemeral"}
    if ttl_value:
        cache_marker["ttl"] = ttl_value

    new_messages = list(messages)
    for i, msg in enumerate(new_messages):
        if msg.get("role") != "system":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            new_messages[i] = {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": cache_marker,
                    }
                ],
            }
        elif isinstance(content, list):
            content = [dict(block) for block in content]
            if content:
                content[-1] = dict(content[-1])
                content[-1]["cache_control"] = cache_marker
            new_messages[i] = {**msg, "content": content}
        break

    new_tools = tools
    if tools:
        new_tools = [t for t in tools]
        last = copy.deepcopy(new_tools[-1])
        fn = last.get("function", last)
        fn["cache_control"] = cache_marker
        new_tools[-1] = last

    return new_messages, new_tools


@dataclass
class ModelUsage:
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_cost_usd: float = 0.0
    calls: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0


DIRECT_PREFIXES = ("bedrock/", "vertex_ai/", "sagemaker/", "ollama/")


class LLMRouter:
    def __init__(
        self,
        models: list[str] | None = None,
        on_cost: callable | None = None,
    ):
        self.models = models or MODELS
        self.usage: dict[str, ModelUsage] = {m: ModelUsage(model=m) for m in self.models}
        self._on_cost = on_cost

        base_url = os.environ.get("LITELLM_BASE_URL")
        api_key = os.environ.get("LITELLM_API_KEY")
        if base_url and api_key:
            self._client = OpenAI(base_url=base_url.rstrip("/"), api_key=api_key)
            self._has_proxy = True
        else:
            self._client = None
            self._has_proxy = False

    def _use_direct(self, model: str) -> bool:
        """Route bedrock/, vertex_ai/, sagemaker/, ollama/ models directly
        through litellm even when a proxy is configured."""
        return any(model.startswith(p) for p in DIRECT_PREFIXES)

    def _interruptible_call(self, fn, cancel_flag):
        """Run a blocking LLM call in a daemon thread so cancel_flag
        can be checked every 0.5s.  If the flag fires we raise immediately
        instead of waiting for the HTTP round-trip to finish."""
        from .agent import ScanCancelled
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(fn)
            while True:
                try:
                    return future.result(timeout=0.5)
                except (concurrent.futures.TimeoutError, TimeoutError):
                    if cancel_flag and cancel_flag.is_set():
                        future.cancel()
                        raise ScanCancelled("Scan stopped by user")

    def complete(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        cancel_flag=None,
        **kwargs,
    ):
        from .agent import ScanCancelled

        delays = _get_retry_delays()
        max_attempts = len(delays) + 1
        last_exc: BaseException | None = None
        use_direct = self._use_direct(model) or not self._has_proxy
        for attempt in range(max_attempts):
            if cancel_flag and cancel_flag.is_set():
                raise ScanCancelled("Scan stopped by user")
            try:
                if use_direct:
                    call_fn = lambda: self._direct_complete(model, messages, tools, **kwargs)
                else:
                    call_fn = lambda: self._proxy_complete(model, messages, tools, **kwargs)

                if cancel_flag:
                    response = self._interruptible_call(call_fn, cancel_flag)
                else:
                    response = call_fn()

                self._track(model, response)
                if cancel_flag and cancel_flag.is_set():
                    raise ScanCancelled("Scan stopped by user")
                return response
            except ScanCancelled:
                raise
            except Exception as e:
                last_exc = e
                err_msg = str(e).lower()
                if "contextwindowexceedederror" in err_msg or "prompt is too long" in err_msg or "input is too long" in err_msg:
                    raise ContextWindowExceeded(str(e)) from e
                if "content_filtered" in err_msg or "content filtered" in err_msg:
                    raise ContentFiltered(
                        f"Model {model} blocked the request (content guardrails). "
                        "Try a model without content filtering (e.g. Claude Haiku/Sonnet)."
                    ) from e
                if "toolresult" in err_msg or "tool_result" in err_msg or "tool_use_id" in err_msg or "tool use block" in err_msg:
                    raise MalformedMessages(str(e)) from e
                is_rate_limit = (
                    "rate limit" in err_msg
                    or "429" in err_msg
                    or "too many requests" in err_msg
                )
                # Transient network/upstream errors. We've observed
                # "All connection attempts failed" (Bedrock side regional
                # blip), 503/504 from Bedrock + LiteLLM proxy, and read
                # timeouts during long generations. These are recoverable
                # on the next attempt and MUST be retried; otherwise the
                # exception propagates to ``run_phases_parallel`` and the
                # whole phase is silently dropped (with all its findings).
                # See tests/test_parallel_phase_resilience.py.
                is_transient = (
                    "all connection attempts failed" in err_msg
                    or "connection error" in err_msg
                    or "service unavailable" in err_msg
                    or "service_unavailable" in err_msg
                    or "503" in err_msg
                    or "502" in err_msg
                    or "504" in err_msg
                    or "timeout" in err_msg
                    or "timed out" in err_msg
                    or "internal server error" in err_msg
                    or "throttling" in err_msg
                    or "throttled" in err_msg
                )
                if attempt < len(delays) and (is_rate_limit or is_transient):
                    delay = delays[attempt]
                    reason = "rate limit" if is_rate_limit else "transient network/upstream error"
                    logger.warning(
                        "%s hit for %s, retrying in %ds (attempt %d/%d): %s",
                        reason, model, delay, attempt + 1, max_attempts - 1, str(e)[:200],
                    )
                    for _ in range(delay):
                        if cancel_flag and cancel_flag.is_set():
                            raise ScanCancelled("Scan stopped by user")
                        time.sleep(1)
                else:
                    raise
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected completion loop exit")

    def _proxy_complete(self, model, messages, tools, **kwargs):
        call_kwargs: dict = {"model": model, "messages": messages, **kwargs}
        if tools is not None:
            call_kwargs["tools"] = tools
        raw = self._client.chat.completions.create(**call_kwargs)
        return raw

    def _direct_complete(self, model, messages, tools, **kwargs):
        cached_messages, cached_tools = _inject_cache_control(messages, tools, model)
        call_kwargs: dict = {"model": model, "messages": cached_messages, **kwargs}
        if cached_tools is not None:
            call_kwargs["tools"] = cached_tools
        return litellm.completion(**call_kwargs)

    def _track(self, model: str, response) -> None:
        u = response.usage
        if model not in self.usage:
            self.usage[model] = ModelUsage(model=model)
        mu = self.usage[model]
        mu.input_tokens += u.prompt_tokens or 0
        mu.output_tokens += u.completion_tokens or 0
        mu.calls += 1

        ptd = getattr(u, "prompt_tokens_details", None)
        if ptd:
            mu.cache_read_tokens += getattr(ptd, "cached_tokens", 0) or 0
        mu.cache_creation_tokens += getattr(u, "cache_creation_input_tokens", 0) or 0

        delta = 0.0
        try:
            cost = litellm.completion_cost(completion_response=response)
            if cost is not None:
                delta = float(cost)
                mu.total_cost_usd += delta
        except Exception:
            pass
        if delta > 0 and self._on_cost:
            try:
                self._on_cost(delta)
            except Exception:
                logger.debug("on_cost callback failed", exc_info=True)

    def get_cost_summary(self) -> list[dict]:
        return [
            {
                "model": u.model,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "cost_usd": round(u.total_cost_usd, 4),
                "calls": u.calls,
                "cache_read_tokens": u.cache_read_tokens,
                "cache_creation_tokens": u.cache_creation_tokens,
            }
            for u in self.usage.values()
        ]

    def get_available_models(self) -> list[str]:
        available: list[str] = []
        for model in self.models:
            try:
                self.complete(
                    model=model,
                    messages=[{"role": "user", "content": "ping"}],
                    max_tokens=5,
                )
                available.append(model)
            except Exception as e:
                logger.debug("Model %s unavailable: %s", model, e)
        return available


def check_connectivity() -> dict:
    base_url = os.environ.get("LITELLM_BASE_URL")
    api_key = os.environ.get("LITELLM_API_KEY")
    has_proxy = bool(base_url and api_key)
    router = LLMRouter()
    available = router.get_available_models()
    routing = {}
    for m in available:
        routing[m] = "direct" if router._use_direct(m) else ("proxy" if has_proxy else "direct")
    return {
        "available_models": available,
        "routing": routing,
    }
