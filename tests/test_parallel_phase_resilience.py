"""Regression tests for parallel-phase failure handling.

Background
----------
Comparing two Sonnet 4.5 scans against the same target on 28-Apr-2026:

- r1 (04:34): 110 findings, phase_log had 43 entries (39 base + 4 retries)
- r2 (08:12):  74 findings, phase_log had 37 entries (39 base, 0 retries,
               but 5 phases COMPLETELY MISSING)

Container logs during r2's window showed transient Bedrock errors:

    All connection attempts failed
    All connection attempts failed
    Evidence summary failed for Application mapping: litellm.BadRequestError:
        BedrockException - "The toolConfig field must be defined when using
        toolUse and toolResult content blocks."

The 5 missing phases (Authentication testing, Endpoint injection testing,
File Upload Testing, Password Reset Flow Testing, Session Management
Testing - one of which produced 5 findings in r1) were lost because:

1. ``LLMRouter.complete`` retried only rate-limit errors, not transient
   network errors like "All connection attempts failed". Network blip
   bubbled the exception up to the phase worker.

2. ``_run_phase_worker`` only catches ``ContentFiltered``,
   ``ContextWindowExceeded``, ``MalformedMessages`` and ``ScanCancelled``.
   Everything else propagated.

3. ``run_phases_parallel`` collected results via
   ``asyncio.gather(..., return_exceptions=True)`` but **never inspected
   the returned exception values**. The phase silently disappeared from
   ``phase_log`` while ``metrics["phases_completed"] += len(...)`` still
   incremented by the full count - exactly the discrepancy seen in r2
   (39 phases_completed vs 37 phase_log entries).

These tests pin three contracts that **must** hold before any change is
merged to master:

A. ``run_phases_parallel`` ALWAYS appends one ``phase_log`` entry per
   phase, even when the worker raises - and the entry carries an
   ``error`` field so the failure is visible to operators.
B. ``LLMRouter.complete`` retries transient connection / 5xx / timeout
   errors with exponential backoff, recovering from the exact Bedrock
   failure mode observed in production.
C. ``ScanCancelled`` continues to propagate (we don't want the new
   defensive try/except to mask user cancellation).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent.prompts import ScanPhase  # noqa: E402
from scanners.ai_agent import agent as agent_module  # noqa: E402
from scanners.ai_agent.agent import (  # noqa: E402
    ScanCancelled,
    run_phases_parallel,
)
from scanners.ai_agent.llm_config import (  # noqa: E402
    ContentFiltered,
    ContextWindowExceeded,
    LLMRouter,
    MalformedMessages,
    _DEFAULT_RETRY_DELAYS,
    _get_retry_delays,
)


def _phase(pid: str, name: str | None = None) -> ScanPhase:
    return ScanPhase(id=pid, name=name or pid, prompt="test", max_steps=2)


@pytest.fixture()
def patch_worker(monkeypatch):
    """Replace _run_phase_worker so tests don't need a real browser/LLM."""
    calls: list[dict] = []

    def make(behaviour: dict):
        async def fake_worker(**kwargs):
            phase = kwargs["phase"]
            calls.append({"phase": phase.id, "worker_id": kwargs.get("worker_id")})
            spec = behaviour.get(phase.id, behaviour.get("__default__", "ok"))
            if isinstance(spec, BaseException):
                raise spec
            if callable(spec):
                spec = spec(phase, kwargs)
            if spec == "ok":
                return (
                    [{"title": f"finding from {phase.id}", "severity": "Medium"}],
                    {
                        "phase": phase.id,
                        "name": phase.name,
                        "tool_calls": 3,
                        "findings_count": 1,
                    },
                )
            if spec == "ok_no_findings":
                return [], {
                    "phase": phase.id,
                    "name": phase.name,
                    "tool_calls": 1,
                    "findings_count": 0,
                }
            raise AssertionError(f"unknown spec: {spec!r}")

        monkeypatch.setattr(agent_module, "_run_phase_worker", fake_worker)
        return calls

    return make


def _common_kwargs():
    return dict(
        system_prompt="sys",
        model="bedrock/test",
        router=MagicMock(spec=LLMRouter),
        browser=None,
        auth_cookies=[],
        http_client=MagicMock(),
        registry=MagicMock(),
        allowed_domains=set(),
        target_url="http://example.test/",
        cancel_flag=None,
        pause_flag=None,
        exclude_urls=[],
        prior_findings=[],
        on_progress=None,
        max_workers=3,
    )


# ── Contract A: failures produce phase_log entries ────────────────────


class TestParallelExceptionsSurfaceInPhaseLog:
    """Pin: a worker exception MUST produce a phase_log entry, not vanish."""

    def test_single_phase_failure_appears_in_phase_log(self, patch_worker):
        """The exact production bug: transient Bedrock error nukes a phase."""
        patch_worker({
            "api_auth": ConnectionError("All connection attempts failed"),
        })
        phases = [_phase("api_auth", "Authentication testing")]
        findings, logs = asyncio.run(run_phases_parallel(phases=phases, **_common_kwargs()))

        # *** The assertion that would have caught the production regression. ***
        assert len(logs) == 1, "phase_log lost the failed phase entirely"
        assert logs[0]["phase"] == "api_auth"
        assert logs[0]["name"] == "Authentication testing"
        assert "error" in logs[0]
        assert "ConnectionError" in logs[0]["error"]
        assert "All connection attempts failed" in logs[0]["error"]
        assert logs[0]["findings_count"] == 0
        assert logs[0]["tool_calls"] == 0
        assert findings == []

    def test_one_phase_fails_others_still_complete(self, patch_worker):
        """Cardinal property: a single failure must NOT poison the whole batch."""
        patch_worker({
            "phase_a": "ok",
            "phase_b": ConnectionError("All connection attempts failed"),
            "phase_c": "ok",
            "phase_d": ConnectionError("Read timeout"),
            "phase_e": "ok",
        })
        phases = [_phase(p) for p in ["phase_a", "phase_b", "phase_c", "phase_d", "phase_e"]]
        findings, logs = asyncio.run(run_phases_parallel(phases=phases, **_common_kwargs()))

        # Every phase must produce exactly one log entry.
        assert len(logs) == 5
        by_id = {log["phase"]: log for log in logs}
        assert set(by_id) == {"phase_a", "phase_b", "phase_c", "phase_d", "phase_e"}

        # Successful phases keep their findings.
        assert "error" not in by_id["phase_a"]
        assert "error" not in by_id["phase_c"]
        assert "error" not in by_id["phase_e"]
        # Failed phases have an error field, no findings.
        assert "error" in by_id["phase_b"]
        assert "error" in by_id["phase_d"]
        assert by_id["phase_b"]["findings_count"] == 0
        assert by_id["phase_d"]["findings_count"] == 0

        # Findings from successful phases survive.
        titles = {f["title"] for f in findings}
        assert titles == {
            "finding from phase_a",
            "finding from phase_c",
            "finding from phase_e",
        }

    def test_progress_callback_emits_failed_phase_end(self, patch_worker):
        """Operators MUST see failed phases in the live UI."""
        patch_worker({"phase_x": RuntimeError("worker exploded")})
        events: list[tuple[str, dict]] = []
        kwargs = _common_kwargs()
        kwargs["on_progress"] = lambda evt, data: events.append((evt, data))

        asyncio.run(run_phases_parallel(phases=[_phase("phase_x", "X Phase")], **kwargs))

        phase_end_events = [(e, d) for e, d in events if e == "phase_end"]
        assert any("FAILED" in d.get("name", "") for _, d in phase_end_events), (
            f"no phase_end event signalled failure: {phase_end_events}"
        )
        failed = [d for _, d in phase_end_events if "FAILED" in d.get("name", "")][0]
        assert failed["findings"] == 0
        assert failed["tool_calls"] == 0
        assert "RuntimeError" in failed.get("error", "")

    def test_all_phases_failing_still_returns_full_phase_log(self, patch_worker):
        """Pathological case: every phase fails. Don't crash, don't lose entries."""
        patch_worker({
            "p1": ConnectionError("network down"),
            "p2": RuntimeError("oops"),
            "p3": ValueError("bad arg"),
        })
        phases = [_phase(p) for p in ["p1", "p2", "p3"]]
        findings, logs = asyncio.run(run_phases_parallel(phases=phases, **_common_kwargs()))
        assert len(logs) == 3
        assert findings == []
        for log in logs:
            assert "error" in log
            assert log["findings_count"] == 0


# ── Contract B: ScanCancelled still propagates ────────────────────────


class TestParallelCancellationStillPropagates:
    """The new try/except must NOT swallow user cancellation."""

    def test_scan_cancelled_inside_worker_propagates(self, patch_worker):
        patch_worker({"phase_a": ScanCancelled("user pressed stop")})
        with pytest.raises(ScanCancelled):
            asyncio.run(run_phases_parallel(phases=[_phase("phase_a")], **_common_kwargs()))


# ── Contract C: LLMRouter retries transient errors ────────────────────


class TestRouterRetriesTransientErrors:
    """Pin: ``LLMRouter.complete`` retries network/5xx/timeout errors.

    These are the exact strings observed in production logs during r2.
    """

    @pytest.fixture()
    def fast_router(self, monkeypatch):
        """Build a router with retry delays neutralised so tests run fast."""
        # Force direct mode (no proxy) and zero out delays.
        router = LLMRouter(models=["bedrock/test-model"])
        router._has_proxy = False
        monkeypatch.setattr(
            "scanners.ai_agent.llm_config.time.sleep",
            lambda _s: None,
        )
        return router

    def _patch_direct(self, monkeypatch, router, side_effects):
        """Replace _direct_complete with a queue of side-effects."""
        seq = iter(side_effects)
        call_log: list[str] = []

        def fake_direct(model, messages, tools, **kwargs):
            call_log.append("call")
            try:
                action = next(seq)
            except StopIteration:
                raise AssertionError("Too many _direct_complete calls")
            if isinstance(action, BaseException):
                raise action
            return action

        # _track is also called on success; stub it.
        monkeypatch.setattr(router, "_direct_complete", fake_direct)
        monkeypatch.setattr(router, "_track", lambda *a, **k: None)
        return call_log

    def test_retries_all_connection_attempts_failed(self, fast_router, monkeypatch):
        """The exact LiteLLM/Bedrock string from prod that killed r2."""
        good_response = MagicMock()
        log = self._patch_direct(monkeypatch, fast_router, [
            ConnectionError("All connection attempts failed"),
            ConnectionError("All connection attempts failed"),
            good_response,
        ])
        result = fast_router.complete("bedrock/test-model", messages=[{"role": "user", "content": "hi"}])
        assert result is good_response
        assert len(log) == 3, "expected 3 calls (2 failures + 1 success)"

    @pytest.mark.parametrize("err_msg", [
        "All connection attempts failed",
        "Connection error",
        "503 Service Unavailable",
        "502 Bad Gateway",
        "504 Gateway Timeout",
        "Read timeout",
        "Request timed out",
        "Internal Server Error",
        "throttling exception",
    ])
    def test_retries_all_known_transient_signatures(self, fast_router, monkeypatch, err_msg):
        good_response = MagicMock()
        log = self._patch_direct(monkeypatch, fast_router, [
            RuntimeError(err_msg),
            good_response,
        ])
        result = fast_router.complete("bedrock/test-model", messages=[{"role": "user", "content": "hi"}])
        assert result is good_response
        assert len(log) == 2

    def test_does_not_retry_unrelated_errors(self, fast_router, monkeypatch):
        """A genuine programming error must surface immediately."""
        log = self._patch_direct(monkeypatch, fast_router, [
            ValueError("malformed messages or whatever - not transient"),
        ])
        with pytest.raises(ValueError):
            fast_router.complete("bedrock/test-model", messages=[{"role": "user", "content": "hi"}])
        assert len(log) == 1, "non-transient errors must NOT be retried"

    def test_retry_exhaustion_raises(self, fast_router, monkeypatch):
        """After all retries are exhausted, raise the last transient error.

        Pinned to 3 retries (= 4 total attempts) via env override so this
        test stays stable regardless of the default budget. The default
        budget is exercised separately in
        ``TestRouterRetryDelaysAreConfigurable``.
        """
        monkeypatch.setenv("LLM_RETRY_DELAYS", "0,0,0")
        log = self._patch_direct(monkeypatch, fast_router, [
            ConnectionError("All connection attempts failed (1)"),
            ConnectionError("All connection attempts failed (2)"),
            ConnectionError("All connection attempts failed (3)"),
            ConnectionError("All connection attempts failed (4)"),
        ])
        with pytest.raises(ConnectionError, match="All connection attempts failed"):
            fast_router.complete("bedrock/test-model", messages=[{"role": "user", "content": "hi"}])
        assert len(log) == 4, "should have made all 4 attempts (1 initial + 3 retries)"

    def test_terminal_errors_never_retried(self, fast_router, monkeypatch):
        """``ContentFiltered``, ``ContextWindowExceeded``, ``MalformedMessages`` are terminal."""
        for terminal_err_text, expected_exc in [
            ("ContextWindowExceededError - prompt is too long", ContextWindowExceeded),
            ("Content filtered by safety system", ContentFiltered),
            ("Invalid tool_use_id reference", MalformedMessages),
        ]:
            log = self._patch_direct(monkeypatch, fast_router, [
                RuntimeError(terminal_err_text),
            ])
            with pytest.raises(expected_exc):
                fast_router.complete("bedrock/test-model", messages=[{"role": "user", "content": "hi"}])
            assert len(log) == 1, f"terminal error {expected_exc.__name__} must NOT retry"


# ── Contract D: retry budget is configurable via LLM_RETRY_DELAYS env ────


class TestRouterRetryDelaysAreConfigurable:
    """Pin: the retry budget is **operator-tunable at runtime** without
    redeploying. This was added to recover from sustained Bedrock 503
    blips that lasted longer than the original 14 s back-off window
    (3 retries × 2/4/8 s).

    Default budget: 5 retries with 2 / 4 / 8 / 16 / 32 s back-off (62 s
    total). Override with ``LLM_RETRY_DELAYS=2,4,8,16,32,60`` etc.
    """

    def test_default_delays_used_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("LLM_RETRY_DELAYS", raising=False)
        assert _get_retry_delays() == list(_DEFAULT_RETRY_DELAYS)

    def test_default_is_five_retries_totalling_62_seconds(self):
        # The exact knob shipped in this PR. If anyone changes the
        # default, this test forces them to think about whether tests
        # downstream still hold.
        assert _DEFAULT_RETRY_DELAYS == (2, 4, 8, 16, 32)
        assert sum(_DEFAULT_RETRY_DELAYS) == 62

    def test_LLM_RETRY_DELAYS_env_overrides_default(self, monkeypatch):
        monkeypatch.setenv("LLM_RETRY_DELAYS", "1,2,3,4,5,6")
        assert _get_retry_delays() == [1, 2, 3, 4, 5, 6]

    def test_LLM_RETRY_DELAYS_tolerates_whitespace(self, monkeypatch):
        monkeypatch.setenv("LLM_RETRY_DELAYS", "  2 , 4 ,  8  ")
        assert _get_retry_delays() == [2, 4, 8]

    def test_LLM_RETRY_DELAYS_empty_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("LLM_RETRY_DELAYS", "")
        assert _get_retry_delays() == list(_DEFAULT_RETRY_DELAYS)

    def test_LLM_RETRY_DELAYS_whitespace_only_uses_default(self, monkeypatch):
        monkeypatch.setenv("LLM_RETRY_DELAYS", "    ")
        assert _get_retry_delays() == list(_DEFAULT_RETRY_DELAYS)

    def test_LLM_RETRY_DELAYS_falls_back_on_invalid_value(self, monkeypatch):
        # Garbage env must NEVER disable retries entirely - that would
        # silently regress the fix this branch is shipping.
        monkeypatch.setenv("LLM_RETRY_DELAYS", "not,numbers,here")
        assert _get_retry_delays() == list(_DEFAULT_RETRY_DELAYS)

    def test_LLM_RETRY_DELAYS_falls_back_on_negative_values(self, monkeypatch):
        # Negative delays would either crash time.sleep or be a foot-gun.
        monkeypatch.setenv("LLM_RETRY_DELAYS", "2,4,-1,8")
        assert _get_retry_delays() == list(_DEFAULT_RETRY_DELAYS)

    def test_extended_default_budget_recovers_from_4_consecutive_503s(
        self, monkeypatch
    ):
        """End-to-end: with the new default budget, a sustained 4-attempt
        Bedrock outage that the old 3-retry code WOULD HAVE LOST is
        absorbed and the call eventually succeeds.

        Old behaviour (delays=[2,4,8], 4 attempts): would raise after 4.
        New behaviour (delays=[2,4,8,16,32], 6 attempts): retries 5 times,
        recovers on the 5th call.
        """
        monkeypatch.delenv("LLM_RETRY_DELAYS", raising=False)
        monkeypatch.setattr(
            "scanners.ai_agent.llm_config.time.sleep",
            lambda _s: None,
        )
        router = LLMRouter(models=["bedrock/test-model"])
        router._has_proxy = False
        good_response = MagicMock()

        seq = iter([
            ConnectionError("All connection attempts failed (1)"),
            ConnectionError("All connection attempts failed (2)"),
            ConnectionError("All connection attempts failed (3)"),
            ConnectionError("All connection attempts failed (4)"),
            good_response,
        ])
        call_count = {"n": 0}

        def fake_direct(*args, **kwargs):
            call_count["n"] += 1
            action = next(seq)
            if isinstance(action, BaseException):
                raise action
            return action

        monkeypatch.setattr(router, "_direct_complete", fake_direct)
        monkeypatch.setattr(router, "_track", lambda *a, **k: None)

        result = router.complete(
            "bedrock/test-model", messages=[{"role": "user", "content": "hi"}],
        )
        assert result is good_response
        assert call_count["n"] == 5, (
            "expected 4 transient failures + 1 success = 5 calls; the OLD "
            "3-retry code would have raised after 4 calls and lost the phase"
        )

    def test_custom_short_budget_via_env_exhausts_correctly(self, monkeypatch):
        """Operator can also REDUCE the budget for fast-fail dev loops."""
        monkeypatch.setenv("LLM_RETRY_DELAYS", "0,0")  # 1 + 2 = 3 attempts
        monkeypatch.setattr(
            "scanners.ai_agent.llm_config.time.sleep",
            lambda _s: None,
        )
        router = LLMRouter(models=["bedrock/test-model"])
        router._has_proxy = False

        # Messages must include a transient signature ("All connection
        # attempts failed", "503", "timeout", etc.) — otherwise the
        # router treats them as non-transient and raises on attempt 1.
        seq = iter([
            ConnectionError("All connection attempts failed 1"),
            ConnectionError("All connection attempts failed 2"),
            ConnectionError("All connection attempts failed 3"),
            ConnectionError("All connection attempts failed 4"),
        ])
        call_count = {"n": 0}

        def fake_direct(*args, **kwargs):
            call_count["n"] += 1
            raise next(seq)

        monkeypatch.setattr(router, "_direct_complete", fake_direct)
        monkeypatch.setattr(router, "_track", lambda *a, **k: None)

        with pytest.raises(ConnectionError):
            router.complete(
                "bedrock/test-model", messages=[{"role": "user", "content": "hi"}],
            )
        assert call_count["n"] == 3, (
            "with LLM_RETRY_DELAYS=0,0 we should make 3 attempts (1 initial + 2 retries)"
        )


# ── Contract E: end-to-end: transient error inside worker recovers ────


class TestEndToEndTransientErrorIsAbsorbed:
    """Integration: a transient Bedrock blip during a parallel phase
    must NOT lose the phase. Either it retries inside ``LLMRouter.complete``
    (best case) or it fails, surfaces an error in phase_log, and the rest
    of the scan proceeds (acceptable case).

    Either behaviour preserves the contract; both are tested above
    individually. This test pins the orchestrator-level invariant:
    ``len(phase_log) == len(phases)`` regardless of failures.
    """

    def test_phase_log_length_invariant_holds_under_failures(self, patch_worker):
        # Mix: 2 OK, 1 raise ConnectionError, 1 OK, 1 raise RuntimeError.
        patch_worker({
            "p1": "ok",
            "p2": ConnectionError("All connection attempts failed"),
            "p3": "ok_no_findings",
            "p4": RuntimeError("worker died"),
            "p5": "ok",
        })
        phases = [_phase(p) for p in ["p1", "p2", "p3", "p4", "p5"]]
        findings, logs = asyncio.run(run_phases_parallel(phases=phases, **_common_kwargs()))

        # The invariant the production bug violated:
        assert len(logs) == len(phases), (
            f"phase_log length {len(logs)} != phases length {len(phases)} - "
            "this is the exact regression that lost 5 phases in r2"
        )
        # And findings from healthy phases survive:
        titles = {f["title"] for f in findings}
        assert titles == {"finding from p1", "finding from p5"}
