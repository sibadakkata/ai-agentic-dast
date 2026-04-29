"""Tests for the parallel-mode hybrid smart retry restoration.

Background
----------
On 22-Apr-2026, commit ``ce2cf83 feat(parallel): multi-agent parallel scan``
introduced ``_run_phase_worker`` for concurrent phase execution. The
worker code was a near-copy of the sequential phase loop, but it
**omitted** the active "smart retry" block that re-runs zero-finding
phases with a phase-tailored prompt. Only a passive evidence-summary
call (no tools) was kept.

Symptom in production: 28-Apr-2026, three Sonnet 4.5 scans against the
same in-house target produced 110 / 74 / 56 findings on the same code.
The 56-finding scan had **15 phases each running 70-85 tool calls and
producing zero findings** — exactly the case the smart retry was
designed to recover, but it never fired in the parallel default mode.

This test suite pins:

A. ``retry_prompts.should_run_smart_retry`` — the decision logic for
   whether retry should fire (used by the parallel worker).
B. ``retry_prompts.phase_has_core_finding`` — keyword-match helper.
C. ``_run_phase_worker`` — actually invokes ``_run_smart_retry_pass``
   when the trigger condition is met. This is the regression the bug
   introduced — sequential path always fired, parallel path never did.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent import agent as agent_module  # noqa: E402
from scanners.ai_agent import retry_prompts as rp  # noqa: E402
from scanners.ai_agent.prompts import ScanPhase  # noqa: E402


# ── Section A: should_run_smart_retry decision logic ──────────────────


class TestShouldRunSmartRetry:
    """Pin the trigger conditions for the active retry pass."""

    def test_fires_when_in_list_and_zero_findings_with_evidence(self):
        should, reason = rp.should_run_smart_retry(
            phase_id="api_authz",
            phase_new_findings_count=0,
            findings_for_phase=[],
            phase_evidence=[{"tool": "navigate", "evidence": "..."}],
            already_retried=False,
        )
        assert should is True
        assert reason == "zero findings"

    def test_does_NOT_fire_when_phase_not_in_retry_list(self):
        # web_app_mapping is a recon phase, not in the active-retry set.
        should, reason = rp.should_run_smart_retry(
            phase_id="web_app_mapping",
            phase_new_findings_count=0,
            findings_for_phase=[],
            phase_evidence=[{"tool": "navigate", "evidence": "..."}],
            already_retried=False,
        )
        assert should is False
        assert reason == ""

    def test_does_NOT_fire_when_no_evidence_was_collected(self):
        # If the phase made no security-relevant tool calls, retrying
        # would just burn tokens with the same starting context.
        should, _ = rp.should_run_smart_retry(
            phase_id="api_authz",
            phase_new_findings_count=0,
            findings_for_phase=[],
            phase_evidence=[],
            already_retried=False,
        )
        assert should is False

    def test_does_NOT_fire_when_already_retried(self):
        should, _ = rp.should_run_smart_retry(
            phase_id="api_authz",
            phase_new_findings_count=0,
            findings_for_phase=[],
            phase_evidence=[{"tool": "navigate", "evidence": "..."}],
            already_retried=True,
        )
        assert should is False

    def test_fires_when_findings_LACK_core_class(self):
        # web_a07 (Auth Failures) findings must mention auth-related
        # keywords. A finding labelled "Cookie missing Secure flag" is
        # off-topic for the phase, so retry should still fire.
        should, reason = rp.should_run_smart_retry(
            phase_id="web_a07",
            phase_new_findings_count=1,
            findings_for_phase=[
                {"title": "Cookie missing Secure flag", "description": ""},
            ],
            phase_evidence=[{"tool": "http_request", "evidence": "..."}],
            already_retried=False,
        )
        assert should is True
        assert reason == "no core-class finding"

    def test_does_NOT_fire_when_findings_MATCH_core_class(self):
        # The phase produced an on-topic finding; no need to retry.
        should, _ = rp.should_run_smart_retry(
            phase_id="web_a07",
            phase_new_findings_count=1,
            findings_for_phase=[
                {"title": "Authentication Bypass via /admin", "description": ""},
            ],
            phase_evidence=[{"tool": "http_request", "evidence": "..."}],
            already_retried=False,
        )
        assert should is False

    def test_phases_without_core_keywords_use_findings_count_only(self):
        # web_a01 IS in core_keywords. Use a phase that's in
        # _ACTIVE_RETRY_PHASES but NOT in _PHASE_CORE_KEYWORDS — none
        # exist today, but the function must still behave sensibly.
        # Test the underlying helper directly.
        assert rp.phase_has_core_finding(
            phase_id="not_a_real_phase",
            findings_for_phase=[{"title": "anything"}],
        ) is True
        assert rp.phase_has_core_finding(
            phase_id="not_a_real_phase",
            findings_for_phase=[],
        ) is False


# ── Section B: phase_has_core_finding keyword matching ────────────────


class TestPhaseHasCoreFinding:
    """Pin the keyword matching across title / description /
    vulnerability_type / category fields."""

    def test_matches_in_title(self):
        assert rp.phase_has_core_finding(
            "api_authz",
            [{"title": "BOLA: User A can read User B resources"}],
        ) is True

    def test_matches_in_description(self):
        assert rp.phase_has_core_finding(
            "web_a10",
            [{
                "title": "Suspicious endpoint",
                "description": "The /webhook endpoint allows SSRF to internal network.",
            }],
        ) is True

    def test_matches_in_vulnerability_type(self):
        assert rp.phase_has_core_finding(
            "web_a03_sqli",
            [{
                "title": "Unexpected response",
                "vulnerability_type": "Time-based SQL injection",
            }],
        ) is True

    def test_matches_in_category(self):
        assert rp.phase_has_core_finding(
            "web_a03_xss",
            [{"title": "weird", "category": "Reflected XSS"}],
        ) is True

    def test_case_insensitive(self):
        assert rp.phase_has_core_finding(
            "web_a07",
            [{"title": "AUTHENTICATION BYPASS detected"}],
        ) is True

    def test_no_match_returns_false(self):
        assert rp.phase_has_core_finding(
            "web_a07",
            [{"title": "Some unrelated finding"}],
        ) is False


# ── Section C: parallel worker actually invokes the retry helper ──────


class TestParallelWorkerInvokesSmartRetry:
    """Cardinal regression: the parallel worker MUST call
    ``_run_smart_retry_pass`` when a phase is eligible.

    This is the bug the parallel-mode rollout introduced — sequential
    path called the active retry, parallel path did not.
    """

    def _build_worker_kwargs(self, phase: ScanPhase, browser=None):
        return dict(
            phase=phase,
            system_prompt="sys",
            model="bedrock/test-model",
            router=MagicMock(),
            browser=browser,
            auth_cookies=[],
            http_client=MagicMock(),
            registry=MagicMock(),
            allowed_domains=set(),
            target_url="http://example.test/",
            cancel_flag=None,
            pause_flag=None,
            exclude_urls=[],
            prior_findings=[],
            worker_id=1,
            on_progress=None,
            auth_headers=None,
        )

    def _stub_router_returning_text(self, router, text: str):
        """Make router.complete return a single text response and stop."""
        msg = MagicMock()
        msg.tool_calls = None
        msg.content = text
        msg.model_dump = lambda: {
            "role": "assistant", "content": text, "tool_calls": None,
        }
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        router.complete = MagicMock(return_value=resp)
        return router

    def _stub_scan_tools(self, monkeypatch):
        """Replace ScanTools with a MagicMock so we don't need a real browser."""
        fake_tools = MagicMock()
        fake_tools.set_findings_ref = MagicMock()
        # Tools.execute is async
        async def _exec(*a, **kw):
            return {"status": "200", "url": "http://example.test/probe"}
        fake_tools.execute = _exec

        def _ScanTools(**kwargs):
            return fake_tools
        monkeypatch.setattr(agent_module, "ScanTools", _ScanTools)
        return fake_tools

    def test_worker_calls_smart_retry_for_eligible_phase(self, monkeypatch):
        """The headline regression test.

        When a phase is in ``_ACTIVE_RETRY_PHASES`` and produces no
        findings with evidence, ``_run_smart_retry_pass`` MUST be
        called from inside ``_run_phase_worker``. Before the fix,
        this never happened in parallel mode.
        """
        self._stub_scan_tools(monkeypatch)
        # Force evidence to exist (so retry condition is met).
        # Patch _capture_evidence so it appends a record on every call.
        original_cap = agent_module._capture_evidence

        def _cap(buf, fn_name, args, summary, full):
            buf.append({
                "tool": fn_name, "url": "x", "payload": "x",
                "status": "200", "flags": "", "evidence": "x",
            })

        monkeypatch.setattr(agent_module, "_capture_evidence", _cap)

        # Stub router to return: tool_call -> tool result -> empty content (ends loop with 0 findings).
        # First response: a tool call. Second: empty content -> phase ends with 0 findings.
        tool_call_msg = MagicMock()
        tool_call_msg.tool_calls = [{
            "id": "tc_1",
            "function": {"name": "http_request", "arguments": '{"url": "/test"}'},
        }]
        tool_call_msg.content = None
        tool_call_msg.model_dump = lambda: {
            "role": "assistant", "content": None,
            "tool_calls": [{
                "id": "tc_1",
                "function": {"name": "http_request", "arguments": '{"url": "/test"}'},
                "type": "function",
            }],
        }
        end_msg = MagicMock()
        end_msg.tool_calls = None
        end_msg.content = "No vulnerabilities found"
        end_msg.model_dump = lambda: {
            "role": "assistant", "content": "No vulnerabilities found",
            "tool_calls": None,
        }
        responses = []
        for m in (tool_call_msg, end_msg):
            choice = MagicMock()
            choice.message = m
            resp = MagicMock()
            resp.choices = [choice]
            responses.append(resp)

        router = MagicMock()
        router.complete = MagicMock(side_effect=responses)

        # CAPTURE: did _run_smart_retry_pass get called?
        retry_calls = []

        async def fake_retry(**kwargs):
            retry_calls.append({
                "phase_id": kwargs["phase"].id,
                "evidence_count": len(kwargs["phase_evidence"]),
            })
            return 2, 5  # retry recovered 2 findings, used 5 tool calls

        monkeypatch.setattr(
            agent_module, "_run_smart_retry_pass", fake_retry,
        )

        phase = ScanPhase(
            id="api_authz",  # IN _ACTIVE_RETRY_PHASES
            name="Authorization / BOLA",
            prompt="test",
            max_steps=2,
        )
        kwargs = self._build_worker_kwargs(phase)
        kwargs["router"] = router

        findings, metrics = asyncio.run(agent_module._run_phase_worker(**kwargs))

        # The bug: retry_calls would be empty because the worker never
        # called the smart-retry helper.
        assert len(retry_calls) == 1, (
            "_run_phase_worker did NOT invoke _run_smart_retry_pass for an "
            "eligible phase — this is the EXACT regression introduced by "
            "commit ce2cf83 (parallel mode rollout)"
        )
        assert retry_calls[0]["phase_id"] == "api_authz"
        assert retry_calls[0]["evidence_count"] >= 1

    def test_worker_does_NOT_call_retry_for_non_eligible_phase(self, monkeypatch):
        """Recon phases (web_app_mapping etc) are NOT in _ACTIVE_RETRY_PHASES
        and must not trigger the retry pass even if they produce 0 findings."""
        self._stub_scan_tools(monkeypatch)
        monkeypatch.setattr(
            agent_module, "_capture_evidence",
            lambda buf, *a, **k: buf.append({
                "tool": "x", "url": "u", "payload": "p",
                "status": "200", "flags": "", "evidence": "x",
            }),
        )

        end_msg = MagicMock()
        end_msg.tool_calls = None
        end_msg.content = "ok"
        end_msg.model_dump = lambda: {
            "role": "assistant", "content": "ok", "tool_calls": None,
        }
        choice = MagicMock()
        choice.message = end_msg
        resp = MagicMock()
        resp.choices = [choice]
        router = MagicMock()
        router.complete = MagicMock(return_value=resp)

        retry_calls = []

        async def fake_retry(**kwargs):
            retry_calls.append(kwargs["phase"].id)
            return 0, 0

        monkeypatch.setattr(
            agent_module, "_run_smart_retry_pass", fake_retry,
        )

        # web_recon is NOT in _ACTIVE_RETRY_PHASES.
        phase = ScanPhase(
            id="web_recon", name="Application mapping",
            prompt="test", max_steps=2,
        )
        kwargs = self._build_worker_kwargs(phase)
        kwargs["router"] = router

        asyncio.run(agent_module._run_phase_worker(**kwargs))
        assert retry_calls == [], (
            "Smart retry must NOT fire for phases outside _ACTIVE_RETRY_PHASES"
        )

    def test_retry_failure_does_not_crash_phase(self, monkeypatch):
        """Even if the retry helper itself raises, the worker must not
        propagate the exception — the phase still completes (possibly
        with 0 findings, but NOT a torn-down worker)."""
        self._stub_scan_tools(monkeypatch)
        monkeypatch.setattr(
            agent_module, "_capture_evidence",
            lambda buf, *a, **k: buf.append({
                "tool": "x", "url": "u", "payload": "p",
                "status": "200", "flags": "", "evidence": "x",
            }),
        )

        end_msg = MagicMock()
        end_msg.tool_calls = None
        end_msg.content = "ok"
        end_msg.model_dump = lambda: {
            "role": "assistant", "content": "ok", "tool_calls": None,
        }
        choice = MagicMock()
        choice.message = end_msg
        resp = MagicMock()
        resp.choices = [choice]
        router = MagicMock()
        router.complete = MagicMock(return_value=resp)

        async def boom(**kwargs):
            raise RuntimeError("retry helper exploded")

        monkeypatch.setattr(agent_module, "_run_smart_retry_pass", boom)

        phase = ScanPhase(
            id="api_authz", name="Authorization / BOLA",
            prompt="test", max_steps=2,
        )
        kwargs = self._build_worker_kwargs(phase)
        kwargs["router"] = router

        # MUST NOT raise.
        findings, metrics = asyncio.run(agent_module._run_phase_worker(**kwargs))
        assert metrics["phase"] == "api_authz"
