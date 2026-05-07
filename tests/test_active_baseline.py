"""Tests for the active baseline probe.

Pins the contract for ``scanners.ai_agent.active_baseline.run_bare_root_sqli_probe``:

1. With a fake http_client that returns control responses fast and attack
   responses slow (>= 4s), the probe MUST emit one Critical finding per
   confirmed host.
2. With a fake http_client that returns all responses fast, the probe
   MUST emit zero findings (no false positives on a non-vulnerable target).
3. With a fake http_client that returns ALL responses slow (slow target,
   not SQLi), the delta is < threshold so probe MUST emit zero findings.
4. ``hosts`` input may be a mix of bare hostnames, full URLs, and
   duplicates — the probe MUST normalize and dedupe internally.
5. ``cancel_flag`` set mid-probe MUST stop iteration cleanly.
6. ``http_client`` raising on attack URL MUST NOT crash the probe (caller
   never sees an exception); the failed payload is silently skipped.

These tests use an asyncio-style mock http_client; they do NOT make any
real network requests.
"""
from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest

from scanners.ai_agent.active_baseline import (
    _BARE_ROOT_PAYLOADS,
    _normalize_hosts,
    run_bare_root_sqli_probe,
)


class _FakeResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


class _FakeAsyncHttpClient:
    """Minimal stub that returns deterministic timings.

    ``timing_for(url)`` is called for every GET and must return the
    seconds to "sleep" before responding. Any URL containing ``"SLEEP"``
    or ``"pg_sleep"`` (case-insensitive) is treated as the attack URL.
    """

    def __init__(self, *, control_s: float, attack_s: float, raise_on_attack: bool = False) -> None:
        self._control_s = control_s
        self._attack_s = attack_s
        self._raise = raise_on_attack
        self.calls: list[tuple[str, float]] = []

    async def get(self, url: str, timeout: float | None = None):
        is_attack = (
            "SLEEP" in url.upper()
            or "PG_SLEEP" in url.upper()
            or "WAITFOR" in url.upper()
        )
        delay = self._attack_s if is_attack else self._control_s
        if self._raise and is_attack:
            await asyncio.sleep(0.001)
            raise RuntimeError("simulated transport error")
        await asyncio.sleep(delay)
        self.calls.append((url, delay))
        return _FakeResponse(200)


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_bare_root_probe_emits_critical_when_attack_is_slow():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["test.example.invalid"],
    ))
    assert len(findings) >= 1, "expected at least one finding when attack is >= 4s"
    f = findings[0]
    assert f["severity"] == "Critical"
    assert f["confidence"] == "High"
    assert f["owasp_category"] == "A03:2021"
    assert f["cwe"] == "CWE-89"
    assert "test.example.invalid" in f["url"]
    assert f["parameter"] == "(raw query string)"
    assert f["phase"] == "Active Baseline (Bare-Root SQLi)"
    assert f["_finding_source"] == "active_baseline"


def test_bare_root_probe_no_finding_when_target_is_clean():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["clean.example.invalid"],
    ))
    assert findings == [], "clean target must not produce findings"


def test_bare_root_probe_no_finding_when_target_is_uniformly_slow():
    """A target where every request takes 4s+ has NO delta — not SQLi."""
    client = _FakeAsyncHttpClient(control_s=4.5, attack_s=4.6)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["slow.example.invalid"],
    ))
    assert findings == [], "uniformly slow target must not produce findings"


def test_bare_root_probe_dedupes_input_hosts():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    _run_async(run_bare_root_sqli_probe(
        client,
        [
            "https://dup.example.invalid/path?q=1",
            "dup.example.invalid",
            "DUP.EXAMPLE.INVALID",
            "http://dup.example.invalid:8080",
        ],
    ))
    # 1 control + len(payloads) attack requests for the single dedup'd host
    expected = 1 + len(_BARE_ROOT_PAYLOADS)
    assert len(client.calls) == expected, (
        f"expected {expected} calls for one dedup'd host, got {len(client.calls)}: "
        f"{[c[0] for c in client.calls]}"
    )


def test_bare_root_probe_normalize_hosts_helper():
    out = _normalize_hosts([
        "https://A.example.invalid/x",
        "a.example.invalid",
        "https://b.example.invalid",
        "",
        None,
    ])
    assert out == ["a.example.invalid", "b.example.invalid"]


def test_bare_root_probe_respects_cancel_flag():
    # Set the cancel flag BEFORE calling the probe — should bail out
    # after at most a control GET on the first host.
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    cancel = threading.Event()
    cancel.set()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["c.example.invalid", "c2.example.invalid"],
        cancel_flag=cancel,
    ))
    assert findings == []
    # No requests should fire because cancel is checked at the top of
    # each host iteration.
    assert len(client.calls) == 0


def test_bare_root_probe_swallows_transport_errors_on_attack():
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05, raise_on_attack=True)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["err.example.invalid"],
    ))
    # Probe must not crash; with all attacks erroring, no findings.
    assert findings == []


def test_bare_root_probe_progress_callback_is_called():
    events: list[tuple[str, dict]] = []
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=0.05)
    _run_async(run_bare_root_sqli_probe(
        client,
        ["p.example.invalid"],
        on_progress=lambda ev, data: events.append((ev, data)),
    ))
    assert any(ev == "active_baseline_start" for ev, _ in events)
    assert any(ev == "active_baseline_end" for ev, _ in events)
    assert any(ev == "active_baseline_step" for ev, _ in events)


def test_bare_root_probe_finding_callback_is_called_per_finding():
    callback_findings: list[dict] = []
    client = _FakeAsyncHttpClient(control_s=0.05, attack_s=4.5)
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["cb.example.invalid"],
        on_finding=callback_findings.append,
    ))
    assert len(findings) == len(callback_findings) >= 1
    assert findings[0] is callback_findings[0]


def test_bare_root_probe_skips_host_when_control_fails():
    """If the control GET errors out, the host MUST be skipped — no
    attacks attempted, no false positive based on missing baseline."""
    class _ControlFailingClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def get(self, url, timeout=None):
            self.calls.append(url)
            await asyncio.sleep(0.001)
            raise RuntimeError("control failed")

    client = _ControlFailingClient()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["bad.example.invalid"],
    ))
    assert findings == []
    # Only the control request should have been attempted.
    assert len(client.calls) == 1, (
        f"expected exactly 1 (control) call when control fails, got {len(client.calls)}"
    )


def test_bare_root_probe_emits_no_finding_when_only_one_attack_hits_then_confirm_fails():
    """Confirmation step MUST run before reporting. If the second attack
    is fast (network jitter cleared up), no finding is emitted."""
    state = {"first_attack": True}

    class _JitterClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, float]] = []

        async def get(self, url, timeout=None):
            if "SLEEP" in url.upper() or "PG_SLEEP" in url.upper():
                if state["first_attack"]:
                    state["first_attack"] = False
                    await asyncio.sleep(4.5)
                    self.calls.append((url, 4.5))
                else:
                    await asyncio.sleep(0.05)
                    self.calls.append((url, 0.05))
            else:
                await asyncio.sleep(0.05)
                self.calls.append((url, 0.05))
            return _FakeResponse(200)

    client = _JitterClient()
    findings = _run_async(run_bare_root_sqli_probe(
        client,
        ["jitter.example.invalid"],
    ))
    assert findings == [], (
        "single jitter spike that doesn't reproduce on confirm MUST NOT "
        "emit a finding"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
