"""Regression tests for the ``fuzz_body`` return-shape contract.

Background
----------
``fuzz_body`` is awaited from ``agent.py`` like::

    fuzz_results, ep_llm_findings = await fuzz_body(...)

i.e. the caller unpacks the result into a 2-tuple.  Earlier two early-exit
paths returned a single empty ``list`` instead of a ``(list, list)`` tuple,
which crashed the caller with::

    ValueError: not enough values to unpack (expected 2, got 0)

These tests exercise both early-exit paths and the success path to make sure
the contract (always returns a 2-tuple of two lists) is preserved.
"""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from scanners.ai_agent.body_fuzzer import FuzzResult, fuzz_body


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ------------------------------------------------------------------- contract
def test_return_annotation_is_two_tuple():
    """The annotated return type must be a 2-tuple, not a bare list."""
    sig = inspect.signature(fuzz_body)
    ann = str(sig.return_annotation)
    assert "tuple[" in ann or "Tuple[" in ann, (
        f"fuzz_body must be annotated as returning a tuple, got: {ann!r}"
    )


# ------------------------------------------------------------- early-exit: bad body
def test_unparseable_body_returns_two_empty_lists():
    """If ``original_body`` is not valid JSON, fuzz_body must still return
    a 2-tuple so the caller's tuple-unpacking does not fail."""
    client = MagicMock()
    out = _run(fuzz_body(
        client=client, method="POST", url="http://example.test/api/x",
        original_body="this is not json",
    ))
    assert isinstance(out, tuple), f"expected tuple, got {type(out).__name__}"
    assert len(out) == 2, f"expected length-2 tuple, got length {len(out)}"
    fuzz_results, llm_findings = out
    assert fuzz_results == []
    assert llm_findings == []


def test_unparseable_body_caller_can_unpack():
    """The caller in ``agent.py`` does ``a, b = await fuzz_body(...)``.
    This test exercises that exact unpack on the unparseable-body path."""
    client = MagicMock()
    a, b = _run(fuzz_body(
        client=client, method="POST", url="http://example.test/api/x",
        original_body="not json",
    ))
    assert a == [] and b == []


def test_none_body_does_not_crash():
    """``None`` body should be handled gracefully via the JSONDecodeError /
    TypeError except branch."""
    client = MagicMock()
    a, b = _run(fuzz_body(
        client=client, method="POST", url="http://example.test/api/x",
        original_body=None,  # type: ignore[arg-type]
    ))
    assert a == [] and b == []


# ------------------------------------------------------- early-exit: baseline fail
def test_baseline_failure_returns_two_empty_lists():
    """If the baseline request fails, fuzz_body must still return a 2-tuple."""
    client = MagicMock()
    client.request = AsyncMock(side_effect=RuntimeError("connection refused"))
    a, b = _run(fuzz_body(
        client=client, method="POST", url="http://example.test/api/x",
        original_body='{"username": "alice"}',
    ))
    assert isinstance(a, list) and isinstance(b, list)
    assert a == [] and b == []


# ------------------------------------------------------- success path: real shape
def test_success_path_returns_two_lists():
    """Happy path: parseable body + working baseline returns
    ``(list[FuzzResult], list[LLMFinding])``."""
    client = MagicMock()

    def _mk_resp(status=200, body='{"ok": true}'):
        r = MagicMock()
        r.status_code = status
        r.text = body
        return r

    client.request = AsyncMock(return_value=_mk_resp())
    a, b = _run(fuzz_body(
        client=client, method="POST", url="http://example.test/api/x",
        original_body='{"username": "alice"}',
        max_priority=1,
    ))
    assert isinstance(a, list)
    assert isinstance(b, list)
    for item in a:
        assert isinstance(item, FuzzResult), f"a contains non-FuzzResult: {type(item)}"
