"""Regression tests for ``/api/results/{scan_id}`` resilience.

Background
----------
On 28-Apr-2026 the deployed scanner hit ``500 Internal Server Error`` on the
live results endpoint for two completed scans (``scan_20260428_081209_b23cf3``
and ``scan_20260428_090227_1760bc``) with the traceback::

    File "/app/web/app.py", line 4026, in _extract_crawled
        url = str(req.get("url", "") or req.get("endpoint", ""))
    AttributeError: 'str' object has no attribute 'get'

The root cause was a non-dict entry in ``SCANS[scan_id]["live_tests"]``
that bled into the read path (``app.py:2629``) when the on-disk
``summary.test_log`` was empty. The previous code in ``_extract_crawled``
did not defensively check item types - and ``_extract_payloads_by_endpoint``
only checked ``request`` but not ``t`` itself.

These tests pin three contracts that *must* hold before any change is
merged to master:

1. ``_extract_crawled`` and ``_extract_payloads_by_endpoint`` never raise
   ``AttributeError`` regardless of malformed shapes inside ``test_log``.
2. ``GET /api/results/{scan_id}`` returns ``200`` even when
   ``SCANS[scan_id]["live_tests"]`` contains string / None / list / scalar
   entries.
3. The ``?enc=b64`` envelope round-trips a complete result document (i.e.
   the encoded payload decodes back to a JSON dict with the expected top
   level keys - no truncation, no double-encoding).
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Auth credentials must be set BEFORE importing web.app because they're
# read at import time.
os.environ.setdefault("DAST_AUTH_USER", "test-user")
os.environ.setdefault("DAST_AUTH_PASS", "test-pass")

from web import app as app_module  # noqa: E402
from web.app import (  # noqa: E402
    _extract_crawled,
    _extract_payloads_by_endpoint,
)


# ── _extract_crawled: defensive type handling ────────────────────────────


class TestExtractCrawledTypeResilience:
    """Pin defensive type checks for ``_extract_crawled``.

    Every assertion in this class corresponds to a real-world malformed
    shape that has been observed (or could plausibly occur) in
    ``live_tests``. None of these inputs should raise.
    """

    def test_empty_list_returns_empty(self):
        assert _extract_crawled({}, []) == []

    def test_none_test_log_returns_empty(self):
        # Defensive: callers occasionally pass None when summary is missing.
        assert _extract_crawled({}, None) == []

    def test_non_list_test_log_returns_empty(self):
        assert _extract_crawled({}, "not a list") == []
        assert _extract_crawled({}, {"oops": 1}) == []
        assert _extract_crawled({}, 42) == []

    def test_string_entry_in_test_log_skipped(self):
        # *** This is the exact production bug: a raw string in live_tests. ***
        log = ["some stringified payload that should never be here"]
        assert _extract_crawled({}, log) == []

    def test_none_entry_in_test_log_skipped(self):
        log = [None, None]
        assert _extract_crawled({}, log) == []

    def test_scalar_entry_in_test_log_skipped(self):
        log = [42, 3.14, True]
        assert _extract_crawled({}, log) == []

    def test_dict_with_non_dict_request_skipped(self):
        log = [{"phase": "recon", "tool": "fetch", "request": "GET /foo"}]
        assert _extract_crawled({}, log) == []

    def test_dict_with_none_request_skipped(self):
        log = [{"phase": "recon", "tool": "fetch", "request": None}]
        assert _extract_crawled({}, log) == []

    def test_mixed_valid_and_invalid_entries(self):
        # Critical case: one bad entry must NOT poison the whole batch.
        log = [
            "garbage string entry",
            {"request": {"url": "http://x.com/a", "method": "GET"}},
            None,
            {"request": "not a dict"},
            42,
            {"request": {"url": "http://x.com/b", "method": "POST"}},
        ]
        out = _extract_crawled({}, log)
        urls = sorted(o["url"] for o in out)
        assert urls == ["http://x.com/a", "http://x.com/b"]
        # Method preserved correctly for the surviving items.
        by_url = {o["url"]: o["method"] for o in out}
        assert by_url["http://x.com/a"] == "GET"
        assert by_url["http://x.com/b"] == "POST"

    def test_non_dict_response_still_extracts_url(self):
        # If response is malformed we should still capture the request URL.
        log = [{"request": {"url": "http://x.com/c"}, "response_summary": "broken"}]
        out = _extract_crawled({}, log)
        assert len(out) == 1
        assert out[0]["url"] == "http://x.com/c"
        assert out[0]["status"] == ""

    def test_endpoint_field_used_when_url_missing(self):
        log = [{"request": {"endpoint": "http://x.com/api/v1/users", "method": "POST"}}]
        out = _extract_crawled({}, log)
        assert out == [{"url": "http://x.com/api/v1/users", "method": "POST", "status": ""}]

    def test_url_dedupe_across_entries(self):
        log = [
            {"request": {"url": "http://x.com/a"}},
            {"request": {"url": "http://x.com/a"}},  # duplicate
            {"request": {"url": "http://x.com/a"}},  # duplicate
        ]
        out = _extract_crawled({}, log)
        assert len(out) == 1


# ── _extract_payloads_by_endpoint: same defensive contract ───────────────


class TestExtractPayloadsTypeResilience:
    """Pin defensive type checks for ``_extract_payloads_by_endpoint``.

    The pre-existing code already guarded ``req`` but NOT ``t`` itself.
    Both must be guarded.
    """

    def test_empty_list(self):
        assert _extract_payloads_by_endpoint([]) == []

    def test_none_test_log(self):
        assert _extract_payloads_by_endpoint(None) == []

    def test_non_list_test_log(self):
        assert _extract_payloads_by_endpoint("string") == []
        assert _extract_payloads_by_endpoint({}) == []

    def test_string_entry_skipped(self):
        assert _extract_payloads_by_endpoint(["raw string"]) == []

    def test_none_entry_skipped(self):
        assert _extract_payloads_by_endpoint([None]) == []

    def test_dict_with_non_dict_request_skipped(self):
        assert _extract_payloads_by_endpoint([{"request": "GET /foo"}]) == []

    def test_mixed_valid_and_invalid(self):
        log = [
            "garbage",
            None,
            {"tool": "fuzz_parameter", "request": {
                "url": "http://x.com/api?id=1",
                "method": "GET",
                "param_name": "id",
                "payloads": ["1' OR 1=1--"],
            }},
            {"request": "string-not-dict"},
        ]
        out = _extract_payloads_by_endpoint(log)
        # Only the valid fuzz_parameter entry should yield output.
        assert len(out) == 1
        ep = out[0]
        # Result shape matches what the frontend renders: {endpoint, payload_count, anomaly_count, payloads}.
        assert ep["endpoint"] == "GET http://x.com/api"
        assert ep["payload_count"] == 1
        assert ep["payloads"][0]["payload"] == "1' OR 1=1--"


# ── End-to-end /api/results/{id} regression ──────────────────────────────


@pytest.fixture()
def client_with_scan(tmp_path, monkeypatch):
    """Spin up a TestClient with a forged scan record on disk + in SCANS.

    The forged ``live_tests`` deliberately contains the malformed shapes
    from the production incident (string entries, dict-with-string-request)
    so the integration test exercises the exact failure mode.
    """
    from fastapi.testclient import TestClient

    scan_id = "test_scan_resilience_001"
    raw_payload = {
        "target": "http://example.test/",
        "scan_mode": "full",
        "findings": [
            {
                "title": "Test finding A",
                "severity": "Medium",
                "url": "http://example.test/a",
                "owasp_category": "A01:2021 - Broken Access Control",
                "cwe": "CWE-285",
                "cvss": 5.4,
                "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            },
        ],
        "metadata": {
            "model": "test-model",
            "scan_duration_seconds": 60,
            "cost_usd": 0.01,
            "total_tokens": 1000,
            "llm_calls": 5,
        },
        "summary": {
            # IMPORTANT: empty test_log on disk forces fallback to live_tests
            # in SCANS - which is where the production bug lived.
            "test_log": [],
        },
    }

    # Write to disk in the structure ``_load_raw_result_dict`` expects.
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    raw_file = raw_dir / f"aiagent_test_{scan_id}.json"
    raw_file.write_text(json.dumps(raw_payload), encoding="utf-8")

    # Point the app at our temporary directory.
    monkeypatch.setattr(app_module, "RAW_DIR", raw_dir)

    # Stub out the DB so ``_load_raw_result_dict`` falls through to disk.
    monkeypatch.setattr(app_module.scandb, "get_scan_result", lambda sid: None)
    monkeypatch.setattr(app_module.scandb, "save_scan_result", lambda *a, **kw: None)

    # *** The malformed live state from production: ***
    app_module.SCANS[scan_id] = {
        "id": scan_id,
        "target": "http://example.test/",
        "status": "completed",
        "result_file": raw_file.name,
        "live_tests": [
            "raw string entry that should be ignored",
            {"phase": "recon", "tool": "fetch", "request": {"url": "http://example.test/page"}, "response": {"status": 200}},
            None,
            {"phase": "recon", "tool": "fetch", "request": "stringified-request"},
            42,
            {"request": {"endpoint": "http://example.test/api", "method": "POST"}},
        ],
    }

    # Also clear the results cache so we exercise the cold path.
    app_module._RESULTS_CACHE.clear()

    client = TestClient(app_module.app)
    yield client, scan_id

    # Cleanup
    app_module.SCANS.pop(scan_id, None)
    app_module._RESULTS_CACHE.pop(scan_id, None)


class TestResultsEndpointWithMalformedLiveTests:
    """End-to-end regression: the endpoint must NOT 500 on malformed live_tests."""

    def test_endpoint_returns_200_with_malformed_live_tests(self, client_with_scan):
        client, scan_id = client_with_scan
        resp = client.get(f"/api/results/{scan_id}", auth=("test-user", "test-pass"))
        # *** This is the exact assertion that would have caught the production bug. ***
        assert resp.status_code == 200, (
            f"Expected 200, got {resp.status_code}: {resp.text[:300]}"
        )
        body = resp.json()
        assert "ai_findings" in body
        assert "triaged_findings" in body
        assert "crawled_endpoints" in body
        # Only the well-formed dict entries should have been crawled.
        urls = {c["url"] for c in body["crawled_endpoints"]}
        assert "http://example.test/page" in urls
        assert "http://example.test/api" in urls
        # No extracted entry should leak the malformed string.
        for c in body["crawled_endpoints"]:
            assert isinstance(c.get("url"), str)
            assert c["url"]  # non-empty

    def test_b64_envelope_roundtrips_completely(self, client_with_scan):
        """Pin that ``?enc=b64`` returns the full payload, not a truncated one.

        Earlier-misdiagnosed Content-Length issue: validate that decoding
        the b64 envelope yields a complete JSON object with all expected
        top-level keys.
        """
        client, scan_id = client_with_scan
        resp = client.get(
            f"/api/results/{scan_id}?enc=b64",
            auth=("test-user", "test-pass"),
        )
        assert resp.status_code == 200, resp.text[:300]
        envelope = resp.json()
        assert "_b64" in envelope
        # Round-trip
        decoded_bytes = base64.b64decode(envelope["_b64"])
        decoded = json.loads(decoded_bytes)
        for required_key in (
            "metadata",
            "coverage",
            "ai_findings",
            "triaged_findings",
            "crawled_endpoints",
            "payloads_by_endpoint",
        ):
            assert required_key in decoded, f"missing key: {required_key}"
        # AI findings made it through intact.
        assert decoded["ai_findings"][0]["title"] == "Test finding A"

    def test_endpoint_returns_200_with_all_string_live_tests(self, client_with_scan):
        """Edge case: every live_tests entry is malformed."""
        client, scan_id = client_with_scan
        app_module.SCANS[scan_id]["live_tests"] = ["a", "b", "c", None, 42]
        app_module._RESULTS_CACHE.pop(scan_id, None)
        resp = client.get(f"/api/results/{scan_id}", auth=("test-user", "test-pass"))
        assert resp.status_code == 200, resp.text[:300]
        body = resp.json()
        assert body["crawled_endpoints"] == []

    def test_endpoint_returns_200_with_empty_live_tests(self, client_with_scan):
        client, scan_id = client_with_scan
        app_module.SCANS[scan_id]["live_tests"] = []
        app_module._RESULTS_CACHE.pop(scan_id, None)
        resp = client.get(f"/api/results/{scan_id}", auth=("test-user", "test-pass"))
        assert resp.status_code == 200

    def test_endpoint_returns_200_with_missing_live_tests_key(self, client_with_scan):
        client, scan_id = client_with_scan
        app_module.SCANS[scan_id].pop("live_tests", None)
        app_module._RESULTS_CACHE.pop(scan_id, None)
        resp = client.get(f"/api/results/{scan_id}", auth=("test-user", "test-pass"))
        assert resp.status_code == 200
