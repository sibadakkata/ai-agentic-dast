"""Tests for full HTTP exchange capture (feature/full-http-evidence).

Validates that:
1. _build_http_exchange produces correct structure
2. _capture_evidence stores http_exchange from tool results
3. _match_evidence_to_finding propagates http_exchange to findings
4. _strip_exchanges removes http_exchange before sending to LLM
5. _cap_result strips exchanges from serialized output
"""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.ai_agent.tools import _build_http_exchange
from scanners.ai_agent.agent import (
    _capture_evidence,
    _match_evidence_to_finding,
    _strip_exchanges,
    _cap_result,
)

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]   {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))
        FAIL += 1


def test_build_http_exchange():
    print("\n=== _build_http_exchange ===")
    ex = _build_http_exchange(
        method="POST",
        url="http://example.com/api/users",
        request_headers={"Content-Type": "application/json", "Authorization": "Bearer tok123"},
        request_body='{"email":"test@test.com"}',
        status_code=200,
        response_headers={"content-type": "application/json", "x-powered-by": "Express"},
        response_body='{"id":1,"email":"test@test.com"}',
    )
    check("has request key", "request" in ex)
    check("has response key", "response" in ex)
    check("request.method is POST", ex["request"]["method"] == "POST")
    check("request.url correct", ex["request"]["url"] == "http://example.com/api/users")
    check("request has all headers", "Authorization" in ex["request"]["headers"])
    check("request.body present", ex["request"]["body"] == '{"email":"test@test.com"}')
    check("response.status_code is 200", ex["response"]["status_code"] == 200)
    check("response has all headers", "x-powered-by" in ex["response"]["headers"])
    check("response.body present", "test@test.com" in ex["response"]["body"])


def test_build_http_exchange_truncation():
    print("\n=== _build_http_exchange body truncation ===")
    big_body = "x" * 20000
    ex = _build_http_exchange(
        method="GET", url="http://x.com", response_body=big_body, status_code=200,
    )
    check("response body truncated to 8192", len(ex["response"]["body"]) == 8192)


def test_capture_evidence_with_exchange():
    print("\n=== _capture_evidence stores http_exchange ===")
    exchange = _build_http_exchange(
        method="GET", url="http://t.com/api", status_code=200,
        response_headers={"content-type": "text/html"},
        response_body="<html>OK</html>",
    )
    result = {
        "status": 200,
        "body_snippet": "<html>OK</html>",
        "http_exchange": exchange,
    }
    evidence = []
    _capture_evidence(evidence, "api_request", {"url": "http://t.com/api"}, {}, result)
    check("evidence has 1 entry", len(evidence) == 1)
    check("evidence entry has http_exchange", "http_exchange" in evidence[0])
    check("exchange has response body", evidence[0]["http_exchange"]["response"]["body"] == "<html>OK</html>")


def test_capture_evidence_fuzz_with_exchange():
    print("\n=== _capture_evidence fuzz_parameter with http_exchange ===")
    ex1 = _build_http_exchange(method="GET", url="http://t.com?q=test", status_code=200, response_body="reflected: test")
    ex2 = _build_http_exchange(method="GET", url="http://t.com?q=<script>", status_code=200, response_body="reflected: <script>")
    result = {
        "endpoint": "http://t.com",
        "param": "q",
        "results": [
            {"payload": "test", "status": 200, "body_snippet": "reflected: test", "anomaly": False, "reflected": True, "http_exchange": ex1},
            {"payload": "<script>", "status": 200, "body_snippet": "reflected: <script>", "anomaly": True, "reflected": True, "http_exchange": ex2},
        ],
    }
    evidence = []
    _capture_evidence(evidence, "fuzz_parameter", {"endpoint": "http://t.com", "param_name": "q"}, {}, result)
    check("evidence has 2 entries", len(evidence) == 2)
    check("entry 0 has http_exchange", "http_exchange" in evidence[0])
    check("entry 1 has http_exchange", "http_exchange" in evidence[1])


def test_match_evidence_with_exchange():
    print("\n=== _match_evidence_to_finding propagates http_exchange ===")
    exchange = _build_http_exchange(
        method="POST", url="http://t.com/api/users",
        request_headers={"Content-Type": "application/json"},
        request_body='{"email":"<script>alert(1)</script>"}',
        status_code=200,
        response_headers={"content-type": "application/json"},
        response_body='{"id":1,"email":"<script>alert(1)</script>"}',
    )
    evidence = [{
        "tool": "fuzz_parameter[email]",
        "url": "http://t.com/api/users",
        "payload": "<script>alert(1)</script>",
        "status": "200",
        "flags": "REFLECTED",
        "evidence": '{"id":1,"email":"<script>',
        "http_exchange": exchange,
    }]
    finding = {
        "title": "Reflected XSS in email parameter",
        "url": "http://t.com/api/users",
        "payload": "<script>alert(1)</script>",
        "severity": "High",
    }
    _match_evidence_to_finding(finding, evidence)
    check("finding has request_response", "request_response" in finding)
    check("request_response has 1 match", len(finding["request_response"]) == 1)
    rr = finding["request_response"][0]
    check("matched entry has http_exchange", "http_exchange" in rr)
    check("exchange has full request headers", "Content-Type" in rr["http_exchange"]["request"]["headers"])
    check("exchange has full response body", "<script>alert(1)</script>" in rr["http_exchange"]["response"]["body"])


def test_strip_exchanges():
    print("\n=== _strip_exchanges removes http_exchange ===")
    data = {
        "status": 200,
        "body_snippet": "ok",
        "http_exchange": {"request": {"method": "GET"}, "response": {"status_code": 200}},
        "results": [
            {"payload": "x", "http_exchange": {"request": {}, "response": {}}},
        ],
    }
    clean = _strip_exchanges(data)
    check("top-level http_exchange removed", "http_exchange" not in clean)
    check("nested http_exchange removed", "http_exchange" not in clean["results"][0])
    check("other fields preserved", clean["status"] == 200)
    check("nested payload preserved", clean["results"][0]["payload"] == "x")


def test_cap_result_strips_exchange():
    print("\n=== _cap_result strips http_exchange from LLM context ===")
    result = {
        "status": 200,
        "body_snippet": "hello",
        "http_exchange": {
            "request": {"method": "GET", "url": "http://x.com", "headers": {"Host": "x.com"}, "body": ""},
            "response": {"status_code": 200, "headers": {"content-type": "text/plain"}, "body": "hello"},
        },
    }
    serialized = _cap_result(result)
    parsed = json.loads(serialized)
    check("serialized has no http_exchange", "http_exchange" not in parsed)
    check("serialized has status", parsed["status"] == 200)
    check("serialized has body_snippet", parsed["body_snippet"] == "hello")


if __name__ == "__main__":
    test_build_http_exchange()
    test_build_http_exchange_truncation()
    test_capture_evidence_with_exchange()
    test_capture_evidence_fuzz_with_exchange()
    test_match_evidence_with_exchange()
    test_strip_exchanges()
    test_cap_result_strips_exchange()
    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    if FAIL:
        sys.exit(1)
    print("All tests passed!")
