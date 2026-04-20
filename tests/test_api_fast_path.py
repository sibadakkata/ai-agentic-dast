"""Tests for the API-only fast path.

Covers:
- can_use_http_only_auth gating for every auth_type variant
- authenticate_http_only produces a correct browserless AuthSession
- autodiscover_openapi finds a spec at a well-known path and skips bad ones
- run_http_only_passive_recon runs without a Playwright page

These tests use lightweight fakes for httpx.AsyncClient instead of pulling in
a real HTTP server — the goal is to verify wiring, not the content of each
individual check.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanners.ai_agent.api_import import autodiscover_openapi
from scanners.ai_agent.auth import (
    AuthSession,
    ScanTarget,
    authenticate_http_only,
    can_use_http_only_auth,
)
from scanners.ai_agent.passive_recon import run_http_only_passive_recon

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} — {detail}")


# ---------------------------------------------------------------------------
# Fake HTTP client — just enough httpx surface area for the tests
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict | None = None, body: str = ""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = body

    def json(self):
        return json.loads(self.text)


class _FakeClient:
    """Minimal httpx.AsyncClient stand-in.  Routes requests from a dict map."""

    def __init__(self, routes: dict[str, _FakeResponse]):
        self._routes = routes
        self.base_url = ""
        self.calls: list[str] = []

    async def get(self, url: str, **_kwargs):
        self.calls.append(url)
        # Exact match, else fall back to 404
        if url in self._routes:
            return self._routes[url]
        # Allow suffix match so tests can write "/openapi.json" without host
        for key, resp in self._routes.items():
            if url.endswith(key):
                return resp
        return _FakeResponse(404, {}, "")

    async def aclose(self):
        pass


# ---------------------------------------------------------------------------
# can_use_http_only_auth — gating logic
# ---------------------------------------------------------------------------


def _target(**kwargs) -> ScanTarget:
    defaults = dict(
        id="t",
        url="https://api.example.com",
        scan_mode="api",
        credentials={},
        auth_config={},
    )
    defaults.update(kwargs)
    return ScanTarget(**defaults)


def test_gate_none_eligible():
    t = _target(auth_config={"type": "none"})
    check("gate: none -> eligible", can_use_http_only_auth(t))


def test_gate_bearer_with_token_eligible():
    t = _target(auth_config={"type": "bearer", "bearer_token": "abc"})
    check("gate: bearer+token -> eligible", can_use_http_only_auth(t))


def test_gate_bearer_without_token_rejected():
    t = _target(auth_config={"type": "bearer"})
    check("gate: bearer w/o token -> rejected", not can_use_http_only_auth(t))


def test_gate_api_key_with_value_eligible():
    t = _target(auth_config={"type": "api_key", "api_key": "key-123"})
    check("gate: api_key with value -> eligible", can_use_http_only_auth(t))


def test_gate_api_key_without_value_rejected():
    t = _target(auth_config={"type": "api_key"})
    check("gate: api_key w/o value -> rejected", not can_use_http_only_auth(t))


def test_gate_basic_with_creds_eligible():
    t = _target(credentials={"username": "u", "password": "p"},
                auth_config={"type": "basic"})
    check("gate: basic+creds -> eligible", can_use_http_only_auth(t))


def test_gate_basic_empty_rejected():
    t = _target(credentials={}, auth_config={"type": "basic"})
    check("gate: basic w/o creds -> rejected", not can_use_http_only_auth(t))


def test_gate_form_rejected():
    t = _target(auth_config={"type": "form"})
    check("gate: form -> rejected (needs browser)", not can_use_http_only_auth(t))


def test_gate_sso_rejected():
    t = _target(auth_config={"type": "sso"})
    check("gate: sso -> rejected", not can_use_http_only_auth(t))


def test_gate_auto_rejected():
    # "auto" means we haven't classified it yet — fall back to browser path.
    t = _target(auth_config={"type": "auto"})
    check("gate: auto -> rejected (fall back to browser)", not can_use_http_only_auth(t))


# ---------------------------------------------------------------------------
# authenticate_http_only — AuthSession shape
# ---------------------------------------------------------------------------


def test_auth_http_only_none():
    t = _target(auth_config={"type": "none"})
    sess: AuthSession = asyncio.run(authenticate_http_only(t))
    check("auth: page is None", sess.page is None)
    check("auth: browserless==True", sess.browserless)
    check("auth: auth_type=none", sess._auth_type == "none")
    check("auth: empty header", sess.get_auth_header() == {})
    check("auth: success flag True", getattr(sess, "success", False) is True)


def test_auth_http_only_bearer():
    t = _target(auth_config={"type": "bearer", "bearer_token": "tok"})
    sess = asyncio.run(authenticate_http_only(t))
    check("auth bearer: header correct",
          sess.get_auth_header() == {"Authorization": "Bearer tok"})


def test_auth_http_only_api_key():
    t = _target(auth_config={"type": "api_key", "api_key": "k1"})
    sess = asyncio.run(authenticate_http_only(t))
    check("auth api_key: header correct",
          sess.get_auth_header() == {"X-API-Key": "k1"})


def test_auth_http_only_basic():
    t = _target(credentials={"username": "u", "password": "p"},
                auth_config={"type": "basic"})
    sess = asyncio.run(authenticate_http_only(t))
    hdr = sess.get_auth_header()
    check("auth basic: produces Authorization header",
          hdr.get("Authorization", "").startswith("Basic "))


def test_auth_http_only_rejects_form():
    t = _target(auth_config={"type": "form"},
                credentials={"username": "u", "password": "p"})
    raised = False
    try:
        asyncio.run(authenticate_http_only(t))
    except ValueError:
        raised = True
    check("auth: form raises ValueError", raised)


# ---------------------------------------------------------------------------
# autodiscover_openapi
# ---------------------------------------------------------------------------


def test_autodiscover_finds_v3_api_docs():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "T"},
        "paths": {"/users/{id}": {"get": {"operationId": "getUser"}}},
    }
    client = _FakeClient({
        "https://api.example.com/v3/api-docs": _FakeResponse(
            200, {"content-type": "application/json"}, json.dumps(spec)
        ),
    })
    endpoints = asyncio.run(autodiscover_openapi(client, "https://api.example.com/"))
    check("autodiscover: found v3/api-docs", len(endpoints) == 1)
    if endpoints:
        ep = endpoints[0]
        check("autodiscover: method GET", ep.method == "GET")
        check("autodiscover: path preserved", ep.path == "/users/{id}")
        check("autodiscover: tag includes autodiscovered",
              any("autodiscovered" in t for t in ep.tags))


def test_autodiscover_falls_through_to_openapi_json():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "T"},
        "paths": {"/things": {"post": {"operationId": "createThing"}}},
    }
    client = _FakeClient({
        "https://api.example.com/v3/api-docs": _FakeResponse(404),
        "https://api.example.com/v2/api-docs": _FakeResponse(404),
        "https://api.example.com/openapi.json": _FakeResponse(
            200, {"content-type": "application/json"}, json.dumps(spec)
        ),
    })
    endpoints = asyncio.run(autodiscover_openapi(client, "https://api.example.com/"))
    check("autodiscover: falls through to openapi.json", len(endpoints) == 1)


def test_autodiscover_returns_empty_when_no_spec():
    client = _FakeClient({})  # every path 404s
    endpoints = asyncio.run(autodiscover_openapi(client, "https://api.example.com/"))
    check("autodiscover: empty when none found", endpoints == [])


def test_autodiscover_skips_html_200():
    # A target may return the Swagger UI HTML page on /api-docs — don't treat
    # that as a spec.
    client = _FakeClient({
        "https://api.example.com/api-docs": _FakeResponse(
            200, {"content-type": "text/html"}, "<html>swagger ui</html>"
        ),
    })
    endpoints = asyncio.run(autodiscover_openapi(client, "https://api.example.com/"))
    check("autodiscover: skips HTML 200", endpoints == [])


def test_autodiscover_skips_malformed_json():
    client = _FakeClient({
        "https://api.example.com/openapi.json": _FakeResponse(
            200, {"content-type": "application/json"}, "{not: valid json}"
        ),
    })
    endpoints = asyncio.run(autodiscover_openapi(client, "https://api.example.com/"))
    check("autodiscover: skips malformed json", endpoints == [])


# ---------------------------------------------------------------------------
# run_http_only_passive_recon — runs without a page and returns findings/tech
# ---------------------------------------------------------------------------


def test_passive_recon_http_only_runs_without_page():
    # Return 404 for everything.  We just want to verify the function runs
    # end-to-end without page and returns the expected tuple shape.
    client = _FakeClient({})
    findings, tech = asyncio.run(
        run_http_only_passive_recon(client, "https://api.example.com/")
    )
    check("passive http-only: returns list of findings", isinstance(findings, list))
    check("passive http-only: returns tech dict", isinstance(tech, dict))
    check("passive http-only: tech has technologies key", "technologies" in tech)


def test_passive_recon_http_only_detects_actuator():
    # Spring Boot-style Actuator exposure.
    actuator_health = {"status": "UP"}
    actuator_env = {"activeProfiles": ["prod"], "propertySources": []}
    client = _FakeClient({
        "https://api.example.com/actuator": _FakeResponse(
            200, {"content-type": "application/json"},
            json.dumps({"_links": {"health": {}, "env": {}}}),
        ),
        "https://api.example.com/actuator/health": _FakeResponse(
            200, {"content-type": "application/json"}, json.dumps(actuator_health)
        ),
        "https://api.example.com/actuator/env": _FakeResponse(
            200, {"content-type": "application/json"}, json.dumps(actuator_env)
        ),
    })
    findings, _ = asyncio.run(
        run_http_only_passive_recon(client, "https://api.example.com/")
    )
    actuator_findings = [f for f in findings if "Actuator" in f.get("title", "")]
    check("passive http-only: detects actuator", len(actuator_findings) >= 1,
          f"got: {[f.get('title') for f in actuator_findings]}")
    # /actuator/env is sensitive — should be High.
    env_findings = [f for f in actuator_findings if "/env" in f.get("title", "")]
    if env_findings:
        check("passive http-only: /env is High severity",
              env_findings[0].get("severity") == "high")


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def main():
    tests = [v for k, v in list(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"Running {len(tests)} fast-path tests...\n")
    for t in tests:
        print(f"• {t.__name__}")
        try:
            t()
        except Exception as e:
            global FAIL
            FAIL += 1
            print(f"  [FAIL] {t.__name__} raised: {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
