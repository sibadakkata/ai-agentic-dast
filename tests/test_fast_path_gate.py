"""Regression tests for the API-only fast-path *gate*.

These tests lock in the invariant: the fast path must only activate for
``scan_mode=="api"`` AND an auth type that can be satisfied over raw HTTP
(none / bearer+token / api_key+value / basic+creds).  Every other
combination — especially every website/both scan — MUST still spawn
Playwright and go through the full browser-based ``authenticate()``.

Why this file exists:
  The fast path touches the top of run_scan() — one wrong ``or`` in the
  gate would silently send every website scan through a browserless
  pipeline with no browser tools.  These tests make that class of
  regression impossible to merge unnoticed.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanners.ai_agent import agent as agent_mod
from scanners.ai_agent.auth import ScanTarget, can_use_http_only_auth
from scanners.ai_agent.llm_config import LLMRouter


PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


# ---------------------------------------------------------------------------
# Pure-function gate matrix — ``can_use_http_only_auth`` + scan_mode check
# ---------------------------------------------------------------------------


def _would_fast_path(scan_mode: str, auth_cfg: dict, creds: dict) -> bool:
    t = ScanTarget(id="t", url="https://x", scan_mode=scan_mode,
                   auth_config=auth_cfg, credentials=creds)
    return can_use_http_only_auth(t) and scan_mode == "api"


def test_gate_blocks_website_scan_mode():
    # No auth variant should ever enable fast path for website scans.
    for auth_cfg, creds in [
        ({"type": "none"}, {}),
        ({"type": "auto"}, {}),
        ({"type": "form"}, {"username": "u", "password": "p"}),
        ({"type": "sso", "sso_provider": "g"}, {"username": "u", "password": "p"}),
        ({"type": "oauth"}, {"username": "u", "password": "p"}),
        ({"type": "interactive_login"}, {}),
        ({"type": "bearer", "bearer_token": "t"}, {}),
        ({"type": "api_key", "api_key": "k"}, {}),
        ({"type": "basic"}, {"username": "u", "password": "p"}),
    ]:
        atype = auth_cfg["type"]
        check(
            f"gate: website + {atype} does NOT fast-path",
            _would_fast_path("website", auth_cfg, creds) is False,
            f"auth_cfg={auth_cfg} creds={creds}",
        )


def test_gate_blocks_both_scan_mode():
    # Same for scan_mode=both — website checks must keep browser.
    for auth_cfg, creds in [
        ({"type": "none"}, {}),
        ({"type": "form"}, {"username": "u", "password": "p"}),
        ({"type": "bearer", "bearer_token": "t"}, {}),
        ({"type": "api_key", "api_key": "k"}, {}),
    ]:
        atype = auth_cfg["type"]
        check(
            f"gate: both + {atype} does NOT fast-path",
            _would_fast_path("both", auth_cfg, creds) is False,
        )


def test_gate_blocks_api_with_browser_auth():
    # API scan mode + auth type that REQUIRES a browser must not fast-path.
    for auth_cfg, creds in [
        ({"type": "auto"}, {}),
        ({"type": "form"}, {"username": "u", "password": "p"}),
        ({"type": "sso", "sso_provider": "g"}, {"username": "u", "password": "p"}),
        ({"type": "oauth"}, {"username": "u", "password": "p"}),
        ({"type": "interactive_login"}, {}),
    ]:
        atype = auth_cfg["type"]
        check(
            f"gate: api + {atype} does NOT fast-path (needs browser)",
            _would_fast_path("api", auth_cfg, creds) is False,
        )


def test_gate_blocks_api_with_missing_static_creds():
    # API + declared bearer/api_key/basic but missing the actual value
    # — must fall back to browser so credentials_b / form flow can resolve.
    for auth_cfg, creds in [
        ({"type": "bearer"}, {}),            # no bearer_token
        ({"type": "api_key"}, {}),           # no api_key value
        ({"type": "basic"}, {}),             # no username/password
    ]:
        atype = auth_cfg["type"]
        check(
            f"gate: api + {atype} (no creds) does NOT fast-path",
            _would_fast_path("api", auth_cfg, creds) is False,
        )


def test_gate_enables_api_with_browserless_auth():
    # The four combinations that SHOULD fast-path.
    check("gate: api + none FAST",
          _would_fast_path("api", {"type": "none"}, {}) is True)
    check("gate: api + bearer+token FAST",
          _would_fast_path("api", {"type": "bearer", "bearer_token": "t"}, {}) is True)
    check("gate: api + api_key+value FAST",
          _would_fast_path("api", {"type": "api_key", "api_key": "k"}, {}) is True)
    check("gate: api + basic+creds FAST",
          _would_fast_path("api", {"type": "basic"}, {"username": "u", "password": "p"}) is True)


# ---------------------------------------------------------------------------
# Integration-level: run_scan actually takes the expected branch
# ---------------------------------------------------------------------------


async def _probe_run_scan(scan_mode: str, auth_cfg: dict, creds: dict) -> dict:
    """Call run_scan with heavy patching to record which branch was taken.

    Authentication raises a sentinel so the scan exits early; we never
    need a real browser, network, or LLM.
    """
    spy = {
        "playwright_launched": False,
        "browser_created": False,
        "authenticate_called_with_browser": None,  # bool once called, None if never
        "authenticate_http_only_called": False,
    }

    @asynccontextmanager
    async def fake_playwright():
        spy["playwright_launched"] = True

        class _P:
            class chromium:
                @staticmethod
                async def launch(**kw):
                    spy["browser_created"] = True
                    b = MagicMock()
                    b.close = AsyncMock()
                    return b
        yield _P()

    async def fake_authenticate(browser, target, router, model, **kw):
        spy["authenticate_called_with_browser"] = browser is not None
        raise RuntimeError("STOP_HERE_AUTH")

    async def fake_authenticate_http_only(target):
        spy["authenticate_http_only_called"] = True
        raise RuntimeError("STOP_HERE_AUTH")

    real_pw = agent_mod.async_playwright
    real_auth = agent_mod.authenticate
    real_auth_http = agent_mod.authenticate_http_only
    agent_mod.async_playwright = fake_playwright
    agent_mod.authenticate = fake_authenticate
    agent_mod.authenticate_http_only = fake_authenticate_http_only
    try:
        target = ScanTarget(id="t", url="https://example.com",
                            scan_mode=scan_mode, credentials=creds,
                            auth_config=auth_cfg)
        router = MagicMock(spec=LLMRouter)
        try:
            await agent_mod.run_scan(
                target=target, router=router,
                model="claude-3-5-haiku-20241022",
                cancel_flag=threading.Event(),
            )
        except RuntimeError as e:
            if "STOP_HERE_AUTH" not in str(e):
                raise
    finally:
        agent_mod.async_playwright = real_pw
        agent_mod.authenticate = real_auth
        agent_mod.authenticate_http_only = real_auth_http
    return spy


def test_run_scan_website_form_uses_browser():
    spy = asyncio.run(_probe_run_scan(
        "website", {"type": "form"}, {"username": "u", "password": "p"}))
    check("run_scan(website,form): playwright launched",
          spy["playwright_launched"] is True)
    check("run_scan(website,form): browser created",
          spy["browser_created"] is True)
    check("run_scan(website,form): authenticate() got real browser",
          spy["authenticate_called_with_browser"] is True)
    check("run_scan(website,form): did NOT call http-only auth",
          spy["authenticate_http_only_called"] is False)


def test_run_scan_both_form_uses_browser():
    spy = asyncio.run(_probe_run_scan(
        "both", {"type": "form"}, {"username": "u", "password": "p"}))
    check("run_scan(both,form): playwright launched",
          spy["playwright_launched"] is True)
    check("run_scan(both,form): authenticate() got real browser",
          spy["authenticate_called_with_browser"] is True)


def test_run_scan_website_bearer_still_uses_browser():
    # A website scan with bearer auth still needs a browser for the
    # website crawl portion — fast path must NOT fire.
    spy = asyncio.run(_probe_run_scan(
        "website", {"type": "bearer", "bearer_token": "t"}, {}))
    check("run_scan(website,bearer): playwright launched",
          spy["playwright_launched"] is True)
    check("run_scan(website,bearer): did NOT call http-only auth",
          spy["authenticate_http_only_called"] is False)


def test_run_scan_api_auto_uses_browser():
    # `auto` is where the scanner inspects the page to pick an auth
    # strategy — it needs a browser.
    spy = asyncio.run(_probe_run_scan("api", {"type": "auto"}, {}))
    check("run_scan(api,auto): playwright launched",
          spy["playwright_launched"] is True)
    check("run_scan(api,auto): did NOT call http-only auth",
          spy["authenticate_http_only_called"] is False)


def test_run_scan_api_none_takes_fast_path():
    spy = asyncio.run(_probe_run_scan("api", {"type": "none"}, {}))
    check("run_scan(api,none): playwright NOT launched",
          spy["playwright_launched"] is False)
    check("run_scan(api,none): no browser",
          spy["browser_created"] is False)
    check("run_scan(api,none): called authenticate_http_only",
          spy["authenticate_http_only_called"] is True)
    check("run_scan(api,none): did NOT call browser auth",
          spy["authenticate_called_with_browser"] is None)


def test_run_scan_api_bearer_takes_fast_path():
    spy = asyncio.run(_probe_run_scan(
        "api", {"type": "bearer", "bearer_token": "t"}, {}))
    check("run_scan(api,bearer): playwright NOT launched",
          spy["playwright_launched"] is False)
    check("run_scan(api,bearer): called authenticate_http_only",
          spy["authenticate_http_only_called"] is True)


def test_run_scan_api_basic_takes_fast_path():
    spy = asyncio.run(_probe_run_scan(
        "api", {"type": "basic"}, {"username": "u", "password": "p"}))
    check("run_scan(api,basic): playwright NOT launched",
          spy["playwright_launched"] is False)
    check("run_scan(api,basic): called authenticate_http_only",
          spy["authenticate_http_only_called"] is True)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def main():
    tests = [v for k, v in list(globals().items())
             if k.startswith("test_") and callable(v)]
    print(f"Running {len(tests)} fast-path-gate regression tests...\n")
    for t in tests:
        print(f"\n• {t.__name__}")
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
