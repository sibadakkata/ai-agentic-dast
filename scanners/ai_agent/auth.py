from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from urllib.parse import parse_qs, urlparse

import pyotp
import yaml
from playwright.async_api import Page

if TYPE_CHECKING:
    from .llm_config import LLMRouter

try:
    import jwt
except ImportError:
    jwt = None

logger = logging.getLogger(__name__)

LOGIN_PAGE_INDICATORS = (
    "login",
    "signin",
    "sign-in",
    "log-in",
    "auth",
    "sso",
    "oauth",
    "saml",
    "password",
    "username",
)


@dataclass
class AuthResult:
    auth_type: str
    tokens: dict[str, str]
    cookies: list[dict]
    success: bool


@dataclass
class ScanTarget:
    id: str
    url: str
    scan_mode: str
    credentials: dict
    auth_config: dict
    postman_file: str | None = None
    postman_env: str | None = None
    openapi_file: str | None = None
    burp_file: str | None = None
    scan_scope: str = "directory"       # url_only | directory | full_site
    focus_urls: list[str] | None = None  # specific URLs/endpoints to test
    focus_areas: list[str] | None = None # e.g. ["XSS"], ["SQLi","XSS"] — empty = all
    scan_intensity: str = "deep"         # light | standard | deep
    exclude_urls: list[str] | None = None  # URLs/paths to skip during crawl and scan


def _resolve_env_vars(obj: Any) -> Any:
    if isinstance(obj, str):
        def repl(m: re.Match[str]) -> str:
            key = m.group(1)
            return os.environ.get(key, m.group(0))
        return re.sub(r"\$\{([^}]+)\}", repl, obj)
    if isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_env_vars(v) for v in obj]
    return obj


def _is_login_url(url: str) -> bool:
    """Check if a URL is a login/auth page based on hostname + path only.

    Query parameters are excluded to avoid false positives like
    OIDC redirect_uri or client_id containing 'login' in their values.
    """
    try:
        parsed = urlparse(url)
        check_str = f"{parsed.hostname or ''}{parsed.path or ''}".lower()
    except Exception:
        check_str = url.lower()
    return any(ind in check_str for ind in LOGIN_PAGE_INDICATORS)


def _jwt_expired(token: str) -> bool:
    if not jwt:
        return False
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp")
        if exp is None:
            return False
        return exp < time.time()
    except Exception:
        return True


class AuthSession:
    def __init__(
        self,
        page: Page,
        auth_type: str,
        tokens: dict[str, str],
        cookies: list[dict],
        credentials: dict,
        refresh_fn: Callable[[], Awaitable[AuthResult]],
        target_url: str = "",
    ):
        self._page = page
        self._auth_type = auth_type
        self._tokens = dict(tokens)
        self._cookies = list(cookies)
        self._credentials = dict(credentials)
        self._refresh_fn = refresh_fn
        self._target_url = target_url or (page.url if page else "")
        self.active = True
        self.refresh_count = 0
        self._monitor_task: asyncio.Task[None] | None = None

    @property
    def page(self) -> Page:
        return self._page

    def start_monitor(self) -> None:
        if self._monitor_task is not None:
            return

        async def _loop() -> None:
            while self.active:
                await asyncio.sleep(60)
                if not self.active:
                    break
                try:
                    if await self._is_expired():
                        await self._refresh()
                except Exception as e:
                    logger.warning("Session monitor check failed: %s", e)

        self._monitor_task = asyncio.create_task(_loop())
        logger.debug("Session monitor started")

    def stop_monitor(self) -> None:
        self.active = False
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            self._monitor_task = None
        logger.debug("Session monitor stopped")

    async def _is_expired(self) -> bool:
        access_token = self._tokens.get("access_token")
        if access_token and _jwt_expired(access_token):
            logger.debug("JWT access token expired")
            return True

        try:
            current = await self._page.context.cookies()
            session_names = {c.get("name", "").lower() for c in self._cookies if "session" in c.get("name", "").lower() or "auth" in c.get("name", "").lower()}
            if session_names:
                current_names = {c.get("name", "").lower() for c in current if c.get("value")}
                if not session_names.intersection(current_names):
                    logger.debug("Session cookie missing or empty")
                    return True
        except Exception:
            pass

        try:
            url = self._target_url or self._page.url
            if not url:
                return False
            response = await self._page.goto(url, wait_until="domcontentloaded", timeout=10000)
            if response is None:
                return False
            status = response.status
            final_url = self._page.url
            if status in (401, 403):
                logger.debug("Lightweight request returned %s", status)
                return True
            if _is_login_url(final_url):
                logger.debug("Redirected to login page: %s", final_url)
                return True
        except Exception as e:
            logger.debug("Lightweight request failed: %s", e)
        return False

    async def _refresh(self) -> None:
        try:
            result = await self._refresh_fn()
            if result.success:
                self._tokens = dict(result.tokens)
                self._cookies = list(result.cookies)
                self.refresh_count += 1
                logger.info("Session refreshed (count=%d)", self.refresh_count)
            else:
                logger.warning("Session refresh failed")
        except Exception as e:
            logger.error("Session refresh error: %s", e)

    def get_auth_header(self) -> dict[str, str]:
        if self._auth_type == "bearer":
            token = self._tokens.get("access_token", "")
            if token:
                return {"Authorization": f"Bearer {token}"}
        if self._auth_type == "api_key":
            key = self._tokens.get("api_key", "") or self._credentials.get("api_key", "")
            if key:
                return {"X-API-Key": key}
        if self._auth_type == "basic":
            user = self._credentials.get("username", "")
            password = self._credentials.get("password", "")
            if user or password:
                creds = base64.b64encode(f"{user}:{password}".encode()).decode()
                return {"Authorization": f"Basic {creds}"}
        return {}


AUTH_CLASSIFY_PROMPT = """Analyze this HTML from a login page. Classify the authentication flow and identify elements to interact with.

Return ONLY valid JSON (no markdown, no explanation) with this structure:
{
  "flow": "form" | "sso" | "oauth",
  "username_selector": "CSS selector for username/email field or null",
  "password_selector": "CSS selector for password field or null",
  "submit_selector": "CSS selector for submit button or null",
  "sso_button_selector": "CSS selector for SSO/OAuth button if flow is sso/oauth, or null",
  "form_selector": "CSS selector for the form element or null"
}

If you cannot determine the flow, use "form" and provide the best guess selectors. Prefer id, name, or data-testid attributes."""


async def _click_visible_submit(page: Page, submit_sel: str | None, form_sel: str | None = None):
    """Click the first visible submit/advance button, or press Enter as fallback."""
    all_sels: list[str] = []
    if submit_sel:
        all_sels.extend(s.strip() for s in submit_sel.split(",") if s.strip())
    all_sels.extend([
        '#continue_button', '#signin_button', 'input[type="button"]',
        'button:has-text("Continue")', 'button:has-text("Next")',
        'button:has-text("Sign in")', 'button:has-text("Log in")',
    ])
    seen = set()
    for sel in all_sels:
        if sel in seen:
            continue
        seen.add(sel)
        try:
            loc = page.locator(sel).first
            if await loc.is_visible(timeout=500):
                await loc.click(timeout=3000)
                return
        except Exception:
            continue
    if form_sel:
        try:
            await page.locator(form_sel).evaluate("f => f.submit()")
            return
        except Exception:
            pass
    await page.keyboard.press("Enter")


async def detect_and_login(
    page: Page,
    target: ScanTarget,
    router: LLMRouter,
    model: str,
) -> AuthResult:

    try:
        html = await page.content()
        snippet = html[:12000] if len(html) > 12000 else html
    except Exception as e:
        logger.error("Failed to get page content: %s", e)
        return AuthResult(auth_type="form", tokens={}, cookies=[], success=False)

    messages = [
        {"role": "user", "content": f"{AUTH_CLASSIFY_PROMPT}\n\nHTML:\n{snippet}"},
    ]
    try:
        response = router.complete(model=model, messages=messages, max_tokens=500)
        raw = response.choices[0].message.content
    except Exception as e:
        logger.error("LLM auth classification failed: %s", e)
        raw = '{"flow": "form"}'

    parsed: dict[str, Any] = {"flow": "form"}
    if raw:
        raw_clean = raw.strip()
        if raw_clean.startswith("```"):
            raw_clean = re.sub(r"^```\w*\n?", "", raw_clean)
            raw_clean = re.sub(r"\n?```\s*$", "", raw_clean)
        try:
            parsed = json.loads(raw_clean)
        except json.JSONDecodeError as e:
            logger.warning("LLM auth JSON parse failed: %s", e)

    flow = parsed.get("flow", "form")
    _DEFAULT_USER = 'input[type="email"], input[name="email"], input[name="username"], input#loginUsername'
    _DEFAULT_PW = 'input[type="password"], input[name="password"], input#loginPassword'
    _DEFAULT_SUBMIT = 'button[type="submit"], input[type="submit"], #continue_button, #signin_button, button#loginSubmitBtn'
    username_sel = parsed.get("username_selector") or _DEFAULT_USER
    password_sel = parsed.get("password_selector") or _DEFAULT_PW
    submit_sel = parsed.get("submit_selector") or _DEFAULT_SUBMIT
    sso_sel = parsed.get("sso_button_selector")
    form_sel = parsed.get("form_selector")
    credentials = target.credentials or {}
    username = credentials.get("username", "")
    password = credentials.get("password", "")

    try:
        if flow == "sso" or flow == "oauth":
            if sso_sel:
                await page.click(sso_sel, timeout=5000)
            else:
                for sel in ('button:has-text("SSO")', 'button:has-text("OAuth")', 'a:has-text("Sign in with")'):
                    try:
                        await page.click(sel, timeout=2000)
                        break
                    except Exception:
                        continue
            await page.wait_for_load_state("networkidle", timeout=15000)

        if username_sel and username:
            await page.fill(username_sel, username, timeout=5000)
        if password_sel and password:
            try:
                await page.fill(password_sel, password, timeout=2000)
            except Exception:
                await _click_visible_submit(page, submit_sel, form_sel)
                await page.wait_for_load_state("networkidle", timeout=10000)
                await asyncio.sleep(2)
                await page.fill(password_sel, password, timeout=8000)

        await _click_visible_submit(page, submit_sel, form_sel)
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception as e:
        logger.warning("Login interaction failed: %s", e)
    auth_config = target.auth_config or {}
    totp_secret = auth_config.get("totp_secret")
    if totp_secret:
        try:
            totp = pyotp.TOTP(totp_secret)
            code = totp.now()
            for sel in ('input[name="otp"]', 'input[name="code"]', 'input[placeholder*="code"]', 'input[placeholder*="OTP"]'):
                try:
                    await page.fill(sel, code, timeout=3000)
                    await page.keyboard.press("Enter")
                    await page.wait_for_load_state("networkidle", timeout=10000)
                    break
                except Exception:
                    continue
        except Exception as e:
            logger.warning("TOTP failed: %s", e)
    else:
        mfa_selectors = ['input[name="otp"]', 'input[name="code"]', 'input[placeholder*="code"]']
        for sel in mfa_selectors:
            try:
                if await page.locator(sel).count() > 0:
                    print("MFA/TOTP code required. Enter code:")
                    code = input().strip()
                    if code:
                        await page.fill(sel, code, timeout=3000)
                        await page.keyboard.press("Enter")
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    break
            except Exception:
                continue

    # Wait for OIDC redirect chain to land on target host
    target_host = urlparse(target.url).hostname or ""
    try:
        current_host = urlparse(page.url or "").hostname or ""
        if target_host and current_host != target_host:
            for _ in range(6):
                await asyncio.sleep(3)
                current_host = urlparse(page.url or "").hostname or ""
                if current_host == target_host:
                    break
            if current_host != target_host:
                logger.info("OIDC redirect didn't land on %s (on %s), navigating directly...",
                            target_host, current_host)
                try:
                    await page.goto(target.url, wait_until="domcontentloaded", timeout=30000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass
                    await asyncio.sleep(3)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        cookies = await page.context.cookies()
        final_url = page.url
        final_host = urlparse(final_url or "").hostname or ""
        target_cookies = [c for c in cookies if target_host in (c.get("domain", ""))]
        success = (final_host == target_host or bool(target_cookies)) and len(cookies) > 0
        tokens: dict[str, str] = {}
        try:
            redirect = page.url
            if "access_token=" in redirect or "#access_token=" in redirect:
                parsed_url = urlparse(redirect)
                frag = parsed_url.fragment or parsed_url.query
                params = parse_qs(frag) if frag else {}
                for key in ("access_token", "refresh_token"):
                    if key in params and params[key]:
                        tokens[key] = params[key][0]
        except Exception:
            pass

        auth_type = flow if flow in ("form", "sso", "oauth") else "form"
        return AuthResult(
            auth_type=auth_type,
            tokens=tokens,
            cookies=[{"name": c["name"], "value": c["value"], "domain": c.get("domain", "")} for c in cookies],
            success=success,
        )
    except Exception as e:
        logger.error("Auth verification failed: %s", e)
        return AuthResult(auth_type="form", tokens={}, cookies=[], success=False)


async def detect_app_type(page: Page) -> dict[str, Any]:
    result: dict[str, Any] = {
        "is_spa": False,
        "framework": None,
        "has_websockets": False,
        "has_service_worker": False,
    }
    try:
        js = """
        () => {
            const out = { is_spa: false, framework: null, has_websockets: false, has_service_worker: false };
            if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || (window.React && window.React.createElement)) out.framework = 'React';
            else if (window.ng || document.querySelector('[ng-version]')) out.framework = 'Angular';
            else if (window.__VUE__ || window.Vue) out.framework = 'Vue';
            else if (window.__svelte) out.framework = 'Svelte';
            else if (window.__NEXT_DATA__) out.framework = 'Next.js';
            else if (window.__NUXT__ || window.$nuxt) out.framework = 'Nuxt';
            if (out.framework) out.is_spa = true;
            if (document.querySelector('#root') || document.querySelector('#app')) out.is_spa = true;
            if ('serviceWorker' in navigator && navigator.serviceWorker.controller) out.has_service_worker = true;
            return out;
        }
        """
        data = await page.evaluate(js)
        result.update(data)
    except Exception as e:
        logger.debug("detect_app_type evaluate failed: %s", e)

    try:
        ws_script = """
        () => {
            const entries = performance.getEntriesByType('resource') || [];
            return entries.some(e => (e.name || '').startsWith('ws://') || (e.name || '').startsWith('wss://'));
        }
        """
        result["has_websockets"] = await page.evaluate(ws_script) or result.get("has_websockets", False)
    except Exception:
        pass

    return result


async def authenticate(
    browser: Any,
    target: ScanTarget,
    router: LLMRouter,
    model: str,
) -> AuthSession:
    auth_config = target.auth_config or {}
    auth_type_config = (auth_config.get("type") or "auto").lower()
    credentials = target.credentials or {}
    has_creds = bool(credentials.get("username") or credentials.get("password")
                     or credentials.get("bearer_token") or credentials.get("api_key"))

    page = await browser.new_page()

    # Start network-level JS capture from the very first navigation.
    # This captures every .js request (login page, OIDC redirects, SPA chunks,
    # CDN scripts, iframe resources) regardless of timing.
    from .passive_recon import start_js_network_capture
    network_js_urls = start_js_network_capture(page)

    if not has_creds and auth_type_config in ("auto", "form", "sso", "oauth"):
        logger.info("No credentials supplied — running unauthenticated scan")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            logger.warning("Initial page load timed out — continuing anyway")
        result = AuthResult(
            auth_type="none",
            tokens={},
            cookies=[],
            success=True,
        )
    elif auth_type_config == "bearer":
        token = auth_config.get("bearer_token", "") or credentials.get("bearer_token", "")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            logger.warning("Initial page load timed out — continuing anyway")
        result = AuthResult(
            auth_type="bearer",
            tokens={"access_token": token},
            cookies=[],
            success=bool(token),
        )
    elif auth_type_config == "api_key":
        key = auth_config.get("api_key", "") or credentials.get("api_key", "")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            logger.warning("Initial page load timed out — continuing anyway")
        result = AuthResult(
            auth_type="api_key",
            tokens={"api_key": key},
            cookies=[],
            success=bool(key),
        )
    else:
        try:
            await page.goto(target.url, wait_until="load", timeout=60000)
        except Exception:
            logger.warning("Initial page load timed out — continuing with auth attempt")
        result = await detect_and_login(page, target, router, model)

    def _refresh_fn() -> Awaitable[AuthResult]:
        return detect_and_login(page, target, router, model)

    session = AuthSession(
        page=page,
        auth_type=result.auth_type,
        tokens=result.tokens,
        cookies=result.cookies,
        credentials=target.credentials or {},
        refresh_fn=_refresh_fn,
        target_url=target.url,
    )
    session.network_js_urls = network_js_urls
    session.start_monitor()
    return session


def load_targets(config_path: str) -> list[ScanTarget]:
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load config %s: %s", config_path, e)
        return []

    if not data or "targets" not in data:
        return []

    resolved = _resolve_env_vars(data)
    targets_data = resolved.get("targets", [])
    result: list[ScanTarget] = []

    for t in targets_data:
        if not isinstance(t, dict):
            continue
        tid = t.get("id", "")
        url = t.get("url", "")
        scan_mode = t.get("scan_mode", "both")
        auth = t.get("auth", {}) or {}
        api_imports = t.get("api_imports", {}) or {}

        credentials = {
            "username": auth.get("username", ""),
            "password": auth.get("password", ""),
        }
        auth_config = {
            "type": auth.get("type", "auto"),
            "totp_secret": auth.get("totp_secret"),
            "sso_provider": auth.get("sso_provider"),
            "api_key": auth.get("api_key"),
            "bearer_token": auth.get("bearer_token"),
        }

        result.append(
            ScanTarget(
                id=tid,
                url=url,
                scan_mode=scan_mode,
                credentials=credentials,
                auth_config=auth_config,
                postman_file=api_imports.get("postman"),
                postman_env=api_imports.get("postman_env"),
                openapi_file=api_imports.get("openapi"),
                burp_file=api_imports.get("burp"),
            )
        )

    return result


def load_targets_from_dict(t: dict) -> ScanTarget:
    """Create a ScanTarget from a plain dict (used by web UI)."""
    auth = t.get("auth", {}) or {}
    api_imports = t.get("api_imports", {}) or {}
    return ScanTarget(
        id=t.get("id", "T1"),
        url=t.get("url", ""),
        scan_mode=t.get("scan_mode", "both"),
        credentials={
            "username": auth.get("username", ""),
            "password": auth.get("password", ""),
        },
        auth_config={
            "type": auth.get("type", "auto"),
            "totp_secret": auth.get("totp_secret"),
            "sso_provider": auth.get("sso_provider"),
            "api_key": auth.get("api_key"),
            "bearer_token": auth.get("bearer_token"),
        },
        postman_file=api_imports.get("postman"),
        postman_env=api_imports.get("postman_env"),
        openapi_file=api_imports.get("openapi"),
        burp_file=api_imports.get("burp"),
        scan_scope=t.get("scan_scope", "directory"),
        focus_urls=t.get("focus_urls") or None,
        focus_areas=t.get("focus_areas") or None,
        scan_intensity=t.get("scan_intensity", "deep"),
        exclude_urls=t.get("exclude_urls") or None,
    )
