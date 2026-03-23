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
import tldextract
import yaml
from playwright.async_api import Page

if TYPE_CHECKING:
    from .llm_config import LLMRouter

try:
    import jwt
except ImportError:
    jwt = None

try:
    from playwright_stealth import Stealth
    _stealth = Stealth()
except ImportError:
    _stealth = None

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
    captcha_detected: bool = False
    screenshot_b64: str = ""


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
    credentials_b: dict | None = None    # optional User B for BOLA/BFLA two-user testing


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


async def _detect_captcha(page: Page) -> bool:
    """Check if the current page contains a CAPTCHA challenge."""
    try:
        return await page.evaluate("""() => {
            // reCAPTCHA v2/v3
            if (document.querySelector('iframe[src*="recaptcha"]')) return true;
            if (document.querySelector('iframe[src*="google.com/recaptcha"]')) return true;
            if (document.querySelector('.g-recaptcha')) return true;
            if (document.querySelector('#recaptcha')) return true;
            // hCaptcha
            if (document.querySelector('iframe[src*="hcaptcha"]')) return true;
            if (document.querySelector('.h-captcha')) return true;
            // Cloudflare Turnstile
            if (document.querySelector('iframe[src*="challenges.cloudflare.com"]')) return true;
            if (document.querySelector('.cf-turnstile')) return true;
            // Generic CAPTCHA indicators
            if (document.querySelector('[class*="captcha" i]')) return true;
            if (document.querySelector('[id*="captcha" i]')) return true;
            // Check for CAPTCHA-related text
            const bodyText = (document.body && document.body.innerText || '').toLowerCase();
            if (bodyText.includes('verify you are human') || bodyText.includes('are you a robot')
                || bodyText.includes('complete the security check')) return true;
            return false;
        }""")
    except Exception:
        return False


async def _take_screenshot_b64(page: Page) -> str:
    """Take a screenshot and return as base64 string."""
    try:
        raw = await page.screenshot(full_page=False, type="png")
        return base64.b64encode(raw).decode("ascii")
    except Exception as e:
        logger.warning("Screenshot failed: %s", e)
        return ""


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
                is_disabled = await loc.is_disabled(timeout=500)
                if is_disabled:
                    logger.debug("Button %s is visible but disabled, skipping", sel)
                    continue
                btn_text = await loc.inner_text(timeout=500)
                print(f"  [AUTH-DEBUG] Clicking button: '{btn_text.strip()[:30]}' (sel={sel})")
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
    print(f"  [AUTH-DEBUG] No visible submit button found, pressing Enter")
    await page.keyboard.press("Enter")


async def detect_and_login(
    page: Page,
    target: ScanTarget,
    router: LLMRouter,
    model: str,
    interactive_session: dict | None = None,
    on_progress: Callable | None = None,
    cancel_flag: Any = None,
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

    logger.info("[AUTH-DEBUG] Flow=%s, username_sel=%s, password_sel=%s, submit_sel=%s, sso_sel=%s",
                flow, username_sel, password_sel, submit_sel, sso_sel)
    print(f"  [AUTH-DEBUG] Flow={flow}, user_sel={username_sel}, pw_sel={password_sel}")
    print(f"  [AUTH-DEBUG] submit_sel={submit_sel}")
    print(f"  [AUTH-DEBUG] URL before interaction: {page.url[:120]}")

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
            print(f"  [AUTH-DEBUG] Filling username: {username[:20]}***")
            await page.fill(username_sel, username, timeout=5000)
            await asyncio.sleep(0.5)
            print(f"  [AUTH-DEBUG] Username filled OK")
        if password_sel and password:
            try:
                await page.fill(password_sel, password, timeout=2000)
                await asyncio.sleep(0.5)
                print(f"  [AUTH-DEBUG] Password filled OK (same page)")
            except Exception:
                print(f"  [AUTH-DEBUG] Password field not visible yet, clicking submit to advance...")
                await _click_visible_submit(page, submit_sel, form_sel)
                await page.wait_for_load_state("networkidle", timeout=15000)
                await asyncio.sleep(3)
                print(f"  [AUTH-DEBUG] URL after username step: {page.url[:120]}")
                # Capture error messages after username step
                try:
                    errs = await page.evaluate("""() => {
                        const els = document.querySelectorAll('[class*="error"], [class*="alert"], [role="alert"], .error-message, .field-error');
                        return Array.from(els).map(e => e.innerText).filter(t => t.trim()).join(' | ');
                    }""")
                    if errs:
                        print(f"  [AUTH-DEBUG] Error messages after username: {errs[:200]}")
                except Exception:
                    pass
                try:
                    await page.fill(password_sel, password, timeout=8000)
                except Exception:
                    # Fallback: type character by character (triggers more JS events)
                    print(f"  [AUTH-DEBUG] fill() failed, trying type() for password...")
                    try:
                        await page.click(password_sel, timeout=3000)
                        await page.keyboard.type(password, delay=50)
                    except Exception as type_err:
                        print(f"  [AUTH-DEBUG] type() also failed: {type_err}")
                        raise
                await asyncio.sleep(0.5)
                print(f"  [AUTH-DEBUG] Password filled OK (second step)")

        # Wait a moment for form validation JS to enable submit button
        await asyncio.sleep(1)
        url_before_submit = page.url
        print(f"  [AUTH-DEBUG] Clicking submit button...")
        await _click_visible_submit(page, submit_sel, form_sel)
        print(f"  [AUTH-DEBUG] Submit clicked, waiting for navigation...")

        # Wait for navigation (OIDC redirect) rather than just networkidle
        try:
            await page.wait_for_url(lambda url: urlparse(url).hostname != urlparse(url_before_submit).hostname,
                                    timeout=20000)
            print(f"  [AUTH-DEBUG] URL changed to different host: {page.url[:120]}")
        except Exception:
            # Fallback to networkidle
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            print(f"  [AUTH-DEBUG] URL after submit: {page.url[:120]}")

        # Capture any error messages after submit
        try:
            errs = await page.evaluate("""() => {
                const els = document.querySelectorAll('[class*="error"], [class*="alert"], [role="alert"], .error-message, .field-error, [class*="Error"]');
                return Array.from(els).map(e => e.innerText).filter(t => t.trim()).join(' | ');
            }""")
            if errs:
                print(f"  [AUTH-DEBUG] Error messages after login: {errs[:300]}")
        except Exception:
            pass

        # Capture full visible text on the page after submit
        try:
            visible = await page.evaluate("() => document.body ? document.body.innerText.substring(0, 800) : ''")
            if visible.strip():
                print(f"  [AUTH-DEBUG] Page text after submit: {visible.strip()[:400]}")
        except Exception:
            pass
    except Exception as e:
        logger.warning("Login interaction failed: %s", e)
        print(f"  [AUTH-DEBUG] Login interaction FAILED: {e}")
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

    # Wait for OIDC redirect chain to land on target host (or same root domain)
    target_host = urlparse(target.url).hostname or ""
    _target_root_dom = _extract_root_domain(target_host)
    print(f"  [AUTH-DEBUG] Waiting for OIDC redirect to {target_host} (root: {_target_root_dom})...")
    try:
        current_host = urlparse(page.url or "").hostname or ""
        print(f"  [AUTH-DEBUG] Current host: {current_host}")
        if target_host and current_host != target_host:
            for wait_i in range(10):
                await asyncio.sleep(3)
                current_host = urlparse(page.url or "").hostname or ""
                current_root = _extract_root_domain(current_host)
                is_login = _is_login_url(page.url or "")
                print(f"  [AUTH-DEBUG] OIDC wait {wait_i+1}/10: host={current_host}, "
                      f"root={current_root}, is_login={is_login}, url={page.url[:100]}")
                if current_host == target_host:
                    print(f"  [AUTH-DEBUG] Landed on target host!")
                    break
                if current_root == _target_root_dom and not is_login:
                    print(f"  [AUTH-DEBUG] On same root domain and not a login page — likely authenticated")
                    break
            if current_host != target_host:
                # Try navigating directly to the target
                logger.info("OIDC redirect didn't land on %s (on %s), navigating directly...",
                            target_host, current_host)
                print(f"  [AUTH-DEBUG] Navigating directly to {target.url[:80]}...")
                try:
                    await page.goto(target.url, wait_until="domcontentloaded", timeout=30000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass
                    await asyncio.sleep(3)
                    print(f"  [AUTH-DEBUG] After direct nav: {page.url[:120]}")
                except Exception as nav_e:
                    print(f"  [AUTH-DEBUG] Direct nav failed: {nav_e}")
        else:
            print(f"  [AUTH-DEBUG] Already on target host: {current_host}")
    except Exception as e:
        print(f"  [AUTH-DEBUG] OIDC redirect check error: {e}")

    # Check if we're still on the login page (auth failed)
    final_check_host = urlparse(page.url or "").hostname or ""
    final_check_root = _extract_root_domain(final_check_host)
    target_root = _extract_root_domain(target_host)

    # Use root domain comparison for SSO flows: login.norton.com and
    # my-int.norton.com share root "norton.com" — that's a normal SSO
    # redirect, not a failure.  Only flag auth_failed when we're on a
    # completely different domain AND the URL looks like a login page.
    on_same_org = final_check_root == target_root
    on_login_url = _is_login_url(page.url or "")

    # Even on same org, if we're STILL on a login page, verify with
    # cookies: if we have target-domain cookies, auth likely succeeded.
    has_target_cookies = False
    try:
        _cookies = await page.context.cookies()
        has_target_cookies = any(
            target_root in (c.get("domain", "") or "")
            for c in _cookies
        ) and len(_cookies) > 0
    except Exception:
        pass

    if on_same_org and on_login_url and has_target_cookies:
        print(f"  [AUTH-DEBUG] On SSO page ({final_check_host}) but have "
              f"{target_root} cookies — treating as SUCCESS (SSO redirect in progress)")
        auth_failed = False
    elif on_same_org and on_login_url and not has_target_cookies:
        # Same org SSO page but no cookies yet — try navigating to target
        print(f"  [AUTH-DEBUG] On same-org SSO page without cookies, navigating to target...")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_load_state("networkidle", timeout=10000)
            await asyncio.sleep(2)
            redir_host = urlparse(page.url or "").hostname or ""
            redir_login = _is_login_url(page.url or "")
            auth_failed = redir_host != target_host and redir_login
            print(f"  [AUTH-DEBUG] After nav to target: host={redir_host}, "
                  f"is_login={redir_login}, auth_failed={auth_failed}")
        except Exception as e:
            print(f"  [AUTH-DEBUG] Nav to target failed: {e}")
            auth_failed = True
    else:
        auth_failed = final_check_host != target_host and on_login_url
    print(f"  [AUTH-DEBUG] Auth check: final_host={final_check_host}, target={target_host}, "
          f"same_org={on_same_org}, login_url={on_login_url}, "
          f"has_cookies={has_target_cookies}, auth_failed={auth_failed}")

    if auth_failed:
        has_captcha = await _detect_captcha(page)
        screenshot_b64 = await _take_screenshot_b64(page)

        # Build a descriptive reason for the challenge
        if has_captcha:
            challenge_reason = "CAPTCHA detected on the login page"
            challenge_action = "Complete the CAPTCHA in the live browser, then click 'Login Complete'."
            print(f"  [AUTH] CAPTCHA detected on login page!")
        elif final_check_host != target_host:
            challenge_reason = (f"Login did not redirect back to {target_host} "
                                f"(stuck on {final_check_host})")
            challenge_action = ("Log in manually in the live browser. Once you see "
                                "the target application, click 'Login Complete'.")
            print(f"  [AUTH] Login failed — stuck on {final_check_host}, not {target_host}")
        else:
            challenge_reason = "Automated login failed (credentials may be wrong or bot detection active)"
            challenge_action = ("Log in manually in the live browser. Once you see "
                                "the target application, click 'Login Complete'.")
            print(f"  [AUTH] Login failed — still on login page after submitting credentials")

        if interactive_session:
            _cb = on_progress or (lambda *a, **k: None)
            print(f"  [AUTH] Opening interactive browser for manual login...")
            _cb("auth_challenge", {
                "screenshot": screenshot_b64,
                "has_captcha": has_captcha,
                "reason": challenge_reason,
                "action": challenge_action,
                "current_url": page.url or "",
                "message": f"{challenge_reason}. {challenge_action}",
            })
            interactive_result = await _run_interactive_login(
                page, target, interactive_session,
                on_progress=on_progress, cancel_flag=cancel_flag,
            )
            _cb("auth_challenge_resolved", {})
            if interactive_result.success:
                return interactive_result
            print(f"  [AUTH] Interactive login did not succeed — auth failed")

        return AuthResult(
            auth_type="form", tokens={}, cookies=[], success=False,
            captcha_detected=has_captcha, screenshot_b64=screenshot_b64,
        )

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


def _extract_root_domain(hostname: str) -> str:
    """Extract the registered root domain from any hostname using the Public Suffix List.
    Examples: my.norton.com -> norton.com, app.bbc.co.uk -> bbc.co.uk, 192.168.1.1 -> 192.168.1.1"""
    hostname = hostname.lstrip(".")
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def _parse_cookie_string(cookie_str: str, domain: str) -> list[dict]:
    """Parse a raw cookie string like 'name1=val1; name2=val2' into Playwright cookie dicts.
    Sets cookies on the root domain so they work across all subdomains."""
    root = _extract_root_domain(domain)
    cookie_domain = f".{root}" if not root.startswith(".") else root

    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        value = value.strip()
        if name:
            cookies.append({
                "name": name,
                "value": value,
                "domain": cookie_domain,
                "path": "/",
            })
    return cookies


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


async def _run_interactive_login(
    page: Page,
    target: ScanTarget,
    interactive_session: dict,
    on_progress: Callable | None = None,
    cancel_flag: Any = None,
) -> AuthResult:
    """Let the user log in manually via the interactive browser.

    Streams screenshots from the Playwright page into ``interactive_session``
    and applies mouse/keyboard events coming from the frontend.
    Blocks until the user signals "done" or timeout (10 min).
    """
    _cb = on_progress or (lambda *a, **k: None)
    viewport = page.viewport_size or {"width": 1280, "height": 720}
    interactive_session["viewport"] = (viewport["width"], viewport["height"])
    interactive_session["active"].set()

    _cb("interactive_browser_ready", {"viewport": [viewport["width"], viewport["height"]]})
    print(f"  [AUTH-INTERACTIVE] Browser ready — viewport {viewport['width']}x{viewport['height']}")
    print(f"  [AUTH-INTERACTIVE] Current URL: {page.url}")

    timeout = 600  # 10 minutes
    elapsed = 0.0
    frame_interval = 0.25

    try:
        while not interactive_session["done"].is_set() and elapsed < timeout:
            if cancel_flag and cancel_flag.is_set():
                raise Exception("Scan cancelled during interactive login")

            # Take screenshot (JPEG for smaller size / faster streaming)
            try:
                raw = await page.screenshot(type="jpeg", quality=55)
                interactive_session["screenshot_b64"] = base64.b64encode(raw).decode("ascii")
            except Exception as e:
                logger.debug("Interactive screenshot failed: %s", e)

            # Process queued input events from frontend
            events_queue = interactive_session["events"]
            while not events_queue.empty():
                try:
                    evt = events_queue.get_nowait()
                except Exception:
                    break
                await _apply_browser_event(page, evt, viewport)

            await asyncio.sleep(frame_interval)
            elapsed += frame_interval
    finally:
        interactive_session["active"].clear()
        _cb("interactive_browser_done", {})

    if elapsed >= timeout:
        print("  [AUTH-INTERACTIVE] Timeout — user did not complete login in 10 min")
        return AuthResult(auth_type="interactive_login", tokens={}, cookies=[], success=False)

    # After user signals "done", wait for any in-flight OIDC/SSO redirects to
    # land on the actual target host (not just the same root domain).
    target_host = urlparse(target.url).hostname or ""
    target_root = _extract_root_domain(target_host)

    # Give SSO redirects up to 15 seconds to complete
    for _redir_wait in range(30):
        current_host = urlparse(page.url or "").hostname or ""
        if current_host == target_host:
            break
        current_root = _extract_root_domain(current_host)
        if current_root != target_root:
            break  # navigated away from target domain entirely
        print(f"  [AUTH-INTERACTIVE] Waiting for SSO redirect... ({current_host} → {target_host})")
        await asyncio.sleep(0.5)

    # Now navigate to the actual target URL if we're not there yet
    current_host = urlparse(page.url or "").hostname or ""
    if current_host != target_host:
        print(f"  [AUTH-INTERACTIVE] Navigating to target: {target.url}")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_load_state("networkidle", timeout=10000)
        except Exception as e:
            print(f"  [AUTH-INTERACTIVE] Navigation to target failed: {e}")

    cookies = await page.context.cookies()
    final_url = page.url or ""
    current_host = urlparse(final_url).hostname or ""
    current_root = _extract_root_domain(current_host)
    on_target = current_root == target_root

    # Detect if we got redirected back to a login/SSO page
    login_indicators = ["login", "signin", "sso/idp", "auth/realms", "oauth", "accounts.google"]
    redirected_to_login = any(ind in final_url.lower() for ind in login_indicators)

    if redirected_to_login:
        print(f"  [AUTH-INTERACTIVE] Redirected to login page — auth NOT successful: {final_url[:120]}")
        return AuthResult(auth_type="interactive_login", tokens={}, cookies=cookies, success=False)

    if on_target and cookies and current_host == target_host:
        print(f"  [AUTH-INTERACTIVE] Login succeeded — URL: {final_url}, cookies: {len(cookies)}")
        return AuthResult(auth_type="interactive_login", tokens={}, cookies=cookies, success=True)

    if on_target and cookies:
        print(f"  [AUTH-INTERACTIVE] On target domain but different host — URL: {final_url}, cookies: {len(cookies)}")
        return AuthResult(auth_type="interactive_login", tokens={}, cookies=cookies, success=True)

    print(f"  [AUTH-INTERACTIVE] Login not confirmed — current: {current_host} (root: {current_root}), "
          f"expected: {target_host} (root: {target_root}), cookies: {len(cookies)}")
    return AuthResult(auth_type="interactive_login", tokens={}, cookies=cookies, success=False)


async def _apply_browser_event(page: Page, evt: dict, viewport: dict) -> None:
    """Translate a frontend input event into a Playwright action on the page."""
    try:
        etype = evt.get("type", "")
        if etype == "click":
            x = evt.get("x", 0) * viewport["width"]
            y = evt.get("y", 0) * viewport["height"]
            button = evt.get("button", "left")
            click_count = evt.get("clickCount", 1)
            await page.mouse.click(x, y, button=button, click_count=click_count)
        elif etype == "type":
            text = evt.get("text", "")
            if text:
                await page.keyboard.type(text, delay=20)
        elif etype == "keypress":
            key = evt.get("key", "")
            if key:
                await page.keyboard.press(key)
        elif etype == "scroll":
            x = evt.get("x", 0.5) * viewport["width"]
            y = evt.get("y", 0.5) * viewport["height"]
            dx = evt.get("deltaX", 0)
            dy = evt.get("deltaY", 0)
            await page.mouse.wheel(dx, dy)
        elif etype == "mousemove":
            x = evt.get("x", 0) * viewport["width"]
            y = evt.get("y", 0) * viewport["height"]
            await page.mouse.move(x, y)
    except Exception as e:
        logger.debug("Interactive event error (%s): %s", evt.get("type"), e)


async def authenticate(
    browser: Any,
    target: ScanTarget,
    router: LLMRouter,
    model: str,
    interactive_session: dict | None = None,
    on_progress: Callable | None = None,
    cancel_flag: Any = None,
) -> AuthSession:
    auth_config = target.auth_config or {}
    auth_type_config = (auth_config.get("type") or "auto").lower()
    credentials = target.credentials or {}
    has_creds = bool(credentials.get("username") or credentials.get("password")
                     or credentials.get("bearer_token") or credentials.get("api_key"))

    page = await browser.new_page()

    # Apply stealth patches to hide automation fingerprints (navigator.webdriver,
    # chrome.runtime, plugins, etc.).  Runs a handful of JS snippets — no delay.
    if _stealth:
        try:
            await _stealth.apply_stealth_async(page)
            logger.info("Stealth anti-detection patches applied")
        except Exception as e:
            logger.debug("Stealth patches failed (non-fatal): %s", e)

    # Start network-level JS capture from the very first navigation.
    # This captures every .js request (login page, OIDC redirects, SPA chunks,
    # CDN scripts, iframe resources) regardless of timing.
    from .passive_recon import start_js_network_capture
    network_js_urls = start_js_network_capture(page)

    if auth_type_config == "interactive_login" and interactive_session:
        logger.info("Interactive login mode — opening browser for manual login")
        try:
            await page.goto(target.url, wait_until="domcontentloaded", timeout=60000)
        except Exception:
            logger.warning("Initial page load timed out — continuing with interactive login")
        result = await _run_interactive_login(
            page, target, interactive_session,
            on_progress=on_progress, cancel_flag=cancel_flag,
        )
    elif not has_creds and auth_type_config in ("auto", "form", "sso", "oauth"):
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
        result = await detect_and_login(
            page, target, router, model,
            interactive_session=interactive_session,
            on_progress=on_progress, cancel_flag=cancel_flag,
        )

    def _refresh_fn() -> Awaitable[AuthResult]:
        return detect_and_login(page, target, router, model,
                                interactive_session=interactive_session,
                                on_progress=on_progress, cancel_flag=cancel_flag)

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
    session.captcha_detected = getattr(result, "captcha_detected", False)
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
    creds_b_raw = t.get("credentials_b") or {}
    creds_b = None
    if creds_b_raw.get("username") or creds_b_raw.get("password"):
        creds_b = {"username": creds_b_raw.get("username", ""), "password": creds_b_raw.get("password", "")}
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
        credentials_b=creds_b,
    )
