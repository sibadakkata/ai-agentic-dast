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
    credentials_admin: dict | None = None   # optional admin-role credentials
    credentials_tenant_b: dict | None = None  # optional second-tenant credentials
    workflow_id: str | None = None       # saved workflow ID to replay before/during scan
    business_flow: str | None = None     # natural-language business flow description
    # Crawl-only mode: when "crawl_only", the agent skips all OWASP vulnerability
    # test phases and the attack-chain phase. Passive recon (TLS, headers, JS
    # CVEs, CSP, CORS, HSTS, clickjacking), API baseline, authentication, and
    # a single broad CRAWL phase still run so the user can verify that the
    # scanner can reach and enumerate their app before committing to a full
    # vulnerability scan. Mirrors Acunetix "Crawl Only" scan type.
    scan_profile: str = "vulnerability_scan"  # vulnerability_scan | crawl_only
    # When True, initial passive TLS audit probes only the seed URL's host —
    # not siblings from landing DOM / robots.txt / sitemap. Sibling hosts
    # still get TLS when observed in browser traffic (host-delta after each
    # phase). Use for "TLS on sibling only after crawl" workflows.
    skip_passive_sibling_tls: bool = False


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
        page: Page | None,
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
    def page(self) -> Page | None:
        """Return the Playwright page, or None when running in HTTP-only mode."""
        return self._page

    @property
    def browserless(self) -> bool:
        """True when this session was created without a browser (API-only fast path)."""
        return self._page is None

    def start_monitor(self) -> None:
        if self._monitor_task is not None:
            return
        if self._page is None and not self._tokens.get("access_token"):
            # No browser and no JWT — nothing to monitor.
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

        if self._page is None:
            # Browserless session — only the JWT check above is available.
            return False

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


# ---------------------------------------------------------------------------
# LLM-driven auth agent — the LLM decides every step of the login flow
# ---------------------------------------------------------------------------

_AUTH_AGENT_SYSTEM = """You are an authentication agent controlling a browser via Playwright.
Your goal: log into a web application using the provided credentials.

At each step you receive the page HTML (trimmed), visible text, current URL,
and the history of your previous actions with their outcomes.
Decide the SINGLE next action to take.

Return ONLY valid JSON (no markdown):
{
  "status": "action" | "success" | "need_mfa" | "need_captcha" | "failed",
  "action": "fill" | "click" | "wait" | "navigate" | null,
  "selector": "CSS selector or locator string" or null,
  "value": "text to fill or URL to navigate" or null,
  "reasoning": "one-line explanation of what you see and why you chose this action"
}

SELECTOR SYNTAX — you can use any of these:
- CSS selectors:  #myId, [name="email"], input[type="password"], .login-btn
- Label text:     label:Username or email     (matches input associated with that label)
- Placeholder:    placeholder:Enter your email (matches input with that placeholder)
- Role+name:      role:button[Sign In]         (matches button with accessible name)
- Text content:   text:Use password            (matches element containing that text)
IMPORTANT: If a CSS selector fails, try label:, placeholder:, or text: on the next step.

ACTIONS:
- "fill": fill a text/email/password field. Provide selector and value.
  For value, use "USERNAME" for the username credential, "PASSWORD" for the password.
- "click": click a button/link/checkbox. Provide selector, value is null.
- "wait": wait 3 seconds for page to load/redirect. selector and value are null.
- "navigate": navigate to a URL. Put the URL in "value", selector is null.

TERMINAL STATUSES (no action needed):
- status="success": the page shows the authenticated app (not a login/SSO page).
- status="need_mfa": you see an MFA/2FA/OTP code input (NOT a regular password field).
- status="need_captcha": you see a CAPTCHA challenge (reCAPTCHA, hCaptcha, Turnstile, etc.).
  Note: "This site is protected by reCAPTCHA" footer text is invisible reCAPTCHA v3 — NOT a CAPTCHA challenge.
- status="failed": login clearly failed (e.g. account locked, invalid user, max retries).

CRITICAL RULES:
- For multi-step logins (email first, then password on next page), fill the visible field, then click the advance button.
- Do NOT try to fill a password field if it is not present in the current HTML.
- If the previous action FAILED, you MUST try a DIFFERENT selector. Never repeat a failed selector.
- If CSS selectors keep failing, switch to label:/placeholder:/text: locators.
- If you see a "Use password" or "Sign in with password" button, click it to reveal the password field.
- If already on the target application (not a login page), return status="success".
- NEVER return the actual credentials in the "reasoning" field."""


async def _get_page_context(page: Page, max_html: int = 10000) -> dict:
    """Capture current page state for the LLM auth agent."""
    url = page.url or ""
    title = ""
    html_snippet = ""
    visible_text = ""
    form_inputs = ""
    try:
        title = await page.title() or ""
    except Exception:
        pass
    try:
        html = await page.content()
        html_snippet = html[:max_html] if len(html) > max_html else html
    except Exception:
        pass
    try:
        visible_text = await page.evaluate(
            "() => document.body ? document.body.innerText.substring(0, 2000) : ''"
        )
    except Exception:
        pass
    # Extract detailed info about interactive elements (inputs, buttons, links)
    try:
        form_inputs = await page.evaluate("""() => {
            const results = [];
            document.querySelectorAll('input, button, select, textarea, a[href]').forEach(el => {
                const tag = el.tagName.toLowerCase();
                const type = el.getAttribute('type') || '';
                const name = el.getAttribute('name') || '';
                const id = el.getAttribute('id') || '';
                const placeholder = el.getAttribute('placeholder') || '';
                const ariaLabel = el.getAttribute('aria-label') || '';
                const text = el.innerText ? el.innerText.substring(0, 50).trim() : '';
                const visible = el.offsetParent !== null || el.offsetWidth > 0;
                const label = document.querySelector('label[for="' + id + '"]');
                const labelText = label ? label.innerText.trim() : '';
                if (!visible && tag !== 'input') return;
                results.push(
                    `<${tag} type="${type}" name="${name}" id="${id}" ` +
                    `placeholder="${placeholder}" aria-label="${ariaLabel}" ` +
                    `label="${labelText}" text="${text}" visible=${visible}>`
                );
            });
            return results.join('\\n');
        }""")
    except Exception:
        pass
    return {
        "url": url,
        "title": title,
        "html": html_snippet,
        "visible_text": visible_text[:2000],
        "form_inputs": form_inputs[:3000],
    }


def _resolve_locator(page: Page, selector: str):
    """Resolve a selector string into a Playwright Locator.

    Supports CSS selectors and custom prefixes:
    - label:Text        → page.get_by_label("Text")
    - placeholder:Text  → page.get_by_placeholder("Text")
    - role:button[Text] → page.get_by_role("button", name="Text")
    - text:Text         → page.get_by_text("Text")
    - Otherwise         → page.locator(selector)   (CSS)
    """
    sel = selector.strip()
    if sel.startswith("label:"):
        return page.get_by_label(sel[6:].strip())
    if sel.startswith("placeholder:"):
        return page.get_by_placeholder(sel[12:].strip())
    if sel.startswith("text:"):
        return page.get_by_text(sel[5:].strip()).first
    if sel.startswith("role:"):
        rest = sel[5:].strip()
        match = re.match(r"(\w+)\[(.+)\]", rest)
        if match:
            return page.get_by_role(match.group(1), name=match.group(2))
        return page.get_by_role(rest)
    return page.locator(sel).first


async def _llm_auth_agent_loop(
    page: Page,
    target: ScanTarget,
    router: "LLMRouter",
    model: str,
    on_progress: Callable | None = None,
    cancel_flag: Any = None,
    max_steps: int = 15,
) -> dict:
    """Drive the login flow step-by-step using the LLM.

    Returns dict with keys: success (bool), need_mfa (bool), need_captcha (bool),
    failed (bool), steps (list of action dicts), last_reasoning (str).
    """
    _cb = on_progress or (lambda *a, **k: None)
    credentials = target.credentials or {}
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    target_host = urlparse(target.url).hostname or ""
    target_root = _extract_root_domain(target_host)

    # Conversation history for the LLM
    conversation: list[dict] = []
    steps_taken: list[dict] = []
    last_reasoning = ""

    for step_i in range(max_steps):
        if cancel_flag and cancel_flag.is_set():
            return {"success": False, "need_mfa": False, "need_captcha": False,
                    "failed": True, "steps": steps_taken, "last_reasoning": "Cancelled"}

        ctx = await _get_page_context(page)
        current_host = urlparse(ctx["url"]).hostname or ""
        current_root = _extract_root_domain(current_host)

        # Quick check: on target (or same root domain, not a login page) → success
        if (current_host == target_host or current_root == target_root) \
                and not _is_login_url(ctx["url"]):
            print(f"  [AUTH-AGENT] Step {step_i+1}: On target ({current_host}) — success")
            return {"success": True, "need_mfa": False, "need_captcha": False,
                    "failed": False, "steps": steps_taken,
                    "last_reasoning": "Already on target application"}

        user_msg = (
            f"Step {step_i+1}/{max_steps}. Current URL: {ctx['url']}\n"
            f"Page title: {ctx['title']}\n"
            f"Target URL: {target.url}\n"
            f"Credentials available: username={'yes' if username else 'no'}, "
            f"password={'yes' if password else 'no'}\n\n"
            f"Interactive elements on page:\n{ctx['form_inputs']}\n\n"
            f"Visible text (first 1000 chars):\n{ctx['visible_text'][:1000]}\n\n"
            f"HTML (first 8000 chars):\n{ctx['html'][:8000]}"
        )

        # Build messages with full conversation history
        messages = [{"role": "system", "content": _AUTH_AGENT_SYSTEM}]
        messages.extend(conversation)
        messages.append({"role": "user", "content": user_msg})

        try:
            resp = router.complete(model=model, messages=messages, max_tokens=400)
            raw = resp.choices[0].message.content or "{}"
        except Exception as e:
            logger.error("LLM auth agent call failed: %s", e)
            print(f"  [AUTH-AGENT] LLM call failed at step {step_i+1}: {e}")
            break

        raw_clean = raw.strip()
        if raw_clean.startswith("```"):
            raw_clean = re.sub(r"^```\w*\n?", "", raw_clean)
            raw_clean = re.sub(r"\n?```\s*$", "", raw_clean)
        try:
            decision = json.loads(raw_clean)
        except json.JSONDecodeError:
            logger.warning("LLM auth agent JSON parse failed: %s", raw_clean[:200])
            print(f"  [AUTH-AGENT] Bad JSON at step {step_i+1}, retrying...")
            conversation.append({"role": "user", "content": user_msg})
            conversation.append({"role": "assistant", "content": raw_clean})
            conversation.append({"role": "user", "content":
                "ERROR: Your response was not valid JSON. Return ONLY a JSON object."})
            continue

        status = decision.get("status", "action")
        action = decision.get("action")
        selector = decision.get("selector")
        value = decision.get("value")
        reasoning = decision.get("reasoning", "")
        last_reasoning = reasoning

        # Mask password in logs
        log_value = "***" if value and value == password else (
            "PASSWORD" if value == "PASSWORD" else (value[:30] if value else ""))
        print(f"  [AUTH-AGENT] Step {step_i+1}: status={status} action={action} "
              f"sel={selector} val={log_value} — {reasoning}")

        steps_taken.append({
            "step": step_i + 1, "status": status, "action": action,
            "selector": selector, "reasoning": reasoning,
        })

        if status == "success":
            return {"success": True, "need_mfa": False, "need_captcha": False,
                    "failed": False, "steps": steps_taken, "last_reasoning": reasoning}
        if status == "need_mfa":
            return {"success": False, "need_mfa": True, "need_captcha": False,
                    "failed": False, "steps": steps_taken, "last_reasoning": reasoning}
        if status == "need_captcha":
            return {"success": False, "need_mfa": False, "need_captcha": True,
                    "failed": False, "steps": steps_taken, "last_reasoning": reasoning}
        if status == "failed":
            return {"success": False, "need_mfa": False, "need_captcha": False,
                    "failed": True, "steps": steps_taken, "last_reasoning": reasoning}

        # Execute the action
        action_result = "OK"
        try:
            if action == "fill" and selector:
                fill_val = value or ""
                # Resolve credential placeholders
                if fill_val.upper() in ("USERNAME", "{{USERNAME}}"):
                    fill_val = username
                elif fill_val.upper() in ("PASSWORD", "{{PASSWORD}}"):
                    fill_val = password
                # Infer from selector context
                if not fill_val:
                    sel_lower = selector.lower()
                    if any(k in sel_lower for k in ("email", "user", "login")):
                        fill_val = username
                    elif "password" in sel_lower:
                        fill_val = password

                loc = _resolve_locator(page, selector)
                try:
                    await loc.fill(fill_val, timeout=5000)
                except Exception:
                    # Fallback: click then type
                    await loc.click(timeout=3000)
                    await asyncio.sleep(0.3)
                    await page.keyboard.type(fill_val, delay=30)
                await asyncio.sleep(0.5)

            elif action == "click" and selector:
                loc = _resolve_locator(page, selector)
                await loc.click(timeout=5000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                await asyncio.sleep(2)

            elif action == "wait":
                await asyncio.sleep(3)

            elif action == "navigate" and value:
                await page.goto(value, wait_until="domcontentloaded", timeout=20000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                await asyncio.sleep(2)

        except Exception as e:
            action_result = f"FAILED: {str(e)[:150]}"
            print(f"  [AUTH-AGENT] Action failed at step {step_i+1}: {e}")

        # Record this exchange in conversation history so the LLM learns
        conversation.append({"role": "user", "content": user_msg})
        conversation.append({"role": "assistant", "content": raw_clean})
        if action_result != "OK":
            conversation.append({"role": "user", "content":
                f"ACTION RESULT: {action_result}\n"
                f"The selector '{selector}' did not work. Try a DIFFERENT approach — "
                f"use label:, placeholder:, text:, or role: locators instead of CSS selectors."})
        else:
            conversation.append({"role": "user", "content": f"ACTION RESULT: {action_result}"})

        # Trim conversation to avoid token overflow (keep last ~6 exchanges)
        if len(conversation) > 18:
            conversation = conversation[-18:]

    # Max steps reached
    print(f"  [AUTH-AGENT] Max steps ({max_steps}) reached without resolution")
    return {"success": False, "need_mfa": False, "need_captcha": False,
            "failed": True, "steps": steps_taken,
            "last_reasoning": f"Max steps reached. Last: {last_reasoning}"}


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

    _cb = on_progress or (lambda *a, **k: None)
    target_host = urlparse(target.url).hostname or ""
    print(f"  [AUTH] Starting LLM-driven auth agent for {target.url[:80]}")
    _cb("progress_msg", {"message": "Auth: LLM agent analyzing login page..."})

    # --- Phase 1: LLM auth agent drives the login flow ---
    agent_result = await _llm_auth_agent_loop(
        page, target, router, model,
        on_progress=on_progress, cancel_flag=cancel_flag,
        max_steps=12,
    )

    steps_log = ", ".join(
        f"[{s['step']}] {s['action'] or s['status']}"
        for s in agent_result.get("steps", [])
    )
    print(f"  [AUTH-AGENT] Result: success={agent_result['success']}, "
          f"mfa={agent_result['need_mfa']}, captcha={agent_result['need_captcha']}, "
          f"failed={agent_result['failed']}")
    print(f"  [AUTH-AGENT] Steps: {steps_log}")

    # --- Phase 2: Handle TOTP if we have a secret and the agent detected MFA ---
    auth_config = target.auth_config or {}
    totp_secret = auth_config.get("totp_secret")
    if agent_result["need_mfa"] and totp_secret:
        print(f"  [AUTH] MFA detected — auto-filling TOTP code")
        _cb("progress_msg", {"message": "Auth: MFA detected, auto-filling TOTP code..."})
        try:
            totp = pyotp.TOTP(totp_secret)
            code = totp.now()
            for sel in ('input[name="otp"]', 'input[name="code"]',
                        'input[placeholder*="code"]', 'input[placeholder*="OTP"]',
                        'input[type="tel"]', 'input[autocomplete="one-time-code"]'):
                try:
                    await page.fill(sel, code, timeout=3000)
                    await page.keyboard.press("Enter")
                    await page.wait_for_load_state("networkidle", timeout=10000)
                    break
                except Exception:
                    continue
        except Exception as e:
            logger.warning("TOTP auto-fill failed: %s", e)

        # Re-check: did TOTP resolve it?
        await asyncio.sleep(3)
        current_host = urlparse(page.url or "").hostname or ""
        if current_host == target_host and not _is_login_url(page.url or ""):
            agent_result["success"] = True
            agent_result["need_mfa"] = False
            print(f"  [AUTH] TOTP succeeded — on target host")

    # --- Phase 3: If agent landed on SSO page, navigate to target to verify ---
    if agent_result["success"]:
        current_host = urlparse(page.url or "").hostname or ""
        if current_host != target_host:
            print(f"  [AUTH] Agent says success but on {current_host}, navigating to target...")
            try:
                await page.goto(target.url, wait_until="domcontentloaded", timeout=20000)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                await asyncio.sleep(3)
                verify_host = urlparse(page.url or "").hostname or ""
                if _is_login_url(page.url or "") or verify_host != target_host:
                    print(f"  [AUTH] Verification failed — redirected to {verify_host}")
                    agent_result["success"] = False
                    agent_result["failed"] = True
                else:
                    print(f"  [AUTH] Verified — on target {verify_host}")
            except Exception as e:
                print(f"  [AUTH] Verification nav failed: {e}")
                agent_result["success"] = False
                agent_result["failed"] = True

    # --- Phase 4: If login succeeded, collect cookies and return ---
    if agent_result["success"]:
        _cb("progress_msg", {"message": "Auth: Login successful (LLM agent)"})
        try:
            cookies = await page.context.cookies()
            tokens: dict[str, str] = {}
            try:
                redirect = page.url or ""
                if "access_token=" in redirect or "#access_token=" in redirect:
                    parsed_url = urlparse(redirect)
                    frag = parsed_url.fragment or parsed_url.query
                    params = parse_qs(frag) if frag else {}
                    for key in ("access_token", "refresh_token"):
                        if key in params and params[key]:
                            tokens[key] = params[key][0]
            except Exception:
                pass
            return AuthResult(
                auth_type="form", tokens=tokens,
                cookies=[{"name": c["name"], "value": c["value"],
                          "domain": c.get("domain", "")} for c in cookies],
                success=True,
            )
        except Exception as e:
            logger.error("Cookie collection failed after successful login: %s", e)
            return AuthResult(auth_type="form", tokens={}, cookies=[], success=True)

    # --- Phase 5: Login needs human help — MFA, CAPTCHA, or outright failure ---
    has_captcha = agent_result.get("need_captcha", False)
    need_mfa = agent_result.get("need_mfa", False)
    screenshot_b64 = await _take_screenshot_b64(page)
    last_reason = agent_result.get("last_reasoning", "")

    if need_mfa:
        challenge_reason = f"MFA/2FA required: {last_reason}"
        challenge_action = ("Enter the MFA/2FA code in the live browser, then click 'Login Complete'.")
        challenge_type = "MFA/2FA"
    elif has_captcha:
        challenge_reason = f"CAPTCHA detected: {last_reason}"
        challenge_action = "Complete the CAPTCHA in the live browser, then click 'Login Complete'."
        challenge_type = "CAPTCHA"
    else:
        challenge_reason = f"Automated login failed: {last_reason}"
        challenge_action = ("Log in manually in the live browser. Once you see "
                            "the target application, click 'Login Complete'.")
        challenge_type = "Login failure"

    print(f"  [AUTH] {challenge_type}: {challenge_reason}")

    if interactive_session:
        _cb("auth_challenge", {
            "screenshot": screenshot_b64,
            "has_captcha": has_captcha,
            "need_mfa": need_mfa,
            "reason": challenge_reason,
            "action": challenge_action,
            "challenge_type": challenge_type,
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
        print(f"  [AUTH] Interactive login did not succeed")

    return AuthResult(
        auth_type="form", tokens={}, cookies=[], success=False,
        captcha_detected=has_captcha, screenshot_b64=screenshot_b64,
    )


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
    def _parse_creds(key: str) -> dict | None:
        raw = t.get(key) or {}
        if raw.get("username") or raw.get("password") or raw.get("bearer_token") or raw.get("api_key"):
            return {k: raw.get(k, "") for k in ("username", "password", "bearer_token", "api_key") if raw.get(k)}
        return None

    creds_b = _parse_creds("credentials_b")
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
        credentials_admin=_parse_creds("credentials_admin"),
        credentials_tenant_b=_parse_creds("credentials_tenant_b"),
        workflow_id=t.get("workflow_id") or None,
        business_flow=t.get("business_flow") or None,
        scan_profile=(t.get("scan_profile") or "vulnerability_scan"),
        skip_passive_sibling_tls=bool(t.get("skip_passive_sibling_tls")),
    )


# ---------------------------------------------------------------------------
# HTTP-only (browserless) authentication — for pure API scans
# ---------------------------------------------------------------------------


def can_use_http_only_auth(target: ScanTarget) -> bool:
    """Return True when this target's auth needs no browser (pure HTTP auth).

    Eligible auth types:
      - "none"         — unauthenticated scan
      - "bearer"       — bearer token supplied in auth_config
      - "api_key"      — API key supplied in auth_config
      - "basic"        — HTTP Basic with username/password

    Ineligible auth types (still need Playwright):
      - "form", "sso", "oauth", "interactive_login" — need to drive a login form
      - "auto"         — we don't know yet; fall back to the browser path so the
                         auth agent can discover it
    """
    auth_config = target.auth_config or {}
    auth_type = (auth_config.get("type") or "auto").lower()
    if auth_type == "none":
        return True
    if auth_type == "bearer":
        return bool(auth_config.get("bearer_token"))
    if auth_type == "api_key":
        return bool(auth_config.get("api_key"))
    if auth_type == "basic":
        creds = target.credentials or {}
        return bool(creds.get("username") or creds.get("password"))
    return False


async def authenticate_http_only(target: ScanTarget) -> AuthSession:
    """Create an AuthSession for pure-API scans without launching a browser.

    Returns an :class:`AuthSession` whose ``page`` attribute is ``None``.  The
    session carries whatever auth header is appropriate for the supplied
    credentials (bearer / api-key / basic) or an empty header dict for
    unauthenticated scans.

    Raises ``ValueError`` if the target's auth type is not browserless-eligible
    — callers should gate with :func:`can_use_http_only_auth` first.
    """
    if not can_use_http_only_auth(target):
        raise ValueError(
            f"authenticate_http_only() cannot handle auth_type="
            f"{(target.auth_config or {}).get('type')!r} — needs Playwright path"
        )

    auth_config = target.auth_config or {}
    auth_type = (auth_config.get("type") or "none").lower()
    credentials = target.credentials or {}

    tokens: dict[str, str] = {}
    if auth_type == "bearer":
        tokens["access_token"] = auth_config.get("bearer_token", "")
    elif auth_type == "api_key":
        tokens["api_key"] = auth_config.get("api_key", "")

    async def _noop_refresh() -> AuthResult:
        # Browserless sessions can't renew via a login form.  Static tokens
        # either keep working or the caller surfaces a 401 and restarts the
        # scan with fresh creds.
        return AuthResult(auth_type=auth_type, tokens=tokens, cookies=[], success=True)

    session = AuthSession(
        page=None,
        auth_type=auth_type,
        tokens=tokens,
        cookies=[],
        credentials=credentials,
        refresh_fn=_noop_refresh,
        target_url=target.url,
    )
    # Expose flags the rest of the agent expects to see on a completed auth.
    session.success = True
    session.need_mfa = False
    session.need_captcha = False
    session.failed = False
    session.network_js_urls = set()
    return session
