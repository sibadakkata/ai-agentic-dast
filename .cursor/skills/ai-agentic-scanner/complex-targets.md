# Complex Target Handling Reference

Detailed implementation guidance for SPA crawling, complex auth flows, WebSocket testing, and session management.

## SPA Crawling Strategy

### Detection

```python
async def detect_app_type(page: Page) -> AppInfo:
    markers = await page.evaluate("""() => ({
        react: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || !!document.querySelector('[data-reactroot]'),
        angular: !!document.querySelector('[ng-version]') || !!window.getAllAngularTestabilities,
        vue: !!window.__VUE__ || !!document.querySelector('[data-v-]'),
        svelte: !!document.querySelector('[class*="svelte-"]'),
        nextjs: !!window.__NEXT_DATA__,
        nuxt: !!window.__NUXT__,
        root_div: !!document.querySelector('#root, #app, #__next'),
        link_count: document.querySelectorAll('a[href]').length,
        script_count: document.querySelectorAll('script[src]').length,
    })""")
    
    has_websockets = await page.evaluate("() => !!window.WebSocket")
    is_spa = markers['react'] or markers['angular'] or markers['vue'] or markers['svelte']
    
    return AppInfo(
        is_spa=is_spa,
        framework=detect_framework(markers),
        has_websockets=has_websockets,
        has_service_worker=await page.evaluate("() => !!navigator.serviceWorker?.controller"),
    )
```

### Interaction-Based Crawl (SPA Mode)

Instead of following `<a>` links, the SPA crawler:

1. **Intercept all network traffic** before any interaction:
```python
discovered_apis = []
await page.route("**/*", lambda route: intercept_and_forward(route, discovered_apis))
```

2. **Find interactive elements** — not just links:
```python
clickables = await page.evaluate("""() => {
    const elements = document.querySelectorAll(
        'a, button, [role="button"], [role="link"], [role="tab"], ' +
        '[role="menuitem"], [onclick], [ng-click], [v-on\\:click], ' +
        '.nav-item, .menu-item, .tab, [data-toggle], [href^="#"]'
    );
    return [...elements].map((el, i) => ({
        index: i,
        tag: el.tagName,
        text: el.textContent?.trim().slice(0, 50),
        href: el.href || null,
        role: el.getAttribute('role'),
        visible: el.offsetParent !== null,
    }));
}""")
```

3. **Click each element and observe**:
```python
for el in clickables:
    url_before = page.url
    await page.click(f":nth-match({el['tag']}, {el['index']})")
    await page.wait_for_load_state("networkidle")
    url_after = page.url
    
    if url_after != url_before:
        discovered_routes.add(url_after)
    
    # Check for new API calls triggered by this click
    new_apis = drain_intercepted(discovered_apis)
    endpoint_registry.add_from_traffic(new_apis)
    
    await page.go_back()
    await page.wait_for_load_state("networkidle")
```

4. **Handle hash-based and pushState routing**:
```python
page.on("framenavigated", lambda frame: on_route_change(frame.url))

await page.evaluate("""() => {
    const orig = history.pushState;
    history.pushState = function() {
        orig.apply(this, arguments);
        window.__route_changed = arguments[2];
    };
}""")
```

### Token/Cookie Extraction from SPAs

SPAs often store auth tokens in `localStorage` or `sessionStorage`:

```python
async def extract_spa_auth(page: Page) -> dict:
    storage = await page.evaluate("""() => ({
        localStorage: Object.fromEntries(
            Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])
        ),
        sessionStorage: Object.fromEntries(
            Object.keys(sessionStorage).map(k => [k, sessionStorage.getItem(k)])
        ),
    })""")
    
    # Look for common token keys
    token_keys = ['token', 'access_token', 'id_token', 'jwt', 'auth', 'session']
    for store in [storage['localStorage'], storage['sessionStorage']]:
        for key, value in store.items():
            if any(tk in key.lower() for tk in token_keys):
                return {"type": "bearer", "token": value, "source": key}
    return None
```

## Complex Authentication Flows

### SSO / SAML Flow

```python
async def handle_sso_login(page: Page, credentials: dict, provider: str) -> AuthResult:
    # 1. Click SSO button (LLM identifies it from page context)
    # 2. Follow redirects to IdP (Okta, Azure AD, Ping Identity)
    # 3. Wait for IdP login page to load
    await page.wait_for_url("**/login**", timeout=10000)  # IdP URL pattern
    
    # 4. Fill credentials on IdP page
    #    LLM identifies the IdP-specific form layout
    
    # 5. Handle consent/MFA screens if they appear
    
    # 6. Follow redirect back to application
    await page.wait_for_url(f"**{target_domain}**", timeout=30000)
    
    # 7. Verify auth by checking for session cookie or token
    cookies = await page.context.cookies()
    tokens = await extract_spa_auth(page)
    
    return AuthResult(auth_type="sso", cookies=cookies, tokens=tokens)
```

### OAuth 2.0 Authorization Code Flow

```python
async def handle_oauth_login(page: Page, credentials: dict) -> AuthResult:
    # 1. Click "Sign in with Google/GitHub/etc" button
    # 2. New window or redirect to OAuth provider
    # 3. Fill credentials on provider page
    # 4. Handle consent screen ("Allow access?")
    # 5. Capture authorization code from redirect URL
    
    auth_code = None
    page.on("response", lambda resp: capture_auth_code(resp, auth_code))
    
    # 6. Application exchanges code for tokens (happens server-side)
    # 7. Verify session established
    
    return AuthResult(auth_type="oauth", cookies=await page.context.cookies())
```

### MFA / TOTP Handling

```python
async def handle_mfa(page: Page, totp_secret: str | None) -> bool:
    if totp_secret:
        import pyotp
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
        # LLM identifies the MFA input field and fills the code
        return True
    else:
        # No TOTP secret available — pause and ask user
        print("MFA code required. Enter the code from your authenticator app:")
        code = input("> ")  # or via callback to Cursor UI
        # Fill the code
        return True
```

## WebSocket Testing Protocol

### Discovery

WebSocket endpoints are discovered by:
1. Intercepting `new WebSocket()` calls during SPA crawl
2. Checking for `ws://` or `wss://` URLs in JavaScript source
3. Looking for common WS paths: `/ws`, `/socket`, `/realtime`, `/live`

```python
ws_endpoints = []
page.on("websocket", lambda ws: ws_endpoints.append({
    "url": ws.url,
    "is_secure": ws.url.startswith("wss://"),
}))
```

### Testing

For each discovered WebSocket endpoint:

1. **Auth test**: Connect without auth headers/cookies — should it reject?
2. **Message injection**: Send crafted messages:
   - JSON with extra fields (mass assignment)
   - Oversized messages (DoS)
   - Messages with XSS payloads (if reflected in UI)
   - Messages with SQLi payloads (if stored server-side)
3. **Cross-origin test**: Connect from different origin header
4. **Rate limit test**: Rapid message burst

## Session Monitor Details

### Expiry Detection Strategies

| Signal | How to Detect | Confidence |
|--------|--------------|------------|
| HTTP 401/403 on known-good endpoint | Periodic health check request | High |
| Redirect to login page | URL contains `/login`, `/signin`, `/auth` | High |
| JWT `exp` claim | Decode JWT, check `exp < now()` | High |
| Session cookie missing | Cookie no longer in `page.context.cookies()` | High |
| Page content changes | "Sign in" / "Log in" text appears on page | Medium |

### Refresh Strategy

```python
async def _refresh(self):
    logger.info("Session expired — re-authenticating")
    
    if self.auth_type == "bearer" and self.refresh_token:
        # Use refresh token endpoint
        resp = await self.http_client.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        })
        self.tokens["access_token"] = resp.json()["access_token"]
        self.http_client.update_auth(self.tokens)
    else:
        # Full re-login
        await self.refresh_fn()
    
    self.refresh_count += 1
    logger.info(f"Session refreshed (total refreshes: {self.refresh_count})")
```
