---
name: ai-agentic-scanner
description: Builds and runs an LLM-powered DAST security scanner using LiteLLM and Playwright. The LLM autonomously reasons about the target, generates its own context-aware payloads, and tests websites and APIs. Parses Postman collections and Burp proxy exports to discover API endpoints. Use when the user mentions AI agent scanner, agentic scanner, LiteLLM scanner, AI security scan, API scan, Postman import, or Burp import.
---

# AI Agentic Security Scanner

## Project Structure

```
├── config/
│   ├── scanner_config.yaml       # Targets, models, scan settings
│   └── targets.env               # Credentials (gitignored)
│   └── targets.env.example       # Template for credentials
├── scanners/ai_agent/
│   ├── agent.py                  # Core agent loop + context management
│   ├── auth.py                   # Authentication (form/SSO/OAuth/MFA)
│   ├── llm_config.py             # LiteLLM routing + cost tracking
│   ├── prompts.py                # System + phase prompts
│   ├── tools.py                  # 27 tools (browser, API, WebSocket)
│   └── api_import.py             # Postman/Burp/OpenAPI parsers
├── scripts/
│   ├── run_scan.py               # CLI entry point for scanning
│   ├── report_generator.py        # PDF report generator (auto-discovers results)
│   ├── triage_engine.py          # 3-layer universal triage engine
│   └── cve_lookup.py             # NVD + OSV.dev dynamic CVE lookup
├── results/
│   ├── raw/                      # Raw scan JSON output
│   ├── reports/                  # Generated PDF reports
│   └── cache/                    # NVD/OSV API cache
├── web/
│   ├── app.py                    # FastAPI backend
│   └── static/index.html         # Single-page web UI
├── imports/                      # API definition files (Postman/Burp/OpenAPI)
├── Dockerfile                    # Production container (Playwright + Chromium)
├── requirements.txt
└── .gitignore
```

## CRITICAL: Do Not Scan Without Approval

Build all code first. Present the plan. Wait for explicit user approval before executing any scan against any target.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Payload generation | **Pure LLM** — agent generates ALL payloads from scratch based on application context | No static payload lists; the LLM's value is reasoning about what to test, not spraying generic payloads |
| API endpoint import | Postman/Burp/OpenAPI parsed into a unified endpoint registry | Enables testing APIs that aren't discoverable via crawling |
| Static payload catalog | **None** — no `payloads.py`, no hardcoded payload files | The agent must never fall back to fixed lists |
| Triage | **Offline, evidence-based** — no LLM used for triage | Deterministic rules + confidence scoring, zero cost, reproducible |
| Cost tracking | **Per-call accumulation** via `litellm.completion_cost()` | Accurate token + dollar tracking per model |

## Scan Modes

This scanner supports complex modern applications. All modes can combine in a single session.

| Mode | Input Source | Discovery Method |
|------|-------------|-----------------|
| **Traditional Website** | Target URL | Playwright crawl (BFS, authenticated, follows `<a>` links) |
| **SPA (React/Angular/Vue)** | Target URL | Playwright interaction-based crawl — clicks elements, monitors route changes via `popstate`/`hashchange`, intercepts `fetch()`/`XHR` to discover API endpoints dynamically |
| **API** | Postman collection JSON, Burp proxy XML, OpenAPI/Swagger spec | Parsed endpoint list with methods, headers, params, body schemas |
| **WebSocket** | Discovered during crawl or from import | Playwright WebSocket interception for real-time endpoint testing |

### Supported Authentication Flows

| Auth Type | Handling |
|-----------|---------|
| Simple form login | LLM-assisted: detects form, fills credentials, submits |
| SSO / SAML | Follows redirect chain through IdP, handles consent screens |
| OAuth 2.0 / OIDC | Authorization code flow via browser, captures tokens from redirect |
| API key / Bearer token | Injected directly into HTTP headers from config |
| Cookie-based sessions | Maintained automatically by Playwright browser context |
| MFA / 2FA (TOTP) | Computes TOTP from shared secret in config (if provided), or pauses for manual entry |
| Session refresh | Background monitor detects expired sessions and re-authenticates mid-scan |

### SPA Detection and Handling

The scanner auto-detects SPAs during `web_recon` by checking for:
- Presence of React (`__REACT_DEVTOOLS_GLOBAL_HOOK__`), Angular (`ng-version`), Vue (`__VUE__`) markers
- Single `<div id="root">` or `<div id="app">` DOM structure
- Client-side routing (`pushState`/`replaceState` usage, hash-based routes)
- Heavy `fetch()`/`XHR` traffic vs minimal `<a>` link navigation

When SPA detected, the crawler switches from link-following to interaction-based discovery:
1. Click all interactive elements (buttons, nav items, tabs, menus)
2. Monitor URL changes via `page.on("framenavigated")` and `page.on("popup")`
3. Intercept all `fetch()`/`XHR` calls via `page.route("**/*")` to discover hidden API endpoints
4. Wait for JS rendering (`page.wait_for_load_state("networkidle")`) before inspecting DOM
5. Track discovered routes/endpoints in the `EndpointRegistry` alongside imported ones

## LLM Provider Options

The scanner's `LLMRouter` (in `llm_config.py`) auto-selects the routing path per model:

| Provider | Setup | Model name example |
|----------|-------|--------------------|
| **LiteLLM Proxy** | Set `LITELLM_BASE_URL` + `LITELLM_API_KEY` in `targets.env` | `claude-haiku-4-5-20251001` |
| **AWS Bedrock** | Set `AWS_DEFAULT_REGION` (IAM role) or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | `bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| **Direct API** | Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY` | `claude-haiku-4-5-20251001`, `gemini/gemini-2.5-flash` |
| **Hybrid** | Set both LiteLLM + AWS creds. `bedrock/` models go direct; others go through proxy | Mix of any above |

## Usage

```bash
# Default (Haiku via whichever provider is configured)
python scripts/run_scan.py

# Override model for this run
python scripts/run_scan.py --model "bedrock/us.anthropic.claude-sonnet-4-6"

# Generate PDF reports
python scripts/report_generator.py

# Dry run (test connectivity)
python scripts/run_scan.py --dry-run
```

## Task Checklist

```
AI Agentic Scanner Components:
- [x] Step 1: LLM connectivity (LiteLLM proxy / Bedrock / direct)
- [x] Step 2: llm_config.py (hybrid model routing + cost tracking)
- [x] Step 3: tools.py (27 tools — browser + SPA + WebSocket + API)
- [x] Step 3b: api_import.py (Postman / Burp / OpenAPI parsers)
- [x] Step 4: prompts.py (system + scan prompts per OWASP category)
- [x] Step 5: agent.py (agent loop with SPA detection + dynamic endpoint discovery)
- [x] Step 6: auth.py (SSO / OAuth / SAML / MFA / form / token auth + session monitor)
- [x] Step 7: triage_engine.py (3-layer universal evidence-based triage)
- [x] Step 8: cve_lookup.py (NVD + OSV.dev dynamic CVE/CVSS)
- [x] Step 9: report_generator.py (PDF with clickable summaries, curl evidence)
- [x] Step 10: run_scan.py (CLI entry point)
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    AI Agentic Scanner                        │
│                                                              │
│  ┌─────────────────────────────────────┐                     │
│  │         Endpoint Discovery          │                     │
│  │  ┌──────────┐ ┌───────┐ ┌────────┐ │                     │
│  │  │ Postman  │ │ Burp  │ │OpenAPI │ │                     │
│  │  │ .json    │ │ .xml  │ │ .yaml  │ │                     │
│  │  └────┬─────┘ └───┬───┘ └───┬────┘ │                     │
│  │       └────────┬───┘────────┘       │                     │
│  │           ┌────▼─────┐              │                     │
│  │           │ Endpoint │              │                     │
│  │           │ Registry │              │                     │
│  │           └────┬─────┘              │                     │
│  └────────────────┼────────────────────┘                     │
│                   │                                          │
│  ┌────────────┐   │   ┌─────────────┐                        │
│  │ Playwright │   │   │  LLMRouter  │   LLM generates ALL   │
│  │ (Browser)  │◄──┼──▶│  ┌────────┐ │   payloads based on   │
│  └────────────┘   │   │  │Bedrock │ │   observed context.   │
│                   │   │  │Proxy   │ │   No static payload   │
│  ┌────────────┐   │   │  │Direct  │ │   lists.              │
│  │ HTTP       │   │   │  └────────┘ │                        │
│  │ Client     │◄──┘   └──────┬──────┘                        │
│  │ (API calls)│       ┌──────▼──────┐     ┌────────────┐    │
│  └────────────┘       │ Agent Loop  │     │ Cost       │    │
│                       │ 1. Observe  │     │ Tracker    │    │
│    ┌──────────┐       │ 2. Think    │─────│ (per model)│    │
│    │  Target  │       │ 3. Act      │     └────────────┘    │
│    │ Web+API  │       │ 4. Analyze  │                        │
│    └──────────┘       │ 5. Plan     │                        │
│                       └─────────────┘                        │
└──────────────────────────────────────────────────────────────┘
```

## Step 1: Verify LLM Connectivity

Check in this order:

1. `LITELLM_BASE_URL` + `LITELLM_API_KEY` env vars → test proxy
2. AWS credentials (`AWS_ACCESS_KEY_ID` etc.) → test Bedrock models
3. Direct API keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`
4. Test the configured model with a trivial completion call
5. Report availability and stop if zero models work

```python
import litellm

for model in ["claude-haiku-4-5-20251001", "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "gemini/gemini-2.5-flash"]:
    try:
        resp = litellm.completion(model=model, messages=[{"role": "user", "content": "ping"}], max_tokens=5)
        print(f"{model}: OK")
    except Exception as e:
        print(f"{model}: FAILED - {e}")
```

## Step 2: Build llm_config.py

Location: `scanners/ai_agent/llm_config.py`

Key capabilities:
- **Hybrid routing**: auto-selects proxy vs direct based on model prefix (`bedrock/` → direct, others → proxy if configured)
- **Retry with backoff**: rate limit errors get 3 retries (2s → 4s → 8s)
- **Context window recovery**: raises `ContextWindowExceeded` so agent.py can trim and retry
- **Cost tracking**: per-call token + dollar accumulation via `litellm.completion_cost()`
- **Proxy + direct**: if `LITELLM_BASE_URL` is set, uses OpenAI client for proxy; otherwise `litellm.completion()` for direct provider calls

## Step 3: Build tools.py

Location: `scanners/ai_agent/tools.py`

### Browser Tools (Website + SPA Scanning)

| Function | Purpose | Returns |
|----------|---------|---------|
| `navigate(url)` | Go to URL, wait for networkidle | page title, status code, is_spa flag |
| `click(selector)` | Click element, wait for navigation/networkidle | success/fail, new URL if navigated, new XHR calls triggered |
| `fill(selector, value)` | Fill form field | success/fail |
| `submit_form(selector)` | Submit a form | response status, redirect URL |
| `inject_payload(selector, payload)` | Fill field with attack payload + submit | response body snippet, status, errors |
| `screenshot()` | Take page screenshot | base64 image (for multimodal models) |
| `get_page_source()` | Get rendered HTML (post-JS execution) | truncated HTML (first 4000 chars) |
| `get_cookies()` | List all cookies | cookie list with flags (Secure, HttpOnly, SameSite) |
| `get_network_log()` | All intercepted fetch/XHR since last call | list of {url, method, status, request_body, response_snippet} |
| `get_forms()` | Extract forms from rendered DOM | list of {action, method, inputs[]} |
| `get_links()` | Extract links + clickable elements | list of {href, text, tag, is_spa_nav} |
| `get_local_storage()` | Read localStorage and sessionStorage | dict of all key-value pairs |
| `execute_js(script)` | Run arbitrary JS in page context | script return value |
| `wait_for_spa_route(timeout)` | Wait for SPA route change (popstate/hashchange) | new URL, route params |
| `intercept_requests(url_pattern)` | Start intercepting requests matching pattern | intercepted request list |

### WebSocket Tools

| Function | Purpose | Returns |
|----------|---------|---------|
| `ws_connect(url, headers)` | Open WebSocket connection | connection_id, success/fail |
| `ws_send(connection_id, message)` | Send message to WebSocket | success/fail |
| `ws_receive(connection_id, timeout)` | Read next message from WebSocket | message content, type |
| `ws_inject(connection_id, payload)` | Send crafted payload via WebSocket | response message, anomaly detected |
| `ws_close(connection_id)` | Close WebSocket connection | success/fail |

### API Tools (API Scanning)

| Function | Purpose | Returns |
|----------|---------|---------|
| `api_request(method, url, headers, body, auth)` | Send HTTP request with full control | status, headers, body snippet, timing |
| `api_request_raw(raw_request)` | Send from raw HTTP request string | same as above |
| `fuzz_parameter(endpoint, param, payloads)` | Batch-fuzz a single param with payload list | list of {payload, status, body_snippet, anomaly} |
| `replay_with_modification(request, modifications)` | Replay a captured request with changes | response diff vs original |
| `get_api_endpoints()` | List all discovered endpoints from import | endpoint registry contents |
| `test_auth_bypass(endpoint, methods)` | Try endpoint without auth / with tampered tokens | list of {method, status, accessible} |
| `test_method_override(endpoint)` | Try PUT/DELETE/PATCH on GET-only endpoints | list of {method, status, response_snippet} |

**Total: 27 tools.** All return structured dicts, truncated to stay within token limits. Tool definitions use OpenAI function calling format. The `fuzz_parameter` tool accepts a `payloads` array — the LLM generates these dynamically, never from static lists.

## Step 3b: Build api_import.py

Location: `scanners/ai_agent/api_import.py`

Parses external API definitions into a unified endpoint registry.

### Supported Import Formats

| Format | File Extension | Parser |
|--------|---------------|--------|
| Postman Collection v2.1 | `.json` | `parse_postman_collection()` |
| Burp Suite Proxy Export | `.xml` | `parse_burp_export()` |
| OpenAPI / Swagger | `.yaml` / `.json` | `parse_openapi_spec()` |

All parsers produce a unified `APIEndpoint` dataclass (method, url, path, headers, query_params, body, body_type, auth_type, auth_value, tags, variables, original_name). Endpoints are deduplicated by (method, path, sorted_param_keys) and indexed in an `EndpointRegistry`.

Key parser behaviors:
- **Postman**: Recursive folder traversal, `{{var}}` replacement, auth inheritance, all body modes (json, form-data, urlencoded, graphql)
- **Burp**: XML parsing, base64-decoded bodies, static asset filtering (.js/.css/.png excluded), cookie/header auth extraction
- **OpenAPI**: Schema-based parameter extraction, example value generation

All parsers produce a unified `APIEndpoint` dataclass that feeds into the agent's endpoint registry.

## Step 4: Build prompts.py

Location: `scanners/ai_agent/prompts.py`

### System Prompt

```
You are an expert penetration tester performing an authorized OWASP Top 10 
security assessment. You have browser and API tools to interact with the 
target application.

IMPORTANT: You generate ALL payloads yourself based on what you observe.
You have NO static payload lists. Your value is reasoning about the 
application context and crafting targeted payloads — not spraying generic 
strings. For example:
- See a PostgreSQL error? Craft PostgreSQL-specific SQLi.
- See a Jinja2 template marker? Craft Jinja2 SSTI payloads.
- See a JWT? Probe for alg:none, key confusion, claim tampering.
- See an API with numeric IDs? Test IDOR with adjacent IDs.

Your approach:
1. OBSERVE: Examine page structure, forms, inputs, API responses, headers
2. THINK: Reason about what vulnerability classes apply to what you see
3. ACT: Craft and inject context-specific payloads via your tools
4. ANALYZE: Examine responses for vulnerability indicators
5. PLAN: Decide what to test next based on findings so far

Rules:
- Only test the authorized target URL and its subpaths
- Never use pre-built payload lists — generate every payload from reasoning
- Record evidence for every finding (request, response, indicator)
- Classify findings by OWASP category and severity
- Stop after exhausting reasonable test cases (max 50 actions per page)

When you find a vulnerability, output a structured finding:
{
  "title": "...",
  "severity": "Critical|High|Medium|Low|Info",
  "owasp_category": "A01-A10",
  "url": "affected URL",
  "parameter": "affected parameter",
  "payload": "what was injected",
  "evidence": "response indicator",
  "confidence": "High|Medium|Low",
  "remediation": "fix recommendation"
}
```

### Scan Phase Prompts

Create separate task prompts for each phase. Each prompt tells the agent what vulnerability class to focus on. The LLM generates its own payloads per phase based on observed context.

#### Website Scan Phases

| Phase | Focus | Key Instructions |
|-------|-------|-----------------|
| `web_recon` | Map the application | Detect SPA vs traditional. SPA: click elements, monitor route changes, intercept fetch/XHR. Traditional: follow links BFS. Both: extract forms, hidden inputs, JS endpoints, localStorage data |
| `web_a01` | Broken Access Control | IDOR on every ID param, forced browsing, method tampering, privilege escalation |
| `web_a02` | Cryptographic Failures | TLS version, cookie flags, sensitive data in URLs/localStorage, mixed content |
| `web_a03_sqli` | SQL Injection (deep) | Error-based, blind boolean, blind time-based, UNION, stacked — per DB type |
| `web_a03_xss` | XSS (deep) | Reflected, stored, DOM-based, polyglot, CSP bypass, event handlers, SVG payloads |
| `web_a03_cmdi` | Command Injection | OS command injection via all input vectors, blind via sleep/ping |
| `web_a03_ssti` | Template Injection | Detect template engine, then engine-specific payloads |
| `web_a04` | Insecure Design | Price tampering, flow bypass, race conditions, rate limit abuse |
| `web_a05` | Security Misconfiguration | Headers, CORS, verbose errors, directory listing, debug endpoints, default creds |
| `web_a06` | Vulnerable Components | Header/response fingerprinting, known CVE checks, outdated JS libraries |
| `web_a07` | Auth Failures | Session fixation, weak tokens, brute force, JWT attacks, password reset flaws |
| `web_a08` | Software Integrity | SRI checks, untrusted CDN resources, client-side prototype pollution |
| `web_a09` | Logging Failures | Security event logging verification, error handling information leak |
| `web_a10` | SSRF | URL-accepting parameters, redirect chains, cloud metadata probes |
| `web_websocket` | WebSocket testing | Connect to discovered WS endpoints, inject payloads, test auth on WS, check for message injection |
| `web_extras` | Beyond OWASP | Open redirect, CRLF injection, HTTP smuggling, clickjacking, CSRF, prototype pollution |

#### API Scan Phases

| Phase | Focus | Key Instructions |
|-------|-------|-----------------|
| `api_recon` | Map all endpoints | Load from import (Postman/Burp), discover undocumented via wordlists, check OPTIONS |
| `api_auth` | Authentication testing | Missing auth, broken auth, token reuse, JWT manipulation, API key in URL |
| `api_authz` | Authorization / BOLA | IDOR on every object ID, horizontal + vertical privilege escalation |
| `api_injection` | Injection (all types) | SQLi, NoSQLi, LDAP injection, XSS in API responses, XXE in XML endpoints |
| `api_mass_assign` | Mass assignment | Send extra fields in POST/PUT, check if unintended fields are saved |
| `api_rate_limit` | Rate limiting / DoS | Rapid-fire same endpoint, check for 429s, resource exhaustion |
| `api_ssrf` | SSRF via API params | URL params, webhook URLs, file import URLs → cloud metadata probes |
| `api_graphql` | GraphQL-specific | Introspection, batching, deep nesting, alias brute-force, field suggestion |
| `api_data_exposure` | Excessive data exposure | Compare response fields vs what UI shows, check for PII/secrets in responses |
| `api_business_logic` | Business logic | Flow bypass, parameter tampering, race conditions, idempotency violations |

## Step 5: Build agent.py

Location: `scanners/ai_agent/agent.py`

Core agent loop — supports both website and API scan modes:

```python
async def run_scan(target: ScanTarget, model: str, router: LLMRouter) -> list[dict]:
    browser = await launch_browser()
    
    # Authenticate (handles form, SSO, OAuth, MFA, bearer token — auto-detected)
    auth_session = await authenticate(browser, target, router, model)
    http_client = HTTPClient(auth_session=auth_session)  # shares tokens/cookies
    
    # Load API endpoints from imports + discover from SPA traffic
    endpoint_registry = EndpointRegistry()
    if target.scan_mode in ("api", "both"):
        if target.postman_file:
            endpoint_registry.add(parse_postman_collection(target.postman_file, target.postman_env))
        if target.burp_file:
            endpoint_registry.add(parse_burp_export(target.burp_file))
        if target.openapi_file:
            endpoint_registry.add(parse_openapi_spec(target.openapi_file))
    
    tools = ScanTools(
        page=auth_session.page,
        http_client=http_client,
        registry=endpoint_registry,
        auth_session=auth_session,  # tools can check/refresh auth
    )
    findings = []
    
    # Detect SPA and choose crawl strategy
    app_info = await detect_app_type(auth_session.page)  # {is_spa, framework, has_websockets}
    phases = get_phases(target.scan_mode, app_info)
    messages = [{"role": "system", "content": build_system_prompt(target, endpoint_registry, app_info)}]

    for phase in phases:
        messages.append({"role": "user", "content": phase.prompt})
        
        for step in range(phase.max_steps):
            response = router.complete(model=model, messages=messages, tools=TOOL_DEFINITIONS)
            msg = response.choices[0].message
            messages.append(msg.model_dump())

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    result = await tools.execute(tc.function.name, tc.function.arguments)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})
                    # Add dynamically discovered API endpoints to registry
                    if tc.function.name in ("get_network_log", "intercept_requests"):
                        endpoint_registry.add_from_traffic(result)
            else:
                findings.extend(extract_findings(msg.content))
                break
        
        messages = trim_context(messages, max_tokens=80000)

    auth_session.stop_monitor()
    await browser.close()
    return findings
```

**Max steps per phase**: 50 tool calls. If the LLM stops calling tools, move to next phase.

**Token budget management**: `trim_context()` summarizes older phases when history exceeds 80K tokens. Current phase is never trimmed.

## Step 6: Build auth.py

Location: `scanners/ai_agent/auth.py`

Handles all authentication complexity. The LLM drives the login flow by observing the page and deciding what to do.

```python
async def authenticate(browser, target: ScanTarget, router: LLMRouter, model: str) -> AuthSession:
    page = await browser.new_page()
    await page.goto(target.url)
    
    auth_result = await detect_and_login(page, target, router, model)
    
    session = AuthSession(
        page=page,
        auth_type=auth_result.auth_type,
        tokens=auth_result.tokens,
        cookies=auth_result.cookies,
        refresh_fn=lambda: detect_and_login(page, target, router, model),
    )
    
    session.start_monitor()  # background task to detect session expiry
    return session
```

### Auth Flow Detection

The LLM observes the login page and classifies the flow:

| Detected Flow | LLM Action |
|---------------|-----------|
| **Simple form** | Identify username/password fields, fill, submit |
| **SSO redirect** | Follow redirect chain through IdP (Okta, Azure AD, Ping), fill credentials on IdP page, handle consent screens, return to app |
| **OAuth 2.0** | Click "Sign in with..." button, complete authorization flow in browser, capture auth code/token from redirect URL |
| **SAML** | Follow SAML redirect, POST assertion, handle relay state |
| **MFA prompt** | If TOTP secret in config → compute code via `pyotp`. If not → pause scan, prompt user to enter code manually, resume |

### Session Monitor

```python
class AuthSession:
    async def start_monitor(self):
        """Background task: every 60s, check if session is still valid."""
        while self.active:
            await asyncio.sleep(60)
            if await self._is_expired():
                await self._refresh()

    async def _is_expired(self) -> bool:
        # Check for: redirect to login page, 401/403 on known-good endpoint,
        # expired JWT (decode and check exp claim), missing session cookie
        ...

    async def _refresh(self):
        # Re-run the full auth flow using stored credentials
        # Update tokens/cookies in HTTP client and browser context
        ...
```

### Target Auth Config

```yaml
targets:
  - id: T1
    url: "${T1_URL}"                        # target URL from env / config
    auth:
      type: auto              # auto | form | sso | oauth | api_key | bearer
      username: "${T1_USERNAME}"
      password: "${T1_PASSWORD}"
      totp_secret: "${T1_TOTP_SECRET}"    # optional — for MFA
      sso_provider: "${T1_SSO_PROVIDER}"  # optional — hint for SSO flow (okta, azure, ping)
      api_key: "${T1_API_KEY}"             # optional — for API-only auth
      bearer_token: "${T1_BEARER}"         # optional — skip login, use token directly
```

When `type: auto`, the LLM detects the auth flow at runtime. Use explicit types to skip detection.

For detailed auth flow handling (SSO redirect chains, OAuth state params, SAML assertion parsing), see [complex-targets.md](complex-targets.md).

## Step 7: Dry Run

Before real scanning, run with `--dry-run` flag:
- Authenticate and crawl (no attack payloads)
- LLM observes and plans but `inject_payload` is stubbed to return "DRY RUN"
- Validates the full pipeline works end-to-end
- Reports which pages/forms/APIs were discovered

## Step 8: Execute Full Scan

One model per run (default: Haiku). Override with `--model`:

```bash
python scripts/run_scan.py                                    # default Haiku
python scripts/run_scan.py --model "bedrock/us.anthropic.claude-sonnet-4-6"
```

The scanner authenticates, crawls, tests all phases, and saves results to `results/raw/aiagent_{model_slug}_{target_id}.json`. Run `python scripts/report_generator.py` afterwards to generate PDF reports with triage.

## Output Format

Raw scan results are saved automatically to `results/raw/aiagent_{model_slug}_{target_id}.json`.

Each result JSON contains:

| Key | Contents |
|-----|----------|
| `scanner` | Always `"ai_agent"` |
| `model` | The model used (as passed via config or `--model`) |
| `target` | The target URL scanned |
| `findings[]` | Array of detected vulnerabilities |
| `findings[].title` | Finding name (e.g. "Reflected XSS in search parameter") |
| `findings[].severity` | Scanner-assigned severity (Critical/High/Medium/Low/Info) |
| `findings[].owasp_category` | OWASP Top 10 mapping (e.g. "A03:2021") |
| `findings[].url` | Affected URL |
| `findings[].parameter` | Affected parameter |
| `findings[].payload` | Exact payload used |
| `findings[].evidence` | What the scanner observed |
| `summary.pages_crawled` | Number of pages discovered and crawled |
| `summary.forms_found` | Number of forms detected |
| `summary.api_endpoints_found` | Number of API endpoints tested |
| `summary.test_log[]` | Full log of every request/response tested |
| `summary.severity_breakdown` | Count per severity level |
| `metadata.scan_duration_seconds` | Total scan time |
| `metadata.llm_calls` | Number of LLM API calls made |
| `metadata.total_tokens` | Tokens consumed |
| `metadata.cost_usd` | Estimated LLM cost |

PDF reports are generated from these JSONs via `python scripts/report_generator.py`.

## Dependencies

All dependencies are in `requirements.txt`. Install with:

```bash
pip install -r requirements.txt
playwright install chromium
```

API import files (optional) go in the `imports/` directory:

```
imports/
├── *.postman_collection.json      # Postman v2.1 collections
├── *.postman_environment.json     # Postman environments (optional)
├── *.xml                          # Burp Suite proxy history exports
└── *.yaml / *.json                # OpenAPI / Swagger specs
```

## Error Handling

| Error | Recovery |
|-------|----------|
| LLM rate limit | Exponential backoff (2s → 4s → 8s, max 3 retries) |
| Context window exceeded | Aggressive message trimming + retry |
| Playwright timeout | Screenshot + log, skip to next page |
| Session expired mid-scan | `AuthSession` auto-refreshes, retries last failed request |
| SSO/OAuth redirect fails | Screenshot error page, log redirect chain, fall back to API-only |
| MFA required but no TOTP secret | Pause scan, prompt user, resume on input |
| WebSocket refused | Log and skip WS phase, continue HTTP testing |
| SPA route detection stalls | Fall back to link-based crawl |
| Any unhandled error | Partial results saved, error logged to `results/errors.log` |

## Additional Resources

- For SPA crawling, SSO/OAuth flow details, and WebSocket testing: [complex-targets.md](complex-targets.md)
