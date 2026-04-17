# Scanner Internals

[← Back to README](../README.md)

Deep dive into the scan engine: tool execution, evidence tracking, hybrid smart retry, evidence summary, context management, and finding extraction.

---

## End-to-End Scan Flow

```
User clicks "Start Scan" (UI or API)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  1. SETUP                                                │
│     Launch Playwright (headless Chromium)                │
│     Create httpx.AsyncClient (for API requests)         │
│     Build ScanTools, EndpointRegistry, allowed_domains  │
├─────────────────────────────────────────────────────────┤
│  2. AUTHENTICATE                                         │
│     detect_and_login() → LLM classifies auth type       │
│     Fill credentials → handle CAPTCHA/MFA → capture     │
│     session cookies/tokens → start session monitor      │
│     Optional: authenticate User B for BOLA testing      │
├─────────────────────────────────────────────────────────┤
│  3. NAVIGATE TO TARGET                                   │
│     Load target URL → wait for SPA readiness            │
├─────────────────────────────────────────────────────────┤
│  4. PASSIVE RECON ($0)                                   │
│     24 deterministic checks (no LLM)                    │
│     Findings added directly to results                  │
├─────────────────────────────────────────────────────────┤
│  5. API BASELINE (if endpoints imported)                 │
│     Execute happy-path for each endpoint                │
│     Capture "known good" responses for comparison       │
├─────────────────────────────────────────────────────────┤
│  6. HYBRID BODY FUZZING                                  │
│     LLM plans payloads ($0.001) → engine executes       │
│     Tests POST/PUT/PATCH endpoints for injection        │
├─────────────────────────────────────────────────────────┤
│  7. LLM PHASE LOOP (main scan)                          │
│     For each phase from get_phases():                   │
│       a. Inject phase prompt into conversation          │
│       b. Inject cross-phase findings context (phase 2+) │
│       c. LLM loop: complete() → tool_calls → execute() │
│       d. Capture evidence for security tool calls       │
│       e. Enforce minimum security calls                 │
│       f. Extract findings when LLM stops                │
│       g. Evidence grounding check                       │
│       h. Hybrid smart retry (tool-enabled, tailored     │
│          prompt) for 15 active-retry phases when the    │
│          core vuln class is missing; otherwise cheap    │
│          evidence-summary pass                          │
│       i. Trim context if needed                         │
├─────────────────────────────────────────────────────────┤
│  7b. ATTACK CHAIN ANALYSIS                               │
│      LLM reviews all findings from prior phases         │
│      Combines into multi-step exploit chains via        │
│      chain_exploit tool → sequential execution          │
├─────────────────────────────────────────────────────────┤
│  8. RUNTIME VERIFICATION                                 │
│     Replay payloads against live target                  │
│     Mark findings: CONFIRMED / DISPROVED                │
├─────────────────────────────────────────────────────────┤
│  9. TRIAGE ENGINE ($0)                                   │
│     3-layer classification: TP / FP / Manual Review     │
│     CWE mapping, CVSS scoring, confidence adjustment    │
├─────────────────────────────────────────────────────────┤
│  10. CLEANUP                                             │
│      Stop session monitor, close httpx, close browser   │
│      Save results to JSON + SQLite                      │
└─────────────────────────────────────────────────────────┘
```

---

## Tool System (`tools.py`)

### Architecture

`ScanTools` wraps Playwright's `Page` and `httpx.AsyncClient` into 30 security-testing tools that the LLM can call.

```
LLM decides to call tool
         │
         ▼
┌─────────────────────────────┐
│  router.complete()          │  LLM returns tool_call:
│  (LiteLLM → Bedrock)       │  {"name":"fuzz_parameter",
│                             │   "arguments":{...}}
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  tools.execute(name, args)  │  Central dispatcher
│                             │  JSON-parses args
│                             │  Calls handler method
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Handler method runs        │  e.g. fuzz_parameter()
│  - Resolves relative URLs   │  uses _resolve_url()
│  - Checks scope (domains)   │
│  - Executes via Playwright  │
│    or httpx                 │
│  - Extracts vuln signals    │
│  - Returns result dict      │
└─────────────────────────────┘
```

### Tool Registration

Tools are exposed to the LLM via `TOOL_DEFINITIONS` — a list of OpenAI-style function schemas:

```python
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "fuzz_parameter",
            "description": "Batch-fuzz a single parameter...",
            "parameters": {
                "type": "object",
                "properties": { ... },
                "required": ["endpoint", "method", "param_name", "payloads"]
            }
        }
    },
    # ... 29 more tools (including chain_exploit, get_findings_so_far)
]
```

These are passed to `router.complete(..., tools=TOOL_DEFINITIONS)`. The LLM returns `tool_calls` in its response, which the agent loops over and executes via `tools.execute()`.

### Key Mechanisms

#### URL Resolution (`_resolve_url`)

The LLM often provides relative URLs (e.g. `/api/search`). `_resolve_url()` converts them to absolute URLs using the page origin or httpx base URL. Used by: `navigate`, `api_request`, `fuzz_parameter`, `replay_with_modification`.

#### Vulnerability Signal Extraction (`_extract_vuln_signals`)

After every HTTP request, tool responses are scanned for vulnerability indicators:

| Signal Type | Examples |
|-------------|----------|
| **SQL errors** | `SQLITE_ERROR`, `mysql_fetch`, `ORA-01756`, `syntax error at or near` |
| **XSS reflection** | `<script>alert(`, payload reflected in response body |
| **Command injection** | `root:x:0:0`, `uid=`, `Windows IP Configuration` |
| **SSTI** | `49` from `{{7*7}}`, template engine error strings |
| **Path traversal** | `root:x:`, `/etc/passwd` content in response |

When signals are detected, the tool result includes:
- `VULNERABILITIES_DETECTED: true` — makes the finding unmissable
- `ACTION_REQUIRED: Report this as a finding` — explicit instruction
- `error_title`, `error_message`, `error_indicators` — structured signal data

#### Scope Enforcement

- `allowed_domains`: Only URLs matching these domains are tested
- `exclude_urls`: Skip specific URL patterns
- Logout blocking: URLs/selectors containing "logout", "sign-out", etc. are blocked
- Out-of-scope tracking: Attempted OOS requests are logged for visibility

---

## Evidence Buffer

The evidence buffer solves a critical problem: LLM context trimming can remove tool call results, causing the LLM to lose track of what it tested. The evidence buffer preserves compact summaries.

### How It Works

```
Security tool call executed
         │
         ▼
┌─────────────────────────────────┐
│  _capture_evidence()            │
│  Stores compact record:         │
│  - tool name                    │
│  - URL tested                   │
│  - payload used                 │
│  - HTTP status code             │
│  - flags: ANOMALY, REFLECTED,   │
│    ERROR, VULN_DETECTED         │
│  - evidence snippet (response)  │
└─────────────┬───────────────────┘
              │
              ▼
  Stored in phase_evidence list
              │
              ▼
  Used by:
  1. _format_evidence_buffer() → retry prompt (active retry) or
     evidence summary prompt (fallback tool-less pass)
  2. _match_evidence_to_finding() → attach request/response to findings
  3. Evidence grounding check → reject unproven findings
  4. Core-class scan (_phase_has_core_finding) → decide whether active
     retry should fire for this phase
```

### Evidence Record Structure

```python
{
    "tool": "fuzz_parameter",
    "url": "http://target/api/search",
    "payload": "test' OR 1=1--",
    "status": 500,
    "flags": ["ERROR", "VULN_DETECTED"],
    "evidence": "SQLITE_ERROR: near \"OR\": syntax error"
}
```

### Evidence Grounding

When the LLM reports findings, each finding's `payload` and `evidence` fields are checked against the evidence buffer. If a finding has no matching evidence (i.e. the LLM hallucinated it), the finding is rejected and the LLM is prompted to re-analyze with the actual evidence buffer.

---

## Hybrid Smart Retry (Zero-Finding / Missing-Core-Class Recovery)

End-of-phase recovery now takes one of two forms depending on the phase. The
agent does **not** choose between the two dynamically — the branch is decided
by whether the phase belongs to `_ACTIVE_RETRY_PHASES`.

### Branch A — Active retry with tool calls (15 high-impact phases)

For these phases the first pass is often not enough to surface the core
vulnerability class (e.g. the auth phase discovered a password-reset issue but
never actually brute-forced credentials). A second, tool-enabled pass is run
with a phase-tailored retry prompt that tells the LLM exactly what to try,
seeded with the evidence collected so far.

Active-retry phases (defined in `_ACTIVE_RETRY_PHASES`):

```
web_a01              api_authz
web_a07              api_auth
web_a10              web_bfla
web_a03_sqli         api_bfla
web_a03_xss          api_injection
web_a03_cmdi         api_ssrf
web_a03_ssti
web_a03_path_traversal
web_a03_xxe
```

### Branch B — Evidence summary (all other phases)

For the remaining phases, when 0 findings are reported but evidence exists, a
single tool-less LLM call reviews the evidence buffer and may emit findings.
This is cheap (~$0.001–$0.01) and avoids re-running the full loop.

### Smart retry trigger — `_PHASE_CORE_KEYWORDS`

The old retry only fired when a phase produced **zero** findings. That was
insufficient: the auth phase often reports peripheral issues (weak password
policy, password-reset leaks) while still never cracking a single credential,
and the old gate would see "findings > 0" and skip retry.

Each active-retry phase now has a list of **core-class keywords** that describe
the signal we actually care about. After the first pass, the agent scans every
new finding's `title`, `description`, `vulnerability_type`, and `category` for
any of those keywords. The retry fires when:

```
phase in _ACTIVE_RETRY_PHASES
AND (phase_new_findings == 0  OR  no finding matches _PHASE_CORE_KEYWORDS[phase.id])
AND evidence buffer is non-empty
AND retry has not already run for this phase
```

Example keyword sets:

```python
"web_a07":        ("default credential", "weak password", "credential stuffing",
                   "brute force successful", "admin:admin", "login bypass",
                   "authentication bypass", "sql injection authentication", ...)
"web_a01":        ("broken access", "idor", "authorization bypass",
                   "privilege escalation", "forced browsing", ...)
"web_a03_sqli":   ("sql injection", "sqli", "blind sql", "union-based", ...)
"api_ssrf":       ("ssrf", "server-side request forgery", "cloud metadata",
                   "169.254.169.254", ...)
```

### How Branch A works

```
Phase completes
         │
         ▼
Is phase in _ACTIVE_RETRY_PHASES?
         │
         ├── No ──▶ Branch B (evidence summary, only if 0 findings)
         │
         └── Yes
                │
                ▼
    phase_new_findings == 0  OR  core-class missing?
                │
                ├── No (core-class found) ──▶ done
                │
                └── Yes, and evidence buffer non-empty
                        │
                        ▼
         Look up phase-tailored prompt in _RETRY_PROMPTS
         via _PHASE_TO_PROMPT_KEY[phase.id] → one of:
           access_control, auth, sqli, xss, cmdi, ssti,
           path_traversal, xxe, ssrf, injection, bfla
                        │
                        ▼
         Emit phase_start for "<name> (retry)" with id
         "<phase.id>_retry" so the UI shows a retry pass
                        │
                        ▼
         Append retry prompt + evidence excerpt as a user
         message; run a fresh max_steps tool-enabled loop
                        │
                        ▼
         extract_findings() on the final assistant turn;
         findings are merged into the same phase results
```

Retry prompts are opinionated — they name specific endpoints, specific payload
sets (e.g. `admin:admin`, `admin@<host>:admin123`, `admin' --`, `' OR 1=1 --`),
and forbid giving up after 1–2 attempts. See `_RETRY_PROMPTS` in `agent.py`.

### Why hybrid

| | Always-active retry (old) | Evidence summary only | **Hybrid (current)** |
|---|---|---|---|
| **When retry fires** | Any phase with 0 findings | Any phase with 0 findings | 15 high-impact phases, on 0 findings **or** missing core class |
| **Tool access** | Full tools | None | Full tools (Branch A) / none (Branch B) |
| **Cost on low-value phases** | ~2x phase cost | ~$0.001 | ~$0.001 (Branch B) |
| **Recovers missed credentials / IDOR / SQLi?** | Sometimes | No (tool-less analysis can't brute-force) | Yes — tool-enabled second pass with tailored payloads |
| **UI** | Separate "Retry Phase" tile | Invisible | Tile labelled `<name> (retry)`, findings merged into the original phase |

### Minimum Security Calls (`_MIN_SECURITY_CALLS`)

Prevents the LLM from "phoning it in" — declaring a phase done after too few tests:

```python
_MIN_SECURITY_CALLS = {
    "web_a03_sqli": 5,
    "web_a03_xss": 5,
    "web_a03_cmdi": 3,
    "api_injection": 5,
    # ... 22 phases total
}
```

If the LLM stops making tool calls before reaching the minimum, the agent injects a continuation message:

```
"STOP — you have only performed 2 security test calls but this phase
requires at least 5. Continue testing with different parameters,
endpoints, and techniques."
```

This forces the LLM to continue testing rather than prematurely concluding.

---

## Context Management

### The Problem

LLM context windows are limited (typically 200K tokens for Claude). A long scan with many tool calls can easily exceed this.

### Context Trimming (`trim_context`)

Triggered when messages approach the token limit (~40K target after trimming):

```
Pass 1: Truncate large tool results to 1500 chars each
         │
         ▼
Pass 2: Replace older phase conversations with a summary
        Keep: system message + last active phase
         │
         ▼
Pass 3: If still over limit, keep system + summary + last 8 messages
         │
         ▼
Repair: _repair_tool_pairs() ensures every assistant tool_call
        has a matching tool result message
```

### Why This Matters

Without trimming, the LLM would hit context limits mid-scan and crash. With trimming, older phase details are compressed but the LLM retains:
- The system prompt (always preserved)
- A summary of what was tested in prior phases
- Full detail of the current phase
- The evidence buffer (preserved separately)

---

## Finding Extraction (`extract_findings`)

When the LLM stops making tool calls, its text response is parsed for findings:

```
LLM response text
         │
         ▼
┌─────────────────────────────────┐
│  1. Parse JSON in ```json        │
│     code fences                  │
│  2. Parse bare JSON objects      │
│  3. For each object:             │
│     - Has "title" + "severity"?  │
│     - Has "payload"?             │
│     - Has "evidence"?            │
│  4. Reject ungrounded findings   │
│  5. Deduplicate by title+severity│
└─────────────┬───────────────────┘
              │
              ▼
  List of validated findings
```

### Rejection Rules

- Missing `payload` → rejected (unless passive finding)
- Missing `evidence` → rejected
- No matching evidence in buffer → flagged, evidence retry triggered
- Duplicate title+severity → deduplicated

---

## Authentication Internals

### Auth Flow (`auth.py`)

```
1. Navigate to target URL
2. LLM classifies page: form / SSO / OAuth / bearer / API key
3. For form auth:
   a. LLM identifies selectors (username, password, submit)
   b. Fill username → fill password → click submit
   c. Handle multi-step (email first, then password)
   d. Handle TOTP/MFA if configured
4. For SSO/OIDC:
   a. Click SSO provider button
   b. Wait for redirect chain to complete
   c. Handle intermediate login pages
5. Post-auth:
   a. Capture cookies and tokens
   b. Start session monitor (checks every 60s)
   c. Auto-refresh on expiry (re-login)
```

### CAPTCHA Handling

When CAPTCHA is detected during auth:
1. Scanner pauses and takes a screenshot
2. Calls `on_captcha(screenshot, has_captcha)` callback
3. UI shows a modal with the screenshot
4. User can provide: cookies (bypass CAPTCHA) or signal "solved"
5. Scanner resumes with user-provided data

This also works during mid-scan re-authentication if the session expires and CAPTCHA appears on re-login.

### Session Monitoring

`AuthSession.start_monitor()` runs a background task every 60 seconds:
1. Check JWT expiry timestamps
2. Check if session cookies still exist
3. Make a lightweight request to target — if 401/403 or redirect to login, session is expired
4. On expiry: call `_refresh_fn` (which runs `detect_and_login` again, with CAPTCHA support)

---

## Runtime Verification

After all LLM phases complete, payloads from findings are replayed against the live target:

1. For each finding with a `payload` and `url`:
   - Replay the exact request (GET/POST with the payload)
   - Check if the vulnerability indicator is still present in the response
2. Mark each finding: `CONFIRMED` (still exploitable) or `DISPROVED` (no longer reproduces)
3. This provides a second layer of evidence beyond the LLM's initial test

### Chain Verification

Exploit chain findings (produced by `chain_exploit`) receive specialized verification:

1. Each step in the chain is replayed sequentially against the live target
2. Step outputs (cookies, tokens, IDs) are carried forward to subsequent steps
3. The chain is marked `CONFIRMED` only if all steps succeed end-to-end
4. Partial success is recorded with per-step evidence for manual review

---

## Cost Tracking

Every LLM call is tracked by `LLMRouter`:

| Metric | Source |
|--------|--------|
| Input tokens | Model response metadata |
| Output tokens | Model response metadata |
| Cost (USD) | Per-model pricing table in `llm_config.py` |
| Total per scan | Accumulated across all phases |

Costs are displayed in real-time in the UI and stored with scan results.

---

## File Map

| File | Role | Key Classes/Functions |
|------|------|----------------------|
| `scanners/ai_agent/agent.py` | Scan orchestrator | `run_scan()`, `extract_findings()`, `trim_context()`, `_capture_evidence()` |
| `scanners/ai_agent/tools.py` | Tool layer | `ScanTools`, `TOOL_DEFINITIONS`, `execute()` |
| `scanners/ai_agent/prompts.py` | LLM instructions | `SYSTEM_PROMPT`, `WEB_PHASES`, `API_PHASES`, `get_phases()` |
| `scanners/ai_agent/auth.py` | Authentication | `detect_and_login()`, `AuthSession`, `_detect_captcha()` |
| `scanners/ai_agent/llm_config.py` | LLM routing | `LLMRouter`, `ModelUsage`, cost tracking |
| `scanners/ai_agent/passive_recon.py` | Passive checks | 24 deterministic security checks |
| `scanners/ai_agent/api_import.py` | API parsers | Postman, OpenAPI, Burp → `EndpointRegistry` |
| `scanners/ai_agent/baseline_executor.py` | API baseline | Happy-path execution, variable chaining |
| `scanners/ai_agent/body_fuzzer.py` | Body fuzzing | LLM-planned, engine-executed fuzzing |
| `scripts/triage_engine.py` | Triage | 3-layer TP/FP classification |
| `scripts/report_generator.py` | PDF reports | Evidence, curl commands, remediation |
| `scripts/excel_exporter.py` | Excel export | Multi-sheet workbook |
| `web/app.py` | API + UI backend | FastAPI routes, scan lifecycle |
| `web/db.py` | Persistence | SQLite for scan metadata |
| `web/static/index.html` | Frontend | Single-page app (vanilla JS) |
