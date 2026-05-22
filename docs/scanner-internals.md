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
│     29 deterministic checks (no LLM)                    │
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
│          prompt) for 20 active-retry phases when the    │
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

`ScanTools` wraps Playwright's `Page` and `httpx.AsyncClient` into 31 security-testing tools that the LLM can call.

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

### Branch A — Active retry with tool calls (20 high-impact phases)

For these phases the first pass is often not enough to surface the core
vulnerability class (e.g. the auth phase discovered a password-reset issue but
never actually brute-forced credentials; the file-upload phase confirmed an
upload but never proved execution). A second, tool-enabled pass is run with a
phase-tailored retry prompt that tells the LLM exactly what to try, seeded
with the evidence collected so far.

Active-retry phases (defined in `_ACTIVE_RETRY_PHASES`):

```
Access Control / Authorization       Injection (A03)
  web_a01                              web_a03_sqli
  api_authz                            web_a03_xss
  web_bfla                             web_a03_cmdi
  api_bfla                             web_a03_ssti
                                       web_a03_path_traversal
Authentication                         web_a03_xxe
  web_a07                              api_injection
  api_auth
                                     SSRF
High-impact misc                       web_a10
  web_file_upload                      api_ssrf
  web_password_reset
  web_session_mgmt                   API-only
  api_mass_assign
  api_data_exposure
```

Tailored retry prompts live in `_RETRY_PROMPTS` under these keys:
`access_control`, `auth`, `sqli`, `xss`, `injection`, `ssrf`, `file_upload`,
`password_reset`, `session_mgmt`, `mass_assign`, `data_exposure`.

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
and forbid giving up after 1–2 attempts. See `_RETRY_PROMPTS` in
`scanners/ai_agent/retry_prompts.py` (the constants module) and
`_run_smart_retry_pass` in `agent.py` (the execution helper).

### Parallel-mode coverage (regression fix, 29-Apr-2026)

The smart retry originally lived **inline inside the sequential `run_scan`
loop**. When parallel mode was added on 22-Apr-2026 (commit `ce2cf83 feat(parallel): multi-agent parallel scan`), the new `_run_phase_worker`
function copied the core scan loop but **omitted the retry block** —
keeping only a passive evidence-summary call (`tools=[]`).

Symptom in production: 28-Apr-2026, three Sonnet 4.5 scans against the same
in-house target produced **110 / 74 / 56 findings** on the same code. The
56-finding scan had **15 phases each running 70–85 tool calls and producing
zero findings** — exactly the case smart retry was designed to recover, but
it never fired in the (default) parallel mode.

**Fix.** The constants and decision helpers were lifted to a new module
`scanners/ai_agent/retry_prompts.py`, and a module-level async helper
`_run_smart_retry_pass` was added to `agent.py`. The parallel worker
(`_run_phase_worker`) now calls `should_run_smart_retry` followed by
`_run_smart_retry_pass` whenever the trigger condition is met, before
falling through to the cheap evidence-summary branch:

```
_run_phase_worker
   ├── main scan loop (unchanged)
   ├── should_run_smart_retry(phase, ...) ──▶ True?
   │       └── _run_smart_retry_pass(...) ── tool-enabled retry with tailored prompt
   └── evidence-summary fallback (no tools) for non-retry-list phases
```

Regression-tested in `tests/test_smart_retry_in_worker.py`:

- `TestParallelWorkerInvokesSmartRetry::test_worker_calls_smart_retry_for_eligible_phase`
  — pins that the worker actually calls `_run_smart_retry_pass` on
  zero-finding phases that are in `_ACTIVE_RETRY_PHASES`. **This is the exact
  regression introduced by `ce2cf83`** and is the canary against future
  parallel-path drift.
- `test_worker_does_NOT_call_retry_for_non_eligible_phase` — recon phases
  must not retry.
- `test_retry_failure_does_not_crash_phase` — if the retry helper itself
  raises, the phase still completes with whatever findings it had.

### Why hybrid

| | Always-active retry (old) | Evidence summary only | **Hybrid (current)** |
|---|---|---|---|
| **When retry fires** | Any phase with 0 findings | Any phase with 0 findings | 20 high-impact phases, on 0 findings **or** missing core class |
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

## Parallel-Phase Failure Surfacing (`run_phases_parallel`)

Phases marked `parallel_ok=True` (most OWASP / API phases) are fanned out concurrently with `asyncio.Semaphore`-bounded `asyncio.gather`. The original implementation used `gather(..., return_exceptions=True)` and ignored the returned exceptions — so a worker that raised any exception (Bedrock 5xx, Playwright timeout, LLM context-window overflow, transient network reset) became an exception object in the result list that was never logged, never surfaced to the UI, and never written into `phase_log`.  Symptom in production: r2 of a Sonnet 4.5 scan completed with **6 phases missing** from `phase_log` vs r1 — the failure was silent end-to-end.

Each worker is now wrapped in a guard that:

1. Catches every non-`ScanCancelled` exception.
2. Emits a synthetic `phase_log` entry with the phase id/name, an `error` field carrying the truncated exception message, and zero findings.
3. Adds a `(FAILED)` suffix to the live `on_progress` callback so the UI shows the failed phase explicitly instead of skipping it.
4. Re-raises `ScanCancelled` so user-stop propagates out of `gather` immediately.

```python
async def _guarded(idx: int, phase: ScanPhase):
    async with sem:
        try:
            f, m = await _run_phase_worker(...)
        except ScanCancelled:
            raise                         # propagate user stop
        except Exception as exc:           # surface, do not silently drop
            err = repr(exc)[:300]
            log_entry = {
                "phase": phase.id, "name": phase.name,
                "tool_calls": 0, "findings_count": 0, "error": err,
            }
            on_progress("phase_end", {**log_entry, "name": f"{phase.name} (FAILED)"})
            return [], log_entry
        return f, m
```

**Invariant (regression-tested in `tests/test_parallel_phase_resilience.py` and `tests/test_scan_error_resilience.py`):** `len(phase_log) == len(phases)` regardless of how many workers raise. The on-disk record always describes every phase, error or not.

`_run_phase_worker`'s own `finally` block continues to close `worker_http` and the browser context, so resource cleanup happens even when the worker raises before reaching its return statement.

---

## LLM Router Retry Contract (`LLMRouter.complete`)

Originally the router only retried `RateLimitError`. Any other transient signature — `ConnectError`, 502/503/504, `ReadTimeout`, throttling — was terminal on first occurrence. In practice this shows up as 1–6 silently-failed phases per scan whenever Bedrock has a ~30 s blip.

The retry loop now treats all of the following as transient and retries with exponential back-off `2 → 4 → 8 → 16 → 32 s` by default — **5 retries / ~62 s total back-off**, sized to absorb the regional capacity blips observed on Bedrock cross-region inference profiles (typically clear within 30–60 s):

| Signature | Source |
|-----------|--------|
| `RateLimitError` | LiteLLM / Anthropic / OpenAI (existing) |
| `ConnectError`, `All connection attempts failed` | network |
| HTTP 502 / 503 / 504 | LiteLLM raises with status code in message |
| `ReadTimeout`, `TimeoutError`, "timeout" | network / LiteLLM |
| Provider throttling messages | various |

**Terminal — never retried** (would just burn ≥1× cost on a deterministic failure):

- `ContextWindowExceeded` — message is too long; bubble so the agent can trim and retry with smaller context
- `ContentFiltered` — guardrail tripped; bubble so the agent can drop the offending message
- `MalformedMessages` — orphaned tool_call / tool_result pair; bubble so the agent can repair the message array
- `ScanCancelled` — user stopped

`cancel_flag` is checked between attempts so a user-stop during the back-off is honoured immediately rather than after the next sleep finishes. Tests live in `tests/test_parallel_phase_resilience.py` and `tests/test_scan_error_resilience.py` (Section F).

### Tunable retry budget — `LLM_RETRY_DELAYS`

The default `(2, 4, 8, 16, 32)` lives in `_DEFAULT_RETRY_DELAYS` in `llm_config.py` and is overridable at runtime via the **`LLM_RETRY_DELAYS`** environment variable (comma-separated integers). Total attempts = `len(LLM_RETRY_DELAYS) + 1` (initial call).

| Use case | `LLM_RETRY_DELAYS` | Attempts | Total back-off |
|----------|--------------------|----------|----------------|
| Default — production | `2,4,8,16,32` (unset) | 6 | 62 s |
| Aggressive — shaky region | `2,4,8,16,32,60,120` | 8 | 242 s |
| Fast-fail dev loop | `0,0` | 3 | 0 s |
| Original behaviour (pre-Apr 2026) | `2,4,8` | 4 | 14 s |

A garbage value (non-integer, negative, or whitespace-only) falls back to the default and emits a `WARNING` log line — never disables retries. Validated in `tests/test_parallel_phase_resilience.py::TestRouterRetryDelaysAreConfigurable`.

### boto3 / botocore retry layer (below LiteLLM)

`LLMRouter.complete` is the **upper** retry layer. The **lower** layer is boto3's own retry config inside LiteLLM, controlled via env vars (no code change needed):

```bash
AWS_RETRY_MODE=adaptive    # token-bucket + jittered exponential back-off
AWS_MAX_ATTEMPTS=10        # was 3 (legacy default)
```

The two layers stack: a 503 first goes through ~7 transparent boto3 retries (jittered, capped per attempt) before our app-level retry layer ever sees it. In practice ~95 % of regional Bedrock blips never bubble up to `LLMRouter.complete`.

Both env vars are documented in `.env.example` and applied automatically by every Bedrock SDK client LiteLLM constructs.

---

## Persistence / Crash Resilience

Scans accumulate live state in memory — counters (cost, tokens, LLM calls, tool calls), the phase log, the crawl list, the out-of-scope list, per-phase tool usage, and the rolling request/response log. Without care, a Python-level error, user `stop`, process kill, or container restart would lose all of this.

**Model: snapshot-on-every-save.** `_snapshot_live_metrics` (in `web/app.py`) promotes each transient `live_*` field into a persisted counterpart before `_clean_scan_for_db` strips the `live_*` keys. Numeric counters use `max()` so a clean finalization (which writes permanent fields directly) never regresses from a stale live value. Runs on every `_save_scan` — there is no status-specific branch, so errored / stopped / paused / crashed scans all benefit equally.

| Live field | → Persisted field | Bound |
|------------|-------------------|-------|
| `live_cost` | `cost` column | — |
| `live_tokens` | `total_tokens` | — |
| `live_llm_calls` | `llm_calls` | — |
| `live_tool_calls` | `total_tool_calls` | — |
| `len(live_findings)` | `findings_count` column | — |
| `len(live_phases)` | `phases_completed` | — |
| `live_phases` | `phases` | full list |
| `live_phase_tools` | `phase_tools` | full dict |
| `live_crawled` | `crawled_urls` | **last 500** |
| `live_out_of_scope` | `out_of_scope_urls` | full list |
| `live_tests` | **not persisted** in `scans.data` | flushed to `scan_results.payload.summary.test_log` only on graceful exit (≤ 20 MB blob would bloat the `scans` table) |

**Save cadence:**

- Every 10 tool calls (hot path)
- Every 5 new findings (intra-phase checkpoint)
- On every `phase_end`
- On every 30 s autosave tick
- On `pause`, `resume`, `auth_challenge`, `progress_msg`, `scan_start`

**Findings checkpoint.** `_persist_partial_findings` writes the current `live_findings` list to the `scan_results` table. In addition to `phase_end`, it runs every 5 new findings and on the 30 s autosave tick so a mid-phase crash loses at most 4 findings.

**Drift budget on hard-kill (OOM / SIGKILL / container restart — no graceful handler):**

| Field | Drift |
|-------|-------|
| `cost`, `total_tokens` | ≤ 30 s or ≤ 10 tool calls of activity |
| `findings_count` | ≤ 4 findings |
| `phases_completed` | 0 or 1 |

Graceful error, user-stop, pause, and completion paths have zero drift.

### Partial-checkpoint fallback (`_load_raw_result_dict`)

`_persist_partial_findings` deliberately writes a **partial** `scan_results.payload` blob (`metadata.partial = True`) every 5 new findings so the UI can show in-progress findings after a crash. When the scan finishes cleanly it writes the full result file to disk (`results/raw/<scan_id>.json`) but the partial DB row from the last checkpoint can shadow it if the read path naively prefers DB > disk.

`_load_raw_result_dict` (in `web/app.py`) now resolves the conflict in this order:

1. Read the DB record. If `metadata.partial` is **not** set (full final write), use it.
2. Otherwise, look for `results/raw/<scan_id>.json`. If present, load it, **back-fill** the DB with the full payload (so subsequent loads serve from DB), and return the disk version.
3. Otherwise, return the partial DB record (best-effort live view of an in-progress / crashed scan).

This eliminates a class of "scan finished with N findings but UI shows M < N" bugs that were caused by partial-checkpoint shadowing.

### Results-API resilience (`/api/results/{scan_id}`)

The frontend's "Results could not be loaded" error was driven by an `AttributeError: 'str' object has no attribute 'get'` thrown deep inside `_extract_crawled` / `_extract_payloads_by_endpoint` / `_build_test_log_index` whenever `summary.test_log` contained a non-dict entry (a string, `None`, a scalar, a list, or a dict whose `request` field wasn't itself a dict). Older scans had any combination of these.

All three readers now guard with `isinstance(t, dict)` (and analogous checks on nested fields) and silently skip malformed rows, so the API endpoint never returns 500 just because of one corrupted log line. Regression coverage is in `tests/test_results_endpoint_resilience.py` and Section D of `tests/test_scan_error_resilience.py`.

---

## File Map

| File | Role | Key Classes/Functions |
|------|------|----------------------|
| `scanners/ai_agent/agent.py` | Scan orchestrator | `run_scan()`, `extract_findings()`, `trim_context()`, `_capture_evidence()`, `_run_smart_retry_pass()`, post-auth SPA re-crawl, crawl coverage metric, parallel worker dedup via `shared_tested` |
| `scanners/ai_agent/retry_prompts.py` | Hybrid Smart Retry constants | `_ACTIVE_RETRY_PHASES`, `_RETRY_PROMPTS`, `_PHASE_CORE_KEYWORDS`, `_PHASE_TO_PROMPT_KEY`; `should_run_smart_retry()`, `phase_has_core_finding()` |
| `scanners/ai_agent/tools.py` | Tool layer | `ScanTools`, `TOOL_DEFINITIONS`, `execute()`, `_detect_waf_block()`, `set_shared_tested()` |
| `scanners/ai_agent/prompts.py` | LLM instructions | `SYSTEM_PROMPT`, `WEB_PHASES`, `API_PHASES`, `get_phases()` |
| `scanners/ai_agent/auth.py` | Authentication | `detect_and_login()`, `AuthSession`, `_detect_captcha()` |
| `scanners/ai_agent/llm_config.py` | LLM routing | `LLMRouter`, `ModelUsage`, cost tracking |
| `scanners/ai_agent/passive_recon.py` | Passive checks | 29+ deterministic checks; hybrid JS-library detection; WAF/CDN fingerprinting (15+ products); source map deep scan (secrets + API endpoints) |
| `scanners/ai_agent/js_registry.py` | Global JS URL registry | `JSUrlRegistry` — collects every JS URL the scanner encounters across auth, SPA, and the network listener; in-scope filtering happens here. Used by passive recon's CVE audit so library detection isn't scoped to the seed page only |
| `scanners/ai_agent/llm_detect.py` | LLM app detection | DOM/network heuristics to identify chatbot/AI features (confidence scoring) |
| `scanners/ai_agent/llm_baseline.py` | LLM security probes | 37 deterministic probes: prompt injection, info disclosure, output handling, excessive agency, prompt leakage, DoS ($0 LLM cost) |
| `scanners/ai_agent/garak_runner.py` | Garak orchestration | NVIDIA Garak integration: config generation, subprocess execution, JSONL result parsing, browser bridge coordination |
| `scanners/ai_agent/browser_llm_bridge.py` | LLM chatbot bridge | Playwright browser interaction for authenticated chatbot testing, stability-based DOM response capture, HTTP bridge server for Garak, preflight validation, loading indicator filtering |
| `scanners/ai_agent/api_import.py` | API parsers | Postman, OpenAPI, Burp → `EndpointRegistry` |
| `scanners/ai_agent/baseline_executor.py` | API baseline | Happy-path execution, variable chaining |
| `scanners/ai_agent/body_fuzzer.py` | Body fuzzing | LLM-planned, engine-executed fuzzing |
| `scripts/triage_engine.py` | Triage | 3-layer TP/FP classification |
| `scripts/report_generator.py` | PDF reports | Evidence, curl commands, remediation |
| `scripts/excel_exporter.py` | Excel export | Multi-sheet workbook |
| `web/app.py` | API + UI backend | FastAPI routes, scan lifecycle |
| `web/db.py` | Persistence | SQLite for scan metadata |
| `web/static/index.html` | Frontend | Single-page app (vanilla JS) |
