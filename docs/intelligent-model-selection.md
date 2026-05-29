# Intelligent model selection & budget gate

[← Documentation index](README.md) · [Web UI](web-ui.md) · [Engineering internals](scanner-internals.md) · [HTTP API](api.md) · [MCP](mcp.md)

## Why Auto mode?

Manual mode runs every scan phase on one Bedrock model you pick in the UI. That is simple and predictable, but wasteful on cheap phases (recon, crawl) and sometimes under-powered on hard phases (broken access control, business logic, attack chains). **Auto mode** keeps manual mode unchanged for operators who want it, and adds an optional policy: the scanner assigns **Haiku** (cheap), **Sonnet** (balanced), or **Opus** (premium) per phase based on phase id and hints. An optional **budget cap** pauses the scan when LLM spend hits the limit so you can approve more budget or stop — only the user who launched the scan (or an admin) can approve.

## How the scanner picks a model

Implementation: `scanners/ai_agent/auto_router.py` (`ModelSelector`, `tier_for_phase`).

| Tier | Typical model | Phase IDs (explicit sets) |
|------|---------------|---------------------------|
| **CHEAP** | Haiku | `web_recon`, `api_recon`, `crawl_only`, `passive_recon`, `subdomain_enum`, `dns_enum`, `js_registry` |
| **BALANCED** | Sonnet | `web_a02`, `web_a03_sqli`, `web_a03_xss`, `web_a03_cmdi`, `web_a03_ssti`, `web_a03_path_traversal`, `web_a03_xxe`, `web_a04`–`web_a10`, `web_websocket`, `web_extras`, `web_host_header`, `web_timing_enum`, `web_file_upload`, `api_auth`, `api_injection`, `api_mass_assign`, `api_rate_limit`, `api_ssrf`, `api_graphql`, `api_data_exposure`, `api_content_type`, `api_method_override` |
| **PREMIUM** | Opus (or strongest Sonnet) | `web_a01`, `web_bfla`, `web_session_mgmt`, `web_password_reset`, `api_authz`, `api_bfla`, `api_business_logic`, `web_race_condition`, `api_race_condition`, `web_business_logic`, `attack_chain_analysis`, `chain_credential_theft`, `chain_data_exfil`, `chain_rce`, `chain_access_escalation`, `web_llm_security` |

**Substring overrides** (phase id contains): `idor`, `authz`, `business_logic`, `business-logic`, `multi_tenant`, `multi-tenant`, `bfla`, `session_mgmt`, `access_control`. Phase ids starting with `chain_` are premium. Recon/crawl/dns-style ids default to cheap; everything else defaults to balanced.

**Retry promotion:** `hint={"retry": True}` (or `tier: premium`) forces **PREMIUM** for that call — used when a Sonnet phase fails and the agent retries a hard target.

---

## Worked examples

### 1. Simple recon scan of a marketing site

- **Profile:** `crawl_only` or light website recon, `model_policy: auto`
- **Routing:** Recon/crawl phases → Haiku only
- **Expected cost:** ~**$0.15** (estimate via `POST /api/scans/estimate`)
- **Budget:** Unlikely to hit a cap; optional `budget_cap_usd: 1.0` is plenty

### 2. OWASP Top 10 scan of a SaaS app with login

- **Settings:** `scan_mode: both`, `scan_intensity: deep`, `model_policy: auto`, login credentials
- **Routing:** Haiku for `web_recon` / crawl; Sonnet for XSS, SQLi, SSRF, etc.; Opus for `web_a01` (broken access control) and `web_session_mgmt`
- **Expected cost:** ~**$1.50**; **recommended budget ~$3**
- **Launch:**

```json
{
  "target_url": "https://app.example.com",
  "scan_mode": "both",
  "model_policy": "auto",
  "budget_cap_usd": 3.0,
  "username": "test@example.com",
  "password": "***"
}
```

### 3. Multi-tenant API with BOLA / business-logic risk

- **Settings:** `scan_mode: api`, deep intensity, Postman import, `model_policy: auto`
- **Routing:** Bulk phases on Sonnet; **Opus** for `api_authz`, `api_bfla`, `api_business_logic`, `attack_chain_analysis`
- **Expected cost:** ~**$4**; **recommended budget ~$8**

### 4. Re-run after a Sonnet phase fails on a hard target

When the agent retries a phase, it passes `hint={"retry": True}` into `ModelSelector.select()`. That phase is promoted to **PREMIUM** (Opus) even if the phase id is normally balanced. Check **Models used by phase** in the live scan header to audit the promotion.

---

## The approval gate

<!-- SCREENSHOT: Yellow budget approval banner on live scan view -->

1. **`budget_status: ok`** — scan runs; `BudgetGuard` accumulates spend from `LLMRouter` cost callbacks.
2. **Cap reached** — `budget_status` → `awaiting_approval`, scan **pauses** (same pause mechanism as manual Pause), progress log notes the cap.
3. **Owner action** — only the **scan-triggering SSO user** or a platform **admin** can:
   - **Increase budget** — UI: enter new cap → “Increase budget and resume”, or `POST /api/scans/{id}/budget/approve` with `{ "new_cap_usd": 10.0 }`
   - **Stop** — “Stop scan” or `POST /api/scans/{id}/budget/stop`
4. **`budget_status: approved`** — pause cleared, scan resumes until the new cap.

Server-side enforcement uses `owner_user_id` from the SSO session at launch (`_user_can_manage_scan_budget`). Automation via Basic Auth must use credentials that map to the owner or admin role.

---

## API quickstart

**Estimate:**

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/scans/estimate" \
  -d '{"scan_mode":"both","scan_intensity":"deep","llm_scan_depth":"standard","model_policy":"auto"}'
```

**Launch (auto + budget):**

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/v1/scans" \
  -d '{
    "target_url": "https://staging.example.com",
    "scan_mode": "both",
    "model_policy": "auto",
    "budget_cap_usd": 5.0
  }'
```

**Approve after pause:**

```bash
curl -s -u "${SCANNER_USER}:${SCANNER_PASS}" \
  -H "Content-Type: application/json" \
  -X POST "${SCANNER_URL}/api/scans/SCAN_ID/budget/approve" \
  -d '{"new_cap_usd": 10.0}'
```

Full schemas: [api.md](api.md) and Swagger at `/docs`.

---

## MCP quickstart (Cursor / Claude Desktop)

Configure `.cursor/mcp.json` per [mcp.md](mcp.md), then in chat:

> Start an auto-mode scan of https://staging.example.com with a $5 budget.

Typical tool sequence:

1. `estimate_scan_cost(model_policy="auto", scan_mode="both")` → read `recommended_budget_usd`
2. `start_scan(target_url="https://staging.example.com", model_policy="auto", budget_cap_usd=5.0)`
3. Poll `get_scan_status` or `get_scan_budget` — if `status` is `awaiting_approval`:
4. `approve_scan_budget(scan_id, new_cap_usd=10.0)` (caller must be owner/admin)

---

## OpenClaw quickstart

User prompt:

> Scan staging.example.com in auto mode with a $3 budget.

Agent should `POST /api/scan` (or `/api/v1/scans`) with `model_policy: "auto"` and `budget_cap_usd: 3.0`. See [openclaw-skill/SKILL.md](../openclaw-skill/SKILL.md) and CLI:

```powershell
python openclaw-skill/test_skill.py scan --url https://staging.example.com --model-policy auto --budget-cap 3
```

---

## Cost transparency

- **Per-scan cost** — shown in the UI header and `GET /api/scan/{id}` (`cost`, `budget_total_usd`).
- **Per-phase audit** — when `model_policy` is `auto`, `model_choices` maps phase id → model id; each `phase_log` entry includes the model used.
- **Platform analytics** — the per-model cost analytics tab aggregates spend across scans (unchanged); use `model_choices` to reconcile auto-mode phase mix vs bill.

---

## See also

| Topic | Doc |
|-------|-----|
| UI toggle, cap field, banner | [web-ui.md](web-ui.md) |
| Extend tier lists, `hint`, BudgetGuard | [scanner-internals.md](scanner-internals.md) |
| REST endpoints | [api.md](api.md) |
| MCP tools | [mcp.md](mcp.md) |
