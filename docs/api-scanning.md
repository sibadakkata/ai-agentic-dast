# API Scanning

[← Back to README](../README.md)

Step-by-step walkthrough of how the scanner tests APIs, using a realistic banking API as an example.

## Example: Banking API

Suppose you have a Postman collection with these endpoints:

```
POST /api/auth/login          {"email": "user@bank.com", "password": "secret"}
GET  /api/accounts/me
POST /api/transfer            {"fromAccount": "ACC-001", "toAccount": "ACC-002", "amount": 500, "currency": "USD", "note": "rent"}
GET  /api/transactions?accountId=ACC-001&limit=50
PUT  /api/profile             {"name": "John", "email": "john@bank.com", "phone": "+1234567890"}
```

## Step 1: Baseline Execution (Happy Path)

The engine runs every endpoint in order with the original data. This is **deterministic** (no LLM).

```
POST /api/auth/login → 200 {"token": "eyJhbGci...", "userId": "USR-42"}
  ↳ Auto-chains: Bearer token captured for subsequent requests
  ↳ Auto-chains: userId=USR-42 stored for variable substitution

GET /api/accounts/me → 200 {"id": "ACC-001", "balance": 5000, "name": "John Doe"}
  ↳ Auto-chains: accountId=ACC-001

POST /api/transfer → 200 {"transactionId": "TXN-99", "status": "completed"}
  ↳ Auto-chains: transactionId=TXN-99

GET /api/transactions?accountId=ACC-001 → 200 [{"id": "TXN-99", ...}]

PUT /api/profile → 200 {"name": "John", "email": "john@bank.com"}
```

**Result**: A "known good" baseline — the exact response codes, body sizes, and JSON structures we expect when everything is normal.

## Step 2: Field Classification

For every POST/PUT/PATCH endpoint, the engine extracts and classifies JSON body fields:

```
POST /api/transfer:
  fromAccount → auth_id (P1)     — account identifier, high IDOR risk
  toAccount   → auth_id (P1)     — account identifier, high IDOR risk
  amount      → financial (P1)   — monetary value, business logic risk
  currency    → enum (P2)        — constrained set, type confusion risk
  note        → freetext (P3)    — user input, XSS/injection risk

PUT /api/profile:
  name        → pii (P2)         — personal data
  email       → contact (P1)     — high-value, account takeover risk
  phone       → contact (P1)     — high-value
```

P1 = highest priority (tested first), P3 = lowest.

## Step 3: LLM Payload Planning (~$0.001 per endpoint)

One LLM call per endpoint. The LLM sees the fields, their types, and the API context:

```json
[
  {"field": "fromAccount", "payloads": ["ACC-002", "ACC-999", "' OR 1=1--", "0"]},
  {"field": "toAccount", "payloads": ["ACC-001", "{{fromAccount}}", "null"]},
  {"field": "amount", "payloads": [-1, 0, 0.001, 999999999, "abc"]},
  {"field": "currency", "payloads": ["", "XXX", "USD'; DROP TABLE--", null]},
  {"field": "note", "payloads": ["<script>alert(1)</script>", "A".repeat(10000)]}
]
```

The LLM understands that `fromAccount` + `toAccount` is a transfer pair (IDOR risk), that `amount` needs boundary testing, and that `currency` is an enum.

## Step 4: Deterministic Execution (Zero LLM Cost)

The engine runs every payload — mutating one field at a time while keeping the rest valid:

```
# Field fuzzing (LLM-planned payloads)
POST /api/transfer {"fromAccount":"ACC-002",...}  → 200 ✗ ANOMALY
POST /api/transfer {"amount":-1,...}              → 200 ✗ ANOMALY
POST /api/transfer {"amount":0,...}               → 200 ✗ ANOMALY

# JSON Schema Probes (auto-generated)
POST /api/transfer {+ "is_admin": true}           → 200 ✗ ANOMALY (extra fields accepted)
POST /api/transfer {"amount": "not_a_number"}     → 200 ✗ ANOMALY (wrong type accepted)
POST /api/transfer {missing "fromAccount"}        → 400 ✓ OK (validation works)

# JSON Injection Probes (auto-generated)
POST /api/transfer {"amount": 500, "amount": -1}  → 200 ✗ ANOMALY (duplicate key)
POST /api/transfer {"__proto__": {"isAdmin": true}} → 200 ✗ ANOMALY
POST /api/transfer {"fromAccount": {"$ne": ""}}    → 200 ✗ ANOMALY (NoSQL operator)
```

### Anomaly Detection

Each response is compared to the baseline:

| Check | What It Detects |
|-------|-----------------|
| **Status change** | Got 200 but expected 400 |
| **Value echo** | Server included `is_admin: true` in response |
| **Response key diff** | Response JSON grew new keys not in baseline |
| **Error strings** | 500 response contains stack traces, SQL errors |
| **Timing** | Request took 5x longer (time-based injection) |
| **Reflection** | Payload echoed back in response body |

## Step 5: LLM Anomaly Analysis (~$0.002 per endpoint)

All anomalous responses (not every response — only deviations) are batched into one LLM call:

```json
[
  {
    "title": "IDOR: Transfer from another user's account",
    "severity": "High",
    "evidence": "Changing fromAccount to ACC-002 returned 200 — transferred without authorization check"
  },
  {
    "title": "Negative transfer amount accepted",
    "severity": "High",
    "evidence": "amount=-1 returned 200 — negative transfer processed, reverses money flow"
  },
  {
    "title": "Mass assignment: extra fields accepted",
    "severity": "Medium",
    "evidence": "is_admin:true accepted (200 OK). If persisted, attacker could escalate privileges"
  }
]
```

**Total cost for this endpoint**: ~$0.003 (plan + analysis).

## Step 6: LLM Deep Scan (10 API Phases)

The LLM agent runs its full OWASP scan, **enriched** with baseline + fuzzing results:

| # | Phase | What the Agent Does |
|---|-------|---------------------|
| 1 | **Endpoint Discovery** | Probes for undocumented endpoints using path patterns and common admin/debug paths |
| 2 | **Authentication Testing** | Removes auth headers, tests JWT manipulation (alg:none, claim tampering) |
| 3 | **Authorization / BOLA** | IDOR payloads on every object ID — horizontal and vertical escalation |
| 4 | **Injection Testing** | SQLi, NoSQLi, LDAP injection, XSS in JSON, XXE in XML endpoints |
| 5 | **Mass Assignment** | Extra fields in POST/PUT, reads resource back to check persistence |
| 6 | **Rate Limiting** | Rapid-fire requests to login/transaction endpoints, checks for 429 |
| 7 | **SSRF** | URL-accepting parameters probed for metadata endpoints and internal services |
| 8 | **GraphQL** | Introspection, query batching, deep nesting (DoS), alias brute-force |
| 9 | **Excessive Data Exposure** | Compares API response fields to what the UI renders — flags hidden PII/debug data |
| 10 | **Business Logic** | Flow bypass, negative amounts, race conditions, idempotency violations |
| 11 | **Race Conditions** | Concurrent identical requests on state-changing endpoints, idempotency key enforcement |
| 12 | **Function-Level Auth** | Access admin/management endpoints with normal user token, method switching |
| 13 | **Host Header Injection** | X-Forwarded-Host reflection, X-Forwarded-For IP bypass, path override headers |
| 14 | **Content-Type Confusion** | Send JSON as XML, form-data as JSON, remove Content-Type — parser differential attacks |
| 15 | **HTTP Method Override** | X-HTTP-Method-Override, X-Method-Override, _method param — bypass method-based ACL |

## Step 7: Runtime Verification

After the LLM reports findings, exact payloads are replayed against the live target:

```
Finding: "SQL Injection in /api/search"
  Replay: POST /api/search {"q": "' OR 1=1--"}
  Response: 200 {"results": [...50 items...]}
  Baseline: 200 {"results": [...3 items...]}
  Verdict: CONFIRMED — response dramatically different

Finding: "XSS in /api/profile name field"
  Replay: PUT /api/profile {"name": "<script>alert(1)</script>"}
  Response: 200 {"name": "&lt;script&gt;..."}
  Verdict: DISPROVED — output is HTML-encoded
```

## Step 8: Triage Engine

Every finding goes through the [Triage Engine](triage-engine.md) for final classification. See that document for details on the 3-layer verdict system.

## Supported Import Formats

| Format | Versions | Notes |
|--------|----------|-------|
| **Postman Collection** | v2.0, v2.1 | Full support including variables, pre-request scripts |
| **Postman Environment** | Any | Variable substitution |
| **OpenAPI / Swagger** | 2.0, 3.0, 3.1 | JSON and YAML |
