# Contributing & Extending the Scanner

[← Back to README](../README.md)

How to add new vulnerability checks, tools, and phases. How to optimize scanner detection. Written so any team member can extend the scanner confidently.

---

## Quick Reference: Common Tasks

| I want to... | Edit this file | Section |
|--------------|----------------|---------|
| Add a new vulnerability phase | `prompts.py` | [Adding a New Phase](#adding-a-new-scan-phase) |
| Add a new tool for the LLM | `tools.py` | [Adding a New Tool](#adding-a-new-tool) |
| Improve detection for an existing vuln | `prompts.py` | [Optimizing a Phase Prompt](#optimizing-a-phase-prompt) |
| Add a new passive check | `passive_recon.py` | [Adding a Passive Check](#adding-a-passive-check) |
| Add a new focus area keyword | `prompts.py` | [Adding a Focus Area](#adding-a-focus-area-keyword) |
| Make a phase retry on 0 findings | `agent.py` | [Enabling Retry](#enabling-retry-for-a-phase) |
| Set minimum test calls for a phase | `agent.py` | [Setting Minimum Calls](#setting-minimum-security-calls) |
| Add a new report type | `report_generator.py` | [Adding a Report Type](#adding-a-report-type) |
| Add a new compliance framework | `web/app.py` | [Adding Compliance](#adding-a-compliance-framework) |

---

## Adding a New Scan Phase

### Step 1: Define the Phase in `prompts.py`

Add a new `ScanPhase` to `WEB_PHASES` or `API_PHASES`:

```python
# In WEB_PHASES list (or API_PHASES for API-specific phases)
ScanPhase(
    id="web_a03_nosqli",
    name="NoSQL Injection",
    prompt="""...""",
    max_steps=50,
    applies_to="website",   # or "api" or "both"
),
```

### Step 2: Write the Phase Prompt

Follow this template:

```
## NoSQL Injection Testing

**Objective**: Test all input points for NoSQL injection vulnerabilities.

### Step 1 — Identify Targets
Use `get_forms`, `get_links`, `get_api_endpoints` to find inputs.
Look for search, filter, login, and data query endpoints.

### Step 2 — Test Payloads
For each identified input, use `fuzz_parameter` or `api_request`:

**MongoDB operator injection:**
- `{"$gt":""}` — always-true condition
- `{"$ne":"invalid"}` — not-equal bypass
- `{"$regex":".*"}` — regex match all
- `{"$where":"sleep(5000)"}` — time-based blind

**Login bypass:**
- username: `{"$gt":""}`, password: `{"$gt":""}`

### Step 3 — Analyze Responses
- Different response body/length between `$gt:""` and `$eq:impossible` → boolean blind
- Timing difference with `$where:sleep()` → time-based blind
- Error messages mentioning MongoDB, Mongoose, BSON → error-based

### Step 4 — Escalate
If injection confirmed:
- Extract data using `$regex` character-by-character
- Enumerate collections if error messages leak names

Report each finding with exact payload, response evidence, and affected URL.
```

### Step 3: Wire Up Supporting Mechanisms

In `agent.py`, optionally add:

```python
# Enable the tool-enabled smart retry for the new phase.
# Retry fires when the first pass has 0 findings OR when findings exist
# but none of them match the phase's core-vuln-class keywords.
_ACTIVE_RETRY_PHASES = {
    ...,
    "web_a03_nosqli",
}

# Core-vuln-class keywords — retry also fires if none of these match.
_PHASE_CORE_KEYWORDS = {
    ...,
    "web_a03_nosqli": (
        "nosql injection", "mongodb injection", "$where", "$ne", "$gt",
    ),
}

# Pick which tailored retry prompt this phase should use.
_PHASE_TO_PROMPT_KEY = {
    ...,
    "web_a03_nosqli": "injection",   # or add a new key in _RETRY_PROMPTS
}

# Set minimum security test calls
_MIN_SECURITY_CALLS = {
    ...,
    "web_a03_nosqli": 4,
}
```

### Step 4: Add to Focus Phase Map

In `prompts.py`, update `_FOCUS_PHASE_MAP`:

```python
_FOCUS_PHASE_MAP = {
    ...,
    "nosql": ["web_a03_nosqli", "api_injection"],
    "nosql injection": ["web_a03_nosqli", "api_injection"],
    "mongodb": ["web_a03_nosqli", "api_injection"],
}
```

### Step 5: Test

```bash
# Run a focused scan on just your new phase
# In the UI: set Focus Areas to "nosql"
# Or via API:
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target:3000",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "focus_areas": "nosql"
  }'
```

Check the test log in scan results to verify the LLM executed the expected tool calls.

---

## Adding a New Tool

### Step 1: Add the Handler Method in `tools.py`

```python
class ScanTools:
    # ... existing methods ...

    async def check_cors_preflight(self, url: str, origin: str) -> dict:
        """Send OPTIONS request to check CORS preflight response."""
        url = self._resolve_url(url)
        self._check_scope(url)

        resp = await self.http.request(
            "OPTIONS", url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization",
            }
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        result = {
            "status": resp.status_code,
            "allow_origin": acao,
            "allow_credentials": acac,
            "all_cors_headers": {
                k: v for k, v in resp.headers.items()
                if k.lower().startswith("access-control")
            },
        }

        if acao == "*" and acac.lower() == "true":
            result["VULNERABILITIES_DETECTED"] = True
            result["ACTION_REQUIRED"] = "Wildcard CORS with credentials — report as finding"

        return result
```

### Step 2: Register in the Dispatcher

In the `execute()` method's `handlers` dict:

```python
handlers = {
    # ... existing handlers ...
    "check_cors_preflight": lambda: self.check_cors_preflight(
        args.get("url"), args.get("origin")
    ),
}
```

### Step 3: Add the Tool Definition

Add to `TOOL_DEFINITIONS` list:

```python
{
    "type": "function",
    "function": {
        "name": "check_cors_preflight",
        "description": "Send an OPTIONS preflight request to test CORS configuration. Returns Access-Control-* headers.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to send the preflight request to"
                },
                "origin": {
                    "type": "string",
                    "description": "The Origin header value to test (e.g. 'https://evil.com')"
                }
            },
            "required": ["url", "origin"]
        }
    }
}
```

### Step 4: Document in System Prompt

In `prompts.py`, add to the `SYSTEM_PROMPT` TOOL REFERENCE section:

```
- check_cors_preflight(url, origin): Send OPTIONS preflight to test CORS.
  Returns allow_origin, allow_credentials, all CORS headers.
```

### Step 5: Test

Run a scan and check if the LLM discovers and uses the new tool. If it doesn't, make the phase prompt explicitly instruct its use.

---

## Optimizing a Phase Prompt

### Diagnosis: Why Isn't the Scanner Finding X?

1. **Run a focused scan** with the relevant phase
2. **Check the test log** — did the LLM call the right tools?
3. **Check payloads** — did the LLM use appropriate payloads?
4. **Check evidence** — did the tool detect vulnerability signals?

### Common Issues and Fixes

| Problem | Cause | Fix |
|---------|-------|-----|
| LLM doesn't test enough endpoints | Phase prompt too vague | Add "Test ALL forms, ALL search params, ALL API endpoints" |
| LLM uses wrong payload format | No examples in prompt | Add explicit payload examples with expected responses |
| LLM misses LIKE-clause SQLi | Not using `baseline_value` | Add "Always prepend a real search term: `test' OR 1=1--`" |
| LLM stops after 2 tests | `_MIN_SECURITY_CALLS` too low | Increase minimum in `agent.py` |
| LLM finds vuln but doesn't report | Finding format unclear | Add response indicator examples: "If you see X, report as Y" |
| Tool returns signal but LLM ignores | Signal not prominent enough | Enhance `_extract_vuln_signals()` in `tools.py` |

### Prompt Writing Best Practices

```
DO:
✓ "Use fuzz_parameter with payloads: [\"test'\", \"test' OR 1=1--\", ...]"
✓ "If response contains 'SQLITE_ERROR', report as Critical SQL Injection"
✓ "Test both GET and POST parameters"
✓ "Use baseline_value='test' to prepend to injection payloads"

DON'T:
✗ "Try some SQL injection payloads"  (too vague)
✗ "Test for vulnerabilities"  (not actionable)
✗ "Be thorough"  (meaningless to LLM)
```

### Validation Workflow

```
1. Edit phase prompt in prompts.py
2. Deploy to EC2 (or test locally)
3. Run focused scan against known-vulnerable target:
   - Juice Shop (http://target:3000) for web vulns
   - DVAPI (http://target:8000) for API vulns
4. Compare findings with known vulnerability list
5. Check test log for:
   - Number of security tool calls (should be >= _MIN_SECURITY_CALLS)
   - Payload variety (not just repeating the same payload)
   - Response analysis (did the LLM notice error signals?)
6. If gaps found: add specific payloads/techniques to the prompt
7. Re-test until detection matches expected results
```

---

## Adding a Passive Check

In `scanners/ai_agent/passive_recon.py`:

```python
async def check_my_new_thing(page, http_client, target_url):
    """Check for <description>."""
    findings = []

    # Your deterministic check logic here
    resp = await http_client.get(target_url + "/.well-known/security.txt")
    if resp.status_code == 404:
        findings.append({
            "title": "Missing security.txt",
            "severity": "Info",
            "owasp_category": "A05:2021",
            "url": target_url,
            "evidence": "GET /.well-known/security.txt returned 404",
            "remediation": "Add a security.txt file per RFC 9116",
            "confidence": "high",
        })

    return findings
```

Then add the function call to the `run_passive_recon()` orchestrator in the same file.

---

## Adding a Focus Area Keyword

In `prompts.py`, add to `_FOCUS_PHASE_MAP`:

```python
_FOCUS_PHASE_MAP = {
    ...,
    "my keyword": ["web_phase_id", "api_phase_id"],
    "alternate spelling": ["web_phase_id", "api_phase_id"],
}
```

Users can then type "my keyword" in the Focus Areas field in the UI.

---

## Enabling Hybrid Smart Retry for a Phase

Active-retry phases run a second, tool-enabled pass with a phase-tailored
prompt whenever the first pass finds 0 vulnerabilities **or** produces
findings but none of them match the phase's core vulnerability class.

In `agent.py`, wire up three structures:

```python
_ACTIVE_RETRY_PHASES = {
    "web_a01", "web_a07", "web_a10",
    "web_a03_sqli", "web_a03_xss", "web_a03_cmdi",
    "web_a03_ssti", "web_a03_path_traversal", "web_a03_xxe",
    "api_injection", "api_ssrf", "api_authz",
    "api_auth", "web_bfla", "api_bfla",
    "web_a03_nosqli",   # ← add here
}

_PHASE_CORE_KEYWORDS = {
    ...,
    "web_a03_nosqli": (
        "nosql injection", "mongodb injection", "$where", "$ne", "$gt",
    ),
}

_PHASE_TO_PROMPT_KEY = {
    ...,
    "web_a03_nosqli": "injection",
}
```

On retry, the agent:

1. Picks the tailored prompt from `_RETRY_PROMPTS` using `_PHASE_TO_PROMPT_KEY[phase.id]` (e.g. `access_control`, `auth`, `sqli`, `xss`, `cmdi`, `ssti`, `path_traversal`, `xxe`, `ssrf`, `injection`, `bfla`).
2. Injects the prompt + a compact excerpt of the phase's evidence buffer as a user message.
3. Runs a full tool-enabled loop (up to `phase.max_steps`) so the LLM can actually re-test — not just analyse.
4. Emits the retry as its own `phase_start` tile (`<name> (retry)`) in the UI; extracted findings merge back into the original phase.

Non-active-retry phases fall back to the cheap **evidence summary** pass (tool-less LLM review of the evidence buffer) only when the phase produced 0 findings.

---

## Setting Minimum Security Calls

In `agent.py`, add to `_MIN_SECURITY_CALLS`:

```python
_MIN_SECURITY_CALLS = {
    "web_a03_sqli": 5,
    "web_a03_xss": 5,
    ...,
    "web_a03_nosqli": 4,   # ← add here
}
```

This prevents the LLM from declaring a phase "done" after fewer than 4 security-testing tool calls.

---

## Adding a Report Type

In `scripts/report_generator.py`:

```python
def generate_my_report(scan_data: dict, output_path: str):
    """Generate a custom report."""
    pdf = FPDF()
    # ... build PDF ...
    pdf.output(output_path)
```

Then add a route in `web/app.py`:

```python
@app.post("/api/results/{scan_id}/my-report")
async def generate_my_report_endpoint(scan_id: str, creds=Depends(_verify)):
    # Load scan data, call generator, return file
    ...
```

---

## Adding a Compliance Framework

In `web/app.py`, add to the compliance mapping section:

```python
COMPLIANCE_FRAMEWORKS = {
    ...,
    "gdpr": {
        "name": "GDPR",
        "controls": {
            "Art. 32": {
                "title": "Security of Processing",
                "owasp_categories": ["A02:2021", "A05:2021", "A07:2021"],
            },
            # ... more controls
        }
    }
}
```

---

## Development Workflow

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Configure
cp .env.example .env
# Edit .env with your AWS Bedrock credentials

# Run locally
uvicorn web.app:app --host 0.0.0.0 --port 8080 --reload

# Test a specific change
# 1. Edit prompts.py or tools.py
# 2. Restart uvicorn (--reload does this automatically)
# 3. Start a focused scan in the UI
# 4. Monitor test log and findings
```

### Deploying Changes to EC2

```powershell
# 1. SCP changed files to EC2 host
$key = "$env:USERPROFILE\.ssh\dast-key.pem"
$ec2 = "ubuntu@<EC2-IP>"
scp -i $key "scanners/ai_agent/prompts.py" "${ec2}:~/ai-dast-scanner/scanners/ai_agent/prompts.py"

# 2. Docker cp into running container
ssh -i $key $ec2 "docker cp ~/ai-dast-scanner/scanners/ai_agent/prompts.py dast-scanner:/app/scanners/ai_agent/prompts.py"

# 3. Restart container
ssh -i $key $ec2 "docker restart dast-scanner"

# 4. Verify health
ssh -i $key $ec2 "curl -sf http://localhost:8080/health"
```

### Testing Against Known-Vulnerable Targets

| Target | URL | Best For |
|--------|-----|----------|
| **OWASP Juice Shop** | `http://<IP>:3000` | XSS, SQLi, auth bypass, IDOR, file upload |
| **DVAPI (vAPI)** | `http://<IP>:8000/vapi/` | BOLA, injection, mass assignment, auth |
| **DVWA** | `http://<IP>/dvwa` | Classic web vulns at configurable difficulty |
| **WebGoat** | `http://<IP>:8080/WebGoat` | OWASP lesson-based vulnerabilities |

### Comparing Scanner Results

After running a scan, compare findings against the target's known vulnerability list:

1. **Juice Shop**: See [pwning-juice-shop](https://pwning.owasp-juice.shop/) for the full vuln list
2. **DVAPI**: Check the vAPI GitHub repo for documented vulnerabilities
3. **Track coverage**: Note which vulns were found vs missed
4. **Gap analysis**: For each miss, check the test log to understand why:
   - Did the LLM test the right endpoint?
   - Did it use the right payload?
   - Did the tool detect the signal but the LLM ignored it?
   - Does the phase prompt need more specific guidance?

---

## Architecture Decision Records

### Why Pure LLM Payloads (No Hardcoded Lists)?

The scanner uses LLM-generated payloads rather than static wordlists because:
- **Context-aware**: The LLM can see the tech stack (SQLite vs PostgreSQL vs MySQL) and craft DB-specific payloads
- **Adaptive**: If a WAF blocks `' OR 1=1--`, the LLM can try encoded or comment-injected variants
- **Novel**: The LLM can generate payloads for application-specific logic (e.g. coupon codes, price fields)
- **Trade-off**: Less deterministic than static lists; compensated by retry mechanism and minimum call enforcement

### Why Evidence Buffer?

LLM context windows are finite. When context is trimmed, tool call results (the evidence) can be lost. The evidence buffer:
- Preserves compact summaries of every security test
- Survives context trimming
- Enables finding grounding (reject hallucinated findings)
- Powers retry prompts with full test history

### Why Retry Phases?

LLM behavior is non-deterministic. The same prompt can produce different results across runs. Retries:
- Give critical phases (SQLi, XSS, etc.) a second chance
- Use the evidence buffer to inform the retry attempt
- Significantly improve detection consistency across runs
