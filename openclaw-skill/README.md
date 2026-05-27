# AI Agentic Scanner - OpenClaw Skill

An [OpenClaw](https://github.com/openclaw/openclaw) skill that lets you trigger and manage AI-powered DAST security scans through natural language chat. The scanner features deterministic CVSS v3.1 severity classification, multi-identity testing (User B/Admin/Tenant B), hardcoded secret scanning (with Shannon entropy validation), exploitation tiers (validated/informational), SPA catch-all false-positive detection, finding deduplication, enriched retry prompts, and step-by-step triage narratives showing what the AI tested vs how the triage engine validated each finding.

## Architecture

```
YOUR MACHINE (local)                        EC2 (remote)
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  test_skill.py      â”‚    HTTP REST API    â”‚  AI Agentic Scanner â”‚
â”‚  (or OpenClaw agent)â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º â”‚  (already running)  â”‚
â”‚                     â”‚ â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  Docker container   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    JSON responses   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

You do **not** need to run the scanner locally. The scanner stays on EC2. Only this skill/test script runs on your machine and talks to EC2 over HTTP.

## Quick Start (No OpenClaw Needed)

The test script works standalone. Just run it from the `POC` folder:

```powershell
cd C:\Projects\Pen-Test\Acunetix\POC
python openclaw-skill/test_skill.py list
```

Default scanner URL: `http://localhost:80`. Override with:
```powershell
$env:SCANNER_URL = "http://your-scanner"
$env:SCANNER_USER = "dast-admin"          # must match server DAST_AUTH_USER (or your SSO API user)
$env:SCANNER_PASS = "your-secret"         # must match server DAST_AUTH_PASS
```

When the scanner runs with RBAC, all `/api/*` calls need Basic Auth — set `SCANNER_USER` / `SCANNER_PASS` to the same values as `DAST_AUTH_USER` / `DAST_AUTH_PASS` on the server. Browser SSO does not apply to this CLI; see [SSO & RBAC](../docs/SSO_RBAC.md).

---

## All Commands & Examples

### 1. List All Scans

```powershell
python openclaw-skill/test_skill.py list
```

Output:
```
All Scans (11 total)
  scan_20260312_082647_cbb4a2   [running   ] both   https://staging.example.com/
                                 Model: Claude Haiku 4.5 (recommended)  findings=0  cost=$0.0000
  scan_20260311_144426_77034d   [completed ] ?      https://app.example.com
                                 Model: Claude Haiku 4.5 (recommended)  findings=68  cost=$29.5729
  ...
```

### 2. Show All Targets Scanned

```powershell
python openclaw-skill/test_skill.py targets
```

Output:
```
Unique Targets (5 targets, 11 total scans)

  https://staging.example.com/
    Scans  : 1
    Models : Claude Haiku 4.5 (recommended)
    Status : running

  https://dev-api.engine.tech
    Scans  : 5
    Models : Claude Haiku 4.5 (recommended), Ministral 8B (cheapest + tools)
    Status : completed
  ...
```

### 3. Show Models Used

```powershell
python openclaw-skill/test_skill.py models
```

Output:
```
Models Used (2 models)

  Claude Haiku 4.5 (recommended)
    Scans    : 4
    Targets  : https://dev-api.engine.tech, https://app.example.com, ...
    Findings : 136
    Cost     : $63.7420

  Ministral 8B (cheapest + tools)
    Scans    : 7
    Findings : 9
    Cost     : $1.8326
```

### 4. Find Scans by URL

```powershell
# All myapp scans
python openclaw-skill/test_skill.py find --url myapp

# All API engine scans
python openclaw-skill/test_skill.py find --url engine.tech
```

### 5. Find Scans by Model

```powershell
# All scans using Haiku
python openclaw-skill/test_skill.py find --model haiku

# All scans using Ministral
python openclaw-skill/test_skill.py find --model ministral
```

### 6. Find by URL + Model (Combined)

```powershell
# Norton scans using Haiku only
python openclaw-skill/test_skill.py find --url myapp --model haiku
```

Output:
```
Scans matching url~'myapp' AND model~'haiku' (2 of 11)
  scan_20260312_082647_cbb4a2   [running   ] both   https://staging.example.com/
                                 Model: Claude Haiku 4.5 (recommended)
  scan_20260311_144426_77034d   [completed ] ?      https://app.example.com
                                 Model: Claude Haiku 4.5 (recommended)  findings=68
```

### 7. Get Report for Latest Scan of a Target

```powershell
# Latest completed myapp scan -> PDF
python openclaw-skill/test_skill.py latest-report --url myapp

# Latest AVG scan -> PDF
python openclaw-skill/test_skill.py latest-report --url avg

# Latest myapp scan using Haiku model -> PDF
python openclaw-skill/test_skill.py latest-report --url myapp --model haiku

# Latest scan of any target using Ministral -> PDF
python openclaw-skill/test_skill.py latest-report --model ministral
```

Output:
```
Latest match: scan_20260311_144535_99d6f9
Target: https://www.avg.com/cs-cz/homepage#pc
Model : Claude Haiku 4.5 (recommended)
Cost  : $26.7496

Generating PDF report...
Report: http://localhost:80/api/reports/scan_bedrock_us_anthropic_claude_haiku_4_5.pdf
```

### 8. Check Status of a Specific Scan

```powershell
python openclaw-skill/test_skill.py status scan_20260312_082647_cbb4a2
```

Output:
```
Scan     : scan_20260312_082647_cbb4a2
Target   : https://staging.example.com/
Mode     : both
Model    : Claude Haiku 4.5 (recommended)
Status   : running
Cost     : $0.0000
Duration : 0s
Phases   : 4 completed
```

### 9. Get Full Findings

```powershell
python openclaw-skill/test_skill.py results scan_20260311_144535_99d6f9
```

Output:
```
RESULTS: https://www.avg.com/cs-cz/homepage#pc
AI findings (raw)  : 48
Triaged findings   : 32 (after dedup)
Severity breakdown : {"Critical": 5, "High": 10, "Medium": 8, "Low": 6, "Info": 3}

True Positives   : 24  (Validated: 8, Informational: 16)
False Positives  : 8   (SPA catch-all: 3, Fake secrets: 2, No evidence: 3)
Precision        : 75%

--- TRUE POSITIVES ---
[Medium      ] Absence of Rate Limiting on Security-Critical Endpoints
               URL: https://api.example.com/v1/promo/validate
               Tier: VALIDATED
               Reason: [RUNTIME VERIFIED] All 50 rapid requests accepted. No 429.

[Critical    ] Credential Brute Force Attack - No Account Lockout
               URL: https://login.example.com/sso/embedded/login
               Tier: VALIDATED
               Reason: [RUNTIME VERIFIED] All 50 rapid requests accepted. No 429.
...
```

### 10. Generate PDF Report by Scan ID

```powershell
python openclaw-skill/test_skill.py report scan_20260311_144535_99d6f9
```

Output:
```
Report: http://localhost:80/api/reports/scan_bedrock_us_anthropic_claude_haiku_4_5.pdf
```

### 11. Start a New Scan

```powershell
# Website scan (default)
python openclaw-skill/test_skill.py scan --url https://testphp.vulnweb.com

# API scan
python openclaw-skill/test_skill.py scan --url https://api.example.com/v1 --mode api

# Both modes
python openclaw-skill/test_skill.py scan --url https://example.com --mode both

# Wait for completion and auto-show results + report
python openclaw-skill/test_skill.py scan --url https://testphp.vulnweb.com --wait
```

### 12. Stop a Running Scan

```powershell
python openclaw-skill/test_skill.py stop scan_20260312_082647_cbb4a2
```

---

## With OpenClaw (Team Chat)

If you want team-wide access via Slack/Web UI:

```bash
bash openclaw-skill/install.sh http://localhost:80
```

Then chat naturally in OpenClaw:
- "Scan https://example.com for vulnerabilities"
- "What targets have been scanned?"
- "Show findings from the myapp scan"
- "Generate a report for the latest AVG scan"

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_URL` | `http://localhost:80` | Scanner backend URL |
| `SCANNER_USER` | `dast-admin` | Basic Auth username (align with server `DAST_AUTH_USER`) |
| `SCANNER_PASS` | (set in env) | Basic Auth password (align with server `DAST_AUTH_PASS`) |

## File Structure

```
openclaw-skill/
â”œâ”€â”€ SKILL.md          # OpenClaw skill definition
â”œâ”€â”€ install.sh        # One-command installer for OpenClaw
â”œâ”€â”€ test_skill.py     # Standalone CLI (no OpenClaw needed)
â””â”€â”€ README.md         # This file
```
