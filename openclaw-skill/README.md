# AI Agentic Scanner - OpenClaw Skill

An [OpenClaw](https://github.com/openclaw/openclaw) skill that lets you trigger and manage AI-powered DAST security scans through natural language chat.

## Architecture

```
YOUR MACHINE (local)                        EC2 (remote)
┌─────────────────────┐                     ┌─────────────────────┐
│  test_skill.py      │    HTTP REST API    │  AI Agentic Scanner │
│  (or OpenClaw agent)│ ──────────────────► │  (already running)  │
│                     │ ◄────────────────── │  Docker container   │
└─────────────────────┘    JSON responses   └─────────────────────┘
```

You do **not** need to run the scanner locally. The scanner stays on EC2. Only this skill/test script runs on your machine and talks to EC2 over HTTP.

## Quick Start (No OpenClaw Needed)

The test script works standalone. Just run it from the `POC` folder:

```powershell
cd C:\Projects\Pen-Test\Acunetix\POC
python openclaw-skill/test_skill.py list
```

Default scanner URL: `http://18.117.143.222:8080`. Override with:
```powershell
$env:SCANNER_URL = "http://your-scanner:8080"
```

---

## All Commands & Examples

### 1. List All Scans

```powershell
python openclaw-skill/test_skill.py list
```

Output:
```
All Scans (11 total)
  scan_20260312_082647_cbb4a2   [running   ] both   https://ebiz-service-qa.norton.com/
                                 Model: Claude Haiku 4.5 (recommended)  findings=0  cost=$0.0000
  scan_20260311_144426_77034d   [completed ] ?      https://my-int.norton.com
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

  https://ebiz-service-qa.norton.com/
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
    Targets  : https://dev-api.engine.tech, https://my-int.norton.com, ...
    Findings : 136
    Cost     : $63.7420

  Ministral 8B (cheapest + tools)
    Scans    : 7
    Findings : 9
    Cost     : $1.8326
```

### 4. Find Scans by URL

```powershell
# All norton scans
python openclaw-skill/test_skill.py find --url norton

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
python openclaw-skill/test_skill.py find --url norton --model haiku
```

Output:
```
Scans matching url~'norton' AND model~'haiku' (2 of 11)
  scan_20260312_082647_cbb4a2   [running   ] both   https://ebiz-service-qa.norton.com/
                                 Model: Claude Haiku 4.5 (recommended)
  scan_20260311_144426_77034d   [completed ] ?      https://my-int.norton.com
                                 Model: Claude Haiku 4.5 (recommended)  findings=68
```

### 7. Get Report for Latest Scan of a Target

```powershell
# Latest completed norton scan -> PDF
python openclaw-skill/test_skill.py latest-report --url norton

# Latest AVG scan -> PDF
python openclaw-skill/test_skill.py latest-report --url avg

# Latest norton scan using Haiku model -> PDF
python openclaw-skill/test_skill.py latest-report --url norton --model haiku

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
Report: http://18.117.143.222:8080/api/reports/scan_bedrock_us_anthropic_claude_haiku_4_5.pdf
```

### 8. Check Status of a Specific Scan

```powershell
python openclaw-skill/test_skill.py status scan_20260312_082647_cbb4a2
```

Output:
```
Scan     : scan_20260312_082647_cbb4a2
Target   : https://ebiz-service-qa.norton.com/
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
Triaged findings   : 48
Severity breakdown : {"Critical": 13, "High": 14, "Medium": 8, "Low": 4, "Info": 9}

True Positives   : 24
False Positives  : 24
Precision        : 50%

--- TRUE POSITIVES ---
[Medium      ] Absence of Rate Limiting on Security-Critical Endpoints
               URL: https://buy.norton.com/api/v1/promo/validate
               Reason: [RUNTIME VERIFIED] All 15 rapid requests accepted. No 429.

[Critical    ] Credential Brute Force Attack - No Account Lockout
               URL: https://login.norton.com/sso/embedded/login
               Reason: [RUNTIME VERIFIED] All 15 rapid requests accepted. No 429.
...
```

### 10. Generate PDF Report by Scan ID

```powershell
python openclaw-skill/test_skill.py report scan_20260311_144535_99d6f9
```

Output:
```
Report: http://18.117.143.222:8080/api/reports/scan_bedrock_us_anthropic_claude_haiku_4_5.pdf
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
bash openclaw-skill/install.sh http://18.117.143.222:8080
```

Then chat naturally in OpenClaw:
- "Scan https://example.com for vulnerabilities"
- "What targets have been scanned?"
- "Show findings from the norton scan"
- "Generate a report for the latest AVG scan"

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_URL` | `http://18.117.143.222:8080` | Scanner backend URL |
| `SCANNER_USER` | `dast-admin` | Basic auth username |
| `SCANNER_PASS` | (set in env) | Basic auth password |

## File Structure

```
openclaw-skill/
├── SKILL.md          # OpenClaw skill definition
├── install.sh        # One-command installer for OpenClaw
├── test_skill.py     # Standalone CLI (no OpenClaw needed)
└── README.md         # This file
```
