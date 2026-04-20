# Deployment Guide

[← Back to README](../README.md)

## EC2 Deployment (Recommended)

### Prerequisites

| Requirement | Value |
|-------------|-------|
| **Instance** | t3.xlarge or larger (4 vCPU, 16 GB RAM) |
| **OS** | Ubuntu 24.04 LTS (x86_64) — required for Playwright Chromium |
| **Disk** | 100 GB |
| **Security Group** | Inbound TCP port 8080 |
| **IAM Role** | Bedrock invoke permissions (see below) |

### Quick Deploy

```bash
# 1. Upload to EC2
scp -i key.pem -r ./POC ubuntu@<EC2-IP>:~/ai-dast-scanner

# 2. Configure
ssh -i key.pem ubuntu@<EC2-IP>
cd ~/ai-dast-scanner
cp .env.example .env
nano .env   # Add your credentials

# 3. Deploy
bash deploy.sh
# → Builds Docker image, starts container
# → Web UI at http://<EC2-IP>:8080
```

### Verify deployment (smoke + optional full scan)

From your laptop (same network as allowed to reach the instance):

```bash
# Read-only HTTP checks
export DAST_BASE_URL=http://YOUR_HOST:8080
export DAST_AUTH_USER=dast-admin
export DAST_AUTH_PASS=YourStrongPassword   # if ui-settings is protected
python scripts/run_regression_ec2.py --pytest

# Start a short scan against a public test app (OWASP Juice Shop demo by default)
export DAST_BASE_URL=http://YOUR_HOST:8080
python scripts/e2e_remote_scan.py --smoke    # health + POST /api/scan + running status
python scripts/e2e_remote_scan.py            # wait until completed / error (needs LLM keys on server)
```

Override target: `E2E_TARGET_URL=https://...` or `--target-url`. Use only sites you are authorized to test.

### Environment Variables

```bash
# .env
AWS_ACCESS_KEY_ID=AKIA...         # For Bedrock models
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
DAST_AUTH_USER=dast-admin          # Web UI login
DAST_AUTH_PASS=YourStrongPassword
ANTHROPIC_API_KEY=sk-ant-...       # Optional (if using Anthropic directly)
```

### Docker Compose

The `deploy.sh` script runs `docker compose build && docker compose up -d`. To customize, edit the `.env` file.

The `--restart unless-stopped` flag ensures auto-restart on crash or EC2 reboot.

## Local Development (No Docker)

```bash
pip install -r requirements.txt
playwright install chromium
cp .env.example .env && nano .env
uvicorn web.app:app --host 0.0.0.0 --port 8080
```

## CLI Usage

```bash
# Default scan
python scripts/run_scan.py

# Override model
python scripts/run_scan.py --model "bedrock/us.anthropic.claude-sonnet-4-6"

# Scan specific target
python scripts/run_scan.py --target T1

# Dry run (test connectivity)
python scripts/run_scan.py --dry-run

# Generate PDF reports from existing results
python scripts/report_generator.py
python scripts/report_generator.py --file results/raw/scan_result.json
```

## AWS Bedrock Setup

### IAM Permissions

Attach to your EC2 instance's IAM role:

- `bedrock:InvokeModel` on `arn:aws:bedrock:*:*:inference-profile/*`
- `bedrock:InvokeModelWithResponseStream` on `arn:aws:bedrock:*:*:inference-profile/*`
- `aws-marketplace:ViewSubscriptions`, `aws-marketplace:Subscribe`

Set region: `export AWS_DEFAULT_REGION=us-east-1`

### LiteLLM Proxy (Optional)

For teams with a LiteLLM proxy for non-Bedrock models:

```bash
export LITELLM_BASE_URL=https://litellm.your-company.com/
export LITELLM_API_KEY=sk-xxxx
```

The router auto-selects: `bedrock/` models go direct to Bedrock; others go through the proxy.

## Supported Models

| Model | Bedrock ID | Cost (in/out per 1M) | Tool Calling | Recommendation |
|-------|-----------|---------------------|-------------|----------------|
| **Ministral 8B** | `bedrock/mistral.ministral-3-8b-instruct` | $0.15 / $0.15 | Good | Cheapest with tool calling — dev/testing |
| **Ministral 14B** | `bedrock/mistral.ministral-3-14b-instruct` | $0.20 / $0.20 | **Strong** | **Best value** — designed for agentic use |
| Mistral Small | `bedrock/mistral.mistral-small-2402-v1:0` | $0.10 / $0.30 | Weak | Legacy — doesn't use tools reliably |
| **Claude Haiku 4.5** | `bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0` | $0.80 / $4 | **Excellent** | **Production scans** — best cost/quality |
| **Claude Sonnet 4.5** | `bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0` | $3 / $15 | **Excellent** | Deep analysis — strong reasoning at Sonnet-tier cost |
| **Claude Sonnet 4.6** | `bedrock/us.anthropic.claude-sonnet-4-6` | $3 / $15 | **Excellent** | Deep analysis — highest quality |

> **Why not other models?**
> - **Amazon Nova** (Micro/Lite/Pro): Content guardrails block security-testing prompts
> - **Gemini**: Requires separate Google API key (not via Bedrock)
> - **Mistral Small**: Responds with hypothetical findings instead of using tools

Minimum for meaningful results: **Ministral 14B** or **Claude Haiku 4.5**.

## Data Persistence

All scan data is stored in Docker named volumes:

| Data | Storage | Survives Restart? |
|------|---------|-------------------|
| Scan history & metadata | SQLite database | Yes |
| Scan results (JSON) | `dast-data/results/raw/*.json` | Yes |
| PDF reports | `dast-data/results/reports/*.pdf` | Yes |
| Uploaded API specs | `dast-data/imports/` | Yes |
| CVE/NVD cache | `dast-data/results/cache/` | Yes |
| Scan counters (cost, tokens, LLM calls, tool calls, findings_count, phases_completed) | SQLite `scans` row | **Yes** — snapshot promoted on every save |
| Phase breakdown, per-phase tool usage, last-500 crawled URLs, out-of-scope URLs | SQLite `scans.data` JSON blob | **Yes** — snapshot promoted on every save |
| Partial findings mid-scan | SQLite `scan_results` | **Yes** — checkpointed every 5 findings, on every phase boundary, and on the 30 s autosave tick |
| Detailed per-tool-call request/response log (`live_tests`, up to ~20 MB) | In-memory; flushed into `scan_results.payload.summary.test_log` on graceful completion/error/stop | No for hard-kill (OOM, SIGKILL, container restart). Yes for every other exit path. |

**Crash, error, stop, and pause resilience.** On every save, the in-memory `live_*` counters and structured summaries are promoted into the persisted `scans` row before the transient keys are stripped. This means:

- **Graceful error / stop / completion** — all numbers and breakdowns are accurate in the DB.
- **`kill -9` / OOM / container restart** — the DB reflects the last save (≤ 30 s or ≤ 10 tool calls before the kill). Cost typically drifts by well under 2 %; findings by 0–4; phases_completed by 0–1. Pre-fix behaviour was `cost=NULL`, `tokens=0`, empty breakdowns.
- **Paused** — state is flushed on pause; resume reads from the in-memory dict.

The only field that is still in-memory-only is the detailed per-tool-call log used by the Live Activity tab (it can reach 20 MB per scan and would bloat the DB). It survives graceful errors via `save_results()` but is lost on hard-kill.
