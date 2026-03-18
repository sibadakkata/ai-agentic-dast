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
| Live activity stream | In-memory only | No (progress log saved) |

Scans interrupted by a restart are marked as "error" with the full progress log preserved.
