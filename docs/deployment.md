# Deployment Guide

[← Back to README](../README.md)

> **Day-to-day code deploys** (hot-patch `docker cp`, `tar` pipe, when to use `deploy.sh`, ECR runner push): see the README sections **[Install from scratch](../README.md#install-from-scratch)** and **[Day-to-day code deploys](../README.md#day-to-day-code-deploys)**. This file covers Bedrock, `.env`, SSO, verification scripts, and failure modes.

## Smart deploy classification

`scripts/deploy/classify_changes.py` maps a git diff to three flags. `deploy.sh` on EC2 (when `.last_deployed_sha` exists) delegates to `scripts/deploy/deploy.sh`, which runs only the needed steps and updates the marker.

| Changed paths | UI hot-patch (`docker cp` + restart) | UI image rebuild (`deploy.sh --full`) | Runner image rebuild (ECR) |
|---------------|--------------------------------------|---------------------------------------|----------------------------|
| `web/**/*.py`, templates, `web/static/**` | Yes (default) | Only if deps/image definition changed | Yes — runner `COPY web/` |
| `scanners/**/*.py` (not only runner entry) | Yes (into UI container) | — | Yes — runner `COPY scanners/` |
| `scanners/runner/**` | — | — | Yes |
| `scripts/**`, `config/**` | Yes (UI) | — | Yes (runner copies both) |
| `requirements*.txt`, `pyproject.toml`, `Pipfile*` | — | Yes | Yes |
| Root `Dockerfile`, `docker-compose*.yml` | — | Yes | — |
| `scanners/runner/Dockerfile` | — | — | Yes |
| `docs/**`, `README.md`, `.cursor/**`, `tests/**`, `infra/**` | — | — | — |

Dry-run on your laptop:

```bash
python scripts/deploy/classify_changes.py HEAD~5..HEAD
python scripts/deploy/classify_changes.py cbf8c61..HEAD --json
```

Runner ECR push is still manual / `scripts/ec2_build_push_runner.py` — incremental `deploy.sh` prints instructions when `needs_runner_rebuild` is true.

## EC2 Deployment (Recommended)

### Prerequisites

| Requirement | Value |
|-------------|-------|
| **Instance** | t3.xlarge or larger (4 vCPU, 16 GB RAM) |
| **OS** | Ubuntu 24.04 LTS (x86_64) — required for Playwright Chromium |
| **Disk** | 100 GB |
| **Security Group** | Inbound TCP port 80 |
| **IAM Role** | Bedrock invoke permissions (see below) |

The Docker image installs **`xmlsec1`**, **`libxmlsec1-dev`**, **`pkg-config`**, **`libssl-dev`**, and **`libffi-dev`** (required by `python3-saml` for SSO). On a **bare-metal** host without Docker, install the same packages before `pip install`:

```bash
sudo apt-get install -y xmlsec1 libxmlsec1-dev pkg-config libssl-dev libffi-dev
```

### Quick Deploy

**First-time / greenfield:** follow README [Install from scratch](../README.md#install-from-scratch) (Terraform → clone → `deploy.sh` → ECR runner → verify).

**Existing host — full image rebuild only:**

```bash
cd ~/ai-dast-scanner
docker exec dast-scanner python3 /tmp/check_scan_active.py   # MANDATORY — must exit 0
bash deploy.sh
```

**Existing host — typical code change:** `git pull` then `bash deploy.sh` (incremental; hot-patch by default). Manual pattern **A**/**B** in the README still works. Use `bash deploy.sh --full` only for dependency/Dockerfile changes.

### Verify deployment (smoke + optional full scan)

From your laptop (same network as allowed to reach the instance):

```bash
# Read-only HTTP checks
export DAST_BASE_URL=http://YOUR_HOST
export DAST_AUTH_USER=dast-admin
export DAST_AUTH_PASS=YourStrongPassword   # if ui-settings is protected
python scripts/run_regression_ec2.py --pytest

# Start a short scan against a public test app (OWASP Juice Shop demo by default)
export DAST_BASE_URL=http://YOUR_HOST
python scripts/e2e_remote_scan.py --smoke    # health + POST /api/scan + running status
python scripts/e2e_remote_scan.py            # wait until completed / error (needs LLM keys on server)
```

Override target: `E2E_TARGET_URL=https://...` or `--target-url`. Use only sites you are authorized to test.

### Pre-deploy scan check (MANDATORY)

**MANDATORY** before **any** code change reaches the running UI container (`docker cp`, `docker restart`, or `bash deploy.sh`). Do not treat this as optional.

```bash
docker exec dast-scanner python3 /tmp/check_scan_active.py
```

The script is normally already on the host at `scripts/check_scan_active.py` and copied into the container at `/tmp/check_scan_active.py` during prior deploys. Refresh from your workstation if missing (see README [Day-to-day code deploys](../README.md#day-to-day-code-deploys)).

- Exit **0** → safe to proceed.
- Exit **1** → **STOP** — a scan is active or paused; wait or stop the scan first.

The script calls `GET /api/scans` with **HTTP Basic Auth** when **both** `DAST_AUTH_USER` and `DAST_AUTH_PASS` are set in the container environment. If you run it from the host shell without those vars exported, it falls back to unauthenticated requests and prints a **WARNING** (only acceptable on pre-RBAC images). Inside the container they are usually already set from `.env`.

**Why:** Scan state (LLM conversation, browser session, findings buffer) lives in process memory. A restart kills in-flight work; pause-deploy-resume does **not** work.

### Authentication

Production uses **SAML 2.0** (Microsoft Entra ID) with invite-based onboarding and `admin` / `user` RBAC. Local dev and API scripts typically use **`SSO_ENABLED=false`** (default) plus `DAST_AUTH_USER` / `DAST_AUTH_PASS` for the login form and Basic Auth.

**First-boot bootstrap (SSO on):** set `INITIAL_ADMIN_EMAILS` to a comma-separated list of admin emails in the deploy environment (not in git). On the **first** successful SAML login for a listed address, that user is created with role `admin`. Once **any** admin user exists in the database, `INITIAL_ADMIN_EMAILS` is ignored.

Full Entra app registration, SAML certificate layout, invites, and troubleshooting: **[docs/SSO_RBAC.md](SSO_RBAC.md)** — do not duplicate that walkthrough here.

### Environment Variables

```bash
# .env — LLM / AWS
AWS_ACCESS_KEY_ID=AKIA...         # For Bedrock models
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
ANTHROPIC_API_KEY=sk-ant-...       # Optional (if using Anthropic directly)

# Platform auth (local admin / API Basic Auth — also used by scripts/check_scan_active.py)
DAST_AUTH_USER=dast-admin
DAST_AUTH_PASS=YourStrongPassword

# SSO / RBAC (see docs/SSO_RBAC.md for Entra setup)
SSO_ENABLED=false                  # true = SAML sign-in; false = local login (default)
INITIAL_ADMIN_EMAILS=              # First SSO bootstrap only; comma-separated admin emails
SAML_IDP_METADATA_URL=
SAML_SP_ENTITY_ID=
SAML_SP_ACS_URL=
SAML_SP_CERT_PATH=                 # Optional PEM paths under config/saml/
SAML_SP_KEY_PATH=
DAST_SESSION_SECRET=               # Session cookie HMAC (set in production)
PUBLIC_BASE_URL=                   # Base URL for invite links (e.g. https://scanner.example.com)
```

### Docker Compose

The `deploy.sh` script runs `docker compose build && docker compose up -d`. To customize, edit the `.env` file.

The `--restart unless-stopped` flag ensures auto-restart on crash or EC2 reboot.

## Common deploy failures

### `IMAGE_NAME` empty / `docker build -t` with no tag

**Symptom:** `deploy.sh` fails building with an empty `-t` argument, or logs show `docker build -t  .`.

**Cause:** `deploy.sh` was started from a **non-interactive** shell (`nohup`, CI, or a truncated SSH one-liner) where `IMAGE_NAME="ai-dast-scanner"` was not set the same way as in an interactive bash session, or the script was invoked without a proper login shell.

**Fix:** SSH in interactively, `cd ~/ai-dast-scanner`, run `bash deploy.sh` in a normal terminal. Do not background the first deploy on a fresh host.

### ECR push from EC2: `ConnectTimeoutError` to `api.ecr.us-east-2.amazonaws.com`

**Symptom:** `aws ecr get-login-password` works but `docker push` times out reaching ECR.

**Cause (usually one or both):**

1. EC2 is in a private subnet **without** VPC interface endpoints for **ECR API** and **ECR DKR** (Terraform: `vpc_endpoints_ecs.tf`) and without a NAT path to the internet.
2. EC2 instance role lacks ECR permissions: `ecr:GetAuthorizationToken` plus `ecr:BatchCheckLayerAvailability`, `ecr:CompleteLayerUpload`, `ecr:InitiateLayerUpload`, `ecr:PutImage`, `ecr:UploadLayerPart` on `arn:aws:ecr:us-east-2:168551359048:repository/dast-scanner-runner`.

**Fix:** Apply Terraform endpoints (or allow HTTPS egress to ECR), attach ECR push policy to the instance role, then retry `docker login` + `docker push`. See README [Step 4](../README.md#step-4-push-fargate-runner-image-to-ecr).

### Hot-patch lost after `bash deploy.sh`

**Symptom:** A fix deployed via `docker cp` worked until someone ran `bash deploy.sh`, then the bug returned.

**Cause:** `deploy.sh` rebuilds the image from the **git tree on the host**, not from uncommitted files you only copied into the running container.

**Fix:** Commit and `git pull` on EC2 (or `scp` the full tree to `~/ai-dast-scanner`) before `deploy.sh`. For quick tests, use hot-patch only for changes that are already committed or will be synced to the host immediately after.

## Local Development (No Docker)

Install SAML system libraries first (same as the Dockerfile):

```bash
sudo apt-get install -y xmlsec1 libxmlsec1-dev pkg-config libssl-dev libffi-dev
pip install -r requirements.txt
playwright install chromium
cp .env.example .env && nano .env   # SSO_ENABLED=false, DAST_AUTH_USER, DAST_AUTH_PASS
uvicorn web.app:app --host 0.0.0.0 --port 80
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
