# DAST Scanner — Terraform (Production)

AWS infrastructure for the AI DAST scanner in **`us-east-2`**: RDS PostgreSQL, ALB + WAFv2, ECS Fargate scan workers, ECR, ElastiCache Redis, weekly DB backups to S3, and VPC endpoints for private-subnet workloads.

Parent overview: [README.md](../../README.md) · Design: [scalable-scanner-platform-proposal.md](../../docs/architecture/scalable-scanner-platform-proposal.md) · Confluence: [Red Team AI Web Scanner](https://confluence.corp.nortonlifelock.com/spaces/CIP/pages/954017481/Red+Team+AI+Web+Scanner)

## What this stack provisions

| Resource | Terraform | Purpose |
|----------|-----------|---------|
| **RDS** | `rds.tf` | PostgreSQL 16, `db.t4g.small`, Multi-AZ, encrypted, deletion protection |
| **ALB** | `alb.tf` | HTTPS (when `domain_name` set) → EC2 UI on port 80; health `GET /healthz` |
| **WAFv2** | `waf.tf` | Regional Web ACL on ALB (managed rules + rate limit + trusted CIDR allowlist) |
| **ECS / Fargate** | `ecs.tf` | Cluster `dast-scanner`, task definition for **one scan per task** |
| **ECR** | `ecr.tf` | Repository `dast-scanner-runner` (built from `scanners/runner/`) |
| **Redis** | `redis.tf` | ElastiCache for live scan events (SSE bridge on UI) |
| **Secrets** | `secrets.tf` | Secrets Manager `dast/rds/master` (master DB credentials) |
| **Backups** | `backups.tf` | Weekly Lambda → S3 `dast-scanner-db-backups-<account_id>` |
| **VPC endpoints** | `vpc_endpoints.tf`, `vpc_endpoints_ecs.tf` | Secrets Manager, S3 gateway, ECR API/DKR, CloudWatch Logs |
| **EC2 IAM** | `ec2_iam.tf` | Instance role for UI host (Bedrock, Secrets Manager, ECS RunTask) |

## Prerequisites

- Terraform >= 1.6
- AWS CLI with profile `dast-poc` configured locally (profile name is legacy; resources use `dast-scanner` naming)

Verify credentials:

```powershell
aws sts get-caller-identity --profile dast-poc
```

## Usage

```powershell
cd infra/terraform
Copy-Item terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set ec2_security_group_id and ec2_private_ip
terraform init
terraform fmt -recursive
terraform validate
terraform plan -var-file=terraform.tfvars -out=tfplan
terraform apply tfplan
```

- **Profile:** `dast-poc` (see `providers.tf`)
- **Region:** `us-east-2`

**Do NOT run `terraform apply` without explicit approval.** Review the plan first; applying creates billable AWS resources. Application code deploys to EC2 separately (`deploy.sh`) — not via Terraform.

## Variables you must supply

| Variable | Description |
|----------|-------------|
| `ec2_security_group_id` | SG of existing EC2 UI host (`3.20.180.251`) |
| `ec2_private_ip` | Private IP of that host (ALB target) |

Optional: `domain_name` — when set, creates ACM cert + HTTPS listener and HTTP→HTTPS redirect.

## Outputs

- `rds_endpoint` — connect string host
- `rds_secret_arn` — Secrets Manager secret **`dast/rds/master`** (username, password, host, port, dbname)
- `ecr_scanner_runner_url` — push target for `scanners/runner` image (when ECS enabled)
- `alb_dns_name` / `alb_zone_id` — when ALB enabled
- `db_security_group_id`

## ALB health check

Target group health check uses `GET /healthz` on the scanner app (port 80 by default).

## State backend

S3 backend is stubbed in `versions.tf` and will be wired in a later PR.

## WAF — Web Application Firewall

When `enable_waf` and `enable_alb` are true (defaults), Terraform attaches a **regional** WAF Web ACL to the ALB with:

| Priority | Rule | Action |
|----------|------|--------|
| 0 | Source IP in `trusted_cidrs` IPSet | **ALLOW** (skip remaining rules) |
| 1 | AWSManagedRulesAmazonIpReputationList | BLOCK |
| 2 | AWSManagedRulesAnonymousIpList | BLOCK |
| 3 | Rate limit (`waf_rate_limit`, default 10,000 / 5 min / IP) | BLOCK |
| 4 | AWSManagedRulesCommonRuleSet | COUNT (log only) |
| 5 | AWSManagedRulesSQLiRuleSet | COUNT (log only) |
| default | — | ALLOW |

**OWASP tuning:** Common Rule Set and SQLi run in **COUNT** mode for ~2 weeks so you can review CloudWatch/WAF logs without blocking legitimate scanner traffic. Promote to BLOCK by changing `override_action` from `count {}` to `none {}` in `waf.tf`.

**Zscaler / trusted proxies:** Add corporate egress CIDRs to `trusted_cidrs` in `terraform.tfvars` (fetch ranges from [config.zscaler.com](https://config.zscaler.com)). The IPSet starts empty; priority-0 **ALLOW** matches only when the client IP is in that set.

**Logging:** WAF logs go to CloudWatch log group `aws-waf-logs-dast-scanner` (30-day retention). AWS requires the `aws-waf-logs-` prefix.

**HTTPS:** WAF is on the ALB; HTTPS listener is still gated on `domain_name` / ACM cert.

## Weekly DB Backup to S3

When `enable_backup_lambda` is true (default):

- **Schedule:** EventBridge `cron(0 2 ? * SUN *)` — every Sunday 02:00 UTC
- **Bucket:** `dast-scanner-db-backups-<account_id>` (see output `db_backups_bucket_name`)
- **Lifecycle:** 90 days Standard → Glacier; delete current objects after 180 days; noncurrent versions after 30 days

**Format:** Each run produces a **gzip'd tar** of per-table **CSV** files plus `manifest.json`. This is **not** `pg_dump` format.

**Restore (manual):**

1. Download the object from S3 (`backups/YYYY/MM/DD/dast_scanner-*.tar.gz`).
2. `tar -xzf` / extract; each `*.csv` is one table.
3. Recreate schema (e.g. `migrations/0001_init.sql`).
4. `COPY tablename FROM 'file.csv' WITH (FORMAT csv, HEADER true);`

**Manual invoke:**

```powershell
aws lambda invoke --function-name dast-scanner-db-backup --profile dast-poc out.json
type out.json
```

### Lambda build artifacts (required before apply)

From `infra/terraform/lambda` on Windows (cross-compile for Lambda Linux):

```powershell
mkdir build\python -Force
pip install --target build/python --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.12 "psycopg[binary]>=3.1"
python -c "import zipfile, pathlib; root=pathlib.Path('.'); z=zipfile.ZipFile('psycopg_layer.zip','w',zipfile.ZIP_DEFLATED); py=root/'build'/'python';
[ z.write(p, p.relative_to(py.parent).as_posix().replace(chr(92),'/')) for p in py.rglob('*') if p.is_file() ]; z.close()"
python -c "import zipfile; z=zipfile.ZipFile('db_backup.zip','w'); z.write('db_backup.py','db_backup.py'); z.close()"
```

Committed zips (`psycopg_layer.zip`, `db_backup.zip`) are used by Terraform; rebuild after changing `db_backup.py` or bumping psycopg. Staging dir `lambda/build/` is gitignored.
