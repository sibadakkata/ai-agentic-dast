# DAST Scanner — Terraform (POC)

Provisions **RDS PostgreSQL 16** (Multi-AZ) and an optional **Application Load Balancer** in `us-east-2` for the scalable-scanner-platform rollout. See [scalable-scanner-platform-proposal.md](../../docs/architecture/scalable-scanner-platform-proposal.md).

## Prerequisites

- Terraform >= 1.6
- AWS CLI with profile `dast-poc` configured locally

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
terraform plan -var-file=terraform.tfvars
```

**Do NOT run `terraform apply` without explicit approval.** Review the plan first; applying creates billable AWS resources.

## Variables you must supply

| Variable | Description |
|----------|-------------|
| `ec2_security_group_id` | SG of existing EC2 UI host (`3.20.180.251`) |
| `ec2_private_ip` | Private IP of that host (ALB target) |

Optional: `domain_name` — when set, creates ACM cert + HTTPS listener and HTTP→HTTPS redirect.

## Outputs

- `rds_endpoint` — connect string host
- `rds_secret_arn` — Secrets Manager (`dast/poc/rds/master`) with username/password/host/port/dbname
- `alb_dns_name` / `alb_zone_id` — when ALB enabled
- `db_security_group_id`

## ALB health check

Target group health check uses `GET /healthz` on the scanner app (port 8080 by default).

## State backend

S3 backend is stubbed in `versions.tf` and will be wired in a later PR.
