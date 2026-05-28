variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.small"
}

variable "allocated_storage" {
  description = "RDS allocated storage (GB)"
  type        = number
  default     = 20
}

variable "backup_retention_period" {
  description = "RDS backup retention (days)"
  type        = number
  default     = 7
}

variable "engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "16.14"
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  default     = "dast_scanner"
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "dast_admin"
}

variable "ec2_public_ip" {
  description = "Existing EC2 UI host public IP (reference)"
  type        = string
  default     = "3.20.180.251"
}

variable "ec2_security_group_id" {
  description = "Security group ID of the existing EC2 scanner host"
  type        = string
}

variable "ec2_private_ip" {
  description = "Private IP of the existing EC2 scanner host (ALB target)"
  type        = string
}

variable "domain_name" {
  description = "Optional domain for ACM + HTTPS; empty = HTTP only on port 80"
  type        = string
  default     = ""
}

variable "enable_alb" {
  description = "Create Application Load Balancer in front of EC2"
  type        = bool
  default     = true
}

variable "app_port" {
  description = "Scanner UI port on EC2"
  type        = number
  default     = 80
}

variable "waf_rate_limit" {
  description = "Rate limit per IP per 5 min for WAF (BLOCK above this)"
  type        = number
  default     = 10000
}

variable "enable_waf" {
  description = "Enable WAF on the ALB"
  type        = bool
  default     = true
}

variable "enable_backup_lambda" {
  description = "Enable weekly DB backup Lambda + S3 bucket"
  type        = bool
  default     = true
}

variable "enable_redis" {
  description = "ElastiCache Redis for live scan events (~$12/mo)"
  type        = bool
  default     = true
}

variable "enable_ecs_runner" {
  description = "ECS cluster + Fargate task definition for per-scan workers"
  type        = bool
  default     = true
}

variable "scanner_runner_image_tag" {
  description = "ECR image tag for scanner runner task definition"
  type        = string
  default     = "latest"
}

variable "ec2_iam_role_name" {
  description = "IAM role name attached to EC2 UI instance (for ecs:RunTask)"
  type        = string
  default     = ""
}
