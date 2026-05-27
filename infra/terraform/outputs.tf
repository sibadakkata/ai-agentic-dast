output "rds_endpoint" {
  description = "RDS hostname"
  value       = aws_db_instance.main.address
}

output "rds_secret_arn" {
  description = "Secrets Manager ARN for RDS credentials"
  value       = aws_secretsmanager_secret.rds_master.arn
}

output "alb_dns_name" {
  description = "ALB DNS name (null if ALB disabled)"
  value       = var.enable_alb ? aws_lb.main[0].dns_name : null
}

output "alb_zone_id" {
  description = "ALB Route53 zone ID for alias records"
  value       = var.enable_alb ? aws_lb.main[0].zone_id : null
}

output "db_security_group_id" {
  description = "RDS security group ID"
  value       = aws_security_group.rds.id
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN when domain_name is set"
  value       = var.domain_name != "" && var.enable_alb ? aws_acm_certificate.main[0].arn : null
}
