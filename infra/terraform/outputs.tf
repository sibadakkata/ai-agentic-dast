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
  description = "ACM certificate ARN for ALB HTTPS listener"
  value       = var.enable_alb && var.ui_acm_certificate_arn != "" ? var.ui_acm_certificate_arn : null
}

output "waf_web_acl_arn" {
  value       = var.enable_waf && var.enable_alb ? aws_wafv2_web_acl.main[0].arn : null
  description = "WAF Web ACL ARN attached to the ALB"
}

output "db_backups_bucket_name" {
  value       = var.enable_backup_lambda ? aws_s3_bucket.db_backups[0].id : null
  description = "S3 bucket holding weekly DB backups"
}

output "db_backups_bucket_arn" {
  value = var.enable_backup_lambda ? aws_s3_bucket.db_backups[0].arn : null
}

output "lambda_backup_function_name" {
  value = var.enable_backup_lambda ? aws_lambda_function.db_backup[0].function_name : null
}
