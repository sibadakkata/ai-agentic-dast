# VPC endpoints so dast-scanner-db-backup (private subnets, no NAT) can reach
# Secrets Manager and S3 without a public egress path.

data "aws_route_tables" "default" {
  count = var.enable_backup_lambda ? 1 : 0

  vpc_id = data.aws_vpc.default.id
}

resource "aws_security_group" "vpce_secretsmanager" {
  count = var.enable_backup_lambda ? 1 : 0

  name        = "dast-scanner-vpce-secretsmanager"
  description = "Interface VPC endpoint for Secrets Manager (backup Lambda)"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "dast-scanner-vpce-secretsmanager"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "vpce_secretsmanager_ingress_from_lambda" {
  count = var.enable_backup_lambda ? 1 : 0

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id         = aws_security_group.vpce_secretsmanager[0].id
  source_security_group_id = aws_security_group.lambda_backup[0].id
  description              = "HTTPS from backup Lambda"
}

resource "aws_vpc_endpoint" "s3" {
  count = var.enable_backup_lambda ? 1 : 0

  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.default[0].ids

  tags = {
    Name = "dast-scanner-s3-gateway"
  }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  count = var.enable_backup_lambda ? 1 : 0

  vpc_id              = data.aws_vpc.default.id
  service_name         = "com.amazonaws.${data.aws_region.current.name}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.default.ids
  security_group_ids  = [aws_security_group.vpce_secretsmanager[0].id]
  private_dns_enabled = true

  tags = {
    Name = "dast-scanner-secretsmanager"
  }
}
