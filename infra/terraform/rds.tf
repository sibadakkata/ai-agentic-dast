resource "random_password" "db_master" {
  length  = 32
  special = true
}

resource "aws_db_subnet_group" "main" {
  name       = "dast-scanner-poc"
  subnet_ids = data.aws_subnets.default.ids

  tags = {
    Name = "dast-scanner-poc-db-subnets"
  }
}

resource "aws_security_group" "rds" {
  name        = "dast-scanner-poc-rds"
  description = "PostgreSQL for DAST scanner POC"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "PostgreSQL from EC2 scanner"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.ec2_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dast-scanner-poc-rds"
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "dast-scanner-poc-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "main" {
  identifier     = "dast-scanner-poc"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  db_name               = var.db_name
  username              = var.db_username
  password              = random_password.db_master.result
  port                  = 5432

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az               = true
  publicly_accessible    = false
  backup_retention_period = var.backup_retention_period
  deletion_protection    = true
  skip_final_snapshot    = false
  final_snapshot_identifier = "dast-scanner-poc-final-${formatdate("YYYYMMDDhhmm", timestamp())}"

  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name = "dast-scanner-poc"
  }

  lifecycle {
    ignore_changes = [final_snapshot_identifier]
  }
}
