resource "aws_s3_bucket" "db_backups" {
  count = var.enable_backup_lambda ? 1 : 0

  bucket = "dast-scanner-db-backups-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "dast-scanner-db-backups"
  }
}

resource "aws_s3_bucket_versioning" "db_backups" {
  count = var.enable_backup_lambda ? 1 : 0

  bucket = aws_s3_bucket.db_backups[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "db_backups" {
  count = var.enable_backup_lambda ? 1 : 0

  bucket = aws_s3_bucket.db_backups[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "db_backups" {
  count = var.enable_backup_lambda ? 1 : 0

  bucket = aws_s3_bucket.db_backups[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "db_backups" {
  count = var.enable_backup_lambda ? 1 : 0

  bucket = aws_s3_bucket.db_backups[0].id

  rule {
    id     = "transition_to_glacier"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "delete_old"
    status = "Enabled"

    filter {}

    expiration {
      days = 180
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_lambda_layer_version" "psycopg" {
  count = var.enable_backup_lambda ? 1 : 0

  layer_name          = "dast-scanner-psycopg"
  filename            = "${path.module}/lambda/psycopg_layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/lambda/psycopg_layer.zip")
  compatible_runtimes = ["python3.12"]
}

resource "aws_iam_role" "lambda_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  name = "dast-scanner-db-backup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "dast-scanner-db-backup"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_backup_vpc" {
  count = var.enable_backup_lambda ? 1 : 0

  role       = aws_iam_role.lambda_backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_backup_basic" {
  count = var.enable_backup_lambda ? 1 : 0

  role       = aws_iam_role.lambda_backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_backup_s3" {
  count = var.enable_backup_lambda ? 1 : 0

  name = "s3-backup"
  role = aws_iam_role.lambda_backup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.db_backups[0].arn,
        "${aws_s3_bucket.db_backups[0].arn}/*"
      ]
    }]
  })
}

resource "aws_iam_role_policy" "lambda_backup_secrets" {
  count = var.enable_backup_lambda ? 1 : 0

  name = "secrets-read"
  role = aws_iam_role.lambda_backup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = aws_secretsmanager_secret.rds_master.arn
    }]
  })
}

resource "aws_security_group" "lambda_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  name        = "dast-scanner-lambda-backup"
  description = "Weekly DB backup Lambda - RDS and AWS API egress"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description     = "PostgreSQL to RDS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
  }

  egress {
    description = "HTTPS for Secrets Manager and AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dast-scanner-lambda-backup"
  }
}

resource "aws_security_group_rule" "rds_ingress_from_lambda" {
  count = var.enable_backup_lambda ? 1 : 0

  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.rds.id
  source_security_group_id = aws_security_group.lambda_backup[0].id
  description              = "PostgreSQL from weekly backup Lambda"
}

resource "aws_lambda_function" "db_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  function_name = "dast-scanner-db-backup"
  role          = aws_iam_role.lambda_backup[0].arn
  handler       = "db_backup.handler"
  runtime       = "python3.12"
  timeout       = 900
  memory_size   = 1024

  filename         = "${path.module}/lambda/db_backup.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/db_backup.zip")

  layers = [aws_lambda_layer_version.psycopg[0].arn]

  environment {
    variables = {
      SECRET_ARN = aws_secretsmanager_secret.rds_master.arn
      S3_BUCKET  = aws_s3_bucket.db_backups[0].id
      DB_NAME    = var.db_name
      DB_HOST    = aws_db_instance.main.address
    }
  }

  vpc_config {
    subnet_ids         = data.aws_subnets.default.ids
    security_group_ids = [aws_security_group.lambda_backup[0].id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_backup_vpc,
    aws_iam_role_policy_attachment.lambda_backup_basic,
    aws_iam_role_policy.lambda_backup_s3,
    aws_iam_role_policy.lambda_backup_secrets,
  ]

  tags = {
    Name = "dast-scanner-db-backup"
  }
}

resource "aws_cloudwatch_log_group" "lambda_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  name              = "/aws/lambda/dast-scanner-db-backup"
  retention_in_days = 30

  tags = {
    Name = "dast-scanner-db-backup-logs"
  }
}

resource "aws_cloudwatch_event_rule" "weekly_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  name                = "dast-scanner-weekly-db-backup"
  description         = "Trigger weekly RDS CSV backup to S3 every Sunday 02:00 UTC"
  schedule_expression = "cron(0 2 ? * SUN *)"
}

resource "aws_cloudwatch_event_target" "weekly_backup" {
  count = var.enable_backup_lambda ? 1 : 0

  rule      = aws_cloudwatch_event_rule.weekly_backup[0].name
  target_id = "db-backup-lambda"
  arn       = aws_lambda_function.db_backup[0].arn
}

resource "aws_lambda_permission" "eventbridge" {
  count = var.enable_backup_lambda ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.db_backup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_backup[0].arn
}
