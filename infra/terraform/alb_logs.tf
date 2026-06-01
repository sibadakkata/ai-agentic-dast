# ALB access logs bucket (HTTPS cutover / go-live hardening).

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket" "alb_logs" {
  count = var.enable_alb ? 1 : 0

  bucket = "dast-scanner-alb-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  lifecycle {
    ignore_changes = [tags, tags_all, force_destroy]
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count = var.enable_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  count = var.enable_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  count = var.enable_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    id     = "expire-90d"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }

  lifecycle {
    ignore_changes = [rule]
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  count = var.enable_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs[0].arn}/dast-scanner/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs[0].arn}/dast-scanner/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs[0].arn
      }
    ]
  })
}