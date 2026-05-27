resource "aws_wafv2_web_acl" "main" {
  count = var.enable_waf && var.enable_alb ? 1 : 0

  name        = "dast-scanner"
  description = "WAF for DAST scanner ALB - public-facing, app-level SSO or local auth"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awsIpReputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-anonymous-ip"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAnonymousIpList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awsAnonymousIp"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rateLimit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-common-rules"
    priority = 4

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awsCommonRules"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli-rules"
    priority = 5

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "awsSqliRules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "dastScannerWebAcl"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "dast-scanner-waf"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count = var.enable_waf && var.enable_alb ? 1 : 0

  resource_arn = aws_lb.main[0].arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn
}

resource "aws_cloudwatch_log_group" "waf" {
  count = var.enable_waf && var.enable_alb ? 1 : 0

  name              = "aws-waf-logs-dast-scanner"
  retention_in_days = 30

  tags = {
    Name = "dast-scanner-waf-logs"
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  count = var.enable_waf && var.enable_alb ? 1 : 0

  policy_name = "waf-logs-dast-scanner"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.waf[0].arn}:*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.enable_waf && var.enable_alb ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.main[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
