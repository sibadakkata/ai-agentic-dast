# CloudWatch alarms + SNS for DAST scanner ALB / ACM.

resource "aws_sns_topic" "alerts" {
  name = "dast-scanner-alerts"

  lifecycle {
    ignore_changes = [tags, tags_all]
  }
}

locals {
  alb_arn_prefix = "arn:aws:elasticloadbalancing:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:"
  alb_dimension_lb = var.enable_alb ? trimprefix(
    aws_lb.main[0].arn,
    "${local.alb_arn_prefix}loadbalancer/"
  ) : ""
  alb_dimension_tg = var.enable_alb ? trimprefix(
    aws_lb_target_group.ui[0].arn,
    local.alb_arn_prefix
  ) : ""
}

resource "aws_cloudwatch_metric_alarm" "alb_target_unhealthy" {
  count = var.enable_alb ? 1 : 0

  alarm_name          = "dast-alb-target-unhealthy"
  alarm_description   = "ALB target unhealthy"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "missing"

  dimensions = {
    LoadBalancer = local.alb_dimension_lb
    TargetGroup  = local.alb_dimension_tg
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  lifecycle {
    ignore_changes = [tags_all, alarm_actions]
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx_rate" {
  count = var.enable_alb ? 1 : 0

  alarm_name          = "dast-alb-5xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "missing"

  dimensions = {
    LoadBalancer = local.alb_dimension_lb
    TargetGroup  = local.alb_dimension_tg
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  lifecycle {
    ignore_changes = [tags_all, alarm_actions]
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_elb_5xx_rate" {
  count = var.enable_alb ? 1 : 0

  alarm_name          = "dast-alb-elb-5xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "missing"

  dimensions = {
    LoadBalancer = local.alb_dimension_lb
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  lifecycle {
    ignore_changes = [tags_all, alarm_actions]
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_target_latency_p99" {
  count = var.enable_alb ? 1 : 0

  alarm_name          = "dast-alb-target-latency-p99"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  extended_statistic  = "p99"
  threshold           = 30
  treat_missing_data  = "missing"

  dimensions = {
    LoadBalancer = local.alb_dimension_lb
    TargetGroup  = local.alb_dimension_tg
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  lifecycle {
    ignore_changes = [tags_all, alarm_actions]
  }
}

resource "aws_cloudwatch_metric_alarm" "cert_expiry" {
  count = var.enable_alb && var.ui_acm_certificate_arn != "" ? 1 : 0

  alarm_name          = "dast-cert-expiry"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DaysToExpiry"
  namespace           = "AWS/CertificateManager"
  period              = 86400
  statistic           = "Minimum"
  threshold           = 30
  treat_missing_data  = "missing"

  dimensions = {
    CertificateArn = var.ui_acm_certificate_arn
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  lifecycle {
    ignore_changes = [tags_all, alarm_actions]
  }
}