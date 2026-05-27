resource "aws_security_group" "alb" {
  count = var.enable_alb ? 1 : 0

  name        = "dast-scanner-poc-alb"
  description = "ALB for DAST scanner UI"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "dast-scanner-poc-alb"
  }
}

resource "aws_lb" "main" {
  count = var.enable_alb ? 1 : 0

  name               = "dast-scanner-poc"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Name = "dast-scanner-poc-alb"
  }
}

resource "aws_lb_target_group" "ui" {
  count = var.enable_alb ? 1 : 0

  name        = "dast-scanner-poc-ui"
  port        = var.app_port
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/healthz"
    matcher             = "200"
  }

  tags = {
    Name = "dast-scanner-poc-ui"
  }
}

resource "aws_lb_target_group_attachment" "ec2" {
  count = var.enable_alb ? 1 : 0

  target_group_arn = aws_lb_target_group.ui[0].arn
  target_id        = var.ec2_private_ip
  port             = var.app_port
}

resource "aws_lb_listener" "http" {
  count = var.enable_alb ? 1 : 0

  load_balancer_arn = aws_lb.main[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.domain_name != "" ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.domain_name != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.domain_name == "" ? aws_lb_target_group.ui[0].arn : null
  }
}

resource "aws_acm_certificate" "main" {
  count = var.enable_alb && var.domain_name != "" ? 1 : 0

  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "dast-scanner-poc"
  }
}

resource "aws_lb_listener" "https" {
  count = var.enable_alb && var.domain_name != "" ? 1 : 0

  load_balancer_arn = aws_lb.main[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-T13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.main[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ui[0].arn
  }

  depends_on = [aws_acm_certificate.main]
}
