resource "aws_security_group" "alb" {
  count = var.enable_alb ? 1 : 0

  name        = "dast-scanner-alb"
  description = "ALB for DAST scanner UI"
  vpc_id      = data.aws_vpc.default.id

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
    Name = "dast-scanner-alb"
  }
}

resource "aws_lb" "main" {
  count = var.enable_alb ? 1 : 0

  name               = "dast-scanner"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = data.aws_subnets.default.ids

  tags = {
    Name = "dast-scanner-alb"
  }
}

resource "aws_lb_target_group" "ui" {
  count = var.enable_alb ? 1 : 0

  name        = "dast-scanner-ui-https"
  port        = var.app_port
  protocol    = "HTTPS"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = {
    Name = "dast-scanner-ui-https"
  }
}

resource "aws_lb_target_group_attachment" "ec2" {
  count = var.enable_alb ? 1 : 0

  target_group_arn = aws_lb_target_group.ui[0].arn
  target_id        = var.ec2_private_ip
  port             = var.app_port
}

resource "aws_lb_listener" "https" {
  count = var.enable_alb && var.ui_acm_certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.main[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.ui_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ui[0].arn
  }
}
