# Phase 1: allow ALB -> EC2 app on port 80 (existing user-managed :8080 rules stay for fallback).
resource "aws_security_group_rule" "ec2_app_from_alb" {
  count = var.enable_alb ? 1 : 0

  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = var.ec2_security_group_id
  source_security_group_id = aws_security_group.alb[0].id
  description              = "App :80 from ALB"
}
