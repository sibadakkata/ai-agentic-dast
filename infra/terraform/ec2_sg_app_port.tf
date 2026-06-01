# Allow ALB -> EC2 app on HTTPS backend port (host nginx on 443).
resource "aws_security_group_rule" "ec2_app_from_alb" {
  count = var.enable_alb ? 1 : 0

  type                     = "ingress"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = var.ec2_security_group_id
  source_security_group_id = aws_security_group.alb[0].id
}
