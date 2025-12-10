resource "aws_lb_target_group" "this" {
  name     = var.name
  port     = var.port
  protocol = var.protocol
  vpc_id   = var.vpc_id
  target_type = "ip"
  deregistration_delay = 20  # Default is 300 (5 mins). Set to 0-30

  health_check {
    path = var.health_check_path
  }
}
