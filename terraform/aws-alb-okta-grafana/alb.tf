# -----------------------------------------------------------------------------
# Data Sources for OIDC and HTTPS
# -----------------------------------------------------------------------------

# Fetch the Route 53 zone based on the provided domain name
data "aws_route53_zone" "primary" {
  name         = var.route53_zone_name
  private_zone = false
}

# Fetch the existing ACM certificate for the application domain
data "aws_acm_certificate" "app" {
  provider    = aws.acm
  domain      = var.acm_certificate_domain
  types       = ["AMAZON_ISSUED"]
  most_recent = true
}

# -----------------------------------------------------------------------------
# Application Load Balancer (ALB)
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# -----------------------------------------------------------------------------
# Target Group for ECS Fargate
# -----------------------------------------------------------------------------

resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip" # Required for Fargate "awsvpc" network mode

  health_check {
    path                = "/api/health"
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# -----------------------------------------------------------------------------
# ALB HTTPS Listener with OIDC Authentication
# -----------------------------------------------------------------------------

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.app.arn

  # Action 1: Forward directly to the Target Group (Grafana handles OAuth natively)
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  tags = {
    Name = "${var.project_name}-listener"
  }
}

# -----------------------------------------------------------------------------
# Route 53 Record for the ALB
# -----------------------------------------------------------------------------

resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = var.alb_record_name
  type    = "A"

  alias {
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}
