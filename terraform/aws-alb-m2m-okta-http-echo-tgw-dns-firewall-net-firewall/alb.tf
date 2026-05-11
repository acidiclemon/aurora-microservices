# -----------------------------------------------------------------------------
# Data Sources for OIDC and HTTPS
# -----------------------------------------------------------------------------

data "aws_route53_zone" "primary" {
  name         = var.route53_zone_name
  private_zone = false
}

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
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
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

resource "aws_lb_target_group" "api" {
  name        = "${var.project_name}-api-tg"
  port        = 4180
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/ping"
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.project_name}-api-tg"
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

  dynamic "default_action" {
    for_each = var.disable_okta_auth_redirect ? [1] : []
    content {
      type = "fixed-response"
      fixed_response {
        content_type = "text/plain"
        message_body = "Access Denied"
        status_code  = "403"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.disable_okta_auth_redirect ? [] : [1]
    content {
      type  = "authenticate-oidc"
      order = 1

      authenticate_oidc {
        authorization_endpoint = var.okta_authorization_endpoint
        client_id              = var.okta_client_id
        client_secret          = var.okta_client_secret
        issuer                 = var.okta_issuer
        token_endpoint         = var.okta_token_endpoint
        user_info_endpoint     = var.okta_user_info_endpoint
        session_cookie_name    = "AWSELBAuthSessionCookie"
        session_timeout        = 3600
      }
    }
  }

  dynamic "default_action" {
    for_each = var.disable_okta_auth_redirect ? [] : [1]
    content {
      type             = "forward"
      order            = 2
      target_group_arn = aws_lb_target_group.app.arn
    }
  }

  tags = {
    Name = "${var.project_name}-listener"
  }
}

# -----------------------------------------------------------------------------
# ALB Listener Rule - Bypass Okta Auth
# -----------------------------------------------------------------------------

resource "aws_lb_listener_rule" "bypass_okta" {
  count        = var.enable_bypass_rule ? 1 : 0
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  condition {
    http_header {
      http_header_name = var.bypass_uuid_header_name
      values           = [var.bypass_uuid_header_value]
    }
  }

  condition {
    source_ip {
      values = var.allowed_source_ips
    }
  }
}

resource "aws_lb_listener_rule" "api_m2m" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 50

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  condition {
    host_header {
      values = [var.api_record_name]
    }
  }

  condition {
    source_ip {
      values = var.api_allowed_source_ips
    }
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

resource "aws_route53_record" "api" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = var.api_record_name
  type    = "A"

  alias {
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}
