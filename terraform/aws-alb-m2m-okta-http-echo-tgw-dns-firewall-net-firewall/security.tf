# =============================================================================
# security.tf  —  Security Groups
#
# Topology:
#   ALB SG          → accepts 443 from internet; egresses to VPC only
#   ECS Tasks SG    → accepts 8080/4180 from ALB; egresses to VPC Endpoints
#                     and the internet (via TGW path) for Okta
#   VPC Endpoints SG → declared in network.tf
# =============================================================================

# -----------------------------------------------------------------------------
# ALB Security Group
# -----------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Internet-facing ALB: accept HTTPS, egress to VPC only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Egress to ECS tasks and Internet (for OIDC token exchange)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# -----------------------------------------------------------------------------
# ECS Tasks Security Group  (main task: http-echo + envoy sidecar)
# -----------------------------------------------------------------------------

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-ecs-tasks-sg"
  description = "Main ECS task: inbound from ALB, egress to VPCE and TGW (for Okta)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTP echo from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Envoy M2M proxy from ALB"
    from_port       = 4180
    to_port         = 4180
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Egress: HTTPS to VPC Endpoints (AWS APIs)
  egress {
    description     = "HTTPS to VPC Endpoints (AWS APIs)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  # Egress: HTTPS to S3 Gateway Endpoint
  egress {
    description     = "HTTPS to S3 Gateway Endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  # Egress: HTTPS to Okta (internet via TGW path)
  # Network Firewall and DNS Firewall will restrict this to Okta domains only.
  egress {
    description = "HTTPS to internet (via TGW/NAT)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-ecs-tasks-sg"
  }
}
