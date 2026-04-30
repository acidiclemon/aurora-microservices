# =============================================================================
# security.tf  —  Security Groups
#
# Topology:
#   ALB SG          → accepts 443 from internet; egresses to VPC only
#   ECS Tasks SG    → accepts 8080/4180 from ALB; egresses to VPC Endpoints
#                     and the envoy-gateway on port 3128
#   Envoy Gateway SG → accepts 3128 from ECS Tasks; egresses to 0.0.0.0/0:443
#   VPC Endpoints SG → declared in network.tf (shared by all endpoints)
#
# Cross-SG references between ecs_tasks ↔ envoy_gateway would create a
# Terraform dependency cycle if inline rules are used.  The cross-referencing
# ingress/egress rules are therefore declared as separate
# aws_security_group_rule resources below (after both SGs exist).
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

  # Egress restricted to VPC CIDR so ALB can only reach ECS tasks
  egress {
    description = "Egress to VPC (reaches ECS tasks)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# -----------------------------------------------------------------------------
# ECS Tasks Security Group  (main task: http-echo + envoy sidecar)
# -----------------------------------------------------------------------------
# Inbound-only rules are declared inline (no cycle risk).
# The egress rule toward envoy_gateway is declared as a separate rule below.

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-ecs-tasks-sg"
  description = "Main ECS task (air-gapped): inbound from ALB, egress to VPCE and envoy-gateway only"
  vpc_id      = aws_vpc.main.id

  # Inbound: HTTP echo on 8080 from ALB
  ingress {
    description     = "HTTP echo from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Inbound: Envoy M2M proxy on 4180 from ALB
  ingress {
    description     = "Envoy M2M proxy from ALB"
    from_port       = 4180
    to_port         = 4180
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Egress: HTTPS to VPC Endpoints (ECR, ECS, CloudWatch, SSM)
  egress {
    description     = "HTTPS to VPC Endpoints (AWS APIs)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  # Egress: HTTPS to S3 Gateway Endpoint (for ECR image layers)
  egress {
    description     = "HTTPS to S3 Gateway Endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  # NOTE: the egress rule to envoy_gateway (port 3128) is declared separately
  # below to avoid a circular dependency between the two SGs.

  tags = {
    Name = "${var.project_name}-ecs-tasks-sg"
  }
}

# -----------------------------------------------------------------------------
# Envoy Gateway Security Group
# -----------------------------------------------------------------------------
# Inbound from ECS tasks only; outbound HTTPS only.
# The inbound rule from ecs_tasks is declared separately below to break the cycle.

resource "aws_security_group" "envoy_gateway" {
  name        = "${var.project_name}-envoy-gw-sg"
  description = "Envoy gateway: accept proxy from ECS tasks, egress HTTPS to Okta only"
  vpc_id      = aws_vpc.main.id

  # Outbound: only HTTPS (port 443) — reaches Okta endpoints via NAT GW
  egress {
    description = "HTTPS to Okta (internet) via NAT GW"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound: HTTPS to VPC Endpoints (CloudWatch logs, SSM exec)
  egress {
    description     = "HTTPS to VPC Endpoints (CloudWatch / SSM)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpc_endpoints.id]
  }

  # NOTE: the ingress rule from ecs_tasks (port 3128) is declared separately
  # below to avoid a circular dependency.

  tags = {
    Name = "${var.project_name}-envoy-gw-sg"
  }
}

# -----------------------------------------------------------------------------
# Cross-SG rules (declared after both SGs exist to break the cycle)
# -----------------------------------------------------------------------------

# ECS Tasks → Envoy Gateway on port 3128 (forward-proxy egress)
resource "aws_security_group_rule" "ecs_tasks_to_gateway_egress" {
  type                     = "egress"
  description              = "Forward proxy to envoy-gateway (Okta egress)"
  from_port                = 3128
  to_port                  = 3128
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_tasks.id
  source_security_group_id = aws_security_group.envoy_gateway.id
}

# Envoy Gateway ← ECS Tasks on port 3128 (forward-proxy ingress)
resource "aws_security_group_rule" "gateway_from_ecs_tasks_ingress" {
  type                     = "ingress"
  description              = "Forward-proxy from main ECS task"
  from_port                = 3128
  to_port                  = 3128
  protocol                 = "tcp"
  security_group_id        = aws_security_group.envoy_gateway.id
  source_security_group_id = aws_security_group.ecs_tasks.id
}
