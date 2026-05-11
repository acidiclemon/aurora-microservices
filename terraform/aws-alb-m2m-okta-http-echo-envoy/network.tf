# =============================================================================
# network.tf  —  Air-Gapped VPC with PrivateLink Endpoints
#
# Architecture overview:
#   • Public subnets  → ALB only (internet-facing)
#   • Private subnets → main echo/envoy task  (NO internet egress)
#   • Gateway subnets → envoy-gateway task    (has internet egress to Okta only,
#                                              enforced by SG rules)
#
# The NAT Gateway is REMOVED.  All AWS-API traffic (ECR, ECS, CloudWatch, SSM)
# travels via Interface VPC Endpoints.  S3 (for ECR layer blobs) uses a
# Gateway Endpoint (free, no hourly charge).
#
# The envoy-gateway task lives in the gateway subnets that still route to the
# internet via NAT, but its Security Group restricts egress to Okta ports/IPs
# only (port 443, Okta domain resolved via DNS).  This is the *only* path out
# to the public internet in the entire stack.
# =============================================================================

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true   # Required for VPC Endpoint DNS resolution
  enable_dns_hostnames = true   # Required for VPC Endpoint DNS resolution

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway – still required for the ALB (public subnets) and for the
# envoy-gateway NAT path to reach Okta.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# -----------------------------------------------------------------------------
# Subnets
# -----------------------------------------------------------------------------

# Public subnets — ALB lives here
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)          # .0/24, .1/24
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
  }
}

# Private subnets — main echo+envoy task (air-gapped: NO internet route)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 2)            # .2/24, .3/24
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
  }
}

# Gateway subnets — envoy-gateway task only (has controlled internet egress)
resource "aws_subnet" "gateway" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 4)            # .4/24, .5/24
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-gateway-subnet-${count.index + 1}"
  }
}

# -----------------------------------------------------------------------------
# NAT Gateway — used ONLY by the envoy-gateway task to reach Okta
# -----------------------------------------------------------------------------

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project_name}-nat"
  }

  depends_on = [aws_internet_gateway.main]
}

# -----------------------------------------------------------------------------
# Route Tables
# -----------------------------------------------------------------------------

# Public route table — routes 0.0.0.0/0 to IGW (for ALB)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Private route table — NO default internet route (air-gapped).
# AWS API traffic goes via PrivateLink Endpoints below.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # No 0.0.0.0/0 route — intentionally air-gapped

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

# Gateway route table — routes 0.0.0.0/0 to NAT GW so envoy-gateway can
# reach Okta.  Egress to the actual internet is further restricted at the
# Security Group level to port 443 / Okta domains only.
resource "aws_route_table" "gateway" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-gateway-rt"
  }
}

# -----------------------------------------------------------------------------
# Route Table Associations
# -----------------------------------------------------------------------------

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "gateway" {
  count          = 2
  subnet_id      = aws_subnet.gateway[count.index].id
  route_table_id = aws_route_table.gateway.id
}

# -----------------------------------------------------------------------------
# VPC Endpoints — PrivateLink (Interface) Endpoints
# These allow the air-gapped private subnets to call AWS APIs without any
# internet route.  Each endpoint creates ENIs in the private subnets and
# registers DNS aliases so SDK/CLI calls transparently hit the endpoint.
# -----------------------------------------------------------------------------

# Shared Security Group for all Interface VPC Endpoints
# (allows HTTPS from within the VPC only)
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project_name}-vpce-sg"
  description = "Allow HTTPS from VPC to AWS PrivateLink endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC CIDR to VPC Endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound (endpoints are AWS-managed)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.project_name}-vpce-sg"
  }
}

# ECR API endpoint — used to authenticate / authorise image pulls
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ecr-api"
  }
}

# ECR DKR endpoint — used to pull actual image layers
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ecr-dkr"
  }
}

# ECS Agent endpoint — required for Fargate task lifecycle / exec plane
resource "aws_vpc_endpoint" "ecs_agent" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecs-agent"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ecs-agent"
  }
}

# ECS Telemetry endpoint — required for Fargate metrics / CloudWatch Container Insights
resource "aws_vpc_endpoint" "ecs_telemetry" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecs-telemetry"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ecs-telemetry"
  }
}

# CloudWatch Logs endpoint — task logs go here without internet
resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-logs"
  }
}

# SSM endpoint — required for ECS Exec (SSM Session Manager control channel)
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ssm"
  }
}

# SSM Messages endpoint — required for ECS Exec data channels
resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ssmmessages"
  }
}

# EC2 Messages endpoint — required by SSM agent on Fargate
resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-vpce-ec2messages"
  }
}

# S3 Gateway Endpoint — used by ECR to fetch image layer blobs from S3
# Gateway endpoints are free and don't use Security Groups; they are
# associated with route tables instead.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  # Associate with BOTH private and gateway route tables so all tasks can
  # reach S3 (ECR layer pulls) without hitting the internet.
  route_table_ids = concat(
    aws_route_table.private[*].id,
    [aws_route_table.gateway.id]
  )

  tags = {
    Name = "${var.project_name}-vpce-s3"
  }
}
