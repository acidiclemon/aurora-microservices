# =============================================================================
# egress.tf  —  Egress VPC with NAT Gateways
#
# This VPC provides the only internet egress path for the entire architecture.
# NAT Gateways are deployed in public subnets (one per AZ) behind an IGW.
# TGW attachment subnets receive inspected traffic from the Firewall VPC
# and route it to the NAT Gateways.
# =============================================================================

# -----------------------------------------------------------------------------
# Egress VPC
# -----------------------------------------------------------------------------

resource "aws_vpc" "egress" {
  cidr_block           = var.egress_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-egress-vpc"
  }
}

# Internet Gateway for the Egress VPC (required by NAT Gateways)
resource "aws_internet_gateway" "egress" {
  vpc_id = aws_vpc.egress.id

  tags = {
    Name = "${var.project_name}-egress-igw"
  }
}

# -----------------------------------------------------------------------------
# Public / NAT Subnets (1 per AZ) — NAT Gateways live here
# -----------------------------------------------------------------------------

resource "aws_subnet" "egress_public" {
  count                   = 1
  vpc_id                  = aws_vpc.egress.id
  cidr_block              = cidrsubnet(var.egress_vpc_cidr, 8, count.index)    # .0/24
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-egress-public-subnet-${count.index + 1}"
  }
}

# -----------------------------------------------------------------------------
# TGW Attachment Subnets in Egress VPC (1 per AZ)
# -----------------------------------------------------------------------------

resource "aws_subnet" "egress_tgw" {
  count             = 1
  vpc_id            = aws_vpc.egress.id
  cidr_block        = cidrsubnet(var.egress_vpc_cidr, 8, count.index + 2)     # .2/24
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-egress-tgw-subnet-${count.index + 1}"
  }
}

# -----------------------------------------------------------------------------
# Elastic IPs + NAT Gateways — one per AZ for HA
# -----------------------------------------------------------------------------

resource "aws_eip" "egress_nat" {
  count  = 1
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-egress-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "egress" {
  count         = 1
  allocation_id = aws_eip.egress_nat[count.index].id
  subnet_id     = aws_subnet.egress_public[count.index].id

  tags = {
    Name = "${var.project_name}-egress-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.egress]
}

# -----------------------------------------------------------------------------
# Route Tables — Egress VPC
# -----------------------------------------------------------------------------

# Public / NAT subnets: 0.0.0.0/0 → IGW (so NAT GW can reach internet)
# Return traffic to ECS VPC → TGW (goes back through Firewall for inspection)
resource "aws_route_table" "egress_public" {
  vpc_id = aws_vpc.egress.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.egress.id
  }

  tags = {
    Name = "${var.project_name}-egress-public-rt"
  }
}

resource "aws_route" "egress_public_return_to_ecs" {
  route_table_id         = aws_route_table.egress_public.id
  destination_cidr_block = var.vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.egress]
}

resource "aws_route_table_association" "egress_public" {
  count          = 1
  subnet_id      = aws_subnet.egress_public[count.index].id
  route_table_id = aws_route_table.egress_public.id
}

# TGW attachment subnets: 0.0.0.0/0 → NAT GW (same AZ)
resource "aws_route_table" "egress_tgw" {
  count  = 1
  vpc_id = aws_vpc.egress.id

  tags = {
    Name = "${var.project_name}-egress-tgw-rt-${count.index + 1}"
  }
}

resource "aws_route" "egress_tgw_to_nat" {
  count                  = 1
  route_table_id         = aws_route_table.egress_tgw[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.egress[count.index].id
}

resource "aws_route_table_association" "egress_tgw" {
  count          = 1
  subnet_id      = aws_subnet.egress_tgw[count.index].id
  route_table_id = aws_route_table.egress_tgw[count.index].id
}
