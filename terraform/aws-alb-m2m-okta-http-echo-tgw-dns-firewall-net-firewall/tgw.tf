# =============================================================================
# tgw.tf  —  Transit Gateway, Attachments, and Route Tables
#
# Centralised inspection architecture:
#
#   ECS VPC ──► TGW ──► Firewall VPC (NW Firewall inspection)
#                           │
#                           ▼
#                       TGW ──► Egress VPC (NAT → Internet)
#
# Return path:  Internet → NAT → TGW → Firewall VPC → TGW → ECS VPC
#
# Three TGW route tables enforce the traffic flow:
#   • Spoke RT     (ECS VPC)      : 0.0.0.0/0  → Firewall attachment
#   • Inspection RT (Firewall VPC): 0.0.0.0/0  → Egress attachment
#                                   ECS CIDR   → ECS attachment (return)
#   • Egress RT    (Egress VPC)   : ECS CIDR   → Firewall attachment (return
#                                                 through inspection)
# =============================================================================

# -----------------------------------------------------------------------------
# Transit Gateway
# -----------------------------------------------------------------------------

resource "aws_ec2_transit_gateway" "main" {
  description                     = "${var.project_name} centralized inspection TGW"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = {
    Name = "${var.project_name}-tgw"
  }
}

# -----------------------------------------------------------------------------
# TGW VPC Attachments
# -----------------------------------------------------------------------------

# ECS VPC attachment — private subnets
resource "aws_ec2_transit_gateway_vpc_attachment" "ecs" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.main.id
  subnet_ids         = aws_subnet.private[*].id

  # Appliance mode ensures symmetric routing through the firewall
  appliance_mode_support = "enable"

  tags = {
    Name = "${var.project_name}-tgw-attach-ecs"
  }
}

# Firewall VPC attachment — TGW subnets (NOT the firewall endpoint subnets)
resource "aws_ec2_transit_gateway_vpc_attachment" "firewall" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.firewall.id
  subnet_ids         = aws_subnet.firewall_tgw[*].id

  appliance_mode_support = "enable"

  tags = {
    Name = "${var.project_name}-tgw-attach-firewall"
  }
}

# Egress VPC attachment — TGW subnets
resource "aws_ec2_transit_gateway_vpc_attachment" "egress" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.egress.id
  subnet_ids         = aws_subnet.egress_tgw[*].id

  tags = {
    Name = "${var.project_name}-tgw-attach-egress"
  }
}

# -----------------------------------------------------------------------------
# TGW Route Tables
# -----------------------------------------------------------------------------

# --- Spoke RT (attached to ECS VPC) ---
resource "aws_ec2_transit_gateway_route_table" "spoke" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name = "${var.project_name}-tgw-rt-spoke"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "ecs" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ecs.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

# All traffic from ECS VPC → Firewall VPC for inspection
resource "aws_ec2_transit_gateway_route" "spoke_default" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.firewall.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.spoke.id
}

# --- Inspection RT (attached to Firewall VPC) ---
resource "aws_ec2_transit_gateway_route_table" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name = "${var.project_name}-tgw-rt-inspection"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "firewall" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.firewall.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

# Inspected egress traffic → Egress VPC for NAT
resource "aws_ec2_transit_gateway_route" "inspection_default" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

# Return traffic to ECS VPC
resource "aws_ec2_transit_gateway_route" "inspection_return_to_ecs" {
  destination_cidr_block         = var.vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.ecs.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection.id
}

# --- Egress RT (attached to Egress VPC) ---
resource "aws_ec2_transit_gateway_route_table" "egress" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name = "${var.project_name}-tgw-rt-egress"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "egress" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.egress.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

# Return traffic from internet/NAT → Firewall VPC for inspection before ECS
resource "aws_ec2_transit_gateway_route" "egress_return_to_firewall" {
  destination_cidr_block         = var.vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.firewall.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress.id
}

# -----------------------------------------------------------------------------
# VPC Route: ECS private subnets → TGW (0.0.0.0/0)
# Declared here (not in network.tf) to avoid a dependency cycle.
# -----------------------------------------------------------------------------

resource "aws_route" "ecs_private_to_tgw" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.ecs]
}
