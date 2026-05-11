# =============================================================================
# firewall.tf  —  Firewall VPC + AWS Network Firewall
#
# This VPC hosts AWS Network Firewall endpoints that inspect all egress
# traffic from the ECS VPC before it reaches the Egress VPC (NAT).
#
# Subnet layout (per AZ):
#   • Firewall subnets  — Network Firewall endpoint ENIs
#   • TGW subnets       — Transit Gateway attachment ENIs
#
# Traffic flow:
#   TGW delivers traffic → TGW subnet → route to FW endpoint → inspected
#   → FW subnet route table → back to TGW (toward Egress VPC)
# =============================================================================

# -----------------------------------------------------------------------------
# Firewall VPC — no IGW, no NAT Gateway
# -----------------------------------------------------------------------------

resource "aws_vpc" "firewall" {
  cidr_block           = var.firewall_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-firewall-vpc"
  }
}

# -----------------------------------------------------------------------------
# Firewall Subnets — Network Firewall endpoints (1 per AZ)
# -----------------------------------------------------------------------------

resource "aws_subnet" "firewall" {
  count             = 2
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = cidrsubnet(var.firewall_vpc_cidr, 8, count.index)       # .0/24, .1/24
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-fw-subnet-${count.index + 1}"
  }
}

# -----------------------------------------------------------------------------
# TGW Attachment Subnets in Firewall VPC (1 per AZ)
# -----------------------------------------------------------------------------

resource "aws_subnet" "firewall_tgw" {
  count             = 2
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = cidrsubnet(var.firewall_vpc_cidr, 8, count.index + 2)   # .2/24, .3/24
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-fw-tgw-subnet-${count.index + 1}"
  }
}

# -----------------------------------------------------------------------------
# AWS Network Firewall — Stateful rule group (allow Okta domain only)
# -----------------------------------------------------------------------------

resource "aws_networkfirewall_rule_group" "allow_okta" {
  capacity = 100
  name     = "${var.project_name}-allow-okta-only"
  type     = "STATEFUL"

  rule_group {
    # Domain-based filtering via TLS SNI inspection
    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["TLS_SNI", "HTTP_HOST"]
        targets              = [".${var.okta_domain}"]
      }
    }

    stateful_rule_options {
      capacity = 100
    }
  }

  tags = {
    Name = "${var.project_name}-nfw-rg-allow-okta"
  }
}

# -----------------------------------------------------------------------------
# Network Firewall Policy
# -----------------------------------------------------------------------------

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.project_name}-fw-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateful_default_actions = ["aws:drop_established"]

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    stateful_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.allow_okta.arn
    }
  }

  tags = {
    Name = "${var.project_name}-fw-policy"
  }
}

# -----------------------------------------------------------------------------
# AWS Network Firewall — deployed into both AZ firewall subnets
# -----------------------------------------------------------------------------

resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.project_name}-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.firewall.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall[*].id
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = {
    Name = "${var.project_name}-network-firewall"
  }
}

# -----------------------------------------------------------------------------
# Locals — extract per-AZ firewall endpoint IDs from the sync_states output
# -----------------------------------------------------------------------------

locals {
  # Build a map of AZ → VPC endpoint ID for routing
  fw_endpoint_ids = {
    for ss in aws_networkfirewall_firewall.main.firewall_status[0].sync_states :
    ss.availability_zone => ss.attachment[0].endpoint_id
  }
}

# -----------------------------------------------------------------------------
# Route Tables — Firewall VPC
# -----------------------------------------------------------------------------

# TGW attachment subnets: route all traffic to the Network Firewall endpoint
# in the same AZ for inspection.
resource "aws_route_table" "firewall_tgw" {
  count  = 2
  vpc_id = aws_vpc.firewall.id

  tags = {
    Name = "${var.project_name}-fw-tgw-rt-${count.index + 1}"
  }
}

resource "aws_route" "firewall_tgw_to_fw_endpoint" {
  count                  = 2
  route_table_id         = aws_route_table.firewall_tgw[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.fw_endpoint_ids[data.aws_availability_zones.available.names[count.index]]
}

resource "aws_route_table_association" "firewall_tgw" {
  count          = 2
  subnet_id      = aws_subnet.firewall_tgw[count.index].id
  route_table_id = aws_route_table.firewall_tgw[count.index].id
}

# Firewall subnets: after inspection, route traffic to TGW (toward Egress VPC).
# Return traffic to ECS VPC also goes via TGW.
resource "aws_route_table" "firewall" {
  count  = 2
  vpc_id = aws_vpc.firewall.id

  tags = {
    Name = "${var.project_name}-fw-rt-${count.index + 1}"
  }
}

resource "aws_route" "firewall_to_tgw" {
  count                  = 2
  route_table_id         = aws_route_table.firewall[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.firewall]
}

resource "aws_route" "firewall_return_to_ecs" {
  count                  = 2
  route_table_id         = aws_route_table.firewall[count.index].id
  destination_cidr_block = var.vpc_cidr
  transit_gateway_id     = aws_ec2_transit_gateway.main.id

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.firewall]
}

resource "aws_route_table_association" "firewall" {
  count          = 2
  subnet_id      = aws_subnet.firewall[count.index].id
  route_table_id = aws_route_table.firewall[count.index].id
}
