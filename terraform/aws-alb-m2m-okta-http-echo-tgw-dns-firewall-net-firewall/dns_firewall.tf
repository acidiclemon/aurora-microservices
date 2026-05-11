# =============================================================================
# dns_firewall.tf  —  Route 53 Resolver DNS Firewall
#
# Restricts DNS resolution in the ECS VPC so that only the Okta domain
# (and essential AWS service domains) can be queried.  All other DNS
# queries are blocked, preventing data exfiltration via DNS tunnelling.
# =============================================================================

# -----------------------------------------------------------------------------
# DNS Firewall Rule Group
# -----------------------------------------------------------------------------

resource "aws_route53_resolver_firewall_domain_list" "okta_allow" {
  name    = "${var.project_name}-okta-domains"
  domains = [
    "${var.okta_domain}",
    "*.${var.okta_domain}",
  ]

  tags = {
    Name = "${var.project_name}-okta-domain-list"
  }
}

# AWS service domains are needed for VPC endpoint private DNS resolution
# and ECR image pulls. Without these, ECS tasks cannot start.
resource "aws_route53_resolver_firewall_domain_list" "aws_services_allow" {
  name    = "${var.project_name}-aws-service-domains"
  domains = [
    "*.amazonaws.com",
    "*.aws.amazon.com",
  ]

  tags = {
    Name = "${var.project_name}-aws-service-domain-list"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "block_all" {
  name    = "${var.project_name}-block-all"
  domains = ["*"]

  tags = {
    Name = "${var.project_name}-block-all-domain-list"
  }
}

# -----------------------------------------------------------------------------
# DNS Firewall Rule Group — rules evaluated in priority order
# -----------------------------------------------------------------------------

resource "aws_route53_resolver_firewall_rule_group" "main" {
  name = "${var.project_name}-dns-fw-rule-group"

  tags = {
    Name = "${var.project_name}-dns-fw-rule-group"
  }
}

# Priority 100: Allow Okta domain queries
resource "aws_route53_resolver_firewall_rule" "allow_okta" {
  name                    = "allow-okta"
  action                  = "ALLOW"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.okta_allow.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  priority                = 100
}

# Priority 200: Allow AWS service domains (VPC endpoints, ECR, etc.)
resource "aws_route53_resolver_firewall_rule" "allow_aws_services" {
  name                    = "allow-aws-services"
  action                  = "ALLOW"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.aws_services_allow.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  priority                = 200
}

# Priority 9000: Block everything else
resource "aws_route53_resolver_firewall_rule" "block_all" {
  name                    = "block-all-other"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.block_all.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  priority                = 9000
}

# -----------------------------------------------------------------------------
# Associate the DNS Firewall rule group with the ECS VPC
# -----------------------------------------------------------------------------

resource "aws_route53_resolver_firewall_rule_group_association" "ecs_vpc" {
  name                   = "${var.project_name}-dns-fw-ecs-vpc"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.main.id
  vpc_id                 = aws_vpc.main.id
  priority               = 101

  tags = {
    Name = "${var.project_name}-dns-fw-assoc-ecs-vpc"
  }
}
