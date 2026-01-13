provider "aws" {
  region = "us-east-1"
}

locals {
  # If hosted_zone_id contains a dot, assume it is a name (e.g. example.com)
  hosted_zone_is_name = can(regex("\\.", var.hosted_zone_id))
}

data "aws_route53_zone" "this" {
  name    = local.hosted_zone_is_name ? var.hosted_zone_id : null
  zone_id = local.hosted_zone_is_name ? null : var.hosted_zone_id
}

module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "~> 5.0"

  domain_name = var.domain_name
  zone_id     = data.aws_route53_zone.this.zone_id

  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}"
  ]

  wait_for_validation = true
}
