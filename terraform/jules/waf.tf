################################################################################
# AWS WAF v2 — CloudFront Web ACL (F-PCI-05 — PCI DSS Req 6.4.1, 6.4.2)
#
# Protects the public-facing application against OWASP Top 10 attacks using
# AWS Managed Rule Groups. Must be in us-east-1 for CloudFront scope.
################################################################################

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1

  name        = "${var.project_name}-${terraform.workspace}-cloudfront-waf"
  description = "WAF for ${var.project_name}-${terraform.workspace} CloudFront distribution"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # ── Rule 1: AWS Common Rule Set (OWASP Top 10 coverage) ──────────────────
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${terraform.workspace}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 2: SQL Injection Protection ─────────────────────────────────────
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${terraform.workspace}-sqli-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 3: Known Bad Inputs (Log4j, etc.) ───────────────────────────────
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${terraform.workspace}-bad-inputs-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 4: Rate Limiting (DDoS / brute-force mitigation) ───────────────
  rule {
    name     = "RateLimit"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${terraform.workspace}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${terraform.workspace}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Environment = terraform.workspace
    Project     = var.project_name
  }
}

################################################################################
# WAF Logging — CloudWatch Log Group (us-east-1)
################################################################################

resource "aws_cloudwatch_log_group" "waf" {
  provider = aws.us_east_1

  # WAF logging requires the log group name to start with "aws-waf-logs-"
  name              = "aws-waf-logs-${var.project_name}-${terraform.workspace}"
  retention_in_days = 30
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  provider = aws.us_east_1

  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.cloudfront.arn
}
