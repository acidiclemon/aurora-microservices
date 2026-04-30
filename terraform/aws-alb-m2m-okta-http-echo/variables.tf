# -----------------------------------------------------------------------------
# General Settings
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "The AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name prefix used for resource naming"
  type        = string
  default     = "alb-okta-echo"
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.111.0.0/16"
}

# -----------------------------------------------------------------------------
# Okta OIDC Variables
# -----------------------------------------------------------------------------

variable "okta_client_id" {
  description = "The OIDC client ID from Okta"
  type        = string
  sensitive   = true
}

variable "okta_client_secret" {
  description = "The OIDC client secret from Okta"
  type        = string
  sensitive   = true
}

variable "okta_issuer" {
  description = "The OIDC issuer URL (e.g., https://<your-okta-domain>/oauth2/default)"
  type        = string
}

variable "okta_authorization_endpoint" {
  description = "The Okta authorization endpoint URL"
  type        = string
}

variable "okta_token_endpoint" {
  description = "The Okta token endpoint URL"
  type        = string
}

variable "okta_user_info_endpoint" {
  description = "The Okta user info endpoint URL"
  type        = string
}

# -----------------------------------------------------------------------------
# DNS & HTTPS Configuration
# -----------------------------------------------------------------------------

variable "route53_zone_name" {
  description = "The Route 53 Hosted Zone name for your domain (e.g., example.com)"
  type        = string
}

variable "alb_record_name" {
  description = "The sub-domain intended for the application (e.g., echo.example.com)"
  type        = string
}

variable "api_record_name" {
  description = "The sub-domain intended for the M2M API requests (e.g., api.example.com)"
  type        = string
}

variable "acm_certificate_domain" {
  description = "The domain name of the ACM certificate to attach to the ALB (must be issued and valid)"
  type        = string
}

variable "allowed_source_ips" {
  description = "List of source IP CIDRs allowed to bypass Okta authentication"
  type        = list(string)
}

variable "bypass_uuid_header_name" {
  description = "The name of the HTTP header required to bypass Okta auth"
  type        = string
}

variable "bypass_uuid_header_value" {
  description = "The value of the HTTP header required to bypass Okta auth"
  type        = string
  sensitive   = true
}

variable "disable_okta_auth_redirect" {
  description = "If true, blocks access completely instead of redirecting to Okta (unless bypass rule matches)"
  type        = bool
  default     = false
}

variable "api_allowed_source_ips" {
  description = "List of allowed IP CIDR blocks for the M2M API endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_bypass_rule" {
  description = "If true, creates the bypass_okta ALB listener rule allowing header-based and IP-based authentication bypass"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# ECS Exec (interactive shell via AWS Systems Manager)
# -----------------------------------------------------------------------------

variable "enable_ecs_exec" {
  description = <<-EOT
    Enable ECS Exec on ECS services, allowing interactive shell access to
    running containers via the AWS Console or CLI without SSH or a bastion host.

    Prerequisites (already wired by this module when true):
      • Task Role has ssmmessages:* IAM permissions      (iam.tf)
      • SSM, SSMMessages, EC2Messages VPC Endpoints exist (network.tf)
      • Cluster execute_command_configuration is set      (ecs.tf)

    Usage (CLI):
      aws ecs execute-command \
        --cluster <cluster-name> \
        --task <task-id> \
        --container http-echo \
        --interactive \
        --command "/bin/sh"

    Usage (Console):
      ECS → Clusters → <cluster> → Tasks → <task> → Execute command tab.

    Set to false in production if interactive access is not required.
  EOT
  type        = bool
  default     = true
}
