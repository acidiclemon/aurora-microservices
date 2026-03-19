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

variable "acm_certificate_domain" {
  description = "The domain name of the ACM certificate to attach to the ALB (must be issued and valid)"
  type        = string
}

variable "grafana_admin_password" {
  description = "The default admin password for Grafana"
  type        = string
  sensitive   = true
}
