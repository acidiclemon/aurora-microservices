variable "domain_name" {
  description = "Domain name for the certificate (e.g. example.com)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID or Name (e.g. example.com) for DNS validation"
  type        = string
}
