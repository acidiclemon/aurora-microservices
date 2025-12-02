variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Domain name for the application (e.g. shop.example.com)"
  type        = string
  default     = ""
}
