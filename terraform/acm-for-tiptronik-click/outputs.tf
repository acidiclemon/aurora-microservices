output "acm_certificate_arn" {
  description = "The ARN of the certificate"
  value       = module.acm.acm_certificate_arn
}

output "acm_certificate_id" {
  description = "The ID of the certificate (extracted from ARN)"
  value       = element(split("/", module.acm.acm_certificate_arn), length(split("/", module.acm.acm_certificate_arn)) - 1)
}
