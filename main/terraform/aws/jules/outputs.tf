output "alb_dns_name" {
  description = "The DNS name of the load balancer"
  value       = module.alb.dns_name
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = try(module.redis.cluster_cache_nodes[0].address, "")
}

output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "ecs_cluster_name" {
  description = "The name of the ECS cluster"
  value       = module.ecs.cluster_name
}

output "cloudfront_domain_name" {
  description = "The domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.this.domain_name
}

output "website_url" {
  description = "The full URL to access the website"
  value       = var.domain_name != "" ? "https://${var.project_name}-${terraform.workspace}.${var.domain_name}" : "http://${module.alb.dns_name}"
}
