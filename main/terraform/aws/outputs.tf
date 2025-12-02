output "alb_dns_name" {
  value = module.alb.dns_name
}

output "redis_endpoint" {
  value = module.redis.endpoint
}
