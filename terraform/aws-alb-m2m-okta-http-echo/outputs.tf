output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "alb_dns_name" {
  description = "The DNS name of the Application Load Balancer"
  value       = aws_lb.app.dns_name
}

output "application_url" {
  description = "The URL of the application via Route53"
  value       = "https://${var.alb_record_name}"
}

output "api_url" {
  description = "The URL of the API (M2M) via Route53"
  value       = "https://${var.api_record_name}"
}

output "ecs_cluster_name" {
  description = "The name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "The name of the ECS service"
  value       = aws_ecs_service.echo.name
}
