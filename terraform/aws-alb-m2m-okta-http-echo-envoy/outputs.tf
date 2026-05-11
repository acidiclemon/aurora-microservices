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
  description = "The name of the main ECS service (http-echo + envoy sidecar)"
  value       = aws_ecs_service.echo.name
}

output "envoy_gateway_service_name" {
  description = "The name of the envoy-gateway ECS service"
  value       = aws_ecs_service.envoy_gateway.name
}

output "service_discovery_namespace" {
  description = "Cloud Map private DNS namespace used for ECS Service Connect"
  value       = aws_service_discovery_private_dns_namespace.main.name
}

output "private_subnet_ids" {
  description = "IDs of the air-gapped private subnets (main task)"
  value       = aws_subnet.private[*].id
}

output "gateway_subnet_ids" {
  description = "IDs of the gateway subnets (envoy-gateway task — has NAT internet egress)"
  value       = aws_subnet.gateway[*].id
}

output "ecs_exec_command_hint" {
  description = "Example CLI command to open an interactive shell in the http-echo container"
  value       = <<-EOT
    aws ecs execute-command \
      --region ${var.aws_region} \
      --cluster ${aws_ecs_cluster.main.name} \
      --task <TASK_ID> \
      --container http-echo \
      --interactive \
      --command "/bin/sh"

    # Tip: find the task ID with:
    aws ecs list-tasks --cluster ${aws_ecs_cluster.main.name} --service-name ${aws_ecs_service.echo.name}
  EOT
}
