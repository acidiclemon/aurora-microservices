output "vpc_id" {
  description = "The ID of the main ECS VPC"
  value       = aws_vpc.main.id
}

output "firewall_vpc_id" {
  description = "The ID of the Firewall VPC"
  value       = aws_vpc.firewall.id
}

output "egress_vpc_id" {
  description = "The ID of the Egress VPC"
  value       = aws_vpc.egress.id
}

output "transit_gateway_id" {
  description = "The ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.id
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
  description = "The name of the main ECS service"
  value       = aws_ecs_service.echo.name
}

output "private_subnet_ids" {
  description = "IDs of the private subnets in the ECS VPC"
  value       = aws_subnet.private[*].id
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
  EOT
}
