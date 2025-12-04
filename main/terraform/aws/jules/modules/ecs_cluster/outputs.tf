output "id" {
  value = aws_ecs_cluster.this.id
}

output "name" {
  value = aws_ecs_cluster.this.name
}

output "service_discovery_namespace_id" {
  value = aws_service_discovery_private_dns_namespace.this.id
}
