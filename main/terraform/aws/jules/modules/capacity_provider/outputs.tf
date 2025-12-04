output "name" {
  value = aws_ecs_capacity_provider.this.name
  depends_on = [
    aws_ecs_cluster_capacity_providers.this
  ]
}
