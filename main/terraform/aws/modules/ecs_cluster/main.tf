resource "aws_ecs_cluster" "this" {
  name = var.name
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = "local"
  description = "Private DNS namespace for ECS services"
  vpc         = var.vpc_id
}

variable "vpc_id" {
  type = string
}
