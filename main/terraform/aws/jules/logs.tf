resource "aws_cloudwatch_log_group" "service_connect" {
  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}/service-connect"
  retention_in_days = 7

  tags = {
    Environment = "${terraform.workspace}"
    Project     = var.project_name
  }
}
