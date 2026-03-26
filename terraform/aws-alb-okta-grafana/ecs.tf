# -----------------------------------------------------------------------------
# CloudWatch Log Group
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/${var.project_name}-server"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-ecs-logs"
  }
}

# -----------------------------------------------------------------------------
# ECS Cluster
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_name}-ecs-cluster"
  }
}

# -----------------------------------------------------------------------------
# ECS Task Definition
# -----------------------------------------------------------------------------

resource "aws_ecs_task_definition" "grafana" {
  family                   = "${var.project_name}-grafana"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name      = "grafana"
      image     = "grafana/grafana:latest"
      essential = true

      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "GF_SERVER_ROOT_URL", value = "https://${var.alb_record_name}/" },
        { name = "GF_AUTH_OKTA_ENABLED", value = "true" },
        { name = "GF_AUTH_OKTA_NAME", value = "Okta" },
        { name = "GF_AUTH_OKTA_CLIENT_ID", value = var.okta_client_id },
        { name = "GF_AUTH_OKTA_CLIENT_SECRET", value = var.okta_client_secret },
        { name = "GF_AUTH_OKTA_AUTH_URL", value = var.okta_authorization_endpoint },
        { name = "GF_AUTH_OKTA_TOKEN_URL", value = var.okta_token_endpoint },
        { name = "GF_AUTH_OKTA_API_URL", value = var.okta_user_info_endpoint },
        { name = "GF_AUTH_OKTA_ALLOW_SIGN_UP", value = "true" },
        { name = "GF_AUTH_OKTA_SCOPES", value = "openid profile email" },
        { name = "GF_SECURITY_ADMIN_PASSWORD", value = var.grafana_admin_password }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_name}-task-def"
  }
}

# -----------------------------------------------------------------------------
# ECS Service
# -----------------------------------------------------------------------------

resource "aws_ecs_service" "grafana" {
  name            = "${var.project_name}-grafana"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.grafana.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "grafana"
    container_port   = 3000
  }

  # Depends on the ALB listener to ensure the target group is fully registered first
  depends_on = [aws_lb_listener.https]

  tags = {
    Name = "${var.project_name}-service"
  }
}
