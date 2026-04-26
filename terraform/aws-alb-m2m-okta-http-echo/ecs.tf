# -----------------------------------------------------------------------------
# CloudWatch Log Group
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/${var.project_name}-echo-server"
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

resource "aws_ecs_task_definition" "echo" {
  family                   = "${var.project_name}-echo"
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
      name      = "http-echo"
      image     = "mendhak/http-https-echo:39"
      essential = true

      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    },
    {
      name      = "envoy"
      image     = "envoyproxy/envoy:v1.30-latest"
      essential = true

      portMappings = [
        {
          containerPort = 4180
          hostPort      = 4180
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name = "ENVOY_CONFIG_YAML"
          value = templatefile("${path.module}/envoy.yaml.tpl", {
            okta_issuer = var.okta_issuer
            okta_domain = replace(replace(var.okta_issuer, "https://", ""), "/\\/oauth2.*/", "")
          })
        }
      ]

      command = [
        "/bin/sh",
        "-c",
        "echo \"$ENVOY_CONFIG_YAML\" > /tmp/envoy.yaml && envoy -c /tmp/envoy.yaml"
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs-proxy"
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

resource "aws_ecs_service" "echo" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.echo.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "http-echo"
    container_port   = 8080
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "envoy"
    container_port   = 4180
  }

  # Depends on the ALB listener to ensure the target group is fully registered first
  depends_on = [aws_lb_listener.https]

  tags = {
    Name = "${var.project_name}-service"
  }
}
