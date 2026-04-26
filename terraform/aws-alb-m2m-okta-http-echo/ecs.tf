# =============================================================================
# ecs.tf  —  ECS Cluster, Task Definitions, and Services
#
# Resources:
#   1. CloudWatch Log Groups (main task + gateway task)
#   2. ECS Cluster (Container Insights enabled)
#   3. ECS Service Connect namespace (for gateway DNS discovery)
#   4. aws_ecs_task_definition.echo  — main task (http-echo + envoy sidecar)
#   5. aws_ecs_service.echo          — main service (ECS Exec enabled)
#   6. aws_ecs_task_definition.envoy_gateway  — standalone egress gateway
#   7. aws_ecs_service.envoy_gateway          — gateway service
# =============================================================================

# -----------------------------------------------------------------------------
# CloudWatch Log Groups
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/${var.project_name}-echo-server"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-ecs-logs"
  }
}

resource "aws_cloudwatch_log_group" "gateway_logs" {
  name              = "/ecs/${var.project_name}-envoy-gateway"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-gateway-logs"
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

  # ECS Exec requires execute_command_configuration on the cluster
  # (the actual toggle is on the ECS Service; this enables the feature cluster-wide)
  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_logs.name
        cloud_watch_encryption_enabled = false
      }
    }
  }

  tags = {
    Name = "${var.project_name}-ecs-cluster"
  }
}

# -----------------------------------------------------------------------------
# AWS Cloud Map namespace — used for Service Connect / DNS-based discovery
# so the main task can resolve the gateway by name.
# -----------------------------------------------------------------------------

resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "${var.project_name}.local"
  description = "Private DNS namespace for ECS Service Connect"
  vpc         = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-sd-namespace"
  }
}

# -----------------------------------------------------------------------------
# ECS Task Definition: main (http-echo + envoy sidecar)
# -----------------------------------------------------------------------------

resource "aws_ecs_task_definition" "echo" {
  family                   = "${var.project_name}-echo"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    # -----------------------------------------------------------------------
    # http-echo: the backend application
    # -----------------------------------------------------------------------
    {
      name      = "http-echo"
      image     = "mendhak/http-https-echo:39"
      essential = true

      portMappings = [
        {
          name          = "http-echo"
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

    # -----------------------------------------------------------------------
    # envoy: sidecar JWT-authentication proxy (listens on 4180)
    # Routes JWKS fetches through the envoy-gateway via HTTP CONNECT proxy.
    # -----------------------------------------------------------------------
    {
      name      = "envoy"
      image     = "envoyproxy/envoy:v1.30-latest"
      essential = true

      portMappings = [
        {
          name          = "envoy"
          containerPort = 4180
          hostPort      = 4180
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "ENVOY_CONFIG_YAML"
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
# ECS Service: main (echo + envoy sidecar)
# -----------------------------------------------------------------------------
# ECS Exec is enabled via enable_execute_command = true.
# Prerequisites already satisfied:
#   • task_role has ssmmessages:* permissions (iam.tf)
#   • SSM, SSMMessages, EC2Messages VPC Endpoints exist (network.tf)
#   • Cluster execute_command_configuration is set above

resource "aws_ecs_service" "echo" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.echo.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  # ----- ECS Exec toggle -----
  # Set var.enable_ecs_exec = true to allow interactive shell access via:
  #   aws ecs execute-command --cluster <name> --task <id> \
  #     --container http-echo --interactive --command "/bin/sh"
  # Or use the AWS Console → ECS → Task → "Execute command" tab.
  enable_execute_command = var.enable_ecs_exec

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

  # Service Connect enables DNS-based discovery within the namespace.
  # The main task is a *client* only; it discovers the gateway by the
  # name "envoy-gateway.${var.project_name}.local".
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_private_dns_namespace.main.arn
  }

  depends_on = [aws_lb_listener.https]

  tags = {
    Name = "${var.project_name}-service"
  }
}

# -----------------------------------------------------------------------------
# ECS Task Definition: envoy-gateway (standalone internet egress gateway)
# -----------------------------------------------------------------------------
# This is a *separate* ECS service running in the gateway subnets.
# It acts as an internet-facing forward proxy, but its SG only permits egress
# to port 443/Okta.  The main task reaches it on port 3128.

resource "aws_ecs_task_definition" "envoy_gateway" {
  family                   = "${var.project_name}-envoy-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"

  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.envoy_gateway_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name      = "envoy-gateway"
      image     = "envoyproxy/envoy:v1.30-latest"
      essential = true

      portMappings = [
        {
          # Port 3128: standard HTTP CONNECT / forward-proxy port.
          # Only the main task's SG is allowed to reach this port (security.tf).
          name          = "proxy"
          containerPort = 3128
          hostPort      = 3128
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "ENVOY_GATEWAY_CONFIG_YAML"
          value = templatefile("${path.module}/envoy_gateway.yaml.tpl", {
            okta_domain = replace(replace(var.okta_issuer, "https://", ""), "/\\/oauth2.*/", "")
          })
        }
      ]

      command = [
        "/bin/sh",
        "-c",
        "echo \"$ENVOY_GATEWAY_CONFIG_YAML\" > /tmp/envoy-gateway.yaml && envoy -c /tmp/envoy-gateway.yaml"
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.gateway_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs-gateway"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_name}-envoy-gateway-task-def"
  }
}

# -----------------------------------------------------------------------------
# ECS Service: envoy-gateway
# -----------------------------------------------------------------------------
# Runs in the gateway subnets (which have NAT internet egress).
# Registers itself in Service Connect so the main task can discover it via DNS.
# ECS Exec is also enabled here for debugging.

resource "aws_ecs_service" "envoy_gateway" {
  name            = "${var.project_name}-envoy-gateway-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.envoy_gateway.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  enable_execute_command = var.enable_ecs_exec

  network_configuration {
    subnets          = aws_subnet.gateway[*].id
    security_groups  = [aws_security_group.envoy_gateway.id]
    assign_public_ip = false   # Uses NAT GW, no public IP needed
  }

  # Service Connect: exposes this service as "envoy-gateway" on port 3128
  # within the namespace so the main task's envoy cluster can resolve it.
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_private_dns_namespace.main.arn

    service {
      port_name      = "proxy"
      discovery_name = "envoy-gateway"
      client_alias {
        dns_name = "envoy-gateway"
        port     = 3128
      }
    }
  }

  tags = {
    Name = "${var.project_name}-envoy-gateway-service"
  }
}
