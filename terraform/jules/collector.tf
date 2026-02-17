locals {
  # ADOT Collector Configuration
  # We configure it to receive OTLP (gRPC/HTTP) and export to AWS X-Ray
  otel_config = yamlencode({
    receivers = {
      otlp = {
        protocols = {
          grpc = {
            endpoint = "0.0.0.0:4317"
          }
          http = {
            endpoint = "0.0.0.0:4318"
          }
        }
      }
    }
    processors = {
      batch = {
        timeout = "1s"
        send_batch_size = 1024
      }
    }
    exporters = {
      awsxray = {
        region = var.region
      }
    }
    service = {
      pipelines = {
        traces = {
          receivers = ["otlp"]
          processors = ["batch"]
          exporters = ["awsxray"]
        }
      }
    }
  })
}

# IAM Role for the Collector Task
# Needed to allow the collector to write to AWS X-Ray
resource "aws_iam_role" "collector_task_role" {
  name = "${var.project_name}-${terraform.workspace}-collector-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "collector_xray" {
  role       = aws_iam_role.collector_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Attach Service Connect TLS Policy (defined in main.tf)
resource "aws_iam_role_policy_attachment" "collector_sc_tls" {
  role       = aws_iam_role.collector_task_role.name
  policy_arn = aws_iam_policy.service_connect_tls.arn
}

# Log Group for Collector
resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}-collector"
  retention_in_days = 30
}

# ECS Task Definition for Collector
resource "aws_ecs_task_definition" "collector" {
  family                   = "${var.project_name}-${terraform.workspace}-collector"
  network_mode             = "awsvpc"
  requires_compatibilities = ["EC2"]
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.collector_task_role.arn
  # Using cluster execution role if default, or we can use the same pattern as others.
  # For simplicity, assuming default/no execution role needed for ECR public, OR we use the one from main.tf if exposed.
  # Actually, `module.ecs` creates an execution role. We should use it.
  execution_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${terraform.workspace}-ecs-role"

  container_definitions = jsonencode([
    {
      name      = "collector"
      image     = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
      essential = true
      portMappings = [
        {
          name          = "collector-4317-tcp"
          containerPort = 4317
          hostPort      = 4317
          protocol      = "tcp"
        },
        {
          name          = "collector-4318-tcp"
          containerPort = 4318
          hostPort      = 4318
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "AOT_CONFIG_CONTENT"
          value = local.otel_config
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.collector.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

# ECS Service for ADOT Collector (Raw Resource to bypass module issues)
resource "aws_ecs_service" "collector" {
  name            = "${var.project_name}-${terraform.workspace}-collector"
  cluster         = module.ecs.cluster_arn
  task_definition = aws_ecs_task_definition.collector.arn
  desired_count   = var.enable_ha ? 2 : 1

  # Network Configuration
  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [module.ecs_sg.security_group_id]
    assign_public_ip = false
  }

  # Capacity Provider Strategy
  capacity_provider_strategy {
    capacity_provider = "${var.project_name}-${terraform.workspace}-microservices"
    weight            = 100
    base              = 1
  }

  # Placement Strategy
  dynamic "ordered_placement_strategy" {
    for_each = var.enable_ha ? [1] : []
    content {
      type  = "spread"
      field = "attribute:ecs.availability-zone"
    }
  }

  # Service Connect Configuration
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_private_dns_namespace.service_connect.arn
    service {
      discovery_name = "collector"
      port_name      = "collector-4317-tcp"
      client_alias {
        port     = 4317
        dns_name = "collector"
      }
      # TLS Configuration for End-to-End Encryption
      tls {
        issuer_cert_authority {
          aws_pca_authority_arn = aws_acmpca_certificate_authority.this.arn
        }
        kms_key  = aws_kms_key.service_connect_tls.arn
        role_arn = aws_iam_role.ecs_sc_tls_infra.arn
      }
    }
    log_configuration {
      log_driver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.collector.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs-sc"
      }
    }
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  wait_for_steady_state = true

  depends_on = [module.ecs]
}
