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

# ECS Service for ADOT Collector
module "collector" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  name        = "${var.project_name}-${terraform.workspace}-collector"
  cluster_arn = module.ecs.cluster_arn

  # We use our custom task role created above
  create_tasks_iam_role = false
  tasks_iam_role_arn    = aws_iam_role.collector_task_role.arn

  create_security_group = false

  cpu          = 256
  memory       = 512
  network_mode = "awsvpc"

  # Service Connect Configuration
  service_connect_configuration = {
    enabled   = true
    namespace = aws_service_discovery_private_dns_namespace.service_connect.arn
    service = {
      discovery_name = "collector"
      client_alias = [
        {
          port     = 4317
          dns_name = "collector"
        },
        {
          port     = 4318
          dns_name = "collector"
        }
      ]
      tls = {
        issuer_cert_authority = {
          aws_pca_authority_arn = aws_acmpca_certificate_authority.this.arn
        }
        kms_key = aws_kms_key.service_connect_tls.arn
        role_arn = null
      }
    }
  }

  container_definitions = {
    collector = {
      image     = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
      essential = true

      # Expose OTLP ports
      port_mappings = [
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

      # Logging to CloudWatch
      enable_cloudwatch_logging = false
      log_configuration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.collector.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  }

  # No manual service registries (handled by Service Connect)

  desired_count = var.enable_ha ? 2 : 1
  ordered_placement_strategy = var.enable_ha ? [
    {
      type  = "spread"
      field = "attribute:ecs.availability-zone"
    }
  ] : []

  autoscaling_min_capacity = var.enable_ha ? 2 : 1

  # Run on EC2 instances (same as other microservices)
  capacity_provider_strategy = {
    "${var.project_name}-${terraform.workspace}-microservices" = {
      capacity_provider = "${var.project_name}-${terraform.workspace}-microservices"
      weight            = 100
      base              = 1
    }
  }

  requires_compatibilities = ["EC2"]

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [module.ecs_sg.security_group_id]

  force_delete = true

  depends_on = [module.ecs]
}
