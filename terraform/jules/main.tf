provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

resource "aws_ecs_account_setting_default" "trunking" {
  name  = "awsvpcTrunking"
  value = "enabled"
}

resource "time_sleep" "wait_for_trunking" {
  create_duration = "30s"
  depends_on      = [aws_ecs_account_setting_default.trunking]
}

locals {
  acm_certificate_arn = var.acm_certificate_id != "" ? "arn:aws:acm:us-east-1:${data.aws_caller_identity.current.account_id}:certificate/${var.acm_certificate_id}" : ""

  cluster_name = "${var.project_name}-${terraform.workspace}-cluster"
  namespace    = "${var.project_name}-${terraform.workspace}.sc"

  services = {
    adservice = {
      port = 9555
    }
    cartservice = {
      port = 7070
      env = [
        { name = "REDIS_ADDR", value = "${module.redis.replication_group_primary_endpoint_address}:6379" }
      ]
    }
    checkoutservice = {
      port = 5050
      env = [
        { name = "PORT", value = "5050" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice:3550" },
        { name = "SHIPPING_SERVICE_ADDR", value = "shippingservice:50051" },
        { name = "PAYMENT_SERVICE_ADDR", value = "paymentservice:50051" },
        { name = "EMAIL_SERVICE_ADDR", value = "emailservice:8080" },
        { name = "CURRENCY_SERVICE_ADDR", value = "currencyservice:7000" },
        { name = "CART_SERVICE_ADDR", value = "cartservice:7070" }
      ]
    }
    currencyservice = {
      port = 7000
      env = [
        { name = "DISABLE_PROFILER", value = "1" }
      ]
    }
    emailservice = {
      port = 8080
    }
    paymentservice = {
      port = 50051
      env = [
        { name = "DISABLE_PROFILER", value = "1" }
      ]
    }
    productcatalogservice = {
      port = 3550
    }
    recommendationservice = {
      port = 8080
      env = [
        { name = "PORT", value = "8080" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice:3550" }
      ]
    }
    shippingservice = {
      port = 50051
    }
  }
}

################################################################################
# VPC
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.project_name}-${terraform.workspace}-vpc"
  cidr = var.cidr_block

  azs             = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway = true
  single_nat_gateway = true # Save cost/time for demo

  manage_default_security_group = false
  manage_default_route_table    = false
  manage_default_network_acl    = false

  tags = {
    Environment = "${terraform.workspace}"
    Project     = var.project_name
  }
}

################################################################################
# Security Groups
################################################################################

module "alb_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${var.project_name}-${terraform.workspace}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "https-443-tcp"]
  egress_rules        = ["all-all"]
}

module "ecs_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${var.project_name}-${terraform.workspace}-ecs-sg"
  description = "Security group for ECS instances"
  vpc_id      = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
      rule                     = "all-all"
      source_security_group_id = module.alb_sg.security_group_id
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 1

  ingress_with_self = [
    {
      rule = "all-all"
    }
  ]
  egress_rules = ["all-all"]
}

module "redis_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${var.project_name}-${terraform.workspace}-redis-sg"
  description = "Security group for Redis"
  vpc_id      = module.vpc.vpc_id

  computed_ingress_with_source_security_group_id = [
    {
      from_port                = 6379
      to_port                  = 6379
      protocol                 = "tcp"
      source_security_group_id = module.ecs_sg.security_group_id
    }
  ]
  number_of_computed_ingress_with_source_security_group_id = 1

  egress_rules = ["all-all"]
}

################################################################################
# ALB
################################################################################

# Regional ACM certificate for ALB (must be in the same region as the ALB)
resource "aws_acm_certificate" "alb" {
  count = var.domain_name != "" ? 1 : 0

  domain_name       = "alb-${var.project_name}-${terraform.workspace}.${var.domain_name}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "alb_cert_validation" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = tolist(aws_acm_certificate.alb[0].domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.alb[0].domain_validation_options)[0].resource_record_type
  records = [tolist(aws_acm_certificate.alb[0].domain_validation_options)[0].resource_record_value]
  ttl     = 60

  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "alb" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  certificate_arn         = aws_acm_certificate.alb[0].arn
  validation_record_fqdns = [aws_route53_record.alb_cert_validation[0].fqdn]
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.0"

  name    = "${var.project_name}-${terraform.workspace}-alb"
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  security_groups = [module.alb_sg.security_group_id]

  enable_deletion_protection = false
  create_security_group = false

  # When domain is set: HTTP redirects to HTTPS, HTTPS forwards to target group
  # When no domain:     HTTP forwards directly (F-PCI-04 — PCI DSS Req 4.2.1)
  listeners = var.domain_name != "" ? {
    http = {
      port     = 80
      protocol = "HTTP"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
    https = {
      port            = 443
      protocol        = "HTTPS"
      ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
      certificate_arn = aws_acm_certificate_validation.alb[0].certificate_arn
      forward = {
        target_group_key = "frontend"
      }
    }
  } : {
    http = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "frontend"
      }
    }
  }

  target_groups = {
    frontend = {
      name_prefix = "front"
      protocol    = var.domain_name != "" ? "HTTPS" : "HTTP"
      port        = 8080
      target_type = "ip"
      health_check = {
        path     = "/_healthz"
        protocol = var.domain_name != "" ? "HTTPS" : "HTTP"
        port     = 8080
      }
      deregistration_delay = 30
      create_attachment = false
    }
  }
}

################################################################################
# ECS Cluster & Capacity Providers
################################################################################

module "ecs" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "~> 5.11"

  cluster_name = local.cluster_name

  # Service Connect Defaults (Cluster-level)
  cluster_service_connect_defaults = {
    namespace = aws_service_discovery_private_dns_namespace.service_connect.arn
  }

  # Capacity Provider
  default_capacity_provider_use_fargate = false
  autoscaling_capacity_providers = {
    "${var.project_name}-${terraform.workspace}-microservices" = {
      auto_scaling_group_arn         = module.autoscaling.autoscaling_group_arn
      managed_termination_protection = "DISABLED"

      managed_scaling = {
        maximum_scaling_step_size = 5
        minimum_scaling_step_size = 1
        status                    = "ENABLED"
        target_capacity           = 100
      }

      default_capacity_provider_strategy = {
        weight = 100
        base   = 1
      }
    }
  }
}

module "autoscaling" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 8.0"

  name = "${var.project_name}-${terraform.workspace}-asg"

  image_id = data.aws_ssm_parameter.ecs_optimized_ami.value

  use_mixed_instances_policy = true
  mixed_instances_policy = {
    instances_distribution = {
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 30
      spot_allocation_strategy                 = "price-capacity-optimized"
    }

    override = [
      {
        instance_type = "m6a.large"
      }
    ]
  }

  security_groups             = [module.ecs_sg.security_group_id]
  user_data = base64encode(<<-EOT
    #!/bin/bash
    echo ECS_CLUSTER=${local.cluster_name} >> /etc/ecs/ecs.config
    # ENI Trunking: ${aws_ecs_account_setting_default.trunking.value}
  EOT
  )
  ignore_desired_capacity_changes = true

  create_iam_instance_profile = true
  iam_role_name               = "${var.project_name}-${terraform.workspace}-ecs-role"
  iam_role_description        = "ECS role for ${local.cluster_name}"
  iam_role_policies = {
    AmazonEC2ContainerServiceforEC2Role = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    AmazonSSMManagedInstanceCore        = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  vpc_zone_identifier = module.vpc.private_subnets
  health_check_type   = "EC2"
  min_size            = 1
  max_size            = 3
  desired_capacity    = 1

  # https://github.com/hashicorp/terraform-provider-aws/issues/12582
  autoscaling_group_tags = {
    AmazonECSManaged = true
  }

  depends_on = [time_sleep.wait_for_trunking]
}

################################################################################
# Service Discovery (Service Connect)
################################################################################

resource "aws_service_discovery_private_dns_namespace" "service_connect" {
  name        = local.namespace
  description = "Service Connect Namespace (Private DNS)"
  vpc         = module.vpc.vpc_id
}

################################################################################
# IAM Policies
################################################################################

resource "aws_iam_policy" "service_connect_tls" {
  count = var.domain_name != "" ? 1 : 0

  name        = "${var.project_name}-${terraform.workspace}-sc-tls-policy"
  description = "Allow ECS tasks to communicate with ACM PCA for Service Connect TLS"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "acm-pca:DescribeCertificateAuthority",
          "acm-pca:GetCertificate",
          "acm-pca:IssueCertificate"
        ]
        Resource = aws_acmpca_certificate_authority.this[0].arn
      }
    ]
  })
}

################################################################################
# ECS Services
################################################################################

# Frontend Service - Task Definition (using module)
module "frontend" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  name        = "${var.project_name}-${terraform.workspace}-frontend"
  cluster_arn = module.ecs.cluster_arn

  # IAM Role for Service Connect TLS (only when TLS is enabled)
  create_tasks_iam_role = true
  tasks_iam_role_policies = var.domain_name != "" ? {
    ServiceConnectTLS = aws_iam_policy.service_connect_tls[0].arn
  } : {}

  # Create ONLY Task Definition, NOT Service
  create_service         = false
  create_security_group  = false

  cpu          = 140
  memory       = 450
  network_mode = "awsvpc"
  requires_compatibilities = ["EC2"]

  container_definitions = {
    frontend = {
      image     = "${var.image_repo_url}/frontend:${var.image_tag}"
      essential = true
      port_mappings = [
        {
          name          = "frontend-8080-tcp"
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "PORT", value = "8080" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice:3550" },
        { name = "CURRENCY_SERVICE_ADDR", value = "currencyservice:7000" },
        { name = "CART_SERVICE_ADDR", value = "cartservice:7070" },
        { name = "RECOMMENDATION_SERVICE_ADDR", value = "recommendationservice:8080" },
        { name = "SHIPPING_SERVICE_ADDR", value = "shippingservice:50051" },
        { name = "CHECKOUT_SERVICE_ADDR", value = "checkoutservice:5050" },
        { name = "AD_SERVICE_ADDR", value = "adservice:9555" },
        { name = "SHOPPING_ASSISTANT_SERVICE_ADDR", value = "shoppingassistantservice:8080" },
        { name = "ENABLE_TRACING", value = "1" },
        { name = "COLLECTOR_SERVICE_ADDR", value = "collector:4317" }
      ]

      # Explicitly managed log group in observability.tf
      enable_cloudwatch_logging = false
      log_configuration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.frontend.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  }

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [module.ecs_sg.security_group_id]
}

# Frontend Service - Raw Service Resource
resource "aws_ecs_service" "frontend" {
  name            = "${var.project_name}-${terraform.workspace}-frontend"
  cluster         = module.ecs.cluster_arn
  force_delete    = true
  task_definition = module.frontend.task_definition_arn

  desired_count = var.enable_ha ? 2 : 1

  # Network Configuration
  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [module.ecs_sg.security_group_id]
    assign_public_ip = false
  }

  # Load Balancer
  load_balancer {
    target_group_arn = module.alb.target_groups["frontend"].arn
    container_name   = "frontend"
    container_port   = 8080
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
  # When domain_name is set: frontend exposes an inbound TLS service for ALB HTTPS.
  # When domain_name is empty: client-only mode (outbound TLS only, inbound HTTP).
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_private_dns_namespace.service_connect.arn
    dynamic "service" {
      for_each = var.domain_name != "" ? [1] : []
      content {
        discovery_name = "frontend"
        port_name      = "frontend-8080-tcp"
        client_alias {
          port     = 8080
          dns_name = "frontend"
        }
        tls {
          issuer_cert_authority {
            aws_pca_authority_arn = aws_acmpca_certificate_authority.this[0].arn
          }
          kms_key  = aws_kms_key.service_connect_tls[0].arn
          role_arn = aws_iam_role.ecs_sc_tls_infra[0].arn
        }
      }
    }
    log_configuration {
      log_driver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.frontend.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs-sc"
      }
    }
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  timeouts {
    delete = "15m"
  }

  depends_on = [
    module.ecs,
    module.vpc,
    terraform_data.backend_readiness_gate
  ]
}

# Microservices - Task Definition (using module)
module "microservices" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  for_each = local.services

  name        = "${var.project_name}-${terraform.workspace}-${each.key}"
  cluster_arn = module.ecs.cluster_arn

  # IAM Role for Service Connect TLS (only when TLS is enabled)
  create_tasks_iam_role = true
  tasks_iam_role_policies = var.domain_name != "" ? {
    ServiceConnectTLS = aws_iam_policy.service_connect_tls[0].arn
  } : {}

  # Create ONLY Task Definition, NOT Service
  create_service         = false
  create_security_group  = false

  cpu          = 140
  memory       = 450
  network_mode = "awsvpc"
  requires_compatibilities = ["EC2"]

  container_definitions = {
    (each.key) = {
      image     = "${var.image_repo_url}/${each.key}:${var.image_tag}"
      essential = true
      port_mappings = try(each.value.port, null) != null ? [
        {
          name          = "${each.key}-${each.value.port}-tcp"
          containerPort = each.value.port
          hostPort      = each.value.port
          protocol      = "tcp"
        }
      ] : []

      environment = concat(
        [
          { name = "PORT", value = tostring(try(each.value.port, "")) }
        ],
        try(each.value.env, [])
      )

      # Explicitly managed log group in observability.tf
      enable_cloudwatch_logging = false
      log_configuration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.microservices[each.key].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  }

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [module.ecs_sg.security_group_id]
}

# Microservices - Raw Service Resource
resource "aws_ecs_service" "microservices" {
  for_each = local.services

  name            = "${var.project_name}-${terraform.workspace}-${each.key}"
  cluster         = module.ecs.cluster_arn
  task_definition = module.microservices[each.key].task_definition_arn
  force_delete    = true

  desired_count = var.enable_ha ? 2 : 1

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
      discovery_name = each.key
      port_name      = try(each.value.port, null) != null ? "${each.key}-${each.value.port}-tcp" : null

      dynamic "client_alias" {
        for_each = try(each.value.port, null) != null ? [1] : []
        content {
          port     = each.value.port
          dns_name = each.key
        }
      }

      dynamic "tls" {
        for_each = var.domain_name != "" ? [1] : []
        content {
          issuer_cert_authority {
            aws_pca_authority_arn = aws_acmpca_certificate_authority.this[0].arn
          }
          kms_key  = aws_kms_key.service_connect_tls[0].arn
          role_arn = aws_iam_role.ecs_sc_tls_infra[0].arn
        }
      }
    }
    log_configuration {
      log_driver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.microservices[each.key].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs-sc"
      }
    }
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  timeouts {
    delete = "15m"
  }

  depends_on = [module.ecs, module.vpc]
}

################################################################################
# Redis
################################################################################

module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.2"

  replication_group_id     = "${var.project_name}-${terraform.workspace}-redis"
  description              = "Redis for ${var.project_name}-${terraform.workspace} (encrypted)"
  create_cluster           = false
  create_replication_group = true
  subnet_group_name        = "${var.project_name}-${terraform.workspace}-redis-subnet-group"
  create_security_group    = false

  engine            = "redis"
  node_type         = "cache.t3.micro"
  num_cache_clusters = 1
  engine_version    = "7.0"
  port              = 6379

  # Encryption at rest (F-PCI-01 / F-HIPAA-01)
  at_rest_encryption_enabled = true
  kms_key_arn                = aws_kms_key.redis.arn

  # Encryption in transit (F-PCI-02 / F-HIPAA-01)
  transit_encryption_enabled = true
  transit_encryption_mode    = "required"

  subnet_ids         = module.vpc.private_subnets
  vpc_id             = module.vpc.vpc_id
  security_group_ids = [module.redis_sg.security_group_id]

  parameter_group_name = "default.redis7"
}

################################################################################
# Route53
################################################################################

locals {
  # If hosted_zone_id contains a dot, assume it is a name (e.g. example.com)
  hosted_zone_is_name = can(regex("\\.", var.hosted_zone_id))
}

data "aws_route53_zone" "this" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  name    = local.hosted_zone_is_name ? var.hosted_zone_id : null
  zone_id = local.hosted_zone_is_name ? null : var.hosted_zone_id
}

resource "aws_route53_record" "this" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = "${var.project_name}-${terraform.workspace}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}

# ALB-specific DNS record — used as CloudFront origin so the ACM cert domain matches
resource "aws_route53_record" "alb" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = "alb-${var.project_name}-${terraform.workspace}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = true
  }
}

################################################################################
# CloudFront
################################################################################

resource "aws_cloudfront_distribution" "this" {
  comment             = "CloudFront for ${var.project_name}-${terraform.workspace}"
  enabled             = true
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100"
  retain_on_delete    = false
  wait_for_deployment = false
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn

  aliases = var.domain_name != "" ? ["${var.project_name}-${terraform.workspace}.${var.domain_name}"] : []

  origin {
    domain_name = var.domain_name != "" && var.hosted_zone_id != "" ? aws_route53_record.alb[0].fqdn : module.alb.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = var.domain_name != "" ? "https-only" : "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    # Redirect HTTP → HTTPS (F-PCI-03 / F-HIPAA-03 — PCI DSS Req 4.2.1)
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    # Forward all for dynamic app
    # Managed-CachingDisabled
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    # Managed-AllViewer
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = local.acm_certificate_arn == ""
    acm_certificate_arn            = local.acm_certificate_arn
    ssl_support_method             = local.acm_certificate_arn != "" ? "sni-only" : null
  }
}

################################################################################
# Cleanup Logic — Pre-Destroy
#
# Runs BEFORE Terraform deletes ECS services. Does two things:
#   1. Scales every service to desired_count=0 (stops ECS from respawning tasks)
#   2. Force-stops ALL running tasks in the cluster
#
# This ensures DeleteService finds 0 running tasks, making it near-instant.
# Combined with force_delete=true on the service resources for belt-and-suspenders.
################################################################################

resource "null_resource" "ecs_pre_destroy" {
  triggers = {
    cluster_name = local.cluster_name
    region       = var.region
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<EOT
      CLUSTER="${self.triggers.cluster_name}"
      REGION="${self.triggers.region}"
      echo "=== ECS Pre-Destroy Cleanup ==="
      echo "Cluster: $CLUSTER | Region: $REGION"

      # Step 1: Scale ALL services to desired_count=0 with force new deployment
      echo "[1/4] Scaling all services to 0..."
      SERVICES=$(aws ecs list-services --cluster "$CLUSTER" --region "$REGION" --query "serviceArns[]" --output text 2>/dev/null || true)
      if [ -n "$SERVICES" ] && [ "$SERVICES" != "None" ]; then
        for svc in $SERVICES; do
          echo "  → $svc → desired_count=0"
          aws ecs update-service --cluster "$CLUSTER" --service "$svc" --desired-count 0 --force-new-deployment --region "$REGION" --no-cli-pager > /dev/null 2>&1 || true
        done
      else
        echo "  No services found."
      fi

      # Step 2: Wait for tasks to actually stop
      TASKS=$(aws ecs list-tasks --cluster "$CLUSTER" --region "$REGION" --query "taskArns[]" --output text 2>/dev/null || true)
      if [ -n "$TASKS" ] && [ "$TASKS" != "None" ]; then
        echo "[2/4] Waiting for tasks to stop..."
        aws ecs wait tasks-stopped --cluster "$CLUSTER" --tasks $TASKS --region "$REGION" --no-cli-pager > /dev/null 2>&1 || true
        echo "  All tasks stopped."
      else
        echo "[2/4] No tasks to wait for."
      fi

      # Step 3: DELETE all services (--force bypasses their own drain wait)
      if [ -n "$SERVICES" ] && [ "$SERVICES" != "None" ]; then
        echo "[3/4] Deleting all services..."
        for svc in $SERVICES; do
          echo "  → Deleting $svc"
          aws ecs delete-service --cluster "$CLUSTER" --service "$svc" --force --region "$REGION" --no-cli-pager > /dev/null 2>&1 || true
        done
      else
        echo "[3/4] No services to delete."
      fi

      # Step 4: Poll until ALL services reach INACTIVE (up to 20 minutes).
      # Service Connect + TLS deregistration takes 10-20 min, so we use a custom
      # loop that keeps polling until all services are gone or we time out.
      if [ -n "$SERVICES" ] && [ "$SERVICES" != "None" ]; then
        echo "[4/4] Waiting for all services to reach INACTIVE (up to 20m)..."
        DEADLINE=$(( $(date +%s) + 660 ))  # 11 minutes from now
        while [ $(date +%s) -lt $DEADLINE ]; do
          STILL_ACTIVE=""
          for svc in $SERVICES; do
            STATUS=$(aws ecs describe-services --cluster "$CLUSTER" --services "$svc" --region "$REGION" --query "services[0].status" --output text 2>/dev/null || echo "MISSING")
            if [ "$STATUS" != "INACTIVE" ] && [ "$STATUS" != "None" ] && [ "$STATUS" != "MISSING" ]; then
              STILL_ACTIVE="$STILL_ACTIVE $svc($STATUS)"
            fi
          done
          if [ -z "$STILL_ACTIVE" ]; then
            echo "  All services are INACTIVE."
            break
          fi
          echo "  Still waiting:$STILL_ACTIVE"
          sleep 15
        done
      else
        echo "[4/4] No services to wait for."
      fi
      echo "=== Pre-destroy cleanup complete ==="
    EOT
  }

  depends_on = [
    # Services (already here)
    aws_ecs_service.frontend,
    aws_ecs_service.microservices,
    aws_ecs_service.collector,

    # Network & Compute
    module.vpc,
    module.alb,
    module.alb_sg,
    module.ecs_sg,
    module.redis_sg,
    module.ecs,
    module.autoscaling,
    module.redis,
    aws_service_discovery_private_dns_namespace.service_connect,
    aws_route53_record.this,
    aws_cloudfront_distribution.this,

    # Task Definitions
    module.frontend,
    module.microservices,
    aws_ecs_task_definition.collector,

    # IAM & Security (Main)
    aws_iam_policy.service_connect_tls,
    
    # Collector Resources
    aws_iam_role.collector_task_role,
    aws_iam_role.collector_exec_role,
    aws_iam_role_policy_attachment.collector_xray,
    aws_iam_role_policy_attachment.collector_exec_policy,
    aws_iam_role_policy_attachment.collector_sc_tls,
    aws_cloudwatch_log_group.collector,

    # PKI & Certs (only when TLS is enabled)
    aws_acmpca_certificate_authority.this,
    aws_acmpca_certificate.root,
    aws_acmpca_certificate_authority_certificate.root,
    aws_iam_role.ecs_sc_tls_infra,
    aws_iam_role_policy_attachment.ecs_sc_tls_infra,
    aws_kms_key.service_connect_tls,
    aws_kms_alias.service_connect_tls,
    aws_kms_key.redis,
    aws_kms_alias.redis,

    # Observability - Logs & Metrics
    aws_cloudwatch_log_group.frontend,
    aws_cloudwatch_log_group.microservices,
    aws_cloudwatch_log_metric_filter.frontend_errors,
    aws_cloudwatch_log_metric_filter.checkout_errors,
    aws_cloudwatch_log_metric_filter.payment_errors,
    aws_cloudwatch_dashboard.main,
    
    # Observability - IAM & KMS
    aws_iam_role.security_team_role,
    aws_iam_role_policy.security_team_policy,
    aws_kms_key.logs_key,
    aws_kms_alias.logs_key,
    aws_kms_key_policy.logs_key,
    aws_kms_key.regulated_data_key,
    aws_kms_alias.regulated_data_key,
    aws_kms_key_policy.regulated_data_key,

    # Observability - S3 & Firehose
    aws_s3_bucket.raw_logs,
    aws_s3_bucket_server_side_encryption_configuration.raw_logs,
    aws_s3_bucket_policy.raw_logs,
    aws_s3_bucket.audit_findings,
    aws_s3_bucket_server_side_encryption_configuration.audit_findings,
    aws_s3_bucket_policy.audit_findings,
    aws_cloudwatch_log_data_protection_policy.frontend,
    aws_cloudwatch_log_data_protection_policy.microservices,
    aws_cloudwatch_log_data_protection_policy.collector,
    aws_iam_role.firehose_role,
    aws_iam_role_policy.firehose_policy,
    aws_kinesis_firehose_delivery_stream.logs_stream,
    aws_iam_role.logs_subscription_role,
    aws_iam_role_policy.logs_subscription_policy,
    aws_cloudwatch_log_subscription_filter.frontend,
    aws_cloudwatch_log_subscription_filter.microservices,

    # Canaries
    aws_s3_bucket.canary_artifacts,
    aws_s3_bucket_lifecycle_configuration.canary_artifacts,
    aws_iam_role.canary_role,
    aws_iam_role_policy.canary_policy,
    aws_synthetics_canary.home,
    aws_synthetics_canary.product,
    aws_synthetics_canary.cart,

    # WAF
    aws_wafv2_web_acl.cloudfront,
    aws_wafv2_web_acl_logging_configuration.cloudfront,
    aws_cloudwatch_log_group.waf,
    aws_kms_key.waf_logs,
    aws_kms_alias.waf_logs,

    # VPC Flow Logs
    aws_s3_bucket.flow_logs,
    aws_s3_bucket_server_side_encryption_configuration.flow_logs,
    aws_s3_bucket_policy.flow_logs,
    aws_flow_log.vpc,

    # CloudTrail
    aws_s3_bucket.cloudtrail,
    aws_s3_bucket_server_side_encryption_configuration.cloudtrail,
    aws_s3_bucket_policy.cloudtrail,
    aws_cloudwatch_log_group.cloudtrail,
    aws_iam_role.cloudtrail_cloudwatch,
    aws_iam_role_policy.cloudtrail_cloudwatch,
    aws_cloudtrail.main
  ]
}
