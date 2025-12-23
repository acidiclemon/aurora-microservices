provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  acm_certificate_arn = var.acm_certificate_id != "" ? "arn:aws:acm:us-east-1:${data.aws_caller_identity.current.account_id}:certificate/${var.acm_certificate_id}" : ""

  cluster_name = "${var.project_name}-${terraform.workspace}-cluster"
  namespace    = "${var.project_name}-${terraform.workspace}.private"

  services = {
    adservice = {
      port = 9555
    }
    cartservice = {
      port = 7070
      env = [
        { name = "REDIS_ADDR", value = "${module.redis.cluster_cache_nodes[0].address}:${module.redis.cluster_cache_nodes[0].port}" }
      ]
    }
    checkoutservice = {
      port = 5050
      env = [
        { name = "PORT", value = "5050" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-productcatalogservice.${var.project_name}-${terraform.workspace}.private:3550" },
        { name = "SHIPPING_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-shippingservice.${var.project_name}-${terraform.workspace}.private:50051" },
        { name = "PAYMENT_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-paymentservice.${var.project_name}-${terraform.workspace}.private:50051" },
        { name = "EMAIL_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-emailservice.${var.project_name}-${terraform.workspace}.private:8080" },
        { name = "CURRENCY_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-currencyservice.${var.project_name}-${terraform.workspace}.private:7000" },
        { name = "CART_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-cartservice.${var.project_name}-${terraform.workspace}.private:7070" }
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
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-productcatalogservice.${var.project_name}-${terraform.workspace}.private:3550" }
      ]
    }
    shippingservice = {
      port = 50051
    }
    loadgenerator = {
      # No port needed for service definition, but task needs envs
      container_port = 80 # dummy port
      env = [
        { name = "FRONTEND_ADDR", value = module.alb.dns_name },
        { name = "USERS", value = "10" }
      ]
    }
    # Shopping Assistant is skipped/commented out logic handled by not including it here
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

  ingress_prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  ingress_rules           = ["http-80-tcp"]
  egress_rules            = ["all-all"]
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

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 9.0"

  name    = "${var.project_name}-${terraform.workspace}-alb"
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  security_groups = [module.alb_sg.security_group_id]

  enable_deletion_protection = false
  create_security_group = false

  listeners = {
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
      name_prefix      = "front"
      backend_protocol = "HTTP"
      backend_port     = 8080
      target_type      = "ip"
      health_check = {
        path = "/_healthz"
      }
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
      on_demand_base_capacity                  = 2
      on_demand_percentage_above_base_capacity = 50
      spot_allocation_strategy                 = "price-capacity-optimized"
    }

    override = [
      {
        instance_type = "t3a.medium"
      },
      {
        instance_type = "t3.medium"
      }
    ]
  }

  security_groups             = [module.ecs_sg.security_group_id]
  user_data                   = base64encode("#!/bin/bash\necho ECS_CLUSTER=${local.cluster_name} >> /etc/ecs/ecs.config")
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
  max_size            = 5
  desired_capacity    = 2

  # https://github.com/hashicorp/terraform-provider-aws/issues/12582
  autoscaling_group_tags = {
    AmazonECSManaged = true
  }
}

################################################################################
# Service Discovery
################################################################################

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = local.namespace
  description = "Private DNS namespace for ECS services"
  vpc         = module.vpc.vpc_id
}

resource "aws_service_discovery_service" "this" {
  for_each = local.services

  name = "${var.project_name}-${terraform.workspace}-${each.key}"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.this.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_cloudwatch_log_group" "service_connect" {
  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}/service-connect"
  retention_in_days = 7
}

################################################################################
# ECS Services
################################################################################

# Frontend Service
module "frontend" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  name        = "${var.project_name}-${terraform.workspace}-frontend"
  cluster_arn = module.ecs.cluster_arn

  create_tasks_iam_role = true
  tasks_iam_role_policies = {
    acm_pca = aws_iam_policy.acm_pca_policy.arn
  }
  create_security_group = false

  cpu          = 256
  memory       = 512
  network_mode = "awsvpc"

  service_connect_configuration = {
    enabled   = true
    namespace = local.namespace
    log_configuration = {
      log_driver = "awslogs"
      options = {
        awslogs-region        = var.region
        awslogs-group         = aws_cloudwatch_log_group.service_connect.name
        awslogs-stream-prefix = "frontend"
      }
    }
    service = {
      discovery_name = "frontend"
      port_name      = "frontend-8080-tcp"
      client_alias = [
        {
          port     = 8080
          dns_name = "frontend"
        }
      ]
      tls = {
        issuer_cert_authority = {
          aws_pca_authority_arn = aws_acmpca_certificate_authority.this.arn
        }
      }
    }
  }

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
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-productcatalogservice.${var.project_name}-${terraform.workspace}.private:3550" },
        { name = "CURRENCY_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-currencyservice.${var.project_name}-${terraform.workspace}.private:7000" },
        { name = "CART_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-cartservice.${var.project_name}-${terraform.workspace}.private:7070" },
        { name = "RECOMMENDATION_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-recommendationservice.${var.project_name}-${terraform.workspace}.private:8080" },
        { name = "SHIPPING_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-shippingservice.${var.project_name}-${terraform.workspace}.private:50051" },
        { name = "CHECKOUT_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-checkoutservice.${var.project_name}-${terraform.workspace}.private:5050" },
        { name = "AD_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-adservice.${var.project_name}-${terraform.workspace}.private:9555" },
        { name = "SHOPPING_ASSISTANT_SERVICE_ADDR", value = "${var.project_name}-${terraform.workspace}-shoppingassistantservice.${var.project_name}-${terraform.workspace}.private:8080" }
      ]
      # Using CloudWatch log group created by the module
      enable_cloudwatch_logging = true
    }
  }

  load_balancer = {
    service = {
      target_group_arn = module.alb.target_groups["frontend"].arn
      container_name   = "frontend"
      container_port   = 8080
    }
  }

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [module.ecs_sg.security_group_id]

  force_delete = true
}

# Backend Services (Loop)
module "microservices" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  for_each = local.services

  name        = "${var.project_name}-${terraform.workspace}-${each.key}"
  cluster_arn = module.ecs.cluster_arn

  create_tasks_iam_role = true
  tasks_iam_role_policies = {
    acm_pca = aws_iam_policy.acm_pca_policy.arn
  }
  create_security_group = false

  cpu          = 256
  memory       = 512
  network_mode = "awsvpc"

  service_connect_configuration = {
    enabled   = true
    namespace = local.namespace
    log_configuration = {
      log_driver = "awslogs"
      options = {
        awslogs-region        = var.region
        awslogs-group         = aws_cloudwatch_log_group.service_connect.name
        awslogs-stream-prefix = each.key
      }
    }
    service = try(each.value.port, null) != null ? {
      discovery_name = "${var.project_name}-${terraform.workspace}-${each.key}"
      port_name      = "${each.key}-${each.value.port}-tcp"
      client_alias = [
        {
          port     = each.value.port
          dns_name = "${var.project_name}-${terraform.workspace}-${each.key}"
        }
      ]
      tls = {
        issuer_cert_authority = {
          aws_pca_authority_arn = aws_acmpca_certificate_authority.this.arn
        }
      }
    } : {}
  }

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

      enable_cloudwatch_logging = true
    }
  }

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [module.ecs_sg.security_group_id]

  force_delete = true
}

################################################################################
# Redis
################################################################################

module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.2"

  cluster_id               = "${var.project_name}-${terraform.workspace}-redis"
  create_cluster           = true
  create_replication_group = false
  subnet_group_name        = "${var.project_name}-${terraform.workspace}-redis-subnet-group"
  create_security_group    = false

  engine          = "redis"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
  engine_version  = "7.0"
  port            = 6379

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

  aliases = var.domain_name != "" ? ["${var.project_name}-${terraform.workspace}.${var.domain_name}"] : []

  origin {
    domain_name = module.alb.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb"
    viewer_protocol_policy = "allow-all"

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
