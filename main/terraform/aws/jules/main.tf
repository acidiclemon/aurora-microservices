provider "aws" {
  region = var.region
}

locals {
  cluster_name = "microservices-cluster"

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
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice.local:3550" },
        { name = "SHIPPING_SERVICE_ADDR", value = "shippingservice.local:50051" },
        { name = "PAYMENT_SERVICE_ADDR", value = "paymentservice.local:50051" },
        { name = "EMAIL_SERVICE_ADDR", value = "emailservice.local:8080" },
        { name = "CURRENCY_SERVICE_ADDR", value = "currencyservice.local:7000" },
        { name = "CART_SERVICE_ADDR", value = "cartservice.local:7070" }
      ]
    }
    currencyservice = {
      port = 7000
    }
    emailservice = {
      port = 8080
    }
    paymentservice = {
      port = 50051
    }
    productcatalogservice = {
      port = 3550
    }
    recommendationservice = {
      port = 8080
      env = [
        { name = "PORT", value = "8080" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice.local:3550" }
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

  name = "microservices-vpc"
  cidr = var.cidr_block

  azs             = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway = true
  single_nat_gateway = true # Save cost/time for demo

  tags = {
    Environment = "dev"
    Project     = "microservices"
  }
}

################################################################################
# Security Groups
################################################################################

module "alb_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "alb-sg"
  description = "Security group for ALB"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp"]
  egress_rules        = ["all-all"]
}

module "ecs_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "ecs-instances-sg"
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

  name        = "redis-sg"
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

  name    = "microservices-alb"
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  security_groups = [module.alb_sg.security_group_id]

  enable_deletion_protection = false

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
    microservices = {
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

  name = "ecs-asg"

  image_id      = data.aws_ssm_parameter.ecs_optimized_ami.value
  instance_type = "t3.medium"

  security_groups             = [module.ecs_sg.security_group_id]
  user_data                   = base64encode("#!/bin/bash\necho ECS_CLUSTER=${local.cluster_name} >> /etc/ecs/ecs.config")
  ignore_desired_capacity_changes = true

  create_iam_instance_profile = true
  iam_role_name               = "ecs-instance-role-custom"
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
  name        = "local"
  description = "Private DNS namespace for ECS services"
  vpc         = module.vpc.vpc_id
}

resource "aws_service_discovery_service" "this" {
  for_each = local.services

  name = each.key

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

# Shopping Assistant Discovery (Commented out)
# resource "aws_service_discovery_service" "shoppingassistantservice" { ... }


################################################################################
# ECS Services
################################################################################

# Frontend Service
module "frontend" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.11"

  name        = "frontend"
  cluster_arn = module.ecs.cluster_arn

  cpu          = 256
  memory       = 512
  network_mode = "awsvpc"

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
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice.local:3550" },
        { name = "CURRENCY_SERVICE_ADDR", value = "currencyservice.local:7000" },
        { name = "CART_SERVICE_ADDR", value = "cartservice.local:7070" },
        { name = "RECOMMENDATION_SERVICE_ADDR", value = "recommendationservice.local:8080" },
        { name = "SHIPPING_SERVICE_ADDR", value = "shippingservice.local:50051" },
        { name = "CHECKOUT_SERVICE_ADDR", value = "checkoutservice.local:5050" },
        { name = "AD_SERVICE_ADDR", value = "adservice.local:9555" },
        { name = "SHOPPING_ASSISTANT_SERVICE_ADDR", value = "shoppingassistantservice.local:8080" }
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

  name        = each.key
  cluster_arn = module.ecs.cluster_arn

  cpu          = 256
  memory       = 512
  network_mode = "awsvpc"

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

  service_registries = {
    discovery = {
      registry_arn = aws_service_discovery_service.this[each.key].arn
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
  source = "terraform-aws-modules/elasticache/aws"
  # Check version compatibility, using 1.0.0 or similar usually

  cluster_id               = "redis-cart"
  create_cluster           = true
  create_replication_group = false

  engine          = "redis"
  node_type       = "cache.t2.micro"
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

resource "aws_route53_record" "this" {
  count = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = true
  }
}
