provider "aws" {
  region = var.region
}

module "vpc" {
  source             = "./modules/vpc"
  cidr_block         = var.cidr_block
  public_subnets     = var.public_subnets
  private_subnets    = var.private_subnets
  availability_zones = var.availability_zones
}

module "alb_sg" {
  source = "./modules/alb_sg"
  vpc_id = module.vpc.vpc_id
}

module "ecs_sg" {
  source    = "./modules/ecs_sg"
  vpc_id    = module.vpc.vpc_id
  alb_sg_id = module.alb_sg.security_group_id
}

module "ecs_instance_role" {
  source = "./modules/ecs_instance_role"
}

module "ecs_task_roles" {
  source = "./modules/ecs_task_roles"
}

module "launch_template" {
  source                   = "./modules/launch_template"
  name_prefix              = "ecs-lt-"
  image_id                 = data.aws_ssm_parameter.ecs_optimized_ami.value
  instance_type            = "t3.medium"
  iam_instance_profile_arn = module.ecs_instance_role.iam_instance_profile_arn
  security_group_ids       = [module.ecs_sg.security_group_id]
  cluster_name             = "microservices-cluster"
}

module "asg" {
  source                  = "./modules/asg"
  name                    = "ecs-asg"
  launch_template_id      = module.launch_template.id
  launch_template_version = module.launch_template.latest_version
  subnet_ids              = module.vpc.private_subnets
  min_size                = 1
  max_size                = 5
  desired_capacity        = 2
}

module "ecs_cluster" {
  source = "./modules/ecs_cluster"
  name   = "microservices-cluster"
  vpc_id = module.vpc.vpc_id
}

module "capacity_provider" {
  source                 = "./modules/capacity_provider"
  name                   = "microservices-cp"
  auto_scaling_group_arn = module.asg.arn
  cluster_name           = module.ecs_cluster.name
}

module "alb" {
  source             = "./modules/alb"
  name               = "microservices-alb"
  subnet_ids         = module.vpc.public_subnets
  security_group_ids = [module.alb_sg.security_group_id]
}

module "log_group" {
  source = "./modules/log_group"
  name   = "/ecs/microservices"
}

module "redis" {
  source     = "./modules/redis"
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  ecs_sg_id  = module.ecs_sg.security_group_id
}

resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
  description      = "A service linked role for autoscaling"
  custom_suffix    = "microservices"
  # This ensures we don't conflict with the default role if it exists,
  # but creates a specific one for this deployment if needed.
  # However, ASG usually uses the default SLR.
  # If the default SLR is missing, ASG creation might fail or instance launch fails.
}

# --- Service Discovery Definitions ---
resource "aws_service_discovery_service" "adservice" {
  name = "adservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "cartservice" {
  name = "cartservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "checkoutservice" {
  name = "checkoutservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "currencyservice" {
  name = "currencyservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "emailservice" {
  name = "emailservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "paymentservice" {
  name = "paymentservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "productcatalogservice" {
  name = "productcatalogservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "recommendationservice" {
  name = "recommendationservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "shippingservice" {
  name = "shippingservice"
  dns_config {
    namespace_id = module.ecs_cluster.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

# resource "aws_service_discovery_service" "shoppingassistantservice" {
#   name = "shoppingassistantservice"
#   dns_config {
#     namespace_id = module.ecs_cluster.service_discovery_namespace_id
#     dns_records {
#       ttl  = 10
#       type = "A"
#     }
#   }
# }

# --- Frontend Service (Public) ---

module "target_group_frontend" {
  source   = "./modules/target_group"
  name     = "frontend-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id
  health_check_path = "/_healthz"
}

module "listener_frontend" {
  source           = "./modules/listener"
  alb_arn          = module.alb.arn
  port             = 80
  target_group_arn = module.target_group_frontend.arn
}

module "task_definition_frontend" {
  source             = "./modules/task_definition"
  family             = "frontend"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = "${var.image_repo_url}/frontend:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
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
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "frontend"
        }
      }
    }
  ])
}

module "ecs_service_frontend" {
  source                 = "./modules/ecs_service"
  name                   = "frontend"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_frontend.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  target_group_arn       = module.target_group_frontend.arn
  container_name         = "frontend"
  container_port         = 8080
}

# --- Backend Services (Internal) ---

module "task_definition_adservice" {
  source             = "./modules/task_definition"
  family             = "adservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "adservice"
      image     = "${var.image_repo_url}/adservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 9555
          hostPort      = 9555
        }
      ]
      environment = [
        { name = "PORT", value = "9555" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "adservice"
        }
      }
    }
  ])
}

module "ecs_service_adservice" {
  source                 = "./modules/ecs_service"
  name                   = "adservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_adservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.adservice.arn
}

module "task_definition_cartservice" {
  source             = "./modules/task_definition"
  family             = "cartservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "cartservice"
      image     = "${var.image_repo_url}/cartservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 7070
          hostPort      = 7070
        }
      ]
      environment = [
        { name = "REDIS_ADDR", value = "${module.redis.endpoint}:${module.redis.port}" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "cartservice"
        }
      }
    }
  ])
}

module "ecs_service_cartservice" {
  source                 = "./modules/ecs_service"
  name                   = "cartservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_cartservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.cartservice.arn
}

module "task_definition_checkoutservice" {
  source             = "./modules/task_definition"
  family             = "checkoutservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "checkoutservice"
      image     = "${var.image_repo_url}/checkoutservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 5050
          hostPort      = 5050
        }
      ]
      environment = [
        { name = "PORT", value = "5050" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice.local:3550" },
        { name = "SHIPPING_SERVICE_ADDR", value = "shippingservice.local:50051" },
        { name = "PAYMENT_SERVICE_ADDR", value = "paymentservice.local:50051" },
        { name = "EMAIL_SERVICE_ADDR", value = "emailservice.local:8080" },
        { name = "CURRENCY_SERVICE_ADDR", value = "currencyservice.local:7000" },
        { name = "CART_SERVICE_ADDR", value = "cartservice.local:7070" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "checkoutservice"
        }
      }
    }
  ])
}

module "ecs_service_checkoutservice" {
  source                 = "./modules/ecs_service"
  name                   = "checkoutservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_checkoutservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.checkoutservice.arn
}

module "task_definition_currencyservice" {
  source             = "./modules/task_definition"
  family             = "currencyservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "currencyservice"
      image     = "${var.image_repo_url}/currencyservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 7000
          hostPort      = 7000
        }
      ]
      environment = [
        { name = "PORT", value = "7000" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "currencyservice"
        }
      }
    }
  ])
}

module "ecs_service_currencyservice" {
  source                 = "./modules/ecs_service"
  name                   = "currencyservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_currencyservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.currencyservice.arn
}

module "task_definition_emailservice" {
  source             = "./modules/task_definition"
  family             = "emailservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "emailservice"
      image     = "${var.image_repo_url}/emailservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
      environment = [
        { name = "PORT", value = "8080" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "emailservice"
        }
      }
    }
  ])
}

module "ecs_service_emailservice" {
  source                 = "./modules/ecs_service"
  name                   = "emailservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_emailservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.emailservice.arn
}

module "task_definition_paymentservice" {
  source             = "./modules/task_definition"
  family             = "paymentservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "paymentservice"
      image     = "${var.image_repo_url}/paymentservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 50051
          hostPort      = 50051
        }
      ]
      environment = [
        { name = "PORT", value = "50051" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "paymentservice"
        }
      }
    }
  ])
}

module "ecs_service_paymentservice" {
  source                 = "./modules/ecs_service"
  name                   = "paymentservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_paymentservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.paymentservice.arn
}

module "task_definition_productcatalogservice" {
  source             = "./modules/task_definition"
  family             = "productcatalogservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "productcatalogservice"
      image     = "${var.image_repo_url}/productcatalogservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 3550
          hostPort      = 3550
        }
      ]
      environment = [
        { name = "PORT", value = "3550" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "productcatalogservice"
        }
      }
    }
  ])
}

module "ecs_service_productcatalogservice" {
  source                 = "./modules/ecs_service"
  name                   = "productcatalogservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_productcatalogservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.productcatalogservice.arn
}

module "task_definition_recommendationservice" {
  source             = "./modules/task_definition"
  family             = "recommendationservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "recommendationservice"
      image     = "${var.image_repo_url}/recommendationservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
      environment = [
        { name = "PORT", value = "8080" },
        { name = "PRODUCT_CATALOG_SERVICE_ADDR", value = "productcatalogservice.local:3550" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "recommendationservice"
        }
      }
    }
  ])
}

module "ecs_service_recommendationservice" {
  source                 = "./modules/ecs_service"
  name                   = "recommendationservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_recommendationservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.recommendationservice.arn
}

module "task_definition_shippingservice" {
  source             = "./modules/task_definition"
  family             = "shippingservice"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "shippingservice"
      image     = "${var.image_repo_url}/shippingservice:${var.image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 50051
          hostPort      = 50051
        }
      ]
      environment = [
        { name = "PORT", value = "50051" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "shippingservice"
        }
      }
    }
  ])
}

module "ecs_service_shippingservice" {
  source                 = "./modules/ecs_service"
  name                   = "shippingservice"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_shippingservice.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
  service_registry_arn   = aws_service_discovery_service.shippingservice.arn
}

# module "task_definition_shoppingassistantservice" {
#   source             = "./modules/task_definition"
#   family             = "shoppingassistantservice"
#   execution_role_arn = module.ecs_task_roles.execution_role_arn
#   task_role_arn      = module.ecs_task_roles.task_role_arn
#   cpu                = "256"
#   memory             = "512"
#   container_definitions = jsonencode([
#     {
#       name      = "shoppingassistantservice"
#       image     = "${var.image_repo_url}/shoppingassistantservice:${var.image_tag}"
#       essential = true
#       portMappings = [
#         {
#           containerPort = 8080
#           hostPort      = 8080
#         }
#       ]
#       environment = [
#         { name = "PROJECT_ID", value = var.shopping_assistant_gcp_project_id },
#         { name = "REGION", value = var.shopping_assistant_gcp_region },
#         { name = "ALLOYDB_DATABASE_NAME", value = var.shopping_assistant_alloydb_database },
#         { name = "ALLOYDB_TABLE_NAME", value = var.shopping_assistant_alloydb_table },
#         { name = "ALLOYDB_CLUSTER_NAME", value = var.shopping_assistant_alloydb_cluster },
#         { name = "ALLOYDB_INSTANCE_NAME", value = var.shopping_assistant_alloydb_instance },
#         { name = "ALLOYDB_SECRET_NAME", value = var.shopping_assistant_alloydb_secret }
#       ]
#       logConfiguration = {
#         logDriver = "awslogs"
#         options = {
#           "awslogs-group"         = module.log_group.name
#           "awslogs-region"        = var.region
#           "awslogs-stream-prefix" = "shoppingassistantservice"
#         }
#       }
#     }
#   ])
# }

# module "ecs_service_shoppingassistantservice" {
#   source                 = "./modules/ecs_service"
#   name                   = "shoppingassistantservice"
#   cluster_id             = module.ecs_cluster.id
#   task_definition_arn    = module.task_definition_shoppingassistantservice.arn
#   desired_count          = 1
#   subnet_ids             = module.vpc.private_subnets
#   security_group_ids     = [module.ecs_sg.security_group_id]
#   capacity_provider_name = module.capacity_provider.name
#   service_registry_arn   = aws_service_discovery_service.shoppingassistantservice.arn
# }

# --- Load Generator ---

module "task_definition_loadgenerator" {
  source             = "./modules/task_definition"
  family             = "loadgenerator"
  execution_role_arn = module.ecs_task_roles.execution_role_arn
  task_role_arn      = module.ecs_task_roles.task_role_arn
  cpu                = "256"
  memory             = "512"
  container_definitions = jsonencode([
    {
      name      = "loadgenerator"
      image     = "${var.image_repo_url}/loadgenerator:${var.image_tag}"
      essential = true
      environment = [
        { name = "FRONTEND_ADDR", value = module.alb.dns_name }, # Point to ALB
        { name = "USERS", value = "10" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = module.log_group.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "loadgenerator"
        }
      }
    }
  ])
}

module "ecs_service_loadgenerator" {
  source                 = "./modules/ecs_service"
  name                   = "loadgenerator"
  cluster_id             = module.ecs_cluster.id
  task_definition_arn    = module.task_definition_loadgenerator.arn
  desired_count          = 1
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [module.ecs_sg.security_group_id]
  capacity_provider_name = module.capacity_provider.name
}

module "route53" {
  source       = "./modules/route53"
  count        = var.domain_name != "" && var.hosted_zone_id != "" ? 1 : 0
  zone_id      = var.hosted_zone_id
  name         = var.domain_name
  alb_dns_name = module.alb.dns_name
  alb_zone_id  = module.alb.zone_id
}
