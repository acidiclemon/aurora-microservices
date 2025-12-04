# 1. VPC & Networking
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "${var.app_name}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = { Name = "${var.app_name}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = { Name = "${var.app_name}-private-${count.index}" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_eip" "nat" {
  count = 2
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

data "aws_availability_zones" "available" {
  state = "available"
}

# 2. Security Groups
resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb-sg"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_tasks" {
  name   = "${var.app_name}-ecs-tasks-sg"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. IAM – ECS Instance Role
resource "aws_iam_role" "ecs_instance_role" {
  name = "${var.app_name}-ecs-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_instance_role_policy" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_instance" {
  name = "${var.app_name}-ecs-instance-profile"
  role = aws_iam_role.ecs_instance_role.name
}

# 4. IAM – Task Execution Role (pulls image + writes logs)
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.app_name}-ecs-task-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# 5. Launch Template (ECS-optimized AMI)
data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
}

resource "aws_launch_template" "ecs" {
  name_prefix   = "${var.app_name}-"
  image_id      = data.aws_ssm_parameter.ecs_ami.value
  instance_type = "t3.medium"

  vpc_security_group_ids = [aws_security_group.ecs_tasks.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_instance.name
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo ECS_CLUSTER=${aws_ecs_cluster.main.name} >> /etc/ecs/ecs.config
    EOF
  )
}

# 6. Auto Scaling Group
resource "aws_autoscaling_group" "ecs" {
  name                = "${var.app_name}-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  min_size            = 1
  max_size            = 10
  desired_capacity    = 2

  launch_template {
    id      = aws_launch_template.ecs.id
    version = aws_launch_template.ecs.latest_version
  }

  tag {
    key                 = "AmazonECSManaged"
    value               = true
    propagate_at_launch = true
  }
}

# 7. ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.app_name}-cluster"
}

# 8. Capacity Provider
resource "aws_ecs_capacity_provider" "main" {
  name = "${var.app_name}-cp"

  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.ecs.arn
    managed_termination_protection = "ENABLED"

    managed_scaling {
      status          = "ENABLED"
      target_capacity = 100
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = [aws_ecs_capacity_provider.main.name]

  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.main.name
    weight            = 100
  }
}

# 10. ALB
resource "aws_lb" "main" {
  name               = "${var.app_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "main" {
  name        = "${var.app_name}-tg"
  port        = 3000           # whatever your container listens on
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"           # important for awsvpc mode

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/xxxx-xxxx-xxxx-xxxx-xxxx"  # ← change or skip for HTTP-only

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# 13. CloudWatch Log Group
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.app_name}"
  retention_in_days = 30
}

# 14. Task Definition
resource "aws_ecs_task_definition" "app" {
  family                   = var.app_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["EC2"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([{
    name      = var.app_name
    ########################################################image     = var.ecr_image_url
    essential = true
    portMappings = [{
      containerPort = 3000
      hostPort      = 3000
      protocol      = "tcp"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.app.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

# 15. ECS Service – THE BIG ONE
resource "aws_ecs_service" "main" {
  name            = "${var.app_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "EC2"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = var.app_name
    container_port   = 3000
  }

  # These explicit depends_on are required because of circular dependency between ALB ↔ service
  depends_on = [
    aws_lb_listener.https,
    aws_ecs_capacity_provider.main,
  ]
}

# 16. Optional Route 53 record
# resource "aws_route53_record" "app" {
#   zone_id = "Z1234567890"
#   name    = "app.example.com"
#   type    = "A"
#   alias {
#     name                   = aws_lb.main.dns_name
#     zone_id                = aws_lb.main.zone_id
#     evaluate_target_health = true
#   }
# }
