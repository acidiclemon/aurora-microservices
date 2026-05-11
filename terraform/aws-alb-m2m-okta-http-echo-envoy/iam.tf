# -----------------------------------------------------------------------------
# ECS Task Execution Role
# -----------------------------------------------------------------------------
# This role allows ECS / Fargate to pull container images from ECR and push
# logs to CloudWatch. In the air-gapped setup, image pulls happen via
# PrivateLink VPC Endpoints (ECR API, ECR DKR, S3 Gateway).

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-task-exec-role"

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

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# -----------------------------------------------------------------------------
# ECS Task Role (main echo + envoy sidecar task)
# -----------------------------------------------------------------------------
# This role is assumed by the running application containers.
# SSM permissions are required to enable ECS Exec (interactive shell via
# AWS Systems Manager Session Manager - no inbound SSH/bastion needed).

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.project_name}-ecs-task-role"

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

# SSM permissions required for ECS Exec (interactive container shell via UI/CLI)
# Docs: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
resource "aws_iam_role_policy" "ecs_task_role_ssm_exec" {
  name = "${var.project_name}-ecs-exec-ssm"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # ECS Exec requires SSM Session Manager to open a channel into the container
        Sid    = "AllowECSExecSSM"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      },
      {
        # Allow the task to write logs / metrics (already covered by exec role
        # but having it here makes the task self-sufficient for CloudWatch Logs
        # streams used by ECS Exec session logging)
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Envoy Gateway Task Role
# -----------------------------------------------------------------------------
# Minimal role for the standalone envoy-gateway ECS task.
# It also needs SSM exec permissions so you can shell into it if needed.

resource "aws_iam_role" "envoy_gateway_task_role" {
  name = "${var.project_name}-envoy-gw-task-role"

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

resource "aws_iam_role_policy" "envoy_gateway_task_role_ssm_exec" {
  name = "${var.project_name}-envoy-gw-exec-ssm"
  role = aws_iam_role.envoy_gateway_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECSExecSSM"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}
