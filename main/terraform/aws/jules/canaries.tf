################################################################################
# CloudWatch Synthetics Canaries
################################################################################

# S3 Bucket for Canary Artifacts
resource "aws_s3_bucket" "canary_artifacts" {
  bucket        = substr("${var.project_name}-${terraform.workspace}-canary-${data.aws_caller_identity.current.account_id}", 0, 63)
  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

# IAM Role for Canaries
resource "aws_iam_role" "canary_role" {
  name = "${var.project_name}-${terraform.workspace}-canary-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "canary_policy" {
  name = "${var.project_name}-${terraform.workspace}-canary-policy"
  role = aws_iam_role.canary_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:GetBucketLocation",
          "s3:ListAllMyBuckets"
        ]
        Resource = [
          aws_s3_bucket.canary_artifacts.arn,
          "${aws_s3_bucket.canary_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "CloudWatchSynthetics"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/cwsyn-*"
      }
    ]
  })
}

# Zip Scripts
data "archive_file" "canary_home" {
  type        = "zip"
  source_file = "${path.module}/canary_scripts/home.js"
  output_path = "${path.module}/canary_scripts/home.zip"
}

data "archive_file" "canary_product" {
  type        = "zip"
  source_file = "${path.module}/canary_scripts/product.js"
  output_path = "${path.module}/canary_scripts/product.zip"
}

data "archive_file" "canary_cart" {
  type        = "zip"
  source_file = "${path.module}/canary_scripts/cart.js"
  output_path = "${path.module}/canary_scripts/cart.zip"
}

data "archive_file" "canary_health" {
  type        = "zip"
  source_file = "${path.module}/canary_scripts/health.js"
  output_path = "${path.module}/canary_scripts/health.zip"
}

locals {
  # Determine base URL: If domain is set, use it; otherwise use ALB DNS
  base_url = var.domain_name != "" ? "https://${var.project_name}-${terraform.workspace}.${var.domain_name}" : "http://${module.alb.dns_name}"
}

# Canary 1: Home Page
resource "aws_synthetics_canary" "home" {
  name                 = "canary-${substr(md5("${var.project_name}-${terraform.workspace}"), 0, 8)}-home"
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/home"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "home.handler"
  zip_file             = data.archive_file.canary_home.output_path
  runtime_version      = "syn-nodejs-puppeteer-9.0"
  start_canary         = true

  schedule {
    expression = "rate(5 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL = local.base_url
    }
  }
}

# Canary 2: Product Page (Microservice 1: ProductCatalog)
resource "aws_synthetics_canary" "product" {
  name                 = "canary-${substr(md5("${var.project_name}-${terraform.workspace}"), 0, 8)}-prod"
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/product"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "product.handler"
  zip_file             = data.archive_file.canary_product.output_path
  runtime_version      = "syn-nodejs-puppeteer-9.0"
  start_canary         = true

  schedule {
    expression = "rate(5 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL = "${local.base_url}/product/OLJCESPC7Z"
    }
  }
}

# Canary 3: Cart Page (Microservice 2: Cart)
resource "aws_synthetics_canary" "cart" {
  name                 = "canary-${substr(md5("${var.project_name}-${terraform.workspace}"), 0, 8)}-cart"
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/cart"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "cart.handler"
  zip_file             = data.archive_file.canary_cart.output_path
  runtime_version      = "syn-nodejs-puppeteer-9.0"
  start_canary         = true

  schedule {
    expression = "rate(5 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL = "${local.base_url}/cart"
    }
  }
}

# Canary 4: Health Check (Microservice 3: Frontend Health)
resource "aws_synthetics_canary" "health" {
  name                 = "canary-${substr(md5("${var.project_name}-${terraform.workspace}"), 0, 8)}-hlth"
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/health"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "health.handler"
  zip_file             = data.archive_file.canary_health.output_path
  runtime_version      = "syn-nodejs-puppeteer-9.0"
  start_canary         = true

  schedule {
    expression = "rate(5 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL = "${local.base_url}/_healthz"
    }
  }
}
