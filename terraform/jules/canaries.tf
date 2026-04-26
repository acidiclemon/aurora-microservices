################################################################################
# CloudWatch Synthetics Canaries
################################################################################

# S3 Bucket for Canary Artifacts
resource "aws_s3_bucket" "canary_artifacts" {
  bucket        = substr("${var.project_name}-${terraform.workspace}-canary-${data.aws_caller_identity.current.account_id}", 0, 63)
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "canary_artifacts" {
  bucket                  = aws_s3_bucket.canary_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "canary_artifacts" {
  bucket = aws_s3_bucket.canary_artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

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
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.canary_artifacts.arn,
          "${aws_s3_bucket.canary_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.logs_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
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
  output_path = "${path.module}/canary_scripts/home.zip"

  source {
    content  = file("${path.module}/canary_scripts/home.py")
    filename = "python/home.py"
  }
}

data "archive_file" "canary_product" {
  type        = "zip"
  output_path = "${path.module}/canary_scripts/product.zip"

  source {
    content  = file("${path.module}/canary_scripts/product.py")
    filename = "python/product.py"
  }
}

data "archive_file" "canary_cart" {
  type        = "zip"
  output_path = "${path.module}/canary_scripts/cart.zip"

  source {
    content  = file("${path.module}/canary_scripts/cart.py")
    filename = "python/cart.py"
  }
}

locals {
  # Determine base URL: If domain is set, use it; otherwise use CloudFront URL (ALB is private)
  base_url = var.domain_name != "" ? "https://${var.project_name}-${terraform.workspace}.${var.domain_name}" : "https://${aws_cloudfront_distribution.this.domain_name}"
}

# Canary 1: Home Page
resource "aws_synthetics_canary" "home" {
  name                 = substr("${var.project_name}-${terraform.workspace}-home", 0, 21)
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/home"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "home.handler"
  zip_file             = data.archive_file.canary_home.output_path
  runtime_version      = "syn-python-selenium-8.0"
  start_canary         = true

  depends_on = [
    aws_cloudfront_distribution.this,
    module.alb
  ]

  schedule {
    expression = "rate(3 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL                = local.base_url
      ARTIFACT_S3_BUCKET = aws_s3_bucket.canary_artifacts.bucket
      CANARY_NAME        = "home"
    }
  }
}

# Canary 2: Product Page (Microservice 1: ProductCatalog)
resource "aws_synthetics_canary" "product" {
  name                 = substr("${var.project_name}-${terraform.workspace}-prod", 0, 21)
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/product"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "product.handler"
  zip_file             = data.archive_file.canary_product.output_path
  runtime_version      = "syn-python-selenium-8.0"
  start_canary         = true

  depends_on = [
    aws_cloudfront_distribution.this,
    module.alb
  ]

  schedule {
    expression = "rate(3 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL                = "${local.base_url}/product/OLJCESPC7Z"
      ARTIFACT_S3_BUCKET = aws_s3_bucket.canary_artifacts.bucket
      CANARY_NAME        = "product"
    }
  }
}

# Canary 3: Cart Page (Microservice 2: Cart)
resource "aws_synthetics_canary" "cart" {
  name                 = substr("${var.project_name}-${terraform.workspace}-cart", 0, 21)
  artifact_s3_location = "s3://${aws_s3_bucket.canary_artifacts.bucket}/cart"
  execution_role_arn   = aws_iam_role.canary_role.arn
  handler              = "cart.handler"
  zip_file             = data.archive_file.canary_cart.output_path
  runtime_version      = "syn-python-selenium-8.0"
  start_canary         = true

  depends_on = [
    aws_cloudfront_distribution.this,
    module.alb
  ]

  schedule {
    expression = "rate(3 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    environment_variables = {
      URL                = "${local.base_url}/cart"
      ARTIFACT_S3_BUCKET = aws_s3_bucket.canary_artifacts.bucket
      CANARY_NAME        = "cart"
    }
  }
}
