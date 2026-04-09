locals {
  metric_namespace = "${var.project_name}/${terraform.workspace}/AppMetrics"
}

# ------------------------------------------------------------------------------
# Data Sources
# ------------------------------------------------------------------------------

# Retrieve ALB details to get the ARN suffix for CloudWatch dimensions
data "aws_lb" "selected" {
  arn = module.alb.arn
}

# ------------------------------------------------------------------------------
# Log Groups
# Explicitly manage Log Groups to ensure existence before Metric Filters
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}-frontend"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs_key.arn

  depends_on = [aws_kms_key_policy.logs_key]
}

resource "aws_cloudwatch_log_group" "microservices" {
  for_each = local.services

  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}-${each.key}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs_key.arn

  depends_on = [aws_kms_key_policy.logs_key]
}

# ------------------------------------------------------------------------------
# Log Metric Filters
# Extract "ErrorCount" from application logs
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "frontend_errors" {
  name           = "FrontendErrors"
  pattern        = "?ERROR ?error ?Exception ?exception"
  log_group_name = aws_cloudwatch_log_group.frontend.name

  metric_transformation {
    name      = "FrontendErrorCount"
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "checkout_errors" {
  name           = "CheckoutErrors"
  pattern        = "?ERROR ?error ?Exception ?exception"
  log_group_name = aws_cloudwatch_log_group.microservices["checkoutservice"].name

  metric_transformation {
    name      = "CheckoutErrorCount"
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "payment_errors" {
  name           = "PaymentErrors"
  pattern        = "?ERROR ?error ?Exception ?exception"
  log_group_name = aws_cloudwatch_log_group.microservices["paymentservice"].name

  metric_transformation {
    name      = "PaymentErrorCount"
    namespace = local.metric_namespace
    value     = "1"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Dashboard
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-${terraform.workspace}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# ${var.project_name} (${terraform.workspace}) Observability"
        }
      },
      # Row 1: Canaries & ALB
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 8
        height = 6
        properties = {
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "Canary Success %"
          metrics = [
            ["CloudWatchSynthetics", "SuccessPercent", "CanaryName", aws_synthetics_canary.home.name],
            ["CloudWatchSynthetics", "SuccessPercent", "CanaryName", aws_synthetics_canary.product.name],
            ["CloudWatchSynthetics", "SuccessPercent", "CanaryName", aws_synthetics_canary.cart.name]
          ]
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 1
        width  = 8
        height = 6
        properties = {
          view    = "timeSeries"
          region  = var.region
          title   = "ALB Traffic & Errors"
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", data.aws_lb.selected.arn_suffix, { stat = "Sum", period = 60 }],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", data.aws_lb.selected.arn_suffix, { stat = "Sum", period = 60, color = "#d13212" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 1
        width  = 8
        height = 6
        properties = {
          view    = "timeSeries"
          region  = var.region
          title   = "ALB Latency (P95)"
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", data.aws_lb.selected.arn_suffix, { stat = "p95", period = 60 }]
          ]
        }
      },
      # Row 2: Application Errors (Log Filters)
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          view    = "timeSeries"
          region  = var.region
          title   = "Application Errors (Logs)"
          metrics = [
            [local.metric_namespace, "FrontendErrorCount", { stat = "Sum", period = 60, label = "Frontend" }],
            [local.metric_namespace, "CheckoutErrorCount", { stat = "Sum", period = 60, label = "Checkout" }],
            [local.metric_namespace, "PaymentErrorCount", { stat = "Sum", period = 60, label = "Payment" }]
          ]
        }
      },
      # Row 3: Cluster Health
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6
        properties = {
          view    = "timeSeries"
          region  = var.region
          title   = "ECS Cluster Utilization"
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", module.ecs.cluster_name, { stat = "Average", period = 60 }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", module.ecs.cluster_name, { stat = "Average", period = 60 }]
          ]
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Security Team IAM Role (for log access)
# ------------------------------------------------------------------------------

resource "aws_iam_role" "security_team_role" {
  name = "${var.project_name}-${terraform.workspace}-security-team-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "security_team_policy" {
  name   = "${var.project_name}-${terraform.workspace}-security-team-policy"
  role   = aws_iam_role.security_team_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.raw_logs.arn,
          "${aws_s3_bucket.raw_logs.arn}/*",
          aws_s3_bucket.audit_findings.arn,
          "${aws_s3_bucket.audit_findings.arn}/*",
          aws_s3_bucket.flow_logs.arn,
          "${aws_s3_bucket.flow_logs.arn}/*",
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
      },
      {
        Sid    = "DecryptOperationalLogs"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.logs_key.arn
      },
      {
        Sid    = "DecryptRegulatedData"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.regulated_data_key.arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Key for Logs
# ------------------------------------------------------------------------------

resource "aws_kms_key" "logs_key" {
  description             = "KMS key for ${var.project_name}-${terraform.workspace} logs"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "logs_key" {
  name          = "alias/${var.project_name}-${terraform.workspace}-logs-key"
  target_key_id = aws_kms_key.logs_key.key_id
}

resource "aws_kms_key_policy" "logs_key" {
  key_id = aws_kms_key.logs_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" : "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Key for Regulated Data (unmasked PII/PHI/PAN)
# Separated from logs_key to enforce data classification boundaries.
# Used by: raw_logs bucket, audit_findings bucket
# ------------------------------------------------------------------------------

resource "aws_kms_key" "regulated_data_key" {
  description             = "KMS key for ${var.project_name}-${terraform.workspace} regulated data (unmasked PII/PHI/PAN)"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "regulated_data_key" {
  name          = "alias/${var.project_name}-${terraform.workspace}-regulated-data-key"
  target_key_id = aws_kms_key.regulated_data_key.key_id
}

resource "aws_kms_key_policy" "regulated_data_key" {
  key_id = aws_kms_key.regulated_data_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs for Audit Findings"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        Sid    = "Allow Kinesis Firehose"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Audit & Raw Logs S3 Buckets
# ------------------------------------------------------------------------------

# Bucket 1: Raw Logs (from Firehose) - Unmasked
resource "aws_s3_bucket" "raw_logs" {
  bucket        = "${var.project_name}-${terraform.workspace}-raw-logs"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.regulated_data_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow Firehose to write
      {
        Sid    = "FirehoseWrite"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.firehose_role.arn
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.raw_logs.arn}/*"
      },
      # Restrict Access to Security Team Role
      {
        Sid    = "SecurityTeamRead"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.raw_logs.arn}/*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              aws_iam_role.security_team_role.arn,        # The Role ARN itself
              "${aws_iam_role.security_team_role.arn}/*"  # Any assumed role session
            ]
          }
        }
      }
    ]
  })
}

# Bucket 2: Audit Findings (from Policy) - Unmasked
resource "aws_s3_bucket" "audit_findings" {
  bucket        = "${var.project_name}-${terraform.workspace}-audit-findings"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "audit_findings" {
  bucket = aws_s3_bucket.audit_findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_findings" {
  bucket = aws_s3_bucket.audit_findings.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.regulated_data_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "audit_findings" {
  bucket = aws_s3_bucket.audit_findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow CloudWatch Logs to write
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.audit_findings.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.audit_findings.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      # Restrict Access to Security Team Role
      {
        Sid    = "SecurityTeamRead"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:GetObject"
        Resource = "${aws_s3_bucket.audit_findings.arn}/*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              aws_iam_role.security_team_role.arn,        # The Role ARN itself
              "${aws_iam_role.security_team_role.arn}/*"  # Any assumed role session
            ]
          }
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Log Data Protection Policy
# ------------------------------------------------------------------------------

# Create a time_sleep to handle S3 bucket policy eventual consistency
resource "time_sleep" "wait_for_bucket_policy" {
  depends_on = [aws_s3_bucket_policy.audit_findings]

  create_duration = "60s"
}

locals {
  data_protection_policy = jsonencode({
    Name        = "data-protection-policy"
    Description = "Mask PCI-DSS sensitive data"
    Version     = "2021-06-01"
    Statement = [
      {
        Sid = "audit-policy"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/CreditCardNumber",
          "arn:aws:dataprotection::aws:data-identifier/CreditCardSecurityCode",
          "arn:aws:dataprotection::aws:data-identifier/Ssn-US",
          "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
          "arn:aws:dataprotection::aws:data-identifier/Address",
          "arn:aws:dataprotection::aws:data-identifier/Name"
        ]
        Operation = {
          Audit = {
            FindingsDestination = {
              S3 = {
                Bucket = aws_s3_bucket.audit_findings.bucket
              }
            }
          }
        }
      },
      {
        Sid = "de-identify-policy"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/CreditCardNumber",
          "arn:aws:dataprotection::aws:data-identifier/CreditCardSecurityCode",
          "arn:aws:dataprotection::aws:data-identifier/Ssn-US",
          "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
          "arn:aws:dataprotection::aws:data-identifier/Address",
          "arn:aws:dataprotection::aws:data-identifier/Name"
        ]
        Operation = {
          Deidentify = {
            MaskConfig = {}
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_data_protection_policy" "frontend" {
  log_group_name  = aws_cloudwatch_log_group.frontend.name
  policy_document = local.data_protection_policy

  depends_on = [time_sleep.wait_for_bucket_policy]
}

resource "aws_cloudwatch_log_data_protection_policy" "microservices" {
  for_each = local.services

  log_group_name  = aws_cloudwatch_log_group.microservices[each.key].name
  policy_document = local.data_protection_policy

  depends_on = [time_sleep.wait_for_bucket_policy]
}

resource "aws_cloudwatch_log_data_protection_policy" "collector" {
  log_group_name  = aws_cloudwatch_log_group.collector.name
  policy_document = local.data_protection_policy

  depends_on = [time_sleep.wait_for_bucket_policy]
}

# ------------------------------------------------------------------------------
# Firehose Delivery Stream for Logs
# ------------------------------------------------------------------------------

resource "aws_iam_role" "firehose_role" {
  name = "${var.project_name}-${terraform.workspace}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose_policy" {
  name   = "${var.project_name}-${terraform.workspace}-firehose-policy"
  role   = aws_iam_role.firehose_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.raw_logs.arn,
          "${aws_s3_bucket.raw_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.regulated_data_key.arn
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "logs_stream" {
  name        = "${var.project_name}-${terraform.workspace}-logs-stream"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.regulated_data_key.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.raw_logs.arn

    buffering_size     = 5
    buffering_interval = 300
    compression_format = "GZIP"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Logs Subscription to Firehose
# ------------------------------------------------------------------------------

resource "aws_iam_role" "logs_subscription_role" {
  name = "${var.project_name}-${terraform.workspace}-logs-subscription-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "logs_subscription_policy" {
  name   = "${var.project_name}-${terraform.workspace}-logs-subscription-policy"
  role   = aws_iam_role.logs_subscription_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "firehose:PutRecord"
        Resource = aws_kinesis_firehose_delivery_stream.logs_stream.arn
      },
      # Allow unmasking logs when sending to destination
      {
        Effect = "Allow"
        Action = "logs:Unmask"
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "frontend" {
  name            = "${var.project_name}-${terraform.workspace}-frontend-to-s3"
  log_group_name  = aws_cloudwatch_log_group.frontend.name
  filter_pattern  = "" # All logs
  destination_arn = aws_kinesis_firehose_delivery_stream.logs_stream.arn
  role_arn        = aws_iam_role.logs_subscription_role.arn
}

resource "aws_cloudwatch_log_subscription_filter" "microservices" {
  for_each = local.services

  name            = "${var.project_name}-${terraform.workspace}-${each.key}-to-s3"
  log_group_name  = aws_cloudwatch_log_group.microservices[each.key].name
  filter_pattern  = "" # All logs
  destination_arn = aws_kinesis_firehose_delivery_stream.logs_stream.arn
  role_arn        = aws_iam_role.logs_subscription_role.arn
}

# ------------------------------------------------------------------------------
# VPC Flow Logs → S3 (F-PCI-06 — PCI DSS Req 10.2.1, HIPAA §164.312(b))
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "flow_logs" {
  bucket        = "${var.project_name}-${terraform.workspace}-flow-logs"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow VPC Flow Logs delivery
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.flow_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.flow_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      # Restrict read access to Security Team Role only
      {
        Sid       = "SecurityTeamRead"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.flow_logs.arn}/*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
              aws_iam_role.security_team_role.arn,
              "${aws_iam_role.security_team_role.arn}/*"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id               = module.vpc.vpc_id
  log_destination      = aws_s3_bucket.flow_logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"

  tags = {
    Name        = "${var.project_name}-${terraform.workspace}-vpc-flow-logs"
    Environment = terraform.workspace
    Project     = var.project_name
  }
}
