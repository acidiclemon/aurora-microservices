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
}

resource "aws_cloudwatch_log_group" "microservices" {
  for_each = local.services

  name              = "/aws/ecs/${var.project_name}-${terraform.workspace}-${each.key}"
  retention_in_days = 30
}

# ------------------------------------------------------------------------------
# Log Metric Filters
# Extract "ErrorCount" from application logs
# ------------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "frontend_errors" {
  name           = "FrontendErrors"
  pattern        = "?ERROR ?Exception"
  log_group_name = aws_cloudwatch_log_group.frontend.name

  metric_transformation {
    name      = "FrontendErrorCount"
    namespace = local.metric_namespace
    value     = "1"
    # Dimensions removed as they are not supported with simple text patterns
  }
}

resource "aws_cloudwatch_log_metric_filter" "checkout_errors" {
  name           = "CheckoutErrors"
  pattern        = "?ERROR ?Exception"
  log_group_name = aws_cloudwatch_log_group.microservices["checkoutservice"].name

  metric_transformation {
    name      = "CheckoutErrorCount"
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "payment_errors" {
  name           = "PaymentErrors"
  pattern        = "?ERROR ?Exception"
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
