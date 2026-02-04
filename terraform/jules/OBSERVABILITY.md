# Observability for Aurora (Jules)

This document describes the observability stack implemented for the Aurora project and provides guidelines for future enhancements, specifically regarding alerting.

## 1. CloudWatch Dashboard

A "Single Pane of Glass" dashboard has been provisioned to visualize the health of the application and infrastructure.
**Dashboard Name:** `<project_name>-<workspace>-dashboard` (e.g., `aurora-prod-dashboard`)

It includes:
*   **Canary Health:** Success percentage of `home`, `product`, and `cart` synthetic tests.
*   **ALB Metrics:** Request counts, 5xx error rates, and P95 latency.
*   **Application Errors:** Counts of "ERROR" or "Exception" logs from `frontend`, `checkoutservice`, and `paymentservice`.
*   **Cluster Health:** CPU and Memory utilization of the ECS Cluster.

## 2. Log Metric Filters

We have configured **Metric Filters** on CloudWatch Log Groups to extract quantitative data from text logs.
*   **Pattern:** `?ERROR ?Exception` (Matches any log line containing "ERROR" or "Exception").
*   **Metric Name:** `ErrorCount`
*   **Namespace:** `<project_name>/<workspace>/AppMetrics`
*   **Dimensions:** `Service` (e.g., `frontend`, `checkoutservice`).

## 3. How to Implement Alarms (Future Guide)

Although alarms are not currently enabled, here is a detailed guide on how to implement them using Terraform when needed.

### Prerequisites
1.  **SNS Topic:** You need an SNS topic to receive notifications (email, SMS, PagerDuty, Slack).
2.  **Alarm Resource:** Use `aws_cloudwatch_metric_alarm`.

### Step-by-Step Implementation

#### A. Create an SNS Topic for Alerts

Add this to `observability.tf`:

```hcl
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${terraform.workspace}-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = "your.email@example.com" # Change this
}
```

#### B. Create an Alarm for Canary Failure

Trigger an alarm if the Canary success rate drops below 100% (i.e., fails).

```hcl
resource "aws_cloudwatch_metric_alarm" "canary_failure" {
  alarm_name          = "${var.project_name}-${terraform.workspace}-canary-home-failure"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SuccessPercent"
  namespace           = "CloudWatchSynthetics"
  period              = "300" # 5 minutes
  statistic           = "Average"
  threshold           = "100" # Alarm if success < 100%
  alarm_description   = "Home Page Canary is failing"
  treat_missing_data  = "breaching" # Assume failure if no data

  dimensions = {
    CanaryName = aws_synthetics_canary.home.name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]
}
```

#### C. Create an Alarm for High Application Error Rate

Trigger an alarm if we see more than 5 errors in a 1-minute period.

```hcl
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "${var.project_name}-${terraform.workspace}-frontend-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ErrorCount"
  namespace           = local.metric_namespace # Defined in observability.tf
  period              = "60"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Frontend service is logging excessive errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Service = "frontend"
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
```

#### D. Create an Alarm for High Latency

Trigger if P95 latency exceeds 1 second (1000ms).

```hcl
resource "aws_cloudwatch_metric_alarm" "high_latency" {
  alarm_name          = "${var.project_name}-${terraform.workspace}-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "p95" # Use percentiles for latency
  threshold           = "1"   # 1 second
  alarm_description   = "ALB Latency is high (>1s)"

  dimensions = {
    LoadBalancer = data.aws_lb.selected.arn_suffix
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
```
