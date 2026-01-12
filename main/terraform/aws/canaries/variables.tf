variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Project name prefix for resources"
  type        = string
  default     = "aurora"
}

variable "app_url" {
  description = "URL of the application to test"
  type        = string
}
