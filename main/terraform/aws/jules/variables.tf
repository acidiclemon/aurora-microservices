variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cidr_block" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnets" {
  description = "List of public subnet CIDRs"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnets" {
  description = "List of private subnet CIDRs"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "image_repo_url" {
  description = "Base URL for the ECR repository"
  type        = string
}

variable "image_tag" {
  description = "Tag for the images"
  type        = string
  default     = "latest"
}

variable "shopping_assistant_gcp_project_id" {
  type = string
  default = ""
}

variable "shopping_assistant_gcp_region" {
  type = string
  default = "us-central1"
}

variable "shopping_assistant_alloydb_database" {
  type = string
  default = ""
}

variable "shopping_assistant_alloydb_table" {
  type = string
  default = ""
}

variable "shopping_assistant_alloydb_cluster" {
  type = string
  default = ""
}

variable "shopping_assistant_alloydb_instance" {
  type = string
  default = ""
}

variable "shopping_assistant_alloydb_secret" {
  type = string
  default = ""
}
