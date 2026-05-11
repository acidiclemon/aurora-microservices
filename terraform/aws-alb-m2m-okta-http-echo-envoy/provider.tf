terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


provider "aws" {
  region = var.aws_region
}

# The AWS provider specifically for fetching the ACM certificate from us-east-1
provider "aws" {
  alias  = "acm"
  region = "us-east-1"
}
