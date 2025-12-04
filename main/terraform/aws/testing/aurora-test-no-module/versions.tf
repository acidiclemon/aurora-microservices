terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }

  # Optional but recommended for real projects
  backend "s3" {
    bucket         = "terraform-state-bcxulybqnmsqcriipmhmbwgprltcevxt"  # CHANGE THIS
    key            = "testing/aurora-test-no-module/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
}
