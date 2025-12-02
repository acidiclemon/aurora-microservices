terraform {
  # ⚠️ RUN 'terraform apply' ON THE RESOURCES ABOVE BEFORE ENABLING THIS!
  backend "s3" {
    bucket         = "terraform-state-bcxulybqnmsqcriipmhmbwgprltcevxt" # Must match bucket name above
    key            = "dynamo-db-s3-lock/terraform.tfstate"
    region         = "us-east-2"
    encrypt        = true

    # ⬇️ The required configuration for v1.5.7 ⬇️
    dynamodb_table = "terraform-locks" # Must match table name above
  }

  # Since you are on Cloud Shell v1.5.7, this constraint is safe for you
  required_version = ">= 1.5.7"
}
