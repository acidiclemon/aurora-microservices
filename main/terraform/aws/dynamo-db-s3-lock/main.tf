provider "aws" {
  region = "us-east-2" # Change this to your preferred region
}

# --- 1. S3 BUCKET FOR STATE STORAGE ---
resource "aws_s3_bucket" "terraform_state" {
  # This name must be GLOBALLY unique (across all AWS users)
  bucket = "terraform-state-bcxulybqnmsqcriipmhmbwgprltcevxt"

  # Prevent accidental deletion of this bucket
  lifecycle {
    prevent_destroy = true
  }
}

# Enable Versioning (Highly Recommended for State recovery)
resource "aws_s3_bucket_versioning" "enabled" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access (Security Best Practice)
resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- 2. DYNAMODB TABLE FOR LOCKING ---
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
