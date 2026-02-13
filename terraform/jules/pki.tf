resource "aws_acmpca_certificate_authority" "this" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_2048"
    signing_algorithm = "SHA256WITHRSA"

    subject {
      common_name = "${var.project_name}-${terraform.workspace}-service-connect-ca"
    }
  }

  usage_mode = "SHORT_LIVED_CERTIFICATE"

  permanent_deletion_time_in_days = 7

  tags = {
    Name = "${var.project_name}-${terraform.workspace}-service-connect-ca"
  }
}

resource "aws_acmpca_certificate" "root" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this.arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = "SHA256WITHRSA"

  template_arn = "arn:aws:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "root" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = aws_acmpca_certificate.root.certificate
  certificate_chain         = aws_acmpca_certificate.root.certificate_chain
}

# KMS Key for Service Connect TLS (Sidecar Encryption)
resource "aws_kms_key" "service_connect_tls" {
  description             = "KMS key for Service Connect TLS certificates"
  deletion_window_in_days = 7
  enable_key_rotation     = true

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
        Sid    = "Allow ECS Service Linked Role to use the key"
        Effect = "Allow"
        Principal = {
          Service = "ecs.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "service_connect_tls" {
  name          = "alias/${var.project_name}-${terraform.workspace}-service-connect-tls-key"
  target_key_id = aws_kms_key.service_connect_tls.key_id
}
