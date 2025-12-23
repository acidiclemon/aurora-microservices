resource "aws_acmpca_certificate_authority" "this" {
  type = "ROOT"

  usage_mode = "SHORT_LIVED_CERTIFICATE"

  certificate_authority_configuration {
    key_algorithm     = "RSA_2048"
    signing_algorithm = "SHA256WITHRSA"

    subject {
      common_name = "AuroraRootCA"
    }
  }

  permanent_deletion_time_in_days = 7
}

resource "aws_acmpca_certificate" "this" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this.arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = "SHA256WITHRSA"

  template_arn = "arn:aws:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "this" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = aws_acmpca_certificate.this.certificate
  certificate_chain         = aws_acmpca_certificate.this.certificate_chain
}

resource "aws_iam_policy" "acm_pca_policy" {
  name        = "${var.project_name}-${terraform.workspace}-acm-pca-policy"
  description = "Policy for ECS tasks to access ACM Private CA"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "acm-pca:DescribeCertificateAuthority",
          "acm-pca:GetCertificate",
          "acm-pca:IssueCertificate"
        ]
        Resource = [
          aws_acmpca_certificate_authority.this.arn
        ]
      }
    ]
  })
}
