resource "aws_acm_pca_certificate_authority" "this" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_2048"
    signing_algorithm = "SHA256WITHRSA"

    subject {
      common_name  = "${var.project_name}-${terraform.workspace}-root-ca"
      organization = "${var.project_name}"
    }
  }

  permanent_deletion_time_in_days = 7
}

resource "aws_acmpca_certificate" "this" {
  certificate_authority_arn   = aws_acm_pca_certificate_authority.this.arn
  certificate_signing_request = aws_acm_pca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = "SHA256WITHRSA"

  template_arn = "arn:aws:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acm_pca_certificate_authority_certificate" "this" {
  certificate_authority_arn = aws_acm_pca_certificate_authority.this.arn
  certificate       = aws_acmpca_certificate.this.certificate
  certificate_chain = aws_acmpca_certificate.this.certificate_chain
}

resource "aws_iam_policy" "service_connect_tls" {
  name        = "${var.project_name}-${terraform.workspace}-service-connect-tls-policy"
  description = "Allow ECS tasks to communicate with ACM PCA for Service Connect TLS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "acm-pca:IssueCertificate",
          "acm-pca:GetCertificate",
          "acm-pca:DescribeCertificateAuthority"
        ]
        Resource = aws_acm_pca_certificate_authority.this.arn
      }
    ]
  })
}
