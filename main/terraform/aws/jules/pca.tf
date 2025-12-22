resource "aws_acmpca_certificate_authority" "this" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_2048"
    signing_algorithm = "SHA256WITHRSA"

    subject {
      common_name = "ecs-service-connect-ca"
    }
  }

  permanent_deletion_time_in_days = 7
}

resource "aws_acmpca_certificate" "this" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this.arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = "SHA256WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "this" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate       = aws_acmpca_certificate.this.certificate
  certificate_chain = aws_acmpca_certificate.this.certificate_chain
}

resource "aws_acmpca_permission" "this" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  actions                   = ["IssueCertificate", "GetCertificate", "ListPermissions"]
  principal                 = "ecs.amazonaws.com"
}
