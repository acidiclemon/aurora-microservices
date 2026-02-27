################################################################################
# Private Certificate Authority (PCA) for Service Connect TLS
# Only created when domain_name is set (full encryption mode)
################################################################################

resource "aws_acmpca_certificate_authority" "this" {
  count = var.domain_name != "" ? 1 : 0

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
    Name              = "${var.project_name}-${terraform.workspace}-service-connect-ca"
    AmazonECSManaged  = "true"
  }
}

resource "aws_acmpca_certificate" "root" {
  count = var.domain_name != "" ? 1 : 0

  certificate_authority_arn   = aws_acmpca_certificate_authority.this[0].arn
  certificate_signing_request = aws_acmpca_certificate_authority.this[0].certificate_signing_request
  signing_algorithm           = "SHA256WITHRSA"

  template_arn = "arn:aws:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 10
  }
}

resource "aws_acmpca_certificate_authority_certificate" "root" {
  count = var.domain_name != "" ? 1 : 0

  certificate_authority_arn = aws_acmpca_certificate_authority.this[0].arn
  certificate               = aws_acmpca_certificate.root[0].certificate
  certificate_chain         = aws_acmpca_certificate.root[0].certificate_chain
}

################################################################################
# ECS Infrastructure IAM Role for Service Connect TLS
################################################################################

resource "aws_iam_role" "ecs_sc_tls_infra" {
  count = var.domain_name != "" ? 1 : 0

  name = "${var.project_name}-${terraform.workspace}-ecs-sc-tls-infra-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccessToECSForInfrastructureManagement"
        Effect = "Allow"
        Principal = {
          Service = "ecs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${terraform.workspace}-ecs-sc-tls-infra-role"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_sc_tls_infra" {
  count = var.domain_name != "" ? 1 : 0

  role       = aws_iam_role.ecs_sc_tls_infra[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForServiceConnectTransportLayerSecurity"
}

################################################################################
# KMS Key for Service Connect TLS (Sidecar Encryption)
################################################################################

resource "aws_kms_key" "service_connect_tls" {
  count = var.domain_name != "" ? 1 : 0

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
      },
      {
        Sid    = "Allow ECS Infrastructure Role for Service Connect TLS"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-${terraform.workspace}-ecs-sc-tls-infra-role"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyPair"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "service_connect_tls" {
  count = var.domain_name != "" ? 1 : 0

  name          = "alias/${var.project_name}-${terraform.workspace}-service-connect-tls-key"
  target_key_id = aws_kms_key.service_connect_tls[0].key_id
}
