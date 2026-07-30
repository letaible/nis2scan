# Cross-account read-only role for nis2scan (STS AssumeRole with ExternalId).
# Deploy this in each TARGET account that nis2scan should scan.
#
#   terraform apply \
#     -var scanner_principal_arn=arn:aws:iam::<SCANNER_ACCOUNT>:root \
#     -var external_id=<PER_TENANT_SECRET>
#
# The attached permissions are a placeholder Reader statement — replace the
# policy body with the exact output of:  nis2scan permissions -p aws -f terraform
# (the generated aws_iam_policy grants only the read actions the checks use).

terraform {
  required_version = ">= 1.0"
  required_providers {
    # Obergrenze wie in infra/aws/providers.tf (30.07.2026). Dieser Stack hat
    # noch keinen Lock (nie appliziert); Basis ist deshalb dieselbe Major wie
    # im OIDC-Stack desselben Kontos.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.36"
    }
  }
}

variable "scanner_principal_arn" {
  description = "ARN allowed to assume this role (the nis2scan CLI user / SaaS worker role)"
  type        = string
}

variable "external_id" {
  description = "Shared secret required in the AssumeRole call (confused-deputy protection). Unique per tenant."
  type        = string
  sensitive   = true
}

variable "role_name" {
  description = "Name of the read-only role nis2scan assumes"
  type        = string
  default     = "nis2scan-readonly"
}

resource "aws_iam_role" "nis2scan_readonly" {
  name        = var.role_name
  description = "Read-only role assumed by nis2scan for NIS2 §30 BSIG compliance scans"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = var.scanner_principal_arn }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = var.external_id }
        }
      }
    ]
  })

  max_session_duration = 3600
  tags                 = { "managed-by" = "nis2scan" }
}

# AWS-managed ReadOnlyAccess as a safe default. For least privilege, replace
# this attachment with a customer-managed policy from the permissions generator.
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.nis2scan_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "role_arn" {
  description = "Pass this to nis2scan --assume-role-arn (or the SaaS cloud account)"
  value       = aws_iam_role.nis2scan_readonly.arn
}
