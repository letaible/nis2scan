# ============================================================================
# nis2scan — OIDC + CI IAM Role for GitHub Actions
# ============================================================================
# This is a ONE-TIME manual apply. It creates the OIDC trust between
# GitHub Actions and your AWS account, plus the IAM role used by CI.
#
# Usage:
#   cd infra/aws/oidc
#   terraform init
#   terraform apply -var="github_repo=letaible/nis2scan" -var="aws_account_id=YOUR_ACCOUNT_ID"
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    # Obergrenzen wie in infra/aws/providers.tf (30.07.2026). Basis ist die
    # Version, mit der dieser Stack zuletzt lief (Lock: aws 6.36.0, tls 4.2.1).
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.36"
    }
    # tls wurde genutzt, aber nicht deklariert.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.2"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --------------------------------------------------------------------------
# Variables
# --------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "aws_account_id" {
  description = "AWS Account ID where the CI role will be created"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository (owner/repo format)"
  type        = string
  default     = "letaible/nis2scan"
}

# GitHub issues ID-hardened OIDC subjects (owner@id/repo@id) for this repo
# since its transfer into the letaible org — the sub claim carries immutable
# numeric IDs to prevent name-reuse attacks. Both formats are trusted.
variable "github_repo_with_ids" {
  description = "GitHub repository in ID-hardened OIDC subject format (owner@id/repo@id)"
  type        = string
  default     = "letaible@308314955/nis2scan@1300122537"
}

# --------------------------------------------------------------------------
# OIDC Provider for GitHub Actions
# --------------------------------------------------------------------------

data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]

  tags = {
    Project = "nis2scan"
    Purpose = "GitHub Actions OIDC"
  }
}

# --------------------------------------------------------------------------
# CI IAM Role — assumed by GitHub Actions via OIDC
# --------------------------------------------------------------------------

data "aws_iam_policy_document" "ci_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repo}:*",
        "repo:${var.github_repo_with_ids}:*",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "nis2scan_ci" {
  name                 = "nis2scan-ci"
  assume_role_policy   = data.aws_iam_policy_document.ci_trust.json
  max_session_duration = 3600

  tags = {
    Project = "nis2scan"
    Purpose = "CI/CD Integration Tests"
  }
}

# --------------------------------------------------------------------------
# CI IAM Policy — scan permissions (read) + terraform CRUD (write)
# --------------------------------------------------------------------------

# --- Policy 1: Scan read permissions (for nis2scan checks) ---
data "aws_iam_policy_document" "ci_scan_read" {
  statement {
    sid    = "ScanReadPermissions"
    effect = "Allow"
    actions = [
      # S3
      "s3:ListAllMyBuckets",
      "s3:GetBucketEncryption",
      "s3:GetBucketLocation",
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketPolicy",
      "s3:GetBucketVersioning",
      # EC2
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeSecurityGroups",
      "ec2:GetSecurityGroupsForVpc",
      "ec2:DescribeRegions",
      # RDS
      "rds:DescribeDBInstances",
      # KMS
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
      # IAM
      "iam:ListUsers",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "iam:GetLoginProfile",
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetAccessKeyLastUsed",
      # ELB
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeSSLPolicies",
      # GuardDuty
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      # CloudWatch
      "cloudwatch:DescribeAlarms",
      # Support (Trusted Advisor)
      "support:DescribeTrustedAdvisorChecks",
      # ECR
      "ecr:DescribeRepositories",
      # SSM
      "ssm:DescribeInstanceInformation",
      # ACM
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      # CloudTrail
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      # STS
      "sts:GetCallerIdentity",
      # Config
      "config:DescribeConfigurationRecorders",
      "config:DescribeConfigurationRecorderStatus",
      "config:DescribeConfigRules",
      "config:DescribeComplianceByConfigRule",
      # Security Hub
      "securityhub:DescribeHub",
      # Lambda
      "lambda:ListFunctions",
      "lambda:GetFunction",
      # CloudWatch Logs
      "logs:DescribeLogGroups",
      # EC2 (Snapshots)
      "ec2:DescribeSnapshots",
      # S3 (Object Lock)
      "s3:GetBucketObjectLockConfiguration",
      # IAM (user tags for break-glass check)
      "iam:ListUserTags",
      # Organizations (NR1-003)
      "organizations:DescribeOrganization",
      "organizations:ListPolicies",
      # Security Hub Findings (NR2-002, NR6-003)
      "securityhub:GetFindings",
      # SSM Incidents (NR2-003)
      "ssm-incidents:ListResponsePlans",
      # Backup (NR3-005)
      "backup:ListBackupPlans",
      # SSM Patch (NR5-003)
      "ssm:DescribePatchBaselines",
      "ssm:DescribeInstancePatchStates",
      # Detective (NR2-005)
      "detective:ListGraphs",
      # Route 53 (NR3-007)
      "route53:ListHealthChecks",
      # RAM (NR4-002)
      "ram:GetResourceShares",
      # IAM Roles (NR4-004)
      "iam:ListRoles",
      "iam:GetRole",
      # EC2 VPN (NR10-003)
      "ec2:DescribeVpnGateways",
      "ec2:DescribeClientVpnEndpoints",
      # SES/SNS (NR10-004)
      "ses:GetAccount",
      "sns:ListTopics",
      "sns:GetTopicAttributes",
    ]
    resources = ["*"]
  }
}

# --- Policy 2: Terraform CRUD for integration test infrastructure ---
data "aws_iam_policy_document" "ci_terraform_crud" {
  statement {
    sid    = "TerraformS3"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:PutBucketTagging",
      "s3:GetBucketTagging",
      "s3:PutEncryptionConfiguration",
      "s3:GetEncryptionConfiguration",
      "s3:PutBucketVersioning",
      "s3:GetBucketVersioning",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:GetBucketPolicy",
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketWebsite",
      "s3:GetBucketLogging",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketRequestPayment",
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformS3Control"
    effect = "Allow"
    actions = [
      "s3:PutAccountPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "s3:DeletePublicAccessBlock",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformEC2"
    effect = "Allow"
    actions = [
      "ec2:CreateVolume",
      "ec2:DeleteVolume",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:DescribeTags",
      "ec2:CreateVpc",
      "ec2:DeleteVpc",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcAttribute",
      "ec2:ModifyVpcAttribute",
      "ec2:CreateSubnet",
      "ec2:DeleteSubnet",
      "ec2:DescribeSubnets",
      "ec2:ModifySubnetAttribute",
      "ec2:CreateInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
      "ec2:DescribeInternetGateways",
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeNetworkInterfaces",
      "ec2:ModifyEbsDefaultEncryption",
      "ec2:GetEbsDefaultKmsKeyId",
      "ec2:GetEbsEncryptionByDefault",
      "ec2:EnableEbsEncryptionByDefault",
      "ec2:DisableEbsEncryptionByDefault",
      "ec2:CreateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:DescribeRouteTables",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:CreateRoute",
      "ec2:DeleteRoute",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformRDS"
    effect = "Allow"
    actions = [
      "rds:CreateDBInstance",
      "rds:DeleteDBInstance",
      "rds:ModifyDBInstance",
      "rds:DescribeDBInstances",
      "rds:CreateDBSubnetGroup",
      "rds:DeleteDBSubnetGroup",
      "rds:DescribeDBSubnetGroups",
      "rds:AddTagsToResource",
      "rds:ListTagsForResource",
      "rds:RemoveTagsFromResource",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformKMS"
    effect = "Allow"
    actions = [
      "kms:CreateKey",
      "kms:ScheduleKeyDeletion",
      "kms:EnableKeyRotation",
      "kms:DisableKeyRotation",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ListResourceTags",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:ListAliases",
      "kms:GetKeyPolicy",
      "kms:PutKeyPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformELB"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:DescribeListenerAttributes",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformACM"
    effect = "Allow"
    actions = [
      "acm:ImportCertificate",
      "acm:DeleteCertificate",
      "acm:DescribeCertificate",
      "acm:ListTagsForCertificate",
      "acm:AddTagsToCertificate",
      "acm:GetCertificate",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformIAM"
    effect = "Allow"
    actions = [
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:GetUser",
      "iam:TagUser",
      "iam:UntagUser",
      "iam:ListUserTags",
      "iam:CreateLoginProfile",
      "iam:DeleteLoginProfile",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:DeactivateMFADevice",
      "iam:ListVirtualMFADevices",
      "iam:TagMFADevice",
      "iam:UntagMFADevice",
      "iam:ListMFADeviceTags",
      "iam:CreateServiceLinkedRole",
      "iam:ListGroupsForUser",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListSigningCertificates",
      "iam:ListSSHPublicKeys",
      "iam:ListServiceSpecificCredentials",
      "iam:DeleteSigningCertificate",
      "iam:DeleteSSHPublicKey",
      "iam:DeleteServiceSpecificCredential",
      "iam:CreatePolicy",
      "iam:DeletePolicy",
      "iam:ListPolicyVersions",
      "iam:DeletePolicyVersion",
      "iam:AttachUserPolicy",
      "iam:DetachUserPolicy",
      "iam:TagPolicy",
      "iam:UntagPolicy",
      "iam:ListPolicyTags",
      "iam:UpdateAccountPasswordPolicy",
      "iam:DeleteAccountPasswordPolicy",
      "iam:GetAccountPasswordPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformCloudTrail"
    effect = "Allow"
    actions = [
      "cloudtrail:CreateTrail",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:AddTags",
      "cloudtrail:RemoveTags",
      "cloudtrail:ListTags",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
    ]
    resources = ["*"]
  }
}

# --- Policy 3: Terraform CRUD overflow (Phase 4+ statements) ---
data "aws_iam_policy_document" "ci_terraform_crud_2" {
  statement {
    sid    = "TerraformCloudWatch"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListTagsForResource",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformECR"
    effect = "Allow"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteRepository",
      "ecr:TagResource",
      "ecr:UntagResource",
      "ecr:ListTagsForResource",
      "ecr:DescribeRepositories",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformLambda"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:ListVersionsByFunction",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:ListTags",
      "iam:PassRole",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformIAMRoles"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:ListRoleTags",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteRetentionPolicy",
      "logs:DescribeLogGroups",
      "logs:ListTagsLogGroup",
      "logs:TagLogGroup",
      "logs:UntagLogGroup",
      "logs:ListTagsForResource",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformEC2Snapshots"
    effect = "Allow"
    actions = [
      "ec2:CreateSnapshot",
      "ec2:DeleteSnapshot",
      "ec2:DescribeSnapshots",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformS3ObjectLock"
    effect = "Allow"
    actions = [
      "s3:PutObjectLockConfiguration",
      "s3:GetObjectLockConfiguration",
      "s3:PutBucketObjectLockConfiguration",
      "s3:BypassGovernanceRetention",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformELBTargetGroups"
    effect = "Allow"
    actions = [
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DeleteTargetGroup",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TerraformInstanceProfiles"
    effect = "Allow"
    actions = [
      "iam:ListInstanceProfiles",
      "iam:DeleteInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "nis2scan_ci_scan" {
  name   = "nis2scan-ci-scan-read"
  policy = data.aws_iam_policy_document.ci_scan_read.json

  tags = {
    Project = "nis2scan"
  }
}

resource "aws_iam_policy" "nis2scan_ci_terraform" {
  name   = "nis2scan-ci-terraform-crud"
  policy = data.aws_iam_policy_document.ci_terraform_crud.json

  tags = {
    Project = "nis2scan"
  }
}

resource "aws_iam_policy" "nis2scan_ci_terraform_2" {
  name   = "nis2scan-ci-terraform-crud-2"
  policy = data.aws_iam_policy_document.ci_terraform_crud_2.json

  tags = {
    Project = "nis2scan"
  }
}

resource "aws_iam_role_policy_attachment" "ci_scan" {
  role       = aws_iam_role.nis2scan_ci.name
  policy_arn = aws_iam_policy.nis2scan_ci_scan.arn
}

resource "aws_iam_role_policy_attachment" "ci_terraform" {
  role       = aws_iam_role.nis2scan_ci.name
  policy_arn = aws_iam_policy.nis2scan_ci_terraform.arn
}

resource "aws_iam_role_policy_attachment" "ci_terraform_2" {
  role       = aws_iam_role.nis2scan_ci.name
  policy_arn = aws_iam_policy.nis2scan_ci_terraform_2.arn
}

# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------

output "ci_role_arn" {
  description = "ARN of the CI IAM role — use in GitHub Actions workflow"
  value       = aws_iam_role.nis2scan_ci.arn
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}
