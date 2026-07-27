# ============================================================================
# Nr. 1 — Risikoanalyse (Risk Analysis)
# ============================================================================
# NR1-004: CloudTrail with Log File Validation
# ============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# S3 Bucket for CloudTrail logs
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "${var.name}-trail-logs-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-trail-logs-${var.suffix}"
    Check = "NR1-004"
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# NR1-004: CloudTrail — Compliant (log validation enabled)
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "compliant" {
  name                       = "${var.name}-trail-compliant"
  s3_bucket_name             = aws_s3_bucket.trail_logs.id
  s3_key_prefix              = "compliant"
  enable_log_file_validation = true
  is_multi_region_trail      = false

  depends_on = [aws_s3_bucket_policy.trail_logs]

  tags = {
    Name  = "${var.name}-trail-compliant"
    Check = "NR1-004"
    Role  = "compliant"
  }
}

# ---------------------------------------------------------------------------
# NR1-004: CloudTrail — Non-compliant (log validation disabled)
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "non_compliant" {
  name           = "${var.name}-trail-non-compliant"
  s3_bucket_name = aws_s3_bucket.trail_logs.id
  s3_key_prefix  = "non-compliant"
  # Task #54 Szenario-Toggle: "hardened"/"mixed" schließen diese Lücke, indem
  # Log-File-Validation aktiviert wird — die Rolle dieser Ressource wechselt
  # dann von "non_compliant" zu "compliant" für AWS-NR1-004 (siehe
  # fixture_expectations in ../../outputs.tf).
  enable_log_file_validation = var.fixture_compliance["nr1_cloudtrail_log_validation"]
  is_multi_region_trail      = false

  depends_on = [aws_s3_bucket_policy.trail_logs]

  tags = {
    Name  = "${var.name}-trail-non-compliant"
    Check = "NR1-004"
    Role  = "non_compliant"
  }
}
