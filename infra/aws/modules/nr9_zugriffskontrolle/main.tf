# ============================================================================
# Nr. 9 — Zugriffskontrolle (Access Control)
# ============================================================================
# NR9-001: IAM User MFA
# NR9-002: Access Key Age
# NR9-003: S3 Public Access Block
# NR9-004: Security Groups
# ============================================================================

# ---------------------------------------------------------------------------
# NR9-001: IAM User MFA
# ---------------------------------------------------------------------------

# --- User WITH MFA (compliant) ---
resource "aws_iam_user" "with_mfa" {
  name          = "${var.name}-nr9-mfa-user"
  force_destroy = true

  tags = { Name = "${var.name}-nr9-mfa-user" }
}

resource "aws_iam_virtual_mfa_device" "with_mfa" {
  virtual_mfa_device_name = "${var.name}-nr9-mfa-device"

  tags = { Name = "${var.name}-nr9-mfa-device" }
}

resource "null_resource" "enable_mfa" {
  depends_on = [
    aws_iam_user.with_mfa,
    aws_iam_virtual_mfa_device.with_mfa,
  ]

  provisioner "local-exec" {
    # Single line: backslash continuations break on Windows (cmd.exe local-exec)
    command = "python3 ${path.module}/../../scripts/enable_mfa.py --username \"${aws_iam_user.with_mfa.name}\" --serial \"${aws_iam_virtual_mfa_device.with_mfa.arn}\" --seed \"${aws_iam_virtual_mfa_device.with_mfa.base_32_string_seed}\""
  }
}

# AWS-NR9-001 only evaluates users WITH console login (B-9-1 fix) — both
# fixture users need a login profile or the check skips them entirely.
# Generated passwords land in the ephemeral CI state; acceptable for test infra.
resource "aws_iam_user_login_profile" "with_mfa" {
  user                    = aws_iam_user.with_mfa.name
  password_reset_required = true
}

# --- User WITHOUT MFA / hardened toggle (Task #54) ---
# "gaps": no MFA device attached (non-compliant, as before).
# "hardened"/"mixed" with fixture_compliance["nr9_iam_mfa"]: attach + enable a
# virtual MFA device just like the with_mfa user above (same enable_mfa.py
# mechanism), so this user becomes AWS-NR9-001-compliant without renaming it
# (the username stays the tracked resource_ref in fixture_expectations).
resource "aws_iam_user" "without_mfa" {
  name          = "${var.name}-nr9-nomfa-user"
  force_destroy = true

  tags = { Name = "${var.name}-nr9-nomfa-user" }
}

resource "aws_iam_user_login_profile" "without_mfa" {
  user                    = aws_iam_user.without_mfa.name
  password_reset_required = true
}

resource "aws_iam_virtual_mfa_device" "without_mfa_hardened" {
  count                   = var.fixture_compliance["nr9_iam_mfa"] ? 1 : 0
  virtual_mfa_device_name = "${var.name}-nr9-nomfa-device"

  tags = { Name = "${var.name}-nr9-nomfa-device" }
}

resource "null_resource" "enable_mfa_without_mfa_hardened" {
  count = var.fixture_compliance["nr9_iam_mfa"] ? 1 : 0

  depends_on = [
    aws_iam_user.without_mfa,
    aws_iam_virtual_mfa_device.without_mfa_hardened,
  ]

  provisioner "local-exec" {
    command = "python3 ${path.module}/../../scripts/enable_mfa.py --username \"${aws_iam_user.without_mfa.name}\" --serial \"${aws_iam_virtual_mfa_device.without_mfa_hardened[0].arn}\" --seed \"${aws_iam_virtual_mfa_device.without_mfa_hardened[0].base_32_string_seed}\""
  }
}

# ---------------------------------------------------------------------------
# NR9-002: Access Key Age
# ---------------------------------------------------------------------------
# A freshly created access key will always pass the age check.
# We create one so the positive-path integration test has something to verify.

resource "aws_iam_user" "access_key_user" {
  name          = "${var.name}-nr9-ak-user"
  force_destroy = true

  tags = { Name = "${var.name}-nr9-ak-user" }
}

resource "aws_iam_access_key" "fresh_key" {
  user = aws_iam_user.access_key_user.name
}

# ---------------------------------------------------------------------------
# NR9-003: S3 Public Access Block
# ---------------------------------------------------------------------------
# "gaps": ignore_public_acls is deliberately false so NOT all four settings
# are true — the check should produce a finding. Task #54 Szenario-Toggle
# "nr9_s3_account_pab" flips it to true for "hardened"/"mixed".
#
# ACHTUNG Konto-global: aws_s3_account_public_access_block is a per-account
# singleton, like the IAM password policy in nr7_cyberhygiene — see the
# concurrency-group comment there. Never run two scenarios' applies in
# parallel against the same account.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  ignore_public_acls      = var.fixture_compliance["nr9_s3_account_pab"]
  block_public_policy     = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# NR9-004: Security Groups
# ---------------------------------------------------------------------------

# --- Compliant SG: restricted ingress on 443 ---
resource "aws_security_group" "compliant" {
  name        = "${var.name}-nr9-sg-compliant"
  description = "Compliant SG - HTTPS from internal only"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-nr9-sg-compliant" }
}

# --- Non-compliant / hardened toggle SG: SSH open to the world ---
resource "aws_security_group" "non_compliant" {
  name        = "${var.name}-nr9-sg-non-compliant"
  description = "Non-compliant SG - SSH from 0.0.0.0/0"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from anywhere (gaps) or restricted internal range (hardened/mixed, Task #54 scenario toggle)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.fixture_compliance["nr9_security_group"] ? ["10.0.0.0/8"] : ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-nr9-sg-non-compliant" }
}

# ---------------------------------------------------------------------------
# NR9-005: IAM Wildcard Policy
# ---------------------------------------------------------------------------
# "gaps": IAM policy with Action: * / Resource: * (non-compliant). Task #54
# Szenario-Toggle "nr9_iam_wildcard_policy" scopes both down to a narrow,
# harmless read-only statement for "hardened"/"mixed".

resource "aws_iam_policy" "wildcard" {
  name        = "${var.name}-nr9-wildcard-policy"
  description = "Non-compliant policy with wildcard permissions for NR9-005 test"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = var.fixture_compliance["nr9_iam_wildcard_policy"] ? ["s3:GetObject"] : ["*"]
        Resource = var.fixture_compliance["nr9_iam_wildcard_policy"] ? ["arn:aws:s3:::${var.name}-nr9-wildcard-scope/*"] : ["*"]
      }
    ]
  })

  tags = { Name = "${var.name}-nr9-wildcard-policy" }
}
