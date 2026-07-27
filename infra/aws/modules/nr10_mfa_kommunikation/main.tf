# ============================================================================
# Nr. 10 — MFA & Kommunikation (MFA & Communication)
# ============================================================================
# NR10-002: IAM User Console MFA Enforcement
# ============================================================================

# --- Console user WITHOUT MFA (non-compliant) ---
resource "random_password" "console_user" {
  length  = 24
  special = true
}

resource "aws_iam_user" "console_no_mfa" {
  name          = "${var.name}-nr10-console-nomfa"
  force_destroy = true

  tags = { Name = "${var.name}-nr10-console-nomfa" }
}

resource "aws_iam_user_login_profile" "console_no_mfa" {
  user                    = aws_iam_user.console_no_mfa.name
  password_reset_required = false
}

# --- Hardened toggle (Task #54): attach + enable MFA for "hardened"/"mixed" ---
# Same enable_mfa.py mechanism as nr9_zugriffskontrolle.without_mfa_hardened.
# The username stays the tracked resource_ref in fixture_expectations.
resource "aws_iam_virtual_mfa_device" "console_no_mfa_hardened" {
  count                   = var.fixture_compliance["nr10_console_mfa"] ? 1 : 0
  virtual_mfa_device_name = "${var.name}-nr10-console-mfa-device"

  tags = { Name = "${var.name}-nr10-console-mfa-device" }
}

resource "null_resource" "enable_mfa_console_no_mfa_hardened" {
  count = var.fixture_compliance["nr10_console_mfa"] ? 1 : 0

  depends_on = [
    aws_iam_user.console_no_mfa,
    aws_iam_virtual_mfa_device.console_no_mfa_hardened,
  ]

  provisioner "local-exec" {
    command = "python3 ${path.module}/../../scripts/enable_mfa.py --username \"${aws_iam_user.console_no_mfa.name}\" --serial \"${aws_iam_virtual_mfa_device.console_no_mfa_hardened[0].arn}\" --seed \"${aws_iam_virtual_mfa_device.console_no_mfa_hardened[0].base_32_string_seed}\""
  }
}
