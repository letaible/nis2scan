# ============================================================================
# Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen
# ============================================================================
# NR6-001: CloudTrail operational effectiveness — uses existing NR1 trails
# NR6-004: CloudWatch Log Retention
# ============================================================================

# ---------------------------------------------------------------------------
# NR6-004: CloudWatch Log Groups
# ---------------------------------------------------------------------------

# --- Compliant: Log group with retention >= 365 days ---
resource "aws_cloudwatch_log_group" "compliant" {
  name              = "/nis2scan/${var.name}-compliant-${var.suffix}"
  retention_in_days = 365

  tags = {
    Name  = "${var.name}-loggroup-compliant-${var.suffix}"
    Check = "NR6-004"
    Role  = "compliant"
  }
}

# --- Non-compliant: Log group with too-short retention ---
resource "aws_cloudwatch_log_group" "non_compliant" {
  name = "/nis2scan/${var.name}-non-compliant-${var.suffix}"
  # Task #54 Szenario-Toggle: "hardened"/"mixed" match the compliant
  # retention (365 days) above.
  retention_in_days = var.fixture_compliance["nr6_log_retention"] ? 365 : 7

  tags = {
    Name  = "${var.name}-loggroup-non-compliant-${var.suffix}"
    Check = "NR6-004"
    Role  = "non_compliant"
  }
}
