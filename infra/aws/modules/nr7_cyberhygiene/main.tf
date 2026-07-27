# ============================================================================
# Nr. 7 — Grundlegende Verfahren der Cyberhygiene (Cyber Hygiene)
# ============================================================================
# NR7-001: IAM Password Policy
# NR7-002: Root Account Access Keys — no infra needed (reads account summary)
# ============================================================================

# ---------------------------------------------------------------------------
# NR7-001: IAM Password Policy — Szenario-umschaltbar (Task #54)
# ---------------------------------------------------------------------------
# "gaps": deliberately weak settings (the check detects minimum_password_length
# < 14, RequireUppercaseCharacters=false, RequireSymbols=false).
# "hardened"/"mixed" with this key: all three thresholds tightened to pass.
#
# ACHTUNG Konto-global: aws_iam_account_password_policy ist ein Konto-Singleton
# (nicht per random-suffix isoliert wie die übrigen Fixtures). Zwei Terraform-
# Applies für UNTERSCHIEDLICHE Szenarien dürfen deshalb NIE parallel gegen
# dasselbe AWS-Konto laufen — sie würden sich gegenseitig überschreiben. Der
# CI-Workflow serialisiert das über eine gemeinsame concurrency-group je
# Provider (siehe .github/workflows/integration-tests-aws.yml), nicht je
# Szenario — das ist beabsichtigt.
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = var.fixture_compliance["nr7_password_policy"] ? 14 : 8
  require_lowercase_characters   = true
  require_uppercase_characters   = var.fixture_compliance["nr7_password_policy"]
  require_numbers                = true
  require_symbols                = var.fixture_compliance["nr7_password_policy"]
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}
