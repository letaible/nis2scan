# --- Identity ---
output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" {
  value = data.aws_region.current.name
}

# --- Nr. 8 Kryptographie ---
output "compliant_s3_bucket" {
  value = module.nr8_kryptographie.compliant_s3_bucket
}

output "non_compliant_s3_bucket" {
  value = module.nr8_kryptographie.non_compliant_s3_bucket
}

output "compliant_ebs_volume_id" {
  value = module.nr8_kryptographie.compliant_ebs_volume_id
}

output "non_compliant_ebs_volume_id" {
  value = module.nr8_kryptographie.non_compliant_ebs_volume_id
}

output "compliant_rds_id" {
  value = module.nr8_kryptographie.compliant_rds_id
}

output "non_compliant_rds_id" {
  value = module.nr8_kryptographie.non_compliant_rds_id
}

output "compliant_kms_key_id" {
  value = module.nr8_kryptographie.compliant_kms_key_id
}

output "non_compliant_kms_key_id" {
  value = module.nr8_kryptographie.non_compliant_kms_key_id
}

output "compliant_alb_arn" {
  value = module.nr8_kryptographie.compliant_alb_arn
}

output "non_compliant_alb_arn" {
  value = module.nr8_kryptographie.non_compliant_alb_arn
}

# --- Nr. 9 Zugriffskontrolle ---
output "iam_user_with_mfa" {
  value = module.nr9_zugriffskontrolle.iam_user_with_mfa
}

output "iam_user_without_mfa" {
  value = module.nr9_zugriffskontrolle.iam_user_without_mfa
}

output "compliant_sg_id" {
  value = module.nr9_zugriffskontrolle.compliant_sg_id
}

output "non_compliant_sg_id" {
  value = module.nr9_zugriffskontrolle.non_compliant_sg_id
}

output "s3_public_access_block_set" {
  value = module.nr9_zugriffskontrolle.s3_public_access_block_set
}

# --- Nr. 9 Zugriffskontrolle (additional) ---
output "non_compliant_iam_policy_arn" {
  value = module.nr9_zugriffskontrolle.non_compliant_iam_policy_arn
}

# --- Nr. 10 MFA & Kommunikation ---
output "iam_console_user_no_mfa" {
  value = module.nr10_mfa_kommunikation.iam_console_user_no_mfa
}

# --- Nr. 1 Risikoanalyse ---
output "compliant_trail_name" {
  value = module.nr1_risikoanalyse.compliant_trail_name
}

output "compliant_trail_arn" {
  value = module.nr1_risikoanalyse.compliant_trail_arn
}

output "non_compliant_trail_name" {
  value = module.nr1_risikoanalyse.non_compliant_trail_name
}

output "non_compliant_trail_arn" {
  value = module.nr1_risikoanalyse.non_compliant_trail_arn
}

# --- Nr. 3 BCM ---
output "compliant_s3_versioning_bucket" {
  value = module.nr3_bcm.compliant_s3_versioning_bucket
}

output "non_compliant_s3_versioning_bucket" {
  value = module.nr3_bcm.non_compliant_s3_versioning_bucket
}

# --- Nr. 2 Vorfallsbewältigung ---
output "alarm_name" {
  value = module.nr2_vorfallsbewaltigung.alarm_name
}

output "alarm_arn" {
  value = module.nr2_vorfallsbewaltigung.alarm_arn
}

# --- Nr. 5 Schwachstellenmanagement ---
output "compliant_ecr_repo_arn" {
  value = module.nr5_schwachstellen.compliant_ecr_repo_arn
}

output "compliant_ecr_repo_name" {
  value = module.nr5_schwachstellen.compliant_ecr_repo_name
}

output "non_compliant_ecr_repo_arn" {
  value = module.nr5_schwachstellen.non_compliant_ecr_repo_arn
}

output "non_compliant_ecr_repo_name" {
  value = module.nr5_schwachstellen.non_compliant_ecr_repo_name
}

# --- Nr. 7 Cyberhygiene ---
output "password_policy_set" {
  value = module.nr7_cyberhygiene.password_policy_set
}

# --- Nr. 3 BCM (additional) ---
output "compliant_object_lock_bucket" {
  value = module.nr3_bcm.compliant_object_lock_bucket
}

output "non_compliant_object_lock_bucket" {
  value = module.nr3_bcm.non_compliant_object_lock_bucket
}

output "compliant_snapshot_volume_id" {
  value = module.nr3_bcm.compliant_snapshot_volume_id
}

output "compliant_snapshot_id" {
  value = module.nr3_bcm.compliant_snapshot_id
}

output "non_compliant_snapshot_volume_id" {
  value = module.nr3_bcm.non_compliant_snapshot_volume_id
}

# --- Nr. 5 Schwachstellenmanagement (additional) ---
output "compliant_lambda_arn" {
  value = module.nr5_schwachstellen.compliant_lambda_arn
}

output "compliant_lambda_name" {
  value = module.nr5_schwachstellen.compliant_lambda_name
}

output "non_compliant_lambda_arn" {
  value = module.nr5_schwachstellen.non_compliant_lambda_arn
}

output "non_compliant_lambda_name" {
  value = module.nr5_schwachstellen.non_compliant_lambda_name
}

# --- Nr. 6 Wirksamkeit ---
output "compliant_log_group_name" {
  value = module.nr6_wirksamkeit.compliant_log_group_name
}

output "compliant_log_group_arn" {
  value = module.nr6_wirksamkeit.compliant_log_group_arn
}

output "non_compliant_log_group_name" {
  value = module.nr6_wirksamkeit.non_compliant_log_group_name
}

output "non_compliant_log_group_arn" {
  value = module.nr6_wirksamkeit.non_compliant_log_group_arn
}

# ============================================================================
# fixture_expectations (Task #54) — scenario-aware fixture map
# ============================================================================
# tests/integration/test_integration_nr0_scenarios.py reads this output
# instead of hard-coding "expected == non_compliant" per check. Each entry:
#   check_id            AWS-NRx-NNN this fixture is evaluated by
#   resource_ref         identifier that appears in (or is a unique substring
#                         of) the Finding.resource_id for this fixture
#   expected              "compliant" | "non_compliant" for THIS apply
#                         (already resolved from var.scenario — the test does
#                         not need to know the scenario logic itself)
#   hardened_supported     false for the two documented exceptions below —
#                         these keep their "gaps" state in EVERY scenario.
#
# Scope note: this map only covers fixtures that have an actual Terraform
# resource to invert (compliant/non-compliant pair or absence-vs-presence
# toggle). Purely account-global absence checks with NO corresponding
# resource in any infra/aws/modules/* module — Config Recorder (AWS-NR1-001),
# SecurityHub (AWS-NR1-002/NR2-002/NR6-003), Organizations/SCP (AWS-NR1-003/
# NR4-003/NR4-005), GuardDuty (AWS-NR1-005/NR2-001), Detective (AWS-NR2-005),
# Incident Manager response plans (AWS-NR2-003), Backup Plans (AWS-NR3-005),
# Route 53 Health Checks (AWS-NR3-007), Trusted Advisor (AWS-NR4-001), Config
# Rules (AWS-NR6-002), VPN Admin Access (AWS-NR10-003), Break-Glass
# (AWS-NR10-005) — are deliberately NOT listed here. nr4_lieferkette is an
# empty module for exactly this reason ("No additional Terraform resources
# needed"). These checks are unaffected by var.scenario in all three cases
# and keep running exactly as today via the legacy per-nr test files, which
# (per SKIP_UNLESS_GAPS_SCENARIO) only execute when scenario == "gaps". See
# the Task #54 final report for the explicit list and reasoning.
locals {
  fixture_expectations = {
    # --- Nr. 1 Risikoanalyse ---
    nr1_cloudtrail_log_validation = {
      check_id           = "AWS-NR1-004"
      resource_ref       = module.nr1_risikoanalyse.non_compliant_trail_arn
      expected           = local.fixture_compliance["nr1_cloudtrail_log_validation"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
    nr3_s3_versioning = {
      check_id           = "AWS-NR3-002"
      resource_ref       = module.nr3_bcm.non_compliant_s3_versioning_bucket
      expected           = local.fixture_compliance["nr3_s3_versioning_objectlock"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr3_s3_object_lock = {
      check_id           = "AWS-NR3-003"
      resource_ref       = module.nr3_bcm.non_compliant_object_lock_bucket
      expected           = local.fixture_compliance["nr3_s3_versioning_objectlock"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr3_rds_backup_retention = {
      check_id           = "AWS-NR3-001"
      resource_ref       = module.nr8_kryptographie.non_compliant_rds_id
      expected           = local.fixture_compliance["nr3_rds_backup_retention"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr3_rds_multi_az = {
      check_id     = "AWS-NR3-004"
      resource_ref = module.nr8_kryptographie.non_compliant_rds_id
      expected     = "non_compliant"
      # Multi-AZ roughly doubles RDS cost and adds significant provisioning/
      # teardown time to every CI run in every scenario — disproportionate
      # for an integration-test fixture. Stays single-AZ always.
      hardened_supported = false
    }
    nr3_ebs_snapshot = {
      check_id           = "AWS-NR3-006"
      resource_ref       = module.nr3_bcm.non_compliant_snapshot_volume_id
      expected           = local.fixture_compliance["nr3_ebs_snapshot"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 5 Schwachstellenmanagement ---
    nr5_ecr_scan_on_push = {
      check_id           = "AWS-NR5-001"
      resource_ref       = module.nr5_schwachstellen.non_compliant_ecr_repo_arn
      expected           = local.fixture_compliance["nr5_ecr_scan_on_push"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr5_lambda_runtime = {
      check_id           = "AWS-NR5-004"
      resource_ref       = module.nr5_schwachstellen.non_compliant_lambda_arn
      expected           = local.fixture_compliance["nr5_lambda_runtime"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 6 Wirksamkeit ---
    nr6_log_retention = {
      check_id           = "AWS-NR6-004"
      resource_ref       = module.nr6_wirksamkeit.non_compliant_log_group_name
      expected           = local.fixture_compliance["nr6_log_retention"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 7 Cyberhygiene (Konto-global) ---
    nr7_password_policy = {
      check_id           = "AWS-NR7-001"
      resource_ref       = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:account-password-policy"
      expected           = local.fixture_compliance["nr7_password_policy"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 8 Kryptographie ---
    nr8_s3_default_encryption = {
      check_id     = "AWS-NR8-001"
      resource_ref = module.nr8_kryptographie.non_compliant_s3_bucket
      # AWS has applied SSE-S3 by default to every new bucket since Jan 2023 —
      # this bucket has been permanently, unavoidably compliant since then
      # regardless of Terraform config in ANY scenario (see the docstring on
      # tests/integration/test_integration_nr8.py::TestNR8001S3Encryption).
      # Not a cost/duration exception like the other hardened_supported=false
      # entries — a structural one: there is no "gaps" state left to harden.
      expected           = "compliant"
      hardened_supported = false
    }
    nr8_ebs_encryption = {
      check_id           = "AWS-NR8-002"
      resource_ref       = module.nr8_kryptographie.non_compliant_ebs_volume_id
      expected           = local.fixture_compliance["nr8_ebs_encryption"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr8_rds_encryption = {
      check_id           = "AWS-NR8-003"
      resource_ref       = module.nr8_kryptographie.non_compliant_rds_id
      expected           = local.fixture_compliance["nr8_rds_encryption"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr8_kms_key_rotation = {
      check_id           = "AWS-NR8-004"
      resource_ref       = module.nr8_kryptographie.non_compliant_kms_key_id
      expected           = local.fixture_compliance["nr8_kms_key_rotation"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr8_alb_tls_deny_list = {
      check_id           = "AWS-NR8-005"
      resource_ref       = module.nr8_kryptographie.non_compliant_alb_arn
      expected           = local.fixture_compliance["nr8_alb_tls_policy"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr8_alb_tls_min_version = {
      check_id           = "AWS-NR8-006"
      resource_ref       = module.nr8_kryptographie.non_compliant_alb_arn
      expected           = local.fixture_compliance["nr8_alb_tls_policy"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 9 Zugriffskontrolle ---
    nr9_iam_mfa = {
      check_id           = "AWS-NR9-001"
      resource_ref       = module.nr9_zugriffskontrolle.iam_user_without_mfa
      expected           = local.fixture_compliance["nr9_iam_mfa"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr9_s3_account_pab = {
      check_id           = "AWS-NR9-003"
      resource_ref       = "arn:aws:s3:::account-${data.aws_caller_identity.current.account_id}"
      expected           = local.fixture_compliance["nr9_s3_account_pab"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr9_security_group = {
      check_id           = "AWS-NR9-004"
      resource_ref       = module.nr9_zugriffskontrolle.non_compliant_sg_id
      expected           = local.fixture_compliance["nr9_security_group"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr9_iam_wildcard_policy = {
      check_id           = "AWS-NR9-005"
      resource_ref       = module.nr9_zugriffskontrolle.non_compliant_iam_policy_arn
      expected           = local.fixture_compliance["nr9_iam_wildcard_policy"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 10 MFA & Kommunikation ---
    nr10_console_mfa = {
      check_id           = "AWS-NR10-002"
      resource_ref       = module.nr10_mfa_kommunikation.iam_console_user_no_mfa
      expected           = local.fixture_compliance["nr10_console_mfa"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
  }
}

output "fixture_expectations" {
  description = "Scenario-resolved expectation per §30 fixture (Task #54) — see locals.fixture_expectations above"
  value       = local.fixture_expectations
}

output "scenario" {
  description = "The compliance scenario this apply was run with (gaps | hardened | mixed)"
  value       = var.scenario
}
