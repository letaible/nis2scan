variable "project_id" {
  description = "GCP Project ID for integration test infrastructure"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west1"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}

# --- Szenario-Steuerung (Task #54, Portierung AWS -> GCP) --------------------
# Same three-scenario model as infra/aws/variables.tf, ported to the much
# smaller set of GCP fixtures that actually have a Terraform resource to
# invert (see local.fixture_compliance_mixed and the "fixture_expectations"
# scope note in outputs.tf for why only 3 of the 51 GCP checks are tracked
# here):
# "gaps"     = all three intentional gaps open — today's behaviour,
#              UNCHANGED. The legacy per-nr test files (test_integration_gcp_
#              nr1.py..nr10.py) run ONLY in this scenario (see
#              tests/integration/conftest.py::SKIP_UNLESS_GAPS_SCENARIO).
# "hardened" = all three supported gaps closed. Unlike AWS, GCP has NO
#              hardened_supported=false exceptions (no cost/duration outlier
#              like AWS's RDS Multi-AZ, no structural always-on default like
#              AWS's S3 SSE-S3) — see outputs.tf.
# "mixed"    = deterministic, hand-assigned split (see
#              local.fixture_compliance_mixed in main.tf) — KEIN Zufall/Hash.
#
# GCP-Besonderheit (CLAUDE.md "Known Pitfalls / GCP"): KMS key rings and keys
# are PERMANENT (no immediate delete, only 24h-minimum scheduled destruction).
# The "nr8_kms_key_rotation" toggle therefore NEVER creates/destroys a key
# across scenarios — it only flips the rotation_period attribute on the
# already-existing non-compliant key in place (see modules/nr8_kryptographie/
# main.tf). No scenario switch in this file ever changes KMS resource
# existence, only in-place-updatable configuration.
#
# All three scenarios are checked by test_integration_gcp_nr0_scenarios.py,
# which reads its expectations from the Terraform output
# "fixture_expectations" (outputs.tf) instead of hard-coding them.
variable "scenario" {
  description = "Compliance-Szenario der Testinfrastruktur: gaps | hardened | mixed"
  type        = string
  default     = "gaps"

  validation {
    condition     = contains(["gaps", "hardened", "mixed"], var.scenario)
    error_message = "Scenario muss einer von \"gaps\", \"hardened\", \"mixed\" sein."
  }
}
