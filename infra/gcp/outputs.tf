output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

# --- Nr. 3 BCM ---
output "compliant_bucket_name" {
  value = module.nr3_bcm.compliant_bucket_name
}

output "non_compliant_bucket_name" {
  value = module.nr3_bcm.non_compliant_bucket_name
}

# --- Nr. 8 Kryptographie ---
output "compliant_kms_key_id" {
  value = module.nr8_kryptographie.compliant_key_id
}

output "non_compliant_kms_key_id" {
  value = module.nr8_kryptographie.non_compliant_key_id
}

# --- Nr. 9 Zugriffskontrolle ---
output "compliant_firewall_name" {
  value = module.nr9_zugriffskontrolle.compliant_firewall_name
}

output "non_compliant_firewall_name" {
  value = module.nr9_zugriffskontrolle.non_compliant_firewall_name
}

# ============================================================================
# fixture_expectations (Task #54, Portierung AWS -> GCP) — scenario-aware
# fixture map
# ============================================================================
# tests/integration/test_integration_gcp_nr0_scenarios.py reads this output
# instead of hard-coding "expected == non_compliant" per check. Each entry:
#   check_id            GCP-NRx-NNN this fixture is evaluated by
#   resource_ref         identifier that appears in (or is a unique substring
#                        of) the Finding.resource_id for this fixture
#   expected             "compliant" | "non_compliant" for THIS apply
#                        (already resolved from var.scenario — the test does
#                        not need to know the scenario logic itself)
#   hardened_supported  false would mark a documented exception that keeps
#                        its "gaps" state in every scenario (cost/duration
#                        outlier or structural always-on default, see the
#                        AWS precedent in infra/aws/outputs.tf). GCP HAS NO
#                        SUCH EXCEPTION: all three tracked fixtures below are
#                        cleanly togglable in-place attributes with no cost,
#                        duration, or permanence obstacle — hardened_supported
#                        is "true" for every entry.
#
# Scope note: of the 51 GCP checks, only the THREE below have an actual
# Terraform resource to invert in infra/gcp/modules/* (a compliant/
# non-compliant pair whose distinguishing attribute is a simple in-place
# toggle). The remaining 48 are project- or organization-scoped
# absence/positive-path checks with NO corresponding Terraform resource
# anywhere in this infra — there is nothing to invert, so var.scenario has no
# effect on them and they are deliberately NOT listed here:
#   - Nr. 1 (alle 4): GCP-NR1-001 Security Command Center, GCP-NR1-002 Org
#     Policies, GCP-NR1-003 Audit Log Config, GCP-NR1-004 Asset Inventory
#   - Nr. 2 (alle 5): GCP-NR2-001..005 (SCC Notifications, Monitoring Alert
#     Policies, Notification Channels, Log-Based Alerts, Logging Sinks)
#   - Nr. 3 (6 von 7, alle außer GCP-NR3-002): GCP-NR3-001 Cloud SQL Backups,
#     GCP-NR3-003 GCS Retention Policy, GCP-NR3-004 Multi-Zone Deployments,
#     GCP-NR3-005 Disk Snapshot Schedules, GCP-NR3-006 Cloud SQL High
#     Availability, GCP-NR3-007 DNS Health Checks — keine Cloud-SQL-Instanz,
#     keine Compute-Instanzen/Snapshot-Policies/DNS-Zonen in dieser Infra
#     (bewusst nicht neu angelegt — Portierung des SZENARIO-Mechanismus,
#     keine neue Test-Infrastruktur)
#   - Nr. 4 (alle 5): GCP-NR4-001..005 (Cross-Project Bindings, Service
#     Account Keys, Workload Identity, Binary Authorization, VPC Service
#     Controls Supply Chain)
#   - Nr. 5 (alle 5): GCP-NR5-001..005 (Container Analysis, OS Config Patch
#     Management, Web Security Scanner, Artifact Registry Scanning, GKE Node
#     Versions) — kein GKE-Cluster, keine Compute-Instanzen, keine Artifact
#     Registry in dieser Infra
#   - Nr. 6 (alle 4): GCP-NR6-001..004 (Audit Log Integrity, Security Health
#     Analytics, Policy Intelligence, Monitoring Dashboards)
#   - Nr. 7 (alle 2): GCP-NR7-001 Org Security Policies, GCP-NR7-002
#     Essential Contacts
#   - Nr. 8 (5 von 6, alle außer GCP-NR8-001): GCP-NR8-002 CMEK Encryption,
#     GCP-NR8-003 SSL Policy Load Balancer, GCP-NR8-004 Cloud SQL SSL,
#     GCP-NR8-005 Disk Encryption, GCP-NR8-006 Certificate Manager — keine
#     Compute-Disks, SSL-Policies/Load-Balancer, Cloud-SQL-Instanz oder
#     verwalteten Zertifikate in dieser Infra
#   - Nr. 9 (7 von 8, alle außer GCP-NR9-004): GCP-NR9-001 IAM Least
#     Privilege, GCP-NR9-002 Service Account Hygiene, GCP-NR9-003
#     Identity-Aware Proxy, GCP-NR9-005 Storage Bucket Public Access (die
#     nr3_bcm-Buckets existieren, aber keiner hat eine öffentliche
#     IAM-Bindung — kein Toggle ohne echte Public-Access-Ressource),
#     GCP-NR9-006 Org Constraints, GCP-NR9-007 Inactive Principals (IAM
#     Recommender), GCP-NR9-008 VPC Service Controls
#   - Nr. 10 (alle 5): GCP-NR10-001..005 (Two-Step Verification, IAP Admin
#     Access, VPN Gateways, OS Login mit 2FA, Secure LDAP)
# These checks are unaffected by var.scenario in all three cases and keep
# running exactly as today via the legacy per-nr test files, which (per
# SKIP_UNLESS_GAPS_SCENARIO) only execute when scenario == "gaps". See the
# Task #54 GCP-Portierung final report for the full per-check reasoning.
locals {
  fixture_expectations = {
    # --- Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
    nr3_gcs_versioning = {
      check_id           = "GCP-NR3-002"
      resource_ref       = module.nr3_bcm.non_compliant_bucket_name
      expected           = local.fixture_compliance["nr3_gcs_versioning"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 8 Kryptographie ---
    nr8_kms_key_rotation = {
      check_id           = "GCP-NR8-001"
      resource_ref       = module.nr8_kryptographie.non_compliant_key_id
      expected           = local.fixture_compliance["nr8_kms_key_rotation"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 9 Zugriffskontrolle ---
    nr9_firewall_source_range = {
      check_id           = "GCP-NR9-004"
      resource_ref       = module.nr9_zugriffskontrolle.non_compliant_firewall_name
      expected           = local.fixture_compliance["nr9_firewall_source_range"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
  }
}

output "fixture_expectations" {
  description = "Scenario-resolved expectation per §30 fixture (Task #54, GCP-Portierung) — see locals.fixture_expectations above"
  value       = local.fixture_expectations
}

output "scenario" {
  description = "The compliance scenario this apply was run with (gaps | hardened | mixed)"
  value       = var.scenario
}
