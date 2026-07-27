# --- Identity ---
output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

# --- Nr. 3 BCM ---
output "compliant_storage_account_grs" {
  value = module.nr3_bcm.compliant_storage_account_name
}

output "non_compliant_storage_account_lrs" {
  value = module.nr3_bcm.non_compliant_storage_account_name
}

# --- Nr. 8 Kryptographie ---
output "compliant_storage_account_cmk" {
  value = module.nr8_kryptographie.compliant_storage_account_name
}

output "non_compliant_storage_account_pmk" {
  value = module.nr8_kryptographie.non_compliant_storage_account_name
}

output "compliant_keyvault_name" {
  value = module.nr8_kryptographie.compliant_keyvault_name
}

output "non_compliant_keyvault_name" {
  value = module.nr8_kryptographie.non_compliant_keyvault_name
}

output "compliant_app_name" {
  value = module.nr8_kryptographie.compliant_app_name
}

output "non_compliant_app_name" {
  value = module.nr8_kryptographie.non_compliant_app_name
}

# --- Nr. 9 Zugriffskontrolle ---
output "compliant_nsg_name" {
  value = module.nr9_zugriffskontrolle.compliant_nsg_name
}

output "non_compliant_nsg_name" {
  value = module.nr9_zugriffskontrolle.non_compliant_nsg_name
}

output "compliant_storage_private" {
  value = module.nr9_zugriffskontrolle.compliant_storage_account_name
}

output "non_compliant_storage_public" {
  value = module.nr9_zugriffskontrolle.non_compliant_storage_account_name
}

# --- Nr. 5 Schwachstellen ---
output "compliant_acr_name" {
  value = module.nr5_schwachstellen.compliant_acr_name
}

output "non_compliant_acr_name" {
  value = module.nr5_schwachstellen.non_compliant_acr_name
}

# --- Nr. 6 Wirksamkeit ---
output "compliant_log_analytics_name" {
  value = module.nr6_wirksamkeit.compliant_workspace_name
}

output "non_compliant_log_analytics_name" {
  value = module.nr6_wirksamkeit.non_compliant_workspace_name
}

# ============================================================================
# fixture_expectations (Task #54, AWS als Muster — siehe infra/aws/outputs.tf)
# ============================================================================
# tests/integration/test_integration_az_nr0_scenarios.py reads this output
# instead of hard-coding "expected == non_compliant" per check. Each entry:
#   check_id            AZ-NRx-NNN this fixture is evaluated by
#   resource_ref         identifier that appears in (or is a unique substring
#                         of) the Finding.resource_id for this fixture. For the
#                         Subscription-weiten Aggregat-Checks (siehe unten) ist
#                         das immer der Subscription-Pfad selbst — diese Checks
#                         liefern GENAU EIN Finding fuer die gesamte
#                         Subscription, nie eines je Ressource (anders als bei
#                         AWS; siehe die ausfuehrliche Erklaerung in main.tf).
#   expected              "compliant" | "non_compliant" for THIS apply
#                         (already resolved from var.scenario — the test does
#                         not need to know the scenario logic itself)
#   hardened_supported     false for the two documented exceptions below —
#                         these keep their "gaps" state in EVERY scenario.
#
# Scope note: this map only covers fixtures that have an actual Terraform
# resource to invert. Azure has far fewer dedizierte Fixture-Module als AWS
# (nur nr3_bcm, nr5_schwachstellen, nr6_wirksamkeit, nr8_kryptographie,
# nr9_zugriffskontrolle unter infra/azure/modules/*) — die uebrigen Checks sind
# reine Tenant-/Subscription-weite Positive-Path- bzw. Abwesenheits-Checks ohne
# jedes Terraform-Fixture (analog GuardDuty/Config bei AWS):
#   AZ-NR1-001..005 (Defender for Cloud, Policy Assignments, Management Groups,
#     Activity-Log-Export, Sentinel-Workspace-Existenz)
#   AZ-NR2-001..005 (Defender Alert Notifications, Sentinel Analytics Rules/
#     Playbooks, Action Groups, Alert Processing Rules)
#   AZ-NR3-001,002,004,005,007 (Backup Vaults, SQL Backup Retention,
#     Availability Zones, Site Recovery, Traffic Manager/Front Door — keine
#     SQL-Server/VMs/Traffic-Manager-Ressourcen in der Testinfrastruktur)
#   AZ-NR4-001..005 (Lighthouse Delegations, Guest Users Conditional Access,
#     Private Endpoints, Service Principal Credentials, Marketplace Image Trust)
#   AZ-NR5-001,002,004,005 (Defender Vuln Assessment, Update Management, App
#     Service Runtime, SQL Vuln Assessment)
#   AZ-NR7-001,002 (Entra-ID Password Protection, Security Defaults — Tenant-
#     weite AAD-Einstellungen, kein Terraform-Fixture wie AWS' Account-Password-
#     Policy moeglich, da azuread kein Password-Protection-Resource anbietet)
#   AZ-NR8-002,003,006 (Disk Encryption, SQL TDE, Application Gateway TLS —
#     keine VM-Disks/SQL-Server/App-Gateway in der Testinfrastruktur)
#   AZ-NR9-001,002,005,006,007 (Conditional Access, PIM, Classic Admins, Guest
#     Access Restrictions, Stale Service Principals — Tenant-/AAD-weite Checks)
#   AZ-NR10-001..005 (MFA fuer alle Nutzer, Phishing-resistente MFA, VPN/
#     Bastion, O365-TLS-Enforcement, Break-Glass-Accounts)
# Diese Checks sind unveraendert Positive-Path-Tests in den bestehenden
# test_integration_az_nrX.py und laufen (wie alle "alten" Tests) ausschliesslich
# im Szenario "gaps" (SKIP_UNLESS_GAPS_SCENARIO).
locals {
  subscription_ref = "/subscriptions/${data.azurerm_subscription.current.subscription_id}"

  fixture_expectations = {
    # --- Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
    nr3_storage_geo_redundant = {
      check_id           = "AZ-NR3-003"
      resource_ref       = local.subscription_ref
      expected           = local.fixture_compliance["nr3_storage_geo_redundant"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr3_immutable_blob = {
      check_id           = "AZ-NR3-006"
      resource_ref       = local.subscription_ref
      expected           = local.fixture_compliance["nr3_immutable_blob"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 5 Schwachstellenmanagement ---
    nr5_acr_sku = {
      check_id           = "AZ-NR5-003"
      resource_ref       = module.nr5_schwachstellen.non_compliant_acr_name
      expected           = local.fixture_compliance["nr5_acr_sku"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 6 Wirksamkeit ---
    nr6_log_retention = {
      check_id           = "AZ-NR6-003"
      resource_ref       = module.nr6_wirksamkeit.non_compliant_workspace_name
      expected           = local.fixture_compliance["nr6_log_retention"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr6_diagnostic_settings = {
      check_id     = "AZ-NR6-004"
      resource_ref = local.subscription_ref
      # Aggregat ueber KeyVaults, SQL-Server, Storage Accounts und NSGs
      # modulübergreifend — Diagnostic Settings auf jeder einzelnen Ressource
      # anzulegen vervielfacht die Fixture-Anzahl unverhaeltnismaessig (siehe
      # Kommentar in modules/nr6_wirksamkeit/main.tf). Bleibt immer im
      # Gaps-Zustand.
      expected           = "non_compliant"
      hardened_supported = false
    }

    # --- Nr. 8 Kryptographie ---
    nr8_storage_cmk = {
      check_id     = "AZ-NR8-001"
      resource_ref = local.subscription_ref
      # Aggregat ueber ALLE Storage Accounts (nr3_bcm, nr8_kryptographie,
      # nr9_zugriffskontrolle) — eine echte Haertung braucht CMK-Verkettung
      # (Key Vault + Access Policy/Role Assignment je Storage-Account-Identity)
      # ueber alle drei Module hinweg. Unverhaeltnismaessiger struktureller
      # Aufwand fuer ein einzelnes Szenario-Fixture (siehe Kommentar in
      # modules/nr8_kryptographie/main.tf). Bleibt immer im Gaps-Zustand.
      expected           = "non_compliant"
      hardened_supported = false
    }
    nr8_keyvault_purge_protection = {
      check_id           = "AZ-NR8-004"
      resource_ref       = module.nr8_kryptographie.non_compliant_keyvault_name
      expected           = local.fixture_compliance["nr8_keyvault_purge_protection"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr8_app_service_https_tls = {
      check_id           = "AZ-NR8-005"
      resource_ref       = module.nr8_kryptographie.non_compliant_app_name
      expected           = local.fixture_compliance["nr8_app_service_https_tls"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }

    # --- Nr. 9 Zugriffskontrolle ---
    nr9_nsg_open_access = {
      check_id           = "AZ-NR9-003"
      resource_ref       = module.nr9_zugriffskontrolle.non_compliant_nsg_name
      expected           = local.fixture_compliance["nr9_nsg_open_access"] ? "compliant" : "non_compliant"
      hardened_supported = true
    }
    nr9_storage_public_access = {
      check_id           = "AZ-NR9-004"
      resource_ref       = local.subscription_ref
      expected           = local.fixture_compliance["nr9_storage_public_access"] ? "compliant" : "non_compliant"
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
