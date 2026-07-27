###############################################################################
# NR6-003: Log Retention >= 365 days — Szenario-umschaltbar (Task #54)
###############################################################################
# "gaps": non_compliant stays at 30 days (today's behaviour, unchanged).
# "hardened"/"mixed" with fixture_compliance["nr6_log_retention"]: raised to
# 365 days. Per-workspace check (CheckLogRetention) — no other module creates
# Log Analytics workspaces, so this fixture is self-contained.

# Compliant: 365-day retention, never toggled
resource "azurerm_log_analytics_workspace" "compliant" {
  name                = "${var.name}-la-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 365

  tags = merge(var.tags, {
    Check = "NR6-003"
    Role  = "compliant"
  })
}

# Non-compliant: retention follows the scenario toggle
resource "azurerm_log_analytics_workspace" "non_compliant" {
  name                = "${var.name}-la-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.fixture_compliance["nr6_log_retention"] ? 365 : 30

  tags = merge(var.tags, {
    Check = "NR6-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR6-004: Diagnostic Settings on critical resources
###############################################################################
# hardened_supported=false (Task #54, see outputs.tf): CheckDiagnosticSettings
# is a Subscription-weit ALL-must-comply aggregate over EVERY KeyVault, SQL
# Server, Storage Account and NSG in the subscription (see CRITICAL_RESOURCE_
# TYPES in nis2scan/engine/providers/azure/checks/nr6_wirksamkeit.py). Wiring
# diagnostic settings onto all 6 storage accounts, both NSGs and all 3 key
# vaults across every module just to invert this ONE fixture is disproportionate
# — stays permanently non-compliant in ALL scenarios, exactly like this vault's
# missing diagnostic settings below (unchanged from the pre-Task-#54 state).

# A Key Vault WITHOUT diagnostic settings — for the check to flag
resource "azurerm_key_vault" "no_diagnostics" {
  name                       = "n2skvnd${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = merge(var.tags, {
    Check = "NR6-004"
    Role  = "non_compliant"
  })
}

data "azurerm_client_config" "current" {}
