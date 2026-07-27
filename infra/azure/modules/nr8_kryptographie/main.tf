###############################################################################
# NR8-001: Storage Account Encryption (CMK preferred)
###############################################################################
# hardened_supported=false (Task #54, see outputs.tf): CheckStorageEncryption
# is a Subscription-weit ALL-must-comply aggregate over EVERY Storage Account
# in the subscription (see modules/nr3_bcm and modules/nr9_zugriffskontrolle,
# which also create storage accounts). A real fix would need CMK — an
# azurerm_storage_account_customer_managed_key resource plus a Key Vault
# access policy/role assignment granting each account's managed identity key
# access — wired across all 6 storage accounts in all three modules. That
# identity/RBAC fan-out is disproportionate for a single scenario fixture, so
# this check stays permanently non-compliant in ALL scenarios (unchanged from
# the pre-Task-#54 state — the "compliant"-tagged storage account below was
# and remains not actually CMK-wired; see the Task #54 final report).
#
# Both storage accounts in this module ARE hardened for the OTHER two
# Subscription-weite Aggregat-Checks this module contributes accounts to
# (AZ-NR3-003 Geo-Redundanz, AZ-NR9-004 Public Access) — this module owns
# neither toggle, so both stay hard-set to the good value always.

# Compliant: Storage with CMK (via Key Vault)
resource "azurerm_key_vault" "compliant" {
  name                       = "n2skvc${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  access_policy {
    tenant_id = var.tenant_id
    object_id = var.object_id

    key_permissions = [
      "Create", "Delete", "Get", "List", "Purge", "Recover",
      "UnwrapKey", "WrapKey", "GetRotationPolicy",
    ]

    secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
  }

  tags = merge(var.tags, {
    Check = "NR8-004"
    Role  = "compliant"
  })
}

resource "azurerm_key_vault_key" "storage_cmk" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.compliant.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["unwrapKey", "wrapKey"]
}

resource "azurerm_storage_account" "compliant" {
  name                = "n2scmk${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  account_tier        = "Standard"
  # Hard-set to GRS/private (not a variable): this module does not own the
  # AZ-NR3-003/AZ-NR9-004 toggles (modules/nr3_bcm and modules/
  # nr9_zugriffskontrolle do) — see the module-level comment above.
  account_replication_type      = "GRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = merge(var.tags, {
    Check = "NR8-001"
    Role  = "compliant"
  })
}

# Non-compliant: Storage with platform-managed keys only (permanently — see
# the hardened_supported=false comment above). GRS/private hard-set for the
# same cross-module reason as the compliant account above.
resource "azurerm_storage_account" "non_compliant" {
  name                          = "n2spmk${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "GRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  tags = merge(var.tags, {
    Check = "NR8-001"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR8-004: Key Vault — soft-delete + purge protection — Szenario-umschaltbar
# (Task #54)
###############################################################################
# "gaps": non_compliant stays without purge protection (today's behaviour,
# unchanged). "hardened"/"mixed" with fixture_compliance["nr8_keyvault_
# purge_protection"]: purge protection enabled. Per-vault check
# (CheckKeyVaultRotation) — no cross-module coupling; the extra Key Vault in
# modules/nr6_wirksamkeit (built for AZ-NR6-004, always without purge
# protection) contributes an additional, untracked non-compliant finding for
# THIS check too, but never interferes with the resource_ref match on this
# module's own vault (see test_integration_az_nr0_scenarios.py).
#
# NOTE: purge_protection_enabled=true means `terraform destroy` cannot fully
# purge this vault immediately (Azure enforces the soft-delete retention even
# for the owning subscription) — it soft-deletes instead. This is not new:
# the "compliant" vault above already does this unconditionally today; scripts/
# post_destroy_verify.py already tolerates soft-deleted vaults as a warning,
# not a hard failure.

# Non-compliant: purge protection follows the scenario toggle
resource "azurerm_key_vault" "non_compliant" {
  name                       = "n2skvnc${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = var.fixture_compliance["nr8_keyvault_purge_protection"]

  access_policy {
    tenant_id = var.tenant_id
    object_id = var.object_id

    key_permissions    = ["Get", "List"]
    secret_permissions = ["Get", "List"]
  }

  tags = merge(var.tags, {
    Check = "NR8-004"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR8-005: App Service HTTPS-Only + TLS 1.2 — Szenario-umschaltbar (Task #54)
###############################################################################
# "gaps": non_compliant stays HTTP-allowed/TLS 1.0 (today's behaviour,
# unchanged). "hardened"/"mixed" with fixture_compliance["nr8_app_service_
# https_tls"]: HTTPS-only + TLS 1.2. Per-app check (CheckAppServiceHttps) — no
# cross-module coupling, this fixture is self-contained.

resource "azurerm_service_plan" "test" {
  name                = "${var.name}-asp-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  os_type             = "Linux"
  sku_name            = "B1"

  tags = var.tags
}

# Compliant: HTTPS-only with TLS 1.2
resource "azurerm_linux_web_app" "compliant" {
  name                = "n2s-app-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.test.id
  https_only          = true

  site_config {
    minimum_tls_version = "1.2"
  }

  tags = merge(var.tags, {
    Check = "NR8-005"
    Role  = "compliant"
  })
}

# Non-compliant: HTTPS-only + TLS-version follow the scenario toggle
resource "azurerm_linux_web_app" "non_compliant" {
  name                = "n2s-app-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.test.id
  https_only          = var.fixture_compliance["nr8_app_service_https_tls"]

  site_config {
    minimum_tls_version = var.fixture_compliance["nr8_app_service_https_tls"] ? "1.2" : "1.0"
  }

  tags = merge(var.tags, {
    Check = "NR8-005"
    Role  = "non_compliant"
  })
}
