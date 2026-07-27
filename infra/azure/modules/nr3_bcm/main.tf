###############################################################################
# NR3-003: Geo-Redundant Storage (GRS) — Szenario-umschaltbar (Task #54)
###############################################################################
# "gaps": non_compliant_lrs stays LRS (today's behaviour, unchanged).
# "hardened"/"mixed" with fixture_compliance["nr3_storage_geo_redundant"]:
# non_compliant_lrs becomes GRS too.
#
# ACHTUNG Aggregat-Check: AZ-NR3-003 (CheckGeoRedundantStorage) is Subscription-
# weit — es liest ALLE Storage Accounts der Subscription und meldet nur EIN
# Finding ("compliant" nur wenn ALLE Accounts geo-redundant sind). Die anderen
# Storage-Account-Fixtures in modules/nr8_kryptographie und modules/
# nr9_zugriffskontrolle sind deshalb HART auf "GRS" gesetzt (nicht ueber
# fixture_compliance getoggled) — sonst wuerde dieser Check unabhaengig vom
# eigenen Toggle hier immer non-compliant bleiben. Siehe die ausfuehrliche
# Erklaerung in root main.tf. Beide Accounts dieses Moduls sind zudem hart auf
# privaten Netzwerkzugriff gesetzt (public_network_access_enabled=false +
# network_rules.default_action=Deny) — dieses Modul besitzt nicht den
# AZ-NR9-004-Toggle (das gehoert modules/nr9_zugriffskontrolle) und darf dessen
# Subscription-weiten Aggregat-Check nicht durch einen "fremden" oeffentlichen
# Account verfaelschen.

# Compliant: GRS replication, always private (never toggled — see above)
resource "azurerm_storage_account" "compliant_grs" {
  name                          = "n2sgrs${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "GRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  tags = merge(var.tags, {
    Check = "NR3-003"
    Role  = "compliant"
  })
}

# Non-compliant: replication follows the scenario toggle; network access
# always private (this module does not own the AZ-NR9-004 toggle — see above).
resource "azurerm_storage_account" "non_compliant_lrs" {
  name                          = "n2slrs${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = var.fixture_compliance["nr3_storage_geo_redundant"] ? "GRS" : "LRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  tags = merge(var.tags, {
    Check = "NR3-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR3-006: Immutable Blob Storage — Szenario-umschaltbar (Task #54)
###############################################################################
# CheckImmutableBlobStorage (AZ-NR3-006) is also Subscription-weit, aber mit
# ANY-Semantik (compliant sobald IRGENDEIN Container in der Subscription eine
# Immutability-Policy hat) statt ALL-Semantik wie AZ-NR3-003 — kein anderes
# Modul legt Blob-Container an, daher ist dieses Fixture modulintern
# eigenstaendig umschaltbar, ohne die anderen Module abstimmen zu muessen.
# "gaps": kein Container wird angelegt (non-compliant, heutiges Verhalten
# geaendert — vorher wurde der Container immer angelegt, was den Check schon
# im "gaps"-Zustand faelschlich compliant meldete; siehe Task #54 Endbericht).
# "hardened"/"mixed" mit fixture_compliance["nr3_immutable_blob"]: Container +
# Immutability-Policy werden angelegt.
resource "azurerm_storage_container" "immutable" {
  count                 = var.fixture_compliance["nr3_immutable_blob"] ? 1 : 0
  name                  = "immutable"
  storage_account_id    = azurerm_storage_account.compliant_grs.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "immutable" {
  count              = var.fixture_compliance["nr3_immutable_blob"] ? 1 : 0
  storage_account_id = azurerm_storage_account.compliant_grs.id

  rule {
    name    = "immutability"
    enabled = true

    filters {
      prefix_match = ["immutable/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = 365
      }
    }
  }

  depends_on = [azurerm_storage_container.immutable]
}
