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
#
# FIX (Azure-mixed-Beweislauf, Run 30297491967, 27.07.2026): dieses Fixture
# legte vorher azurerm_storage_management_policy an — das ist eine Blob-
# LIFECYCLE-Management-Regel (automatisches Tiering/Loeschen nach N Tagen,
# ARM-Pfad .../storageAccounts/{n}/managementPolicies/default), NICHT die
# Container-Immutability/WORM-Policy, die CheckImmutableBlobStorage tatsaechlich
# liest (container.immutability_policy, ARM-Pfad .../blobServices/default/
# containers/{n} mit einer eigenen ImmutabilityPolicy-Property). Belegt ueber
# `terraform providers schema -json`: der azurerm-Provider hat dafuer die
# eigene Resource azurerm_storage_container_immutability_policy — die wurde
# hier nie verwendet. Auf UNLOCKED (locked=false) gesetzt: eine gesperrte
# Policy verhindert `terraform destroy` fuer die Laufzeit der Aufbewahrungs-
# frist unwiderruflich (Account/Container koennen dann nicht mehr geloescht
# werden) — fuer eine Testinfrastruktur, die jeden CI-Lauf zerstoert wird,
# unbrauchbar. KONSEQUENZ (Rechts-Review 28.07.2026, Auflage 1+3): Der Check
# AZ-NR3-006 verlangt seit 28.07.2026 eine LOCKED-Policy fuer den
# Positivnachweis — dieses Fixture kann den Compliant-Pfad daher NIE beweisen
# und ist in fixture_expectations als hardened_supported=false mit expected=
# non_compliant in ALLEN Szenarien gefuehrt (siehe infra/azure/outputs.tf).
# Der Compliant-Pfad wird per Unit-Test gegen die echte SDK-Form bewiesen.
resource "azurerm_storage_container" "immutable" {
  count                 = var.fixture_compliance["nr3_immutable_blob"] ? 1 : 0
  name                  = "immutable"
  storage_account_id    = azurerm_storage_account.compliant_grs.id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "immutable" {
  count                                 = var.fixture_compliance["nr3_immutable_blob"] ? 1 : 0
  storage_container_resource_manager_id = azurerm_storage_container.immutable[0].resource_manager_id
  immutability_period_in_days           = 365
  locked                                = false
}
