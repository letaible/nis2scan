# ============================================================================
# nis2scan — Integration Test Infrastructure (Azure)
# ============================================================================
# Creates compliant AND non-compliant resources for each implemented check.
# Designed to be created and destroyed within a single CI pipeline run.
# ============================================================================

# --- Random suffix for unique resource names ---
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "nis2scan-${local.suffix}"
  tags = {
    Project     = "nis2scan"
    Environment = "integration-test"
    RunId       = var.run_id
    ManagedBy   = "terraform"
  }
}

# ============================================================================
# Szenario-Steuerung (Task #54): fixture_compliance je Fixture-Key
# ============================================================================
# Jeder Key entspricht GENAU einer unabhaengig umschaltbaren Ressourcen-
# Konfiguration (siehe Kommentare in den jeweiligen Modulen).
#
# WICHTIGER UNTERSCHIED zu AWS: mehrere Azure-Checks (CheckGeoRedundantStorage
# AZ-NR3-003, CheckStorageEncryption AZ-NR8-001, CheckStoragePublicAccess
# AZ-NR9-004, CheckDiagnosticSettings AZ-NR6-004) sind KEINE Pro-Ressource-
# Checks wie bei AWS, sondern Subscription-weite AGGREGAT-Checks: sie lesen
# ALLE Storage Accounts / kritischen Ressourcen der Subscription auf einmal
# und liefern GENAU EIN Finding ("compliant" nur wenn ALLE Ressourcen dieses
# Typs die Eigenschaft erfuellen). Die drei Module nr3_bcm, nr8_kryptographie
# und nr9_zugriffskontrolle legen zusammen 6 Storage Accounts an — ohne
# Abstimmung wuerde das eigene Fixture jedes Moduls von den "fremden" Accounts
# der jeweils anderen Module ueberschattet (z. B. macht ein einzelner LRS-
# Account in JEDEM anderen Modul AZ-NR3-003 fuer die gesamte Subscription
# dauerhaft non-compliant, unabhaengig vom eigenen Toggle).
#
# Deshalb: fuer AZ-NR3-003 (Geo-Redundanz) und AZ-NR9-004 (Public Access) sind
# die "fremden" Storage Accounts in den JEWEILS ANDEREN Modulen hart auf den
# GUTEN Wert gesetzt (siehe Kommentare in modules/nr3_bcm, nr8_kryptographie,
# nr9_zugriffskontrolle) — nur das EIGENE Modul des Checks bewegt sich mit dem
# Szenario, exakt wie bei AWS' "compliant bleibt immer gut, nur non_compliant
# bewegt sich"-Prinzip, nur eben modulübergreifend angewendet. Fuer AZ-NR8-001
# (CMK, erfordert Key-Vault-Identitaets-Verkettung ueber alle 6 Accounts
# hinweg) und AZ-NR6-004 (Diagnostic Settings auf JEDER kritischen Ressource:
# KeyVaults, Storage Accounts, NSGs modulübergreifend) ist der Aufwand fuer
# eine echte modulübergreifende Haertung unverhaeltnismaessig — beide bleiben
# hardened_supported=false (siehe outputs.tf, Begruendung dort).
#
# Fixtures OHNE eigenen Terraform-Toggle (reine Tenant-/Subscription-weite
# Abwesenheits-Checks wie Defender for Cloud, Management Groups, Activity-Log-
# Export, Conditional Access, PIM, Sentinel — analog GuardDuty/Config bei AWS
# ausgeschlossen) tauchen hier bewusst NICHT auf — siehe Scope-Note in
# outputs.tf. Diese Checks bleiben unveraendert Positive-Path-Tests in den
# bestehenden test_integration_az_nrX.py und laufen (wie alle "alten" Tests)
# ausschliesslich im Szenario "gaps" (SKIP_UNLESS_GAPS_SCENARIO).
locals {
  # "mixed": von Hand zugeteilt, angenaehert haelftig (4/8 compliant) und ueber
  # die §30-Bereiche gestreut. KEIN Zufall, kein Hash (Gruender-Vorgabe).
  fixture_compliance_mixed = {
    nr3_storage_geo_redundant     = true
    nr3_immutable_blob            = false
    nr5_acr_sku                   = true
    nr6_log_retention             = false
    nr8_keyvault_purge_protection = true
    nr8_app_service_https_tls     = false
    nr9_nsg_open_access           = false
    nr9_storage_public_access     = true
  }

  fixture_keys = keys(local.fixture_compliance_mixed)

  # scenario == "gaps"     -> alle Keys false (heutiges Verhalten, unveraendert)
  # scenario == "hardened" -> alle Keys true
  # scenario == "mixed"    -> siehe fixture_compliance_mixed oben
  fixture_compliance = (
    var.scenario == "hardened" ? { for k in local.fixture_keys : k => true } :
    var.scenario == "mixed" ? local.fixture_compliance_mixed :
    { for k in local.fixture_keys : k => false }
  )
}

# --- Identity ---
data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

# --- Shared Resource Group ---
resource "azurerm_resource_group" "test" {
  name     = "${local.name}-rg"
  location = var.location
  tags     = local.tags
}

# --- Shared VNet for network-dependent resources ---
resource "azurerm_virtual_network" "test" {
  name                = "${local.name}-vnet"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "default" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "secondary" {
  name                 = "secondary"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.2.0/24"]
}

# --- Module: Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
  fixture_compliance  = local.fixture_compliance
}

# --- Module: Nr. 8 Kryptographie ---
module "nr8_kryptographie" {
  source = "./modules/nr8_kryptographie"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  subnet_id           = azurerm_subnet.default.id
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
  tags                = local.tags
  fixture_compliance  = local.fixture_compliance
}

# --- Module: Nr. 9 Zugriffskontrolle ---
module "nr9_zugriffskontrolle" {
  source = "./modules/nr9_zugriffskontrolle"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  vnet_id             = azurerm_virtual_network.test.id
  tags                = local.tags
  fixture_compliance  = local.fixture_compliance
}

# --- Module: Nr. 5 Schwachstellen ---
module "nr5_schwachstellen" {
  source = "./modules/nr5_schwachstellen"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
  fixture_compliance  = local.fixture_compliance
}

# --- Module: Nr. 6 Wirksamkeit ---
module "nr6_wirksamkeit" {
  source = "./modules/nr6_wirksamkeit"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
  fixture_compliance  = local.fixture_compliance
}
