###############################################################################
# NR5-003: Container Registry Image Scan — Szenario-umschaltbar (Task #54)
###############################################################################
# "gaps": non_compliant stays Basic (today's behaviour, unchanged).
# "hardened"/"mixed" with fixture_compliance["nr5_acr_sku"]: upgraded to
# Standard. Per-registry check (CheckContainerRegistryScan) — no cross-module
# coupling, this fixture is self-contained.

# Compliant: Standard SKU (supports scanning), never toggled
resource "azurerm_container_registry" "compliant" {
  name                = "n2sacrc${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"

  tags = merge(var.tags, {
    Check = "NR5-003"
    Role  = "compliant"
  })
}

# Non-compliant: SKU follows the scenario toggle
resource "azurerm_container_registry" "non_compliant" {
  name                = "n2sacrnc${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.fixture_compliance["nr5_acr_sku"] ? "Standard" : "Basic"

  tags = merge(var.tags, {
    Check = "NR5-003"
    Role  = "non_compliant"
  })
}
