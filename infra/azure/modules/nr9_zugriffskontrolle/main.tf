###############################################################################
# NR9-003: NSG Rules — no open inbound from Internet — Szenario-umschaltbar
# (Task #54)
###############################################################################
# "gaps": non_compliant stays open to 0.0.0.0/0 (today's behaviour, unchanged).
# "hardened"/"mixed" with fixture_compliance["nr9_nsg_open_access"]: source
# restricted to the internal range. Per-NSG check (CheckNsgOpenAccess) — no
# cross-module coupling, this fixture is self-contained.

# Compliant: Only allow HTTPS from internal range
resource "azurerm_network_security_group" "compliant" {
  name                = "${var.name}-nsg-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowHTTPSInternal"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, {
    Check = "NR9-003"
    Role  = "compliant"
  })
}

# Non-compliant: source address follows the scenario toggle
resource "azurerm_network_security_group" "non_compliant" {
  name                = "${var.name}-nsg-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowSSHAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.fixture_compliance["nr9_nsg_open_access"] ? "10.0.0.0/8" : "*"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, {
    Check = "NR9-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR9-004: Storage Account — Private Access Only — Szenario-umschaltbar
# (Task #54)
###############################################################################
# "gaps": non_compliant stays public (today's behaviour, unchanged).
# "hardened"/"mixed" with fixture_compliance["nr9_storage_public_access"]:
# switched to private.
#
# ACHTUNG Aggregat-Check: AZ-NR9-004 (CheckStoragePublicAccess) is Subscription-
# weit — see the comment in modules/nr3_bcm for the full explanation. The
# storage accounts in modules/nr3_bcm and modules/nr8_kryptographie are hard-
# set to private (this module owns the toggle, they don't) so only this
# module's own non_compliant account moves the aggregate result. Both accounts
# here are hard-set to GRS (not toggled) for the same cross-module reason
# regarding AZ-NR3-003, which modules/nr3_bcm owns instead.

# Compliant: Public access disabled, default deny, never toggled
resource "azurerm_storage_account" "compliant" {
  name                          = "n2sprv${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "GRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  tags = merge(var.tags, {
    Check = "NR9-004"
    Role  = "compliant"
  })
}

# Non-compliant: public network access follows the scenario toggle
resource "azurerm_storage_account" "non_compliant" {
  name                          = "n2spub${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "GRS"
  public_network_access_enabled = var.fixture_compliance["nr9_storage_public_access"] ? false : true

  network_rules {
    default_action = var.fixture_compliance["nr9_storage_public_access"] ? "Deny" : "Allow"
  }

  tags = merge(var.tags, {
    Check = "NR9-004"
    Role  = "non_compliant"
  })
}
