# Provider-Obergrenzen (30.07.2026, Release-Gate-Ausfall v0.2.0): Die
# Constraints lauteten ">= 3.80" ohne Obergrenze UND die .terraform.lock.hcl
# ist per .gitignore vom Repo ausgeschlossen — CI löste deshalb bei JEDEM
# `terraform init` die neueste Version auf. Als hashicorp/azurerm 5.0.0
# erschien, brach der Azure-Integrationslauf ohne eine einzige Code-Änderung
# (resource_manager_id am Storage-Container entfernt, rbac_authorization_enabled
# am Key Vault jetzt Pflicht). Gleiche Fehlerklasse wie die SDK-Drift, gegen
# die pyproject.toml längst Obergrenzen setzt.
#
# `~>` erlaubt Patches und Minors innerhalb der belegt grünen Major-Version und
# sperrt den nächsten Major. Belegt grün: Lauf 30345928601 vom 28.07.2026
# (azurerm 4.81.0, azuread 3.9.0, random 3.9.0).
#
# Beim Anheben eines Majors: Migrationsleitfaden des Providers lesen, Constraint
# hier hochziehen, Integrationslauf per workflow_dispatch fahren — NICHT über
# einen Release-Tag herausfinden.
terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.9"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

provider "azuread" {}
