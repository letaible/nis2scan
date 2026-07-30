# ============================================================================
# nis2scan — OIDC + Service Principal for GitHub Actions (Azure)
# ============================================================================
# This is a ONE-TIME manual apply. It creates the federated credential
# between GitHub Actions and your Azure tenant.
#
# Prerequisites:
#   - Azure CLI logged in with Owner/Global Admin
#   - Azure subscription ready
#
# Usage:
#   cd infra/azure/oidc
#   terraform init
#   terraform apply \
#     -var="github_repo=letaible/nis2scan" \
#     -var="subscription_id=YOUR_SUBSCRIPTION_ID"
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    # Obergrenzen wie in infra/azure/providers.tf (30.07.2026). Basis ist die
    # Version, mit der dieser Stack zuletzt lief (Lock: azurerm 4.65.0,
    # azuread 3.8.0) — bewusst nicht die neuere des Test-Stacks, damit der
    # naechste Apply auf den OIDC-Trust keine ungeplante Provider-Anhebung
    # mitbringt.
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.65"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.8"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azuread" {}

# --------------------------------------------------------------------------
# Variables
# --------------------------------------------------------------------------

variable "subscription_id" {
  description = "Azure Subscription ID for integration tests"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository (owner/repo format)"
  type        = string
  default     = "letaible/nis2scan"
}

# GitHub issues ID-hardened OIDC subjects (owner@id/repo@id) for this repo
# since its transfer into the letaible org. Entra federated credentials match
# subjects exactly, so both formats get their own credential set.
variable "github_repo_with_ids" {
  description = "GitHub repository in ID-hardened OIDC subject format (owner@id/repo@id)"
  type        = string
  default     = "letaible@308314955/nis2scan@1300122537"
}

# --------------------------------------------------------------------------
# Data Sources
# --------------------------------------------------------------------------

data "azuread_client_config" "current" {}
data "azurerm_subscription" "current" {}

# --------------------------------------------------------------------------
# App Registration + Service Principal
# --------------------------------------------------------------------------

resource "azuread_application" "nis2scan_ci" {
  display_name = "nis2scan-ci"
  owners       = [data.azuread_client_config.current.object_id]

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
      type = "Role"
    }
    resource_access {
      id   = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" # Application.Read.All
      type = "Role"
    }
    resource_access {
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68" # Policy.Read.All
      type = "Role"
    }
    resource_access {
      id   = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c" # RoleManagement.Read.Directory
      type = "Role"
    }
    resource_access {
      id   = "b0afded3-3588-46d8-8b3d-9842eff778da" # AuditLog.Read.All (AZ-NR9-007 sign-in report)
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "nis2scan_ci" {
  client_id = azuread_application.nis2scan_ci.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# --------------------------------------------------------------------------
# Federated Credential for GitHub Actions OIDC
# --------------------------------------------------------------------------

resource "azuread_application_federated_identity_credential" "github_main" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-main"
  description    = "GitHub Actions OIDC for main branch"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo}:ref:refs/heads/main"
}

resource "azuread_application_federated_identity_credential" "github_pr" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-pr"
  description    = "GitHub Actions OIDC for pull requests"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo}:pull_request"
}

resource "azuread_application_federated_identity_credential" "github_env" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-env"
  description    = "GitHub Actions OIDC for integration-test-azure environment"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo}:environment:integration-test-azure"
}

resource "azuread_application_federated_identity_credential" "github_main_ids" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-main-ids"
  description    = "GitHub Actions OIDC for main branch (ID-hardened subject)"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo_with_ids}:ref:refs/heads/main"
}

resource "azuread_application_federated_identity_credential" "github_pr_ids" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-pr-ids"
  description    = "GitHub Actions OIDC for pull requests (ID-hardened subject)"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo_with_ids}:pull_request"
}

resource "azuread_application_federated_identity_credential" "github_env_ids" {
  application_id = azuread_application.nis2scan_ci.id
  display_name   = "github-actions-env-ids"
  description    = "GitHub Actions OIDC for integration-test-azure environment (ID-hardened subject)"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_repo_with_ids}:environment:integration-test-azure"
}

# --------------------------------------------------------------------------
# Azure RBAC — Contributor + User Access Admin on subscription
# --------------------------------------------------------------------------

resource "azurerm_role_assignment" "contributor" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.nis2scan_ci.object_id
}

resource "azurerm_role_assignment" "user_access_admin" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "User Access Administrator"
  principal_id         = azuread_service_principal.nis2scan_ci.object_id
}

# --------------------------------------------------------------------------
# Outputs — set these as GitHub Secrets
# --------------------------------------------------------------------------

output "azure_client_id" {
  description = "AZURE_CLIENT_ID — set in GitHub Secrets"
  value       = azuread_application.nis2scan_ci.client_id
}

output "azure_tenant_id" {
  description = "AZURE_TENANT_ID — set in GitHub Secrets"
  value       = data.azuread_client_config.current.tenant_id
}

output "azure_subscription_id" {
  description = "AZURE_SUBSCRIPTION_ID — set in GitHub Secrets"
  value       = var.subscription_id
}

output "service_principal_object_id" {
  description = "SP object ID (for admin consent of Graph permissions)"
  value       = azuread_service_principal.nis2scan_ci.object_id
}

output "admin_consent_url" {
  description = "Open this URL to grant admin consent for Graph API permissions"
  value       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/adminconsent?client_id=${azuread_application.nis2scan_ci.client_id}"
}
