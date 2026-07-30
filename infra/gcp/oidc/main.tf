terraform {
  required_version = ">= 1.0"
  required_providers {
    # Obergrenzen wie in infra/gcp/providers.tf (30.07.2026). Basis ist die
    # Version, mit der dieser Stack zuletzt lief (Lock: google/google-beta
    # 7.27.0).
    google = {
      source  = "hashicorp/google"
      version = "~> 7.27"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.27"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ---------- Variables ----------

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository (owner/repo)"
  type        = string
  default     = "letaible/nis2scan"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west1"
}

# ---------- Workload Identity Federation ----------

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "Workload Identity Pool for GitHub Actions OIDC"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository=='${var.github_repo}'"
}

# ---------- Service Account ----------

resource "google_service_account" "nis2scan_ci" {
  account_id   = "nis2scan-ci"
  display_name = "nis2scan CI"
  description  = "Service account for nis2scan integration tests"
}

resource "google_service_account_iam_binding" "workload_identity" {
  service_account_id = google_service_account.nis2scan_ci.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}",
  ]
}

# ---------- IAM Roles ----------

locals {
  ci_roles = [
    # --- Scan (read-only) roles ---
    "roles/viewer",
    "roles/securitycenter.sourcesViewer",
    "roles/iam.securityReviewer",
    "roles/monitoring.viewer",
    "roles/logging.viewer",
    "roles/storage.objectViewer",
    "roles/compute.viewer",
    "roles/container.clusterViewer",
    # --- Test infra (write) roles for CI Terraform ---
    "roles/storage.admin",         # create/delete GCS buckets
    "roles/cloudkms.admin",        # create/delete KMS keys
    "roles/compute.networkAdmin",  # create/delete VPC + firewall rules
    "roles/compute.securityAdmin", # manage firewall rules
  ]
}

resource "google_project_iam_member" "ci_roles" {
  for_each = toset(local.ci_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.nis2scan_ci.email}"
}

# ---------- Outputs ----------

output "project_id" {
  value = var.project_id
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  value = google_service_account.nis2scan_ci.email
}
