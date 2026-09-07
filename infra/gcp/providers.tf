# Provider-Obergrenzen — siehe die ausführliche Begründung in
# infra/azure/providers.tf (Release-Gate-Ausfall v0.2.0 am 30.07.2026 durch
# azurerm 5.0.0). GCP war davon nicht betroffen, hatte aber dieselbe
# unbegrenzte Constraint und damit dasselbe latente Risiko.
# Belegt grün: Lauf 30575696673 vom 30.07.2026 (google 7.42.0, random 3.9.0).
terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
