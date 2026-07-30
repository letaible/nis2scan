# Provider-Obergrenzen — siehe die ausführliche Begründung in
# infra/azure/providers.tf (Release-Gate-Ausfall v0.2.0 am 30.07.2026 durch
# azurerm 5.0.0). AWS war davon nicht betroffen, hatte aber dieselbe
# unbegrenzte Constraint und damit dasselbe latente Risiko.
# Belegt grün: Lauf 30575696673 vom 30.07.2026 (aws 6.56.0, tls 4.3.0,
# random 3.9.0, archive 2.8.0).
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.56"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.3"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.8"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "nis2scan"
      Environment = "integration-test"
      RunId       = var.run_id
      ManagedBy   = "terraform"
    }
  }
}
