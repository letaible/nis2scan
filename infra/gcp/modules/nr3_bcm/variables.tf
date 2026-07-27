variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "suffix" {
  description = "Random suffix for resource names"
  type        = string
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
}

variable "fixture_compliance" {
  description = "Szenario-Umschaltung je Fixture-Key (Task #54, siehe root main.tf)"
  type        = map(bool)
}
