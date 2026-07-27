variable "suffix" { type = string }
variable "name" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_id" { type = string }
variable "tenant_id" { type = string }
variable "object_id" { type = string }
variable "tags" { type = map(string) }

variable "fixture_compliance" {
  description = "Szenario-Umschaltung je Fixture-Key (Task #54, siehe root main.tf)"
  type        = map(bool)
}
