variable "suffix" {
  description = "Unique suffix for resource naming to avoid collisions"
  type        = string
}

variable "name" {
  description = "Name prefix for all resources"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for networking resources (ALB, RDS subnet group)"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for ALB and RDS subnet group"
  type        = list(string)
}

variable "region" {
  description = "AWS region for the resources"
  type        = string
}

variable "fixture_compliance" {
  description = "Szenario-Umschaltung je Fixture-Key (Task #54, siehe root main.tf)"
  type        = map(bool)
}
