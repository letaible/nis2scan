variable "region" {
  description = "AWS region for integration test infrastructure"
  type        = string
  default     = "eu-central-1"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}

# --- Szenario-Steuerung (Task #54, Gründer-Vorgabe 27.07.2026) ---------------
# "gaps"     = alle absichtlichen Lücken offen — das heutige Verhalten,
#              UNVERÄNDERT. Bestehende Integrationstests (test_integration_nr1..
#              nr10.py, *_phaseN.py, exceptions.py) sind fest auf diesen Zustand
#              verdrahtet und laufen NUR in diesem Szenario (siehe
#              tests/integration/conftest.py::SKIP_UNLESS_GAPS_SCENARIO).
# "hardened" = jede unterstützte Lücke geschlossen. Ausnahmen (unverhältnismäßig
#              in Kosten/Dauer oder strukturell nicht beobachtbar) bleiben im
#              Gaps-Zustand — siehe hardened_supported=false Einträge im
#              output "fixture_expectations" (outputs.tf) inkl. Begründung.
# "mixed"    = deterministische, von Hand zugeteilte Mischung (siehe
#              local.fixture_compliance_mixed in main.tf) — KEIN Zufall/Hash.
#
# Alle drei Szenarien werden von test_integration_nr0_scenarios.py geprüft,
# das seine Erwartungen aus dem Terraform-Output "fixture_expectations" liest
# statt sie hart zu kodieren.
variable "scenario" {
  description = "Compliance-Szenario der Testinfrastruktur: gaps | hardened | mixed"
  type        = string
  default     = "gaps"

  validation {
    condition     = contains(["gaps", "hardened", "mixed"], var.scenario)
    error_message = "Scenario muss einer von \"gaps\", \"hardened\", \"mixed\" sein."
  }
}
