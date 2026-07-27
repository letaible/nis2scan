variable "location" {
  description = "Azure region for integration test infrastructure"
  type        = string
  default     = "westeurope"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}

# --- Szenario-Steuerung (Task #54, AWS als Muster, siehe infra/aws/variables.tf) ---
# "gaps"     = alle absichtlichen Luecken offen — das heutige Verhalten,
#              UNVERAENDERT. Bestehende Integrationstests (test_integration_az_
#              nr1..nr10.py) sind fest auf diesen Zustand verdrahtet und laufen
#              NUR in diesem Szenario (siehe tests/integration/conftest.py::
#              SKIP_UNLESS_GAPS_SCENARIO — derselbe Helfer wie bei AWS, ein
#              gemeinsamer Env-Var NIS2SCAN_SCENARIO fuer beide Provider).
# "hardened" = jede unterstuetzte Luecke geschlossen. Ausnahmen (strukturell
#              nicht unabhaengig umschaltbar oder unverhaeltnismaessiger aufwand)
#              bleiben im Gaps-Zustand — siehe hardened_supported=false Eintraege
#              im Output "fixture_expectations" (outputs.tf) inkl. Begruendung.
# "mixed"    = deterministische, von Hand zugeteilte Mischung (siehe
#              local.fixture_compliance_mixed in main.tf) — KEIN Zufall/Hash.
#
# Alle drei Szenarien werden von test_integration_az_nr0_scenarios.py geprueft,
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
