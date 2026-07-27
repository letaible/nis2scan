resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "nis2scan"
  labels = {
    project     = "nis2scan"
    environment = "integration-test"
    run-id      = var.run_id
    managed-by  = "terraform"
  }
}

# ============================================================================
# Szenario-Steuerung (Task #54): fixture_compliance je Fixture-Key
# ============================================================================
# Portierung des AWS-Musters (siehe infra/aws/main.tf) auf GCP. Von den 51 GCP-
# Checks haben nur DREI ein eigenes, unabhängig umschaltbares Terraform-Attribut
# — jeweils genau die drei Ressourcen, die die bestehenden Module nr3_bcm/
# nr8_kryptographie/nr9_zugriffskontrolle bereits als compliant/non_compliant-
# Paar anlegen:
#   - nr3_gcs_versioning     -> GCP-NR3-002 (GCS Bucket-Versionierung)
#   - nr8_kms_key_rotation   -> GCP-NR8-001 (KMS-Schluesselrotation) — togglet
#     NUR das rotation_period-Attribut des bestehenden Schluessels, niemals
#     seine Existenz (KMS-Keys/Key-Rings sind in GCP PERMANENT, siehe
#     variables.tf und CLAUDE.md "Known Pitfalls / GCP").
#   - nr9_firewall_source_range -> GCP-NR9-004 (VPC-Firewallregeln)
#
# Die uebrigen 48 Checks (GCP-NR1-*, NR2-*, NR4-*, NR5-*, NR6-*, NR7-*, NR10-*
# sowie GCP-NR3-001/003/004/005/006/007, GCP-NR8-002/003/004/005/006, GCP-NR9-
# 001/002/003/005/006/007/008) sind projektweite Abwesenheits-/Positiv-Pfad-
# Checks OHNE eigene Terraform-Ressource in infra/gcp/modules/* — es gibt fuer
# sie nichts zu invertieren. Sie bleiben unveraendert Positive-Path-Tests in
# den bestehenden test_integration_gcp_nrX.py und laufen ausschliesslich im
# Szenario "gaps" (siehe SKIP_UNLESS_GAPS_SCENARIO). Vollstaendige Liste und
# Begruendung: Scope-Note in outputs.tf.
#
# Projektweite Singletons (Task #54 Punkt 3, analog AWS-Kommentare in
# modules/nr7_cyberhygiene und modules/nr9_zugriffskontrolle dort): diese
# GCP-Infrastruktur legt AKTUELL KEINE projektweiten Konfigurations-Singletons
# an (kein Org-Policy-, Essential-Contacts- oder Audit-Log-Config-Resource
# unter infra/gcp/modules/*) — alle drei Fixtures oben sind ueber
# "-${local.suffix}" eindeutig benannt, nicht Projekt-globale Attribute wie
# AWS' account-password-policy oder ebs-encryption-by-default. Zwei Szenario-
# Applies koennten sich hier also nicht gegenseitig ueberschreiben. Die
# providerweite concurrency-group in .github/workflows/integration-tests-gcp.yml
# bleibt trotzdem bestehen (KMS-Permanenz und ein gemeinsames GCP-Testprojekt
# sind Grund genug, nie zwei Szenarien parallel laufen zu lassen). Sollte
# kuenftig ein echtes projektweites Toggle hinzukommen (z. B. Essential
# Contacts oder eine Org Policy), braucht es denselben Singleton-Hinweis wie
# bei AWS.
locals {
  # "mixed": von Hand zugeteilt, ueber die drei betroffenen §30-Bereiche
  # gestreut (NR3/NR8/NR9 — je einer). KEIN Zufall, kein Hash (Gruender-Vorgabe,
  # wie beim AWS-Muster). Mit nur drei Fixtures ist eine exakte Haelfte nicht
  # moeglich; zwei von drei compliant kommt der AWS-Quote (~9/17) am naechsten.
  fixture_compliance_mixed = {
    nr3_gcs_versioning        = true
    nr8_kms_key_rotation      = false
    nr9_firewall_source_range = true
  }

  fixture_keys = keys(local.fixture_compliance_mixed)

  # scenario == "gaps"     -> alle Keys false (heutiges Verhalten, unveraendert)
  # scenario == "hardened" -> alle Keys true
  # scenario == "mixed"    -> siehe fixture_compliance_mixed oben
  fixture_compliance = (
    var.scenario == "hardened" ? { for k in local.fixture_keys : k => true } :
    var.scenario == "mixed" ? local.fixture_compliance_mixed :
    { for k in local.fixture_keys : k => false }
  )
}

# ---------- NR3: Business Continuity Management ----------

module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  project_id         = var.project_id
  region             = var.region
  suffix             = local.suffix
  labels             = local.labels
  fixture_compliance = local.fixture_compliance
}

# ---------- NR8: Kryptographie ----------

module "nr8_kryptographie" {
  source = "./modules/nr8_kryptographie"

  project_id         = var.project_id
  region             = var.region
  suffix             = local.suffix
  labels             = local.labels
  fixture_compliance = local.fixture_compliance
}

# ---------- NR9: Zugriffskontrolle ----------

module "nr9_zugriffskontrolle" {
  source = "./modules/nr9_zugriffskontrolle"

  project_id         = var.project_id
  region             = var.region
  suffix             = local.suffix
  labels             = local.labels
  fixture_compliance = local.fixture_compliance
}
