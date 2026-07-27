# NR3: Business Continuity Management — GCS Buckets
#
# "compliant" is a stable positive control: versioning stays enabled in every
# scenario. "non_compliant" is the Task #54 scenario-toggle fixture for
# GCP-NR3-002 (CheckGcsVersioning) — versioning flips with
# var.fixture_compliance["nr3_gcs_versioning"], so THIS bucket becomes
# GCS-NR3-002-compliant in "hardened"/"mixed" without renaming it (the name
# stays the tracked resource_ref in ../../outputs.tf::fixture_expectations).
# Toggling a bucket's versioning setting in place never requires recreating
# the bucket (no GCP permanence concern here, unlike KMS).

resource "google_storage_bucket" "compliant" {
  name                        = "nis2-nr3-ok-${var.suffix}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
  labels                      = var.labels

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket" "non_compliant" {
  name                        = "nis2-nr3-bad-${var.suffix}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
  labels                      = var.labels

  versioning {
    # Task #54 Szenario-Toggle "nr3_gcs_versioning".
    enabled = var.fixture_compliance["nr3_gcs_versioning"]
  }
}
