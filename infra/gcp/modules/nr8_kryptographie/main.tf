# NR8: Kryptographie — KMS Key Ring and Keys
#
# GCP-Besonderheit (CLAUDE.md "Known Pitfalls / GCP", Task #54 variables.tf-
# Kommentar): KMS key rings and keys are PERMANENT — they can never be
# deleted, only scheduled for destruction (24h minimum). The Task #54
# scenario toggle below therefore NEVER creates or destroys a key ring/key
# across scenarios — the key ring and both keys ("compliant"/"non_compliant")
# exist identically in all three scenarios. Only the rotation_period
# CONFIGURATION ATTRIBUTE on the already-existing non-compliant key moves
# (an in-place update via the KMS API's patch/updateMask, not a replace) —
# this is the only Szenario-Toggle in this repo where existence vs.
# configuration matters enough to call out explicitly.

resource "google_kms_key_ring" "test" {
  name     = "nis2-nr8-${var.suffix}"
  location = var.region
}

resource "google_kms_crypto_key" "compliant" {
  name            = "nis2-nr8-ok-${var.suffix}"
  key_ring        = google_kms_key_ring.test.id
  rotation_period = "7776000s" # 90 days
  labels          = var.labels
}

resource "google_kms_crypto_key" "non_compliant" {
  name     = "nis2-nr8-bad-${var.suffix}"
  key_ring = google_kms_key_ring.test.id
  labels   = var.labels
  # Task #54 Szenario-Toggle "nr8_kms_key_rotation" (GCP-NR8-001). "gaps": no
  # rotation period (null == unset, not "0s" — non-compliant). "hardened"/
  # "mixed" with this key: same 90-day period as the compliant key above.
  # Same key the whole time — only the attribute value changes.
  rotation_period = var.fixture_compliance["nr8_kms_key_rotation"] ? "7776000s" : null
}
