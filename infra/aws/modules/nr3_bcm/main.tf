# ============================================================================
# Nr. 3 — Aufrechterhaltung des Betriebs (Business Continuity)
# ============================================================================
# NR3-001: RDS Backup Retention — uses existing NR8 RDS instances (retention=0)
# NR3-002: S3 Versioning
# ============================================================================
# Task #54 note: the NR3-001 (backup_retention_period) and NR3-004 (multi_az)
# toggles for the shared NR8 RDS instance live in
# ../nr8_kryptographie/main.tf (aws_db_instance.non_compliant), since that is
# where the physical resource is defined. NR3-004 stays hardened_supported =
# false (see fixture_expectations in ../../outputs.tf) — Multi-AZ roughly
# doubles RDS cost and adds significant provisioning/teardown time, which is
# disproportionate for an integration-test fixture.
# ============================================================================

# ---------------------------------------------------------------------------
# NR3-002: S3 Versioning
# ---------------------------------------------------------------------------

# --- Compliant: Versioning enabled ---
resource "aws_s3_bucket" "versioning_compliant" {
  bucket        = "${var.name}-versioning-c-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-versioning-compliant-${var.suffix}"
    Check = "NR3-002"
    Role  = "compliant"
  }
}

resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.versioning_compliant.id

  versioning_configuration {
    status = "Enabled"
  }
}

# --- Non-compliant: Versioning disabled (Task #54: szenario-umschaltbar) ---
# Object Lock (NR3-003 unten) teilt sich diese Ressource per Doppelnutzung mit
# NR3-002 und hängt an DERSELBEN fixture_compliance-Taste
# "nr3_s3_versioning_objectlock": AWS erlaubt Object Lock nur auf Buckets mit
# aktivierter Versionierung, die beiden Zustände dürfen also nie auseinander-
# laufen. object_lock_enabled ist ein Erstellungs-Attribut (kann nachträglich
# nicht mehr geändert werden) — hier unkritisch, weil diese Infrastruktur pro
# CI-Lauf frisch angelegt und wieder zerstört wird, nie in-place aktualisiert.
resource "aws_s3_bucket" "versioning_non_compliant" {
  bucket        = "${var.name}-versioning-nc-${var.suffix}"
  force_destroy = true

  object_lock_enabled = var.fixture_compliance["nr3_s3_versioning_objectlock"]

  tags = {
    Name  = "${var.name}-versioning-non-compliant-${var.suffix}"
    Check = "NR3-002"
    Role  = "non_compliant"
  }
}

resource "aws_s3_bucket_versioning" "non_compliant" {
  bucket = aws_s3_bucket.versioning_non_compliant.id

  versioning_configuration {
    # "gaps": Suspended (= wie zuvor "keine Konfiguration", vom Check gleich
    # bewertet). "hardened"/"mixed" mit dieser Taste: Enabled.
    status = var.fixture_compliance["nr3_s3_versioning_objectlock"] ? "Enabled" : "Suspended"
  }
}

# Objekt-Sperrkonfiguration nur anlegen, wenn Object Lock auf dem Bucket
# aktiviert ist (sonst lehnt die AWS-API die Konfiguration ab).
resource "aws_s3_bucket_object_lock_configuration" "non_compliant_hardened" {
  count  = var.fixture_compliance["nr3_s3_versioning_objectlock"] ? 1 : 0
  bucket = aws_s3_bucket.versioning_non_compliant.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# ---------------------------------------------------------------------------
# NR3-003: S3 Object Lock
# ---------------------------------------------------------------------------

# --- Compliant: Object Lock enabled ---
resource "aws_s3_bucket" "object_lock_compliant" {
  bucket        = "${var.name}-objlock-c-${var.suffix}"
  force_destroy = true

  object_lock_enabled = true

  tags = {
    Name  = "${var.name}-object-lock-compliant-${var.suffix}"
    Check = "NR3-003"
    Role  = "compliant"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "compliant" {
  bucket = aws_s3_bucket.object_lock_compliant.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# --- Non-compliant / hardened toggle: Object Lock ---
# The non-compliant S3 versioning bucket (above) serves double duty: its
# object_lock_enabled + aws_s3_bucket_object_lock_configuration.non_compliant_hardened
# (both driven by fixture_compliance["nr3_s3_versioning_objectlock"]) are the
# non-compliant/hardened case for NR3-003 as well as NR3-002.

# ---------------------------------------------------------------------------
# NR3-006: EBS Snapshots (encrypted)
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

# --- Compliant: Encrypted volume with an encrypted snapshot ---
resource "aws_ebs_volume" "snapshot_compliant" {
  availability_zone = "${data.aws_region.current.name}a"
  size              = 1
  encrypted         = true

  tags = {
    Name  = "${var.name}-snap-compliant-${var.suffix}"
    Check = "NR3-006"
    Role  = "compliant"
  }
}

resource "aws_ebs_snapshot" "compliant" {
  volume_id = aws_ebs_volume.snapshot_compliant.id

  tags = {
    Name  = "${var.name}-snap-compliant-${var.suffix}"
    Check = "NR3-006"
    Role  = "compliant"
  }
}

# --- Non-compliant / hardened toggle: Volume with NO snapshot ---
# Task #54: "hardened"/"mixed" close this gap by both encrypting the volume
# AND creating a snapshot of it — a snapshot taken from an unencrypted volume
# is itself unencrypted (AWS does not support in-place re-encryption on plain
# CreateSnapshot), so the volume's own encrypted flag must flip together with
# snapshot presence for AWS-NR3-006 to actually read "compliant". This volume
# is not shared with any other tracked fixture, so flipping it is safe.
resource "aws_ebs_volume" "snapshot_non_compliant" {
  availability_zone = "${data.aws_region.current.name}a"
  size              = 1
  encrypted         = var.fixture_compliance["nr3_ebs_snapshot"]

  tags = {
    Name  = "${var.name}-snap-nc-${var.suffix}"
    Check = "NR3-006"
    Role  = "non_compliant"
  }
}

resource "aws_ebs_snapshot" "non_compliant_hardened" {
  count     = var.fixture_compliance["nr3_ebs_snapshot"] ? 1 : 0
  volume_id = aws_ebs_volume.snapshot_non_compliant.id

  tags = {
    Name  = "${var.name}-snap-nc-hardened-${var.suffix}"
    Check = "NR3-006"
    Role  = "hardened"
  }
}
