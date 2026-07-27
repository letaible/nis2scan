# NR9: Zugriffskontrolle — VPC and Firewall Rules

resource "google_compute_network" "test" {
  name                    = "nis2-nr9-${var.suffix}"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_firewall" "compliant" {
  name    = "nis2-nr9-ok-${var.suffix}"
  network = google_compute_network.test.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"] # Restricted — compliant
}

# Task #54 Szenario-Toggle "nr9_firewall_source_range" (GCP-NR9-004). "gaps":
# open to the world (non-compliant, as before). "hardened"/"mixed" with this
# key: restricted to the same internal range as the compliant rule above —
# same firewall rule name the whole time (the tracked resource_ref in
# ../../outputs.tf::fixture_expectations), only source_ranges moves.
resource "google_compute_firewall" "non_compliant" {
  name    = "nis2-nr9-bad-${var.suffix}"
  network = google_compute_network.test.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.fixture_compliance["nr9_firewall_source_range"] ? ["10.0.0.0/8"] : ["0.0.0.0/0"]
}
