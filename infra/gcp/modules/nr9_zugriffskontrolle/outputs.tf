output "compliant_firewall_name" {
  value = google_compute_firewall.compliant.name
}

output "non_compliant_firewall_name" {
  value = google_compute_firewall.non_compliant.name
}
