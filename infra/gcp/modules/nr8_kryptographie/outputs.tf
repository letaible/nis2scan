output "compliant_key_id" {
  value = google_kms_crypto_key.compliant.id
}

output "non_compliant_key_id" {
  value = google_kms_crypto_key.non_compliant.id
}
