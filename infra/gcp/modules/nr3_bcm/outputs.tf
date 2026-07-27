output "compliant_bucket_name" {
  value = google_storage_bucket.compliant.name
}

output "non_compliant_bucket_name" {
  value = google_storage_bucket.non_compliant.name
}
