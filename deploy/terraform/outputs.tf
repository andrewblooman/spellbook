output "control_url" {
  value       = google_cloud_run_v2_service.control.uri
  description = "Control-plane service URL (also the workers' SPELLBOOK_CONTROL_URL)."
}

output "worker_service_accounts" {
  value       = google_service_account.worker.email
  description = "Service account the agent workers run as."
}

output "secret_ids" {
  value = {
    anthropic_api_key = google_secret_manager_secret.anthropic_api_key.secret_id
    worker_token      = google_secret_manager_secret.worker_token.secret_id
    database_url      = google_secret_manager_secret.database_url.secret_id
  }
  description = "Secret Manager ids — seed the anthropic-api-key and worker-token versions out of band."
}
