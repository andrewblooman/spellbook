locals {
  worker_image = var.worker_image != "" ? var.worker_image : var.image
  # The workers reach the control plane's /internal API over the VPC connector at
  # its Cloud Run URL; both sides share SPELLBOOK_WORKER_TOKEN.
  control_url = google_cloud_run_v2_service.control.uri
}

# --- APIs -------------------------------------------------------------------
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "vpcaccess.googleapis.com",
    "secretmanager.googleapis.com",
    "compute.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# --- Serverless VPC connector (puts the workers inside the VPC) --------------
resource "google_vpc_access_connector" "connector" {
  name          = "spellbook-conn"
  region        = var.region
  network       = var.network
  ip_cidr_range = var.connector_cidr
  depends_on    = [google_project_service.apis]
}

# --- Secrets ----------------------------------------------------------------
resource "google_secret_manager_secret" "anthropic_api_key" {
  secret_id = "spellbook-anthropic-api-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "worker_token" {
  secret_id = "spellbook-worker-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "spellbook-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret      = google_secret_manager_secret.database_url.id
  secret_data = var.database_url
}
# NB: seed the anthropic-api-key and worker-token secret versions out of band
# (e.g. `gcloud secrets versions add`) so real secrets never enter Terraform state.

# --- Service accounts -------------------------------------------------------
resource "google_service_account" "control" {
  account_id   = "spellbook-control"
  display_name = "Spellbook control plane"
}

resource "google_service_account" "worker" {
  account_id   = "spellbook-worker"
  display_name = "Spellbook agent worker"
}

# Least-privilege: each SA reads only the secrets it needs.
resource "google_secret_manager_secret_iam_member" "control_db" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control.email}"
}

resource "google_secret_manager_secret_iam_member" "control_token" {
  secret_id = google_secret_manager_secret.worker_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_token" {
  secret_id = google_secret_manager_secret.worker_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_anthropic" {
  secret_id = google_secret_manager_secret.anthropic_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker.email}"
}

# --- Control plane ----------------------------------------------------------
resource "google_cloud_run_v2_service" "control" {
  name                = "spellbook-control"
  location            = var.region
  ingress             = var.control_ingress
  deletion_protection = false

  template {
    service_account = google_service_account.control.email
    scaling {
      min_instance_count = 1
      max_instance_count = 3
    }
    containers {
      image = var.image
      ports {
        container_port = 8000 # server.py honors Cloud Run's injected PORT
      }

      env {
        name  = "SPELLBOOK_SEED"
        value = "0"
      }
      env {
        name = "SPELLBOOK_DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "SPELLBOOK_WORKER_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.worker_token.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# --- Agent workers (one per posture, inside the VPC) ------------------------
resource "google_cloud_run_v2_service" "worker" {
  for_each = {
    external = var.scope_external
    internal = var.scope_internal
  }

  name                = "spellbook-worker-${each.key}"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY" # pull model: no external callers
  deletion_protection = false

  template {
    service_account = google_service_account.worker.email
    # One always-on instance per posture so the pull loop keeps claiming work.
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      # Route private ranges through the VPC (targets + control plane's internal URL);
      # egress to api.anthropic.com goes direct to the internet.
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = local.worker_image

      env {
        name  = "SPELLBOOK_POSTURE"
        value = each.key
      }
      env {
        name  = "SPELLBOOK_SCOPE"
        value = each.value
      }
      env {
        name  = "SPELLBOOK_CONTROL_URL"
        value = local.control_url
      }
      env {
        name  = "SPELLBOOK_AGENT_MODEL"
        value = var.agent_model
      }
      env {
        name = "SPELLBOOK_WORKER_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.worker_token.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "ANTHROPIC_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.anthropic_api_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# Workers invoke the control plane's internal-ingress service; grant run.invoker.
resource "google_cloud_run_v2_service_iam_member" "worker_invokes_control" {
  name     = google_cloud_run_v2_service.control.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.worker.email}"
}
