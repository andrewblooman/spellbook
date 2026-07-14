variable "project_id" {
  type        = string
  description = "GCP project to deploy into."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "Region for Cloud Run services and the VPC connector."
}

variable "image" {
  type        = string
  description = <<-EOT
    Fully-qualified container image (e.g. REGION-docker.pkg.dev/PROJECT/spellbook/app:TAG).
    The control plane runs the default `runtime` target; the workers run the same
    repo image built with `--target worker` (Node + Claude Code CLI).
  EOT
}

variable "worker_image" {
  type        = string
  default     = ""
  description = "Worker image (`--target worker`). Defaults to `var.image` when empty."
}

variable "network" {
  type        = string
  default     = "default"
  description = "VPC network the workers (and their targets) live in."
}

variable "connector_cidr" {
  type        = string
  default     = "10.8.0.0/28"
  description = "Unused /28 for the Serverless VPC Access connector."
}

variable "database_url" {
  type        = string
  sensitive   = true
  description = "SQLAlchemy URL for the control-plane store (postgresql+psycopg://…)."
}

variable "scope_external" {
  type        = string
  description = "Owned-asset allowlist for the external (shields-up) worker (comma-separated)."
}

variable "scope_internal" {
  type        = string
  description = "Owned-asset allowlist for the internal (assumed-breach) worker (comma-separated)."
}

variable "agent_model" {
  type        = string
  default     = "claude-opus-4-8"
  description = "Claude model id the workers use."
}

variable "control_ingress" {
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  description = <<-EOT
    Control-plane ingress. Default keeps it off the public internet; the `/internal`
    API is reachable from the workers over the VPC connector and is additionally
    bearer-gated. Front the UI with an external HTTPS load balancer + IAP, or set
    this to INGRESS_TRAFFIC_ALL for a public UI (the `/internal` API stays token-gated).
  EOT
}
