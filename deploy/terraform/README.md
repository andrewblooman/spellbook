# Spellbook — Cloud Run + VPC deployment

Deploys the control plane plus two in-VPC agent-workers (external + internal).

```
                 ┌──────────────────────────────┐
   humans ─LB/IAP┤ spellbook-control (Cloud Run) │  FastAPI + SPA + store
                 │   internal-ingress /internal  │◄─┐ claim / result (bearer)
                 └──────────────┬───────────────┘  │
                     VPC connector (PRIVATE_RANGES) │
        ┌──────────────────────┴───────────────────┴────────┐
        │  spellbook-worker-external   spellbook-worker-internal
        │  = Claude Agent SDK loop + in-process runner tools │  egress → api.anthropic.com
        └────────────────────────────────────────────────────┘
                          │ target assets (in / adjacent to the VPC)
```

## Prerequisites
- Build and push both image targets from the repo `Dockerfile`:
  ```sh
  IMG=REGION-docker.pkg.dev/PROJECT/spellbook/app
  docker build -t "$IMG:TAG" .                       # control plane (default target)
  docker build --target worker -t "$IMG-worker:TAG" .  # worker (Node + Claude Code CLI)
  docker push "$IMG:TAG" && docker push "$IMG-worker:TAG"
  ```
- A Postgres reachable from the control plane (e.g. Cloud SQL) → `database_url`.

## Apply
```sh
terraform init
terraform apply \
  -var project_id=PROJECT \
  -var image="$IMG:TAG" \
  -var worker_image="$IMG-worker:TAG" \
  -var database_url='postgresql+psycopg://user:pass@HOST:5432/spellbook' \
  -var scope_external='example.com,shop.example.com' \
  -var scope_internal='10.4.0.0/16'
```

## Seed the secrets (kept out of Terraform state)
```sh
printf '%s' "$ANTHROPIC_API_KEY" | gcloud secrets versions add spellbook-anthropic-api-key --data-file=-
openssl rand -hex 32           | gcloud secrets versions add spellbook-worker-token       --data-file=-
```
The control plane and workers read the **same** `spellbook-worker-token` — it gates
the `/internal` claim/result API.

## Notes
- Workers use `min_instance_count = 1` so the pull loop keeps claiming work; they
  have `INGRESS_TRAFFIC_INTERNAL_ONLY` (nothing calls *into* them).
- `PRIVATE_RANGES_ONLY` egress routes VPC-internal traffic (targets + the control
  plane's internal URL) through the connector while letting `api.anthropic.com` go
  direct.
- The control plane defaults to internal-load-balancer ingress. Front the UI with an
  external HTTPS LB + IAP, or set `-var control_ingress=INGRESS_TRAFFIC_ALL` for a
  public UI — the `/internal` API stays bearer-gated regardless.
- **Follow-ups:** per-run scoped tokens / dynamically-provisioned workers, and
  mTLS/IAM-only service-to-service auth on `/internal` (see the plan's out-of-scope list).
```
