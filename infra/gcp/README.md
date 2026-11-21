# Deploy Eisoptric to Google Cloud

Each Eisoptric app is a separate GitHub repo. Push `main` to deploy that service to Cloud Run.

- Backend: Cloud Run (API `gateway-backend`, internal webhook worker `gateway-worker`) + Cloud SQL + Memorystore Redis
- Frontend: Cloud Run
- Ops (operator console, repo `MCP-gateway-ops`): Cloud Run

GitHub authenticates with Workload Identity Federation. No JSON key is stored in the repo.

Every hardening option below is opt-in through a GitHub variable. When a variable is unset, the
workflow behaves as it did before the variable existed. The [runbooks](#runbooks) list the manual
GCP / GitHub step each option needs, in the order to apply them.

## One-time Google Cloud setup (new project)

This is the setup for a new project.

### Workload Identity Federation

Only workflows running on `main` of a repo in your org can get a Google token. Pull requests and
other branches never can, even if a workflow asks for `id-token: write`.

```bash
PROJECT_ID=your-gcp-project
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
GITHUB_ORG=YOUR_GITHUB_ORG
POOL=github
PROVIDER=gateway

gcloud iam workload-identity-pools create "$POOL" \
  --location global \
  --display-name "GitHub"

gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
  --location global \
  --workload-identity-pool "$POOL" \
  --display-name "GitHub OIDC" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.owner=assertion.repository_owner,attribute.ref=assertion.ref" \
  --attribute-condition "assertion.repository_owner == '${GITHUB_ORG}' && assertion.ref == 'refs/heads/main'"
```

Jobs that use `environment: production` still carry `ref: refs/heads/main` in their token, so this
condition holds for the deploy and provision jobs.

Provider resource name to put in the `GCP_WORKLOAD_IDENTITY_PROVIDER` secret:

```
projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/gateway
```

### Identities

Use one identity per job, each bound to one repo only:

| Identity | Used by | Roles |
|---|---|---|
| `github-deployer-backend` | backend `deploy-cloud-run.yml` | `roles/run.developer` (project), `roles/run.admin` on the `gateway-backend` and `gateway-worker` services (lets the deploy set their invoker policy), `roles/vpcaccess.user` (project), `roles/artifactregistry.writer` on the `gateway` repository, `roles/iam.serviceAccountUser` on `gateway-runtime` only |
| `github-provisioner` | backend `provision-gcp.yml` | `roles/cloudsql.admin`, `roles/redis.admin`, `roles/compute.networkAdmin`, `roles/vpcaccess.admin`, `roles/artifactregistry.admin`, `roles/serviceusage.serviceUsageAdmin` |
| `gateway-runtime` | the API, the worker and the migration job at runtime | see [Runtime service account](#runtime-service-account) |
| one deployer per other repo | `gateway-frontend`, `gateway-ops` (repo `MCP-gateway-ops`), `acme-demo` (repo `demosystem`) | `roles/run.developer` plus `roles/run.admin` on its own service, `roles/artifactregistry.writer` on its registry, `roles/iam.serviceAccountUser` on its own runtime SA |

No identity holds `roles/iam.serviceAccountUser` on the whole project. That role on the project
lets the holder deploy a service that runs as *any* service account. The frontend repos cannot
redeploy the backend.

```bash
REGION=asia-east1
GAR_LOCATION=asia-east1
DEPLOYER=github-deployer-backend@${PROJECT_ID}.iam.gserviceaccount.com
PROVISIONER=github-provisioner@${PROJECT_ID}.iam.gserviceaccount.com
REPO_PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/attribute.repository/${GITHUB_ORG}/MCP-gateway-backend"

gcloud iam service-accounts create github-deployer-backend --display-name "GitHub deployer (backend)"
gcloud iam service-accounts create github-provisioner --display-name "GitHub provisioner (backend)"

for SA in "$DEPLOYER" "$PROVISIONER"; do
  gcloud iam service-accounts add-iam-policy-binding "$SA" \
    --role roles/iam.workloadIdentityUser \
    --member "$REPO_PRINCIPAL"
done

for ROLE in roles/run.developer roles/vpcaccess.user; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${DEPLOYER}" --role "$ROLE"
done

for ROLE in roles/cloudsql.admin roles/redis.admin roles/compute.networkAdmin \
  roles/vpcaccess.admin roles/artifactregistry.admin roles/serviceusage.serviceUsageAdmin; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${PROVISIONER}" --role "$ROLE"
done
```

Set the backend repo secrets: `GCP_SERVICE_ACCOUNT_EMAIL=$DEPLOYER` and
`GCP_PROVISION_SERVICE_ACCOUNT_EMAIL=$PROVISIONER`. Then run **Provision Google Cloud Resources**.
Then grant the resource-level roles, which need the resources to exist first:

```bash
gcloud artifacts repositories add-iam-policy-binding gateway \
  --location "$GAR_LOCATION" --member "serviceAccount:${DEPLOYER}" --role roles/artifactregistry.writer
```

Create the runtime service account ([below](#runtime-service-account)) with
`DEPLOYER_SA=$DEPLOYER`, and set `RUNTIME_SERVICE_ACCOUNT`. After the first deploy has created the
service, run:

```bash
gcloud run services add-iam-policy-binding gateway-backend \
  --region "$REGION" --member "serviceAccount:${DEPLOYER}" --role roles/run.admin
```

The first deploy of a new project needs `roles/run.admin` on the project for one run, because the
service does not exist yet. Grant it, deploy once, then remove it.

### GitHub environment and branch protection

The deploy and provision jobs run in the `production` environment. GitHub creates the environment
on first use, with no rules. Add the rules under **Settings → Environments → production**:

- **Required reviewers**: at least one person other than the author.
- **Deployment branches and tags**: *Selected branches and tags*, rule `main`.

Under **Settings → Branches** (or Rulesets), protect `main`:

- Require a pull request before merging, with at least one approval.
- Require the `Test / test` status check.
- Block force pushes and deletion. Do not let administrators bypass the rules.

The deploy job also refuses to run from any ref but `refs/heads/main`, so a manual **Run workflow**
from another branch fails before it authenticates.

## Provision data plane

In the backend GitHub repo, set the variables below, then run **Actions → Provision Google Cloud Resources**.

| Variable | Example |
|---|---|
| `GCP_PROJECT_ID` | `gateway-prod` |
| `GCP_REGION` | `asia-east1` |
| `GAR_LOCATION` | `asia-east1` |
| `GAR_REPOSITORY` | `gateway` |
| `CLOUD_SQL_INSTANCE` | `gateway-pg` |
| `CLOUD_SQL_DATABASE` | `gateway` |
| `CLOUD_SQL_USER` | `gateway` |
| `CLOUD_SQL_TIER` | `db-g1-small` (Enterprise edition) |
| `CLOUD_SQL_AVAILABILITY_TYPE` | `zonal` (default) or `regional` |
| `CLOUD_SQL_BACKUP_START_TIME` | `18:00` (UTC, default) |
| `REDIS_INSTANCE` | `gateway-redis` |
| `REDIS_TIER` | `BASIC` |
| `REDIS_SIZE_GB` | `1` |
| `VPC_NETWORK` | `default` |
| `SERVERLESS_VPC_CONNECTOR` | `gateway-vpc` |
| `SERVERLESS_VPC_CONNECTOR_RANGE` | `10.8.0.0/28` |
| `SETUP_RUNTIME_SERVICE_ACCOUNT` | unset; `true` only if the provision identity may grant IAM |

Secret: `CLOUD_SQL_PASSWORD`.

`bootstrap.sh` only creates what is missing; it never modifies an existing instance. On an existing
instance it prints a warning for each hardening setting that is off. New resources are created
hardened:

- **Cloud SQL**: requires TLS (`--ssl-mode ENCRYPTED_ONLY`; Cloud Run's Cloud SQL connection already
  uses TLS), deletion protection, daily backups kept 14 days, point-in-time recovery with 7 days of
  logs, private IP only. The database user is created through the Cloud SQL Admin API. The password
  goes in a request body on stdin, never in a command-line argument.
- **Redis**: AUTH and in-transit encryption (TLS on port 6378, server authentication).

The job prints the Cloud SQL connection name and the Redis host and port. Then create the secrets:

```
DATABASE_URL=postgresql+asyncpg://gateway:PASSWORD@/gateway?host=/cloudsql/PROJECT:REGION:INSTANCE
CLOUD_SQL_INSTANCE_CONNECTION_NAME=PROJECT:REGION:INSTANCE   # GitHub variable
```

For a new (TLS) Redis, store `REDIS_URL` as
`rediss://:AUTH_STRING@HOST:6378/0?ssl_cert_reqs=required&ssl_ca_certs=/etc/secrets/redis-ca/ca.pem`
(the AUTH string from `gcloud redis instances get-auth-string`) and `REDIS_CA` as the instance's
`serverCaCerts`, and set the `REDIS_CA_SECRET` variable. An instance without TLS uses `REDIS_URL=redis://REDIS_HOST:6379/0`.

## GitHub variables and secrets

Shared by all three repos:

| Name | Type | Used by |
|---|---|---|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | secret | all |
| `GCP_SERVICE_ACCOUNT_EMAIL` | secret | all (each repo its own deployer) |
| `GCP_PROJECT_ID` | variable | all |
| `GCP_REGION` | variable | all |
| `GAR_LOCATION` | variable | all |
| `GAR_REPOSITORY` | variable | all (default `gateway`) |
| `RUNTIME_SERVICE_ACCOUNT` | variable | all (unset: each service keeps its current identity) |
| `MAX_INSTANCES` | variable | all (default `10`) |

Backend only:

| Name | Type | Default when unset |
|---|---|---|
| `BACKEND_CLOUD_RUN_SERVICE` | variable, e.g. `gateway-backend` | `gateway-backend` |
| `CLOUD_SQL_INSTANCE_CONNECTION_NAME` | variable | required |
| `SERVERLESS_VPC_CONNECTOR` | variable | required |
| `GATEWAY_KMS_KEY` | variable, full `cryptoKeyVersions/N` name of the MAC key (a resource name, not key material; read by deploy and provisioning) | required |
| `CLOUD_SQL_PASSWORD` | secret, read only by provisioning; `rotate-db-password.sh` keeps it current | required to provision |
| `GCP_PROVISION_SERVICE_ACCOUNT_EMAIL` | secret | provisioning uses `GCP_SERVICE_ACCOUNT_EMAIL` |
| `MIGRATIONS_JOB` | variable, `true` to run migrations in a Cloud Run Job | each container migrates on start |
| `MIGRATIONS_JOB_NAME` | variable | `gateway-migrate` |
| `MIGRATIONS_DATABASE_URL_SECRET` | variable, secret name holding a schema-owner DSN | `DATABASE_URL` |
| `MIGRATIONS_SERVICE_ACCOUNT` | variable | `RUNTIME_SERVICE_ACCOUNT` |
| `SEED_ON_DEPLOY` | variable, `true` to mount `SEED_USER_EMAIL` on the API | not mounted |
| `REDIS_URL_SECRET` | variable, secret name holding `REDIS_URL` | `REDIS_URL` |
| `REDIS_CA_SECRET` | variable, secret name holding the Memorystore server CA (PEM) | no CA mounted |
| `LEGACY_PASSWORD_UNTIL` | variable, `YYYY-MM-DD` | legacy (pre-argon2) passwords refused; set it only while accounts from before 2026-10-16 remain |
| `IMAGE_ATTESTATIONS` | variable, `true` for provenance and SBOM | no attestations |
| `CONSOLE_PROXY_SECRET_NAME` | variable, secret name shared with the console (set the same variable on Frontend) | console users share the per-address login limits |
| `DEFAULT_ORG_ID`, `DEFAULT_ACTOR_ID` | variable | `org_default`, `user_operator` |
| `SESSION_TTL_DAYS` | variable | `7` |
| Provisioning: `CLOUD_SQL_*`, `REDIS_INSTANCE`, `REDIS_TIER`, `REDIS_SIZE_GB`, `VPC_NETWORK`, `SERVERLESS_VPC_CONNECTOR_RANGE`, `SETUP_RUNTIME_SERVICE_ACCOUNT` | variable | see [Provision data plane](#provision-data-plane) |

The public origins are fixed in the workflows, not read from GitHub: the backend sets
`PUBLIC_WS_URL=https://api.eisoptric.com` and `CORS_ORIGINS=https://console.eisoptric.com`, and the
frontend builds with `API_URL=https://api.eisoptric.com`. Change them in the workflow files.

Runtime secrets live in **Secret Manager**, not GitHub. Cloud Run mounts them directly (see the
table below), so the deploy job never reads their values:

| Secret Manager secret | Required |
|---|---|
| `DATABASE_URL`, `REDIS_URL` | yes |
| `ORIGIN_AUTH_SECRET` | yes on Cloud Run |
| `GATEWAY_GITHUB_OAUTH_CLIENT_ID` / `_SECRET`, `GATEWAY_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` | for social sign-in |
| `RESEND_API_KEY`, `RESEND_FROM` | for email |
| `POLICY_LLM_BASE_URL`, `POLICY_LLM_API_KEY`, `POLICY_LLM_MODEL` | for policy drafting: an OpenAI-compatible `/chat/completions` endpoint, its key and the model name; drafting is off without them |
| `SEED_USER_EMAIL` | only read when `SEED_ON_DEPLOY=true` |

GitHub repository secrets with those names are left over from before the move to Secret Manager.
Nothing reads them; delete them. The same goes for `GATEWAY_KEM_SEED`, which the app stopped reading
when tenant keys moved to Cloud KMS. Delete `GATEWAY_KEM_SEED` only after every stored value has been
re-sealed under the KMS key.

Frontend / Ops:

| Name | Type |
|---|---|
| `FRONTEND_CLOUD_RUN_SERVICE` | variable, e.g. `gateway-frontend` |
| `OPS_CLOUD_RUN_SERVICE` | variable, e.g. `gateway-ops` |

The public API origin is `https://api.eisoptric.com`. The frontend bakes it into the `/gateway-api`
HTTP rewrite, and the backend sets `PUBLIC_WS_URL` to it so MCP OAuth callbacks use
`${PUBLIC_WS_URL}/mcp-servers/oauth/callback`. A `BACKEND_PUBLIC_URL` variable is no longer read.

### Secrets per service

`--set-secrets` replaces the whole set on every deploy, so a secret left out of the list is
unmounted.

| Secret | API | Worker | Migration job |
|---|---|---|---|
| `DATABASE_URL` | yes | yes | yes (or `MIGRATIONS_DATABASE_URL_SECRET`) |
| `REDIS_URL` (or `REDIS_URL_SECRET`), `REDIS_CA_SECRET` | yes | yes | no |
| `RESEND_API_KEY`, `RESEND_FROM` | yes | yes (approval expiry sends the task-outcome email) | no |
| `GATEWAY_GITHUB_OAUTH_*`, `GATEWAY_GOOGLE_OAUTH_*` | yes | no | no |
| `POLICY_LLM_API_KEY` | yes | no | no |
| `ORIGIN_AUTH_SECRET` | yes | no (internal ingress; fails closed) | no |
| `CONSOLE_PROXY_SECRET_NAME` (when set) | yes | no | no |
| `SEED_USER_EMAIL` | only with `SEED_ON_DEPLOY=true` | no | no |

## Deploy

Frontend and backend go to Cloud Run only through GitHub Actions. Do not deploy them with a local `docker push` or `gcloud run` unless that path is explicitly requested.

1. Run **Provision Google Cloud Resources** once from the backend repo.
2. Push `main` on backend. Actions tests the commit, waits for the `production` environment's reviewers, builds `linux/amd64` and deploys that image digest. If `MIGRATIONS_JOB=true`, it runs `alembic upgrade head` once in the migration job before deploying either service. Environment variables come from this repo's GitHub variables and the workflow, secrets from Secret Manager, and that file replaces the Cloud Run environment.
3. Push `main` on frontend, then dashboard. Deploy backend before frontend, because the frontend calls the new API as soon as it starts.

Each deploy workflow also has **Run workflow** for a manual release. It deploys only when run on `main`.

The container runs as uid 10001. uvicorn no longer gets `--proxy-headers --forwarded-allow-ips='*'`,
so it trusts `X-Forwarded-*` only from 127.0.0.1. Behind Cloud Run, `request.client` is the Google
front end and `request.url.scheme` is `http`. Code that needs the public origin or scheme must use
`PUBLIC_WS_URL` (`app/core/public_origin.py`), not `request.base_url`.

## Runbooks

Apply them in this order. Each step is safe on its own, and nothing changes until its variable is
set.

### Runtime service account

Without `RUNTIME_SERVICE_ACCOUNT`, both services run as the project's default compute service
account. In most projects that account holds `roles/editor`, so any SSRF or RCE in the app can read
every secret and use every KMS key through the metadata server.

`runtime-service-account.sh` creates `gateway-runtime` with:

- `roles/secretmanager.secretAccessor` on each runtime secret by name, not project-wide
- `roles/cloudkms.signerVerifier` on the one key named by `GATEWAY_KMS_KEY`, the MAC key the app derives tenant keys with (`pq_crypto.py`)
- `roles/cloudsql.client`, `roles/logging.logWriter`, `roles/monitoring.metricWriter`

Redis needs no IAM: access is by network plus AUTH.

1. As a project IAM admin:

   ```bash
   GCP_PROJECT_ID=gateway-prod \
   GATEWAY_KMS_KEY=projects/gateway-prod/locations/asia-east1/keyRings/gateway/cryptoKeys/kem-root/cryptoKeyVersions/1 \
   DEPLOYER_SA=github-deployer-backend@gateway-prod.iam.gserviceaccount.com \
   bash infra/gcp/runtime-service-account.sh   # from the Backend repo root
   ```

   Add `RUNTIME_SECRETS="... REDIS_URL_TLS REDIS_CA"` (the defaults plus any extra names) when you
   use `REDIS_URL_SECRET` / `REDIS_CA_SECRET` or `MIGRATIONS_DATABASE_URL_SECRET`. Add
   `SEED_USER_EMAIL` only while `SEED_ON_DEPLOY=true`.
2. Set the GitHub variable `RUNTIME_SERVICE_ACCOUNT` to the printed email and deploy. The migration
   job uses the same account unless `MIGRATIONS_SERVICE_ACCOUNT` is set.
3. Check both services serve and the worker delivers webhooks, then remove project-wide access from
   the default compute account if nothing else uses it (for example `roles/editor`).

Cloud Run keeps the last service account it was given. Unsetting the variable later does not switch
back; deploy once with `--service-account` set to the old account to revert.

If `GATEWAY_SECRET_PROJECT` is ever turned on, the app also creates and deletes `sat-org-*` secrets.
Grant `roles/secretmanager.admin` with an IAM condition
`resource.name.startsWith("projects/PROJECT_NUMBER/secrets/sat-")` in that project. Do not grant it
project-wide.

### Migrations in a Cloud Run Job

Without the job, every container start runs `alembic upgrade head` with the app's DB user.
`alembic/env.py` now serialises concurrent runners with a Postgres advisory lock. Other backends are
no longer terminated: a DDL statement that waits more than 60 s on a lock held by live traffic fails
the migration, and it can be retried.

1. Make sure the deployer can create and run jobs (`roles/run.developer`, which `run.admin` also
   covers) and can act as the job's service account. The job's account needs `secretAccessor` on
   `DATABASE_URL` (or `MIGRATIONS_DATABASE_URL_SECRET`) and `roles/cloudsql.client`. The runtime
   service account already has both.
2. Set `MIGRATIONS_JOB=true` and deploy. The workflow deploys and executes
   `gateway-migrate` (`alembic upgrade head`, one task, no retries, 15 min timeout) and waits for it.
   It then deploys both services with `RUN_MIGRATIONS=false`. A failed migration stops the release
   before any service changes.
3. Optional, least-privilege database: create a schema-owner role for migrations and a DML-only role
   for the app. Put the owner DSN in a secret, set `MIGRATIONS_DATABASE_URL_SECRET` to its name, and
   point `DATABASE_URL` at the DML-only role.
4. Optional: `ALTER ROLE gateway SET idle_in_transaction_session_timeout = '60s';`. This bounds the
   stuck transactions that `env.py` used to terminate.

### Harden an existing Cloud SQL instance

`bootstrap.sh` warns but never changes an existing instance. In a maintenance window:

```bash
INSTANCE=gateway-pg
gcloud sql instances patch "$INSTANCE" --deletion-protection
gcloud sql instances patch "$INSTANCE" --backup-start-time 18:00 --retained-backups-count 14 \
  --enable-point-in-time-recovery --retained-transaction-log-days 7
# Cloud Run's Cloud SQL connection already uses TLS. Check first that no other client
# (a VM, or psql over private IP) connects without TLS.
gcloud sql instances patch "$INSTANCE" --ssl-mode ENCRYPTED_ONLY
```

For high availability, also run `--availability-type regional` (this roughly doubles the cost).

Earlier versions of `bootstrap.sh` passed `CLOUD_SQL_PASSWORD` as a command-line argument on the CI
runner. `rotate-db-password.sh` rotates it end to end: the password set through the Admin API, a new
`DATABASE_URL` version, the API and worker rolled onto that version, and the GitHub secret. If
it cannot write the secret after changing the password, it puts the old password back. By
hand, use
`gcloud sql users set-password gateway --instance gateway-pg --prompt-for-password` at an interactive
terminal. Then update the `DATABASE_URL` secret and redeploy.

### Ingress: Cloudflare on the free plan

Cloudflare (free plan) proxies `api.eisoptric.com` and `console.eisoptric.com` straight to the
services' public Cloud Run addresses, so both deploy with ingress `all`. There is no Google load
balancer or Cloud Armor policy in front of them: on the free plan they would cost more than the rest
of the deployment, and Cloudflare's own WAF, bot and rate rules apply only to traffic it proxies.

What keeps a request that bypasses Cloudflare out is `ORIGIN_AUTH_SECRET`. A Cloudflare Transform
Rule (Rules → Transform Rules → Modify Request Header, available on the free plan) sets
`X-Eisoptric-Origin-Auth` to its value on every request, and the API and the console refuse any
request without it, except `/health`. The app trusts `CF-Connecting-IP` for rate limits only on a
request that carries the secret, so a direct caller cannot choose the address it is limited by.

Rotate the secret on any suspected leak, and at least yearly. The app accepts the previous value
alongside the new one while `ORIGIN_AUTH_SECRET_PREVIOUS` is mounted, so nothing is refused during
the switch:

1. Copy the current value into its own secret:
   `gcloud secrets versions access latest --secret ORIGIN_AUTH_SECRET | gcloud secrets create ORIGIN_AUTH_SECRET_PREVIOUS --data-file -`
   (use `versions add` if that secret already exists), and grant the runtime service account
   `roles/secretmanager.secretAccessor` on it.
2. `openssl rand -hex 32 | gcloud secrets versions add ORIGIN_AUTH_SECRET --data-file -`
3. Set the repository variable `ORIGIN_AUTH_SECRET_PREVIOUS_NAME=ORIGIN_AUTH_SECRET_PREVIOUS`
   and deploy the backend. It now accepts both values.
4. Update the Cloudflare Transform Rule that sets `X-Eisoptric-Origin-Auth` to the new value, and
   deploy the console so it reads the new version too.
5. Remove the repository variable and deploy again, so the old value stops working.

### Uptime checks from Cloud Monitoring

The outside check of production is a Cloud Monitoring uptime check, not a GitHub workflow. On the
Cloudflare free plan, Bot Fight Mode challenges GitHub-hosted runners with a 403, and no rule can
exempt a request from it. Requests from Google Cloud pass: the worker checks the API through its
public address every minute, and those checks succeed.

`uptime-checks.sh` creates, for each of `api.eisoptric.com` and `console.eisoptric.com`:

- an uptime check on `https://<host>/health` every 5 minutes from three regions, which passes only
  on a 200 with a valid certificate, and
- an alert policy that emails `ALERT_EMAIL` when two regions or more fail.

```bash
GCP_PROJECT_ID=... ALERT_EMAIL=you@example.com bash infra/gcp/uptime-checks.sh
```

Run it as someone who can edit Monitoring (`roles/monitoring.editor`) and enable services. It is
safe to re-run: what exists is reused. To change a check or policy, delete it in the console and
run the script again.

After the first run, open Monitoring > Uptime checks and confirm both checks pass. If they fail
with 403, Bot Fight Mode is challenging Google's probes too, and the only remedy left on the free
plan is to turn Bot Fight Mode off. Three regions every 5 minutes is about 26,000 runs a month per
check, which should be inside Cloud Monitoring's free allotment; check the current pricing.

### Per-browser rate limits through the console

Console requests reach the API from the console's own address, so `CF-Connecting-IP` names the
console and every console user would share one login, sign-up and invite bucket. The console sends
each browser's address in `X-Eisoptric-Client-IP` with a secret only it and the API hold, and the API
trusts that address only when the secret matches.

1. `openssl rand -hex 32 | gcloud secrets create CONSOLE_PROXY_SECRET --data-file -`
2. Grant both runtime service accounts `roles/secretmanager.secretAccessor` on it.
3. Set the repository variable `CONSOLE_PROXY_SECRET_NAME=CONSOLE_PROXY_SECRET` on both Backend and
   Frontend, deploy the backend, then the frontend.

To rotate, store the old value in its own secret and set the repository variable
`CONSOLE_PROXY_SECRET_PREVIOUS_NAME` to that secret's name on the Backend while both services move
to the new version. Remove the variable and deploy again afterwards.

### Seeding the first admin

No admin password is configured anywhere. `SEED_USER_EMAIL` is mounted on the API only when
`SEED_ON_DEPLOY=true`. While the platform has no platform admin, an email sign-up at that address
becomes one: the emailed code proves the address, and the promotion is written to the audit log
as `platform_admin_bootstrapped`. Once any platform admin exists, nothing is promoted again, so a
demotion sticks.

For a new project, set `SEED_ON_DEPLOY=true` for the first deploy and sign up at that address.
Then unset it, deploy again, and disable the secret's versions (`gcloud secrets versions list
SEED_USER_EMAIL`, then `gcloud secrets versions disable VERSION --secret SEED_USER_EMAIL`).
An existing project already has its admin and needs nothing.

### Legacy passwords

Legacy (pre-argon2) passwords are refused unless `LEGACY_PASSWORD_UNTIL=YYYY-MM-DD` is set; they are
then accepted until that day. While it is in the future every failed sign-in also sends the legacy
proofs, the raw password included, so set it only while accounts from before 2026-10-16 remain.
Users who have not signed in by then must reset their password. The deploy fails if the value
is not a valid ISO date.

### Image provenance and SBOM

With `IMAGE_ATTESTATIONS=true`, the build uses a BuildKit container builder and attaches SLSA
provenance (`mode=max`) and an SBOM. Artifact Registry stores both. The pushed image then becomes an
OCI index (the amd64 image plus attestation manifests), and the workflow deploys that index digest.
Check on a staging project that `gcloud run deploy` accepts it before you set the variable in
production. To roll back, unset the variable.
