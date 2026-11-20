#!/usr/bin/env bash
# "Move to a new project" in infra/gcp/README.md: builds the whole deployment in a new Google Cloud
# project and carries over the settings and secrets that still hold, from the old project, which it
# only reads. The data starts fresh: the database and Redis are new and empty.
#
#   bash infra/gcp/move-project.sh setup               create everything up to the first deploy
#   bash infra/gcp/move-project.sh after-first-deploy  narrow the deployers once the services exist
#
# Run on your own computer, signed in with `gcloud auth login` as someone who can create projects,
# link billing and grant IAM. With GITHUB_SETUP=true and the `gh` command signed in, it also sets the
# repositories' variables and secrets; otherwise it prints the commands. Safe to re-run.
set -euo pipefail

STEP="${1:-setup}"
: "${NEW_PROJECT_ID:?NEW_PROJECT_ID is required, for example eisoptric-prod}"
GCP_PROJECT_ID="${NEW_PROJECT_ID}"
# GitHub sends the owner as the organization spells it, and the provider's condition compares it
# exactly, so this must match the casing of github.com/Eisoptric.
GITHUB_ORG="${GITHUB_ORG:-Eisoptric}"
BACKEND_REPO="${BACKEND_REPO:-MCP-gateway-backend}"
FRONTEND_REPO="${FRONTEND_REPO:-MCP-gateway-frontend}"
# The operator console (ops.eisoptric.com). Its identities keep their dashboard names.
DASHBOARD_REPO="${DASHBOARD_REPO:-MCP-gateway-ops}"
REGION="${GCP_REGION:-asia-east1}"
GAR_LOCATION="${GAR_LOCATION:-${REGION}}"
GAR_REPOSITORY="${GAR_REPOSITORY:-gateway}"
POOL="${WIF_POOL:-github}"
PROVIDER="${WIF_PROVIDER:-gateway}"
KMS_KEYRING="${KMS_KEYRING:-gateway}"
KMS_KEY_NAME="${KMS_KEY_NAME:-kem-root}"
GITHUB_SETUP="${GITHUB_SETUP:-false}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

email() { echo "$1@${GCP_PROJECT_ID}.iam.gserviceaccount.com"; }
say() { printf '\n== %s\n' "$*"; }

# bootstrap.sh points gcloud's default project at the new one; put the user's own default back.
previous_project="$(gcloud config get-value project 2>/dev/null || true)"
restore_project() {
  if [[ -n "${previous_project}" ]]; then
    gcloud config set project "${previous_project}" >/dev/null 2>&1 || true
  else
    gcloud config unset project >/dev/null 2>&1 || true
  fi
}
trap restore_project EXIT

# A new account or binding takes a few seconds to be visible to IAM.
retry() {
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if "$@" >/dev/null; then
      return 0
    fi
    echo "Retrying in $((attempt * 5))s: $*" >&2
    sleep $((attempt * 5))
  done
  "$@" >/dev/null
}

secret_exists() { gcloud secrets describe "$1" --project "$2" >/dev/null 2>&1; }

# Stores stdin as the newest version of a secret in the new project. The value never reaches the
# terminal or a command line.
put_secret() {
  if secret_exists "$1" "${GCP_PROJECT_ID}"; then
    gcloud secrets versions add "$1" --project "${GCP_PROJECT_ID}" --data-file - >/dev/null
  else
    gcloud secrets create "$1" --project "${GCP_PROJECT_ID}" --replication-policy automatic --data-file - >/dev/null
  fi
}

# Copies the latest version of OLD_PROJECT_ID's secret $1 to the new project as $2, once.
copy_secret() {
  if secret_exists "$2" "${GCP_PROJECT_ID}"; then
    echo "  $2 already exists, kept"
  elif secret_exists "$1" "${OLD_PROJECT_ID}"; then
    gcloud secrets versions access latest --secret "$1" --project "${OLD_PROJECT_ID}" | put_secret "$2"
    echo "  $1 -> $2"
  else
    echo "  $1 is not in ${OLD_PROJECT_ID}; skipped" >&2
  fi
}

# Creates a random secret once, so a re-run never changes a value already in use.
random_secret() {
  if secret_exists "$1" "${GCP_PROJECT_ID}"; then
    echo "  $1 already exists, kept"
  else
    openssl rand -hex 32 | tr -d '\n' | put_secret "$1"
    echo "  $1 created"
  fi
}

# Sets a repository variable or secret with gh, or prints the command when GITHUB_SETUP is off.
github_variable() {
  if [[ "${GITHUB_SETUP}" == "true" ]]; then
    gh variable set "$2" -R "${GITHUB_ORG}/$1" --body "$3"
  else
    echo "gh variable set $2 -R ${GITHUB_ORG}/$1 --body '$3'"
  fi
}
github_secret() {
  if [[ "${GITHUB_SETUP}" == "true" ]]; then
    gh secret set "$2" -R "${GITHUB_ORG}/$1" --body "$3"
  else
    echo "gh secret set $2 -R ${GITHUB_ORG}/$1 --body '$3'"
  fi
}

project_role() {
  retry gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
    --member "serviceAccount:$(email "$1")" --role "$2" --condition None
}

ensure_sa() {
  if ! gcloud iam service-accounts describe "$(email "$1")" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
    # A project may create only a few service accounts a minute, so wait out the quota and try again.
    local attempt
    for attempt in 1 2 3 4; do
      if gcloud iam service-accounts create "$1" --project "${GCP_PROJECT_ID}" --display-name "$2" >/dev/null; then
        return 0
      fi
      echo "Retrying in 65s: service account $1" >&2
      sleep 65
    done
    gcloud iam service-accounts create "$1" --project "${GCP_PROJECT_ID}" --display-name "$2" >/dev/null
  fi
}

# Lets one repository's main-branch workflows act as this account, and nothing else.
bind_repo() {
  local number
  number="$(gcloud projects describe "${GCP_PROJECT_ID}" --format='value(projectNumber)')"
  retry gcloud iam service-accounts add-iam-policy-binding "$(email "$1")" --project "${GCP_PROJECT_ID}" \
    --role roles/iam.workloadIdentityUser \
    --member "principalSet://iam.googleapis.com/projects/${number}/locations/global/workloadIdentityPools/${POOL}/attribute.repository/${GITHUB_ORG}/$2"
}

# The deployer may deploy a service that runs as this one account only.
act_as() {
  retry gcloud iam service-accounts add-iam-policy-binding "$(email "$2")" --project "${GCP_PROJECT_ID}" \
    --role roles/iam.serviceAccountUser --member "serviceAccount:$(email "$1")"
}

registry_writer() {
  retry gcloud artifacts repositories add-iam-policy-binding "${GAR_REPOSITORY}" \
    --project "${GCP_PROJECT_ID}" --location "${GAR_LOCATION}" \
    --member "serviceAccount:$(email "$1")" --role roles/artifactregistry.writer
}

secret_reader() {
  retry gcloud secrets add-iam-policy-binding "$2" --project "${GCP_PROJECT_ID}" \
    --member "serviceAccount:$(email "$1")" --role roles/secretmanager.secretAccessor
}

setup() {
  : "${OLD_PROJECT_ID:?OLD_PROJECT_ID is required: the Saturn project to read secrets from}"
  : "${BILLING_ACCOUNT:?BILLING_ACCOUNT is required: see gcloud billing accounts list}"
  : "${SEED_USER_EMAIL:?SEED_USER_EMAIL is required: the first admin of the new, empty database}"

  say "Project ${GCP_PROJECT_ID}"
  if ! gcloud projects describe "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
    # PROJECT_PARENT: organizations/ID or folders/ID; unset for a project with no organization.
    parent=()
    case "${PROJECT_PARENT:-}" in
      organizations/*) parent=(--organization "${PROJECT_PARENT#organizations/}") ;;
      folders/*) parent=(--folder "${PROJECT_PARENT#folders/}") ;;
      "") ;;
      *) echo "PROJECT_PARENT must be organizations/ID or folders/ID" >&2; exit 1 ;;
    esac
    gcloud projects create "${GCP_PROJECT_ID}" --name "Eisoptric" ${parent[@]+"${parent[@]}"}
  fi
  # Linking again counts against the billing account's project quota even when nothing changes.
  if [[ "$(gcloud billing projects describe "${GCP_PROJECT_ID}" --format='value(billingAccountName)')" != "billingAccounts/${BILLING_ACCOUNT}" ]]; then
    gcloud billing projects link "${GCP_PROJECT_ID}" --billing-account "${BILLING_ACCOUNT}" >/dev/null
  fi
  gcloud services enable --project "${GCP_PROJECT_ID}" \
    cloudresourcemanager.googleapis.com iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
    secretmanager.googleapis.com cloudkms.googleapis.com run.googleapis.com artifactregistry.googleapis.com \
    sqladmin.googleapis.com redis.googleapis.com vpcaccess.googleapis.com compute.googleapis.com \
    servicenetworking.googleapis.com logging.googleapis.com monitoring.googleapis.com

  say "Data plane (bootstrap.sh): Artifact Registry, VPC, Cloud SQL, Redis"
  # The database password is made here and goes only into DATABASE_URL and the GitHub secret.
  CLOUD_SQL_PASSWORD="$(openssl rand -hex 24)"
  if secret_exists DATABASE_URL "${GCP_PROJECT_ID}"; then
    # The user exists already; bootstrap.sh does not change it, so keep the password in use.
    CLOUD_SQL_PASSWORD="$(gcloud secrets versions access latest --secret DATABASE_URL --project "${GCP_PROJECT_ID}" |
      python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(urllib.parse.urlsplit(sys.stdin.read()).password or ""))')"
  fi
  export CLOUD_SQL_PASSWORD
  GCP_PROJECT_ID="${GCP_PROJECT_ID}" GCP_REGION="${REGION}" GAR_LOCATION="${GAR_LOCATION}" \
    GAR_REPOSITORY="${GAR_REPOSITORY}" CLOUD_SQL_INSTANCE=gateway-pg CLOUD_SQL_DATABASE=gateway \
    CLOUD_SQL_USER=gateway CLOUD_SQL_TIER="${CLOUD_SQL_TIER:-db-g1-small}" \
    CLOUD_SQL_AVAILABILITY_TYPE="${CLOUD_SQL_AVAILABILITY_TYPE:-zonal}" CLOUD_SQL_BACKUP_START_TIME=18:00 \
    REDIS_INSTANCE=gateway-redis REDIS_TIER=BASIC REDIS_SIZE_GB=1 VPC_NETWORK=default \
    VPC_CONNECTOR=gateway-vpc VPC_CONNECTOR_RANGE="${VPC_CONNECTOR_RANGE:-10.9.0.0/28}" SETUP_RUNTIME_SERVICE_ACCOUNT=false \
    bash "${HERE}/bootstrap.sh"
  connection="$(gcloud sql instances describe gateway-pg --project "${GCP_PROJECT_ID}" --format='value(connectionName)')"

  say "Secrets"
  if ! secret_exists DATABASE_URL "${GCP_PROJECT_ID}"; then
    python3 -c 'import os, sys, urllib.parse
password = urllib.parse.quote(os.environ["CLOUD_SQL_PASSWORD"], safe="")
sys.stdout.write(f"postgresql+asyncpg://gateway:{password}@/gateway?host=/cloudsql/{sys.argv[1]}")' "${connection}" |
      put_secret DATABASE_URL
    echo "  DATABASE_URL created"
  fi
  redis() { gcloud redis instances describe gateway-redis --region "${REGION}" --project "${GCP_PROJECT_ID}" "$@"; }
  if ! secret_exists REDIS_CA "${GCP_PROJECT_ID}"; then
    redis --format=json | python3 -c 'import json, sys; print("\n".join(c["cert"] for c in json.load(sys.stdin)["serverCaCerts"]))' |
      put_secret REDIS_CA
    echo "  REDIS_CA created"
  fi
  if ! secret_exists REDIS_URL "${GCP_PROJECT_ID}"; then
    host="$(redis --format='value(host)')"
    port="$(redis --format='value(port)')"
    gcloud redis instances get-auth-string gateway-redis --region "${REGION}" --project "${GCP_PROJECT_ID}" \
      --format='value(authString)' |
      python3 -c 'import sys; sys.stdout.write("rediss://:%s@%s:%s/0?ssl_cert_reqs=required&ssl_ca_certs=/etc/secrets/redis-ca/ca.pem" % (sys.stdin.read().strip(), sys.argv[1], sys.argv[2]))' "${host}" "${port}" |
      put_secret REDIS_URL
    echo "  REDIS_URL created"
  fi
  # The services read these under their GATEWAY_ names now; the old project kept them as SATURN_.
  copy_secret SATURN_GITHUB_OAUTH_CLIENT_ID GATEWAY_GITHUB_OAUTH_CLIENT_ID
  copy_secret SATURN_GITHUB_OAUTH_CLIENT_SECRET GATEWAY_GITHUB_OAUTH_CLIENT_SECRET
  copy_secret SATURN_GOOGLE_OAUTH_CLIENT_ID GATEWAY_GOOGLE_OAUTH_CLIENT_ID
  copy_secret SATURN_GOOGLE_OAUTH_CLIENT_SECRET GATEWAY_GOOGLE_OAUTH_CLIENT_SECRET
  for name in RESEND_API_KEY RESEND_FROM POLICY_LLM_BASE_URL POLICY_LLM_API_KEY POLICY_LLM_MODEL; do
    copy_secret "${name}" "${name}"
  done
  # New values, not copies: the move is the time to rotate them, and Cloudflare's rule changes anyway.
  random_secret ORIGIN_AUTH_SECRET
  random_secret CONSOLE_PROXY_SECRET
  if ! secret_exists SEED_USER_EMAIL "${GCP_PROJECT_ID}"; then
    printf '%s' "${SEED_USER_EMAIL}" | put_secret SEED_USER_EMAIL
  fi
  if ! secret_exists SEED_USER_PASSWORD "${GCP_PROJECT_ID}"; then
    read -r -s -p "Password for the first admin (${SEED_USER_EMAIL}): " seed_password
    echo
    printf '%s' "${seed_password}" | put_secret SEED_USER_PASSWORD
    unset seed_password
  fi

  say "Cloud KMS MAC key"
  gcloud kms keyrings describe "${KMS_KEYRING}" --location "${REGION}" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1 ||
    gcloud kms keyrings create "${KMS_KEYRING}" --location "${REGION}" --project "${GCP_PROJECT_ID}"
  gcloud kms keys describe "${KMS_KEY_NAME}" --keyring "${KMS_KEYRING}" --location "${REGION}" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1 ||
    gcloud kms keys create "${KMS_KEY_NAME}" --keyring "${KMS_KEYRING}" --location "${REGION}" --project "${GCP_PROJECT_ID}" \
      --purpose mac --default-algorithm hmac-sha256 --protection-level "${KMS_PROTECTION_LEVEL:-software}"
  KMS_KEY="projects/${GCP_PROJECT_ID}/locations/${REGION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY_NAME}/cryptoKeyVersions/1"

  say "Workload Identity Federation for ${GITHUB_ORG}"
  gcloud iam workload-identity-pools describe "${POOL}" --location global --project "${GCP_PROJECT_ID}" >/dev/null 2>&1 ||
    gcloud iam workload-identity-pools create "${POOL}" --location global --project "${GCP_PROJECT_ID}" --display-name GitHub
  gcloud iam workload-identity-pools providers describe "${PROVIDER}" --workload-identity-pool "${POOL}" \
    --location global --project "${GCP_PROJECT_ID}" >/dev/null 2>&1 ||
    gcloud iam workload-identity-pools providers create-oidc "${PROVIDER}" --workload-identity-pool "${POOL}" \
      --location global --project "${GCP_PROJECT_ID}" --display-name "GitHub OIDC" \
      --issuer-uri https://token.actions.githubusercontent.com \
      --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.owner=assertion.repository_owner,attribute.ref=assertion.ref" \
      --attribute-condition "assertion.repository_owner == '${GITHUB_ORG}' && assertion.ref == 'refs/heads/main'"
  number="$(gcloud projects describe "${GCP_PROJECT_ID}" --format='value(projectNumber)')"
  provider_name="projects/${number}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"

  say "Identities"
  ensure_sa github-deployer-backend "GitHub deployer (Backend)"
  ensure_sa github-provisioner "GitHub provisioner (Backend)"
  ensure_sa github-deployer-frontend "GitHub deployer (Frontend)"
  ensure_sa github-deployer-dashboard "GitHub deployer (Dashboard)"
  ensure_sa gateway-frontend-runtime "Eisoptric frontend runtime"
  ensure_sa gateway-dashboard-runtime "Eisoptric dashboard runtime"

  # The backend's runtime identity: its secrets by name, MAC signing on the one key, Cloud SQL.
  GCP_PROJECT_ID="${GCP_PROJECT_ID}" GATEWAY_KMS_KEY="${KMS_KEY}" DEPLOYER_SA="$(email github-deployer-backend)" \
    RUNTIME_SECRETS="DATABASE_URL REDIS_URL REDIS_CA GATEWAY_GITHUB_OAUTH_CLIENT_ID GATEWAY_GITHUB_OAUTH_CLIENT_SECRET GATEWAY_GOOGLE_OAUTH_CLIENT_ID GATEWAY_GOOGLE_OAUTH_CLIENT_SECRET RESEND_API_KEY RESEND_FROM POLICY_LLM_BASE_URL POLICY_LLM_API_KEY POLICY_LLM_MODEL ORIGIN_AUTH_SECRET CONSOLE_PROXY_SECRET SEED_USER_EMAIL SEED_USER_PASSWORD" \
    bash "${HERE}/runtime-service-account.sh"

  for runtime in gateway-frontend-runtime gateway-dashboard-runtime; do
    project_role "${runtime}" roles/logging.logWriter
    project_role "${runtime}" roles/monitoring.metricWriter
  done
  secret_reader gateway-frontend-runtime ORIGIN_AUTH_SECRET
  secret_reader gateway-frontend-runtime CONSOLE_PROXY_SECRET

  bind_repo github-deployer-backend "${BACKEND_REPO}"
  bind_repo github-provisioner "${BACKEND_REPO}"
  bind_repo github-deployer-frontend "${FRONTEND_REPO}"
  bind_repo github-deployer-dashboard "${DASHBOARD_REPO}"
  for role in roles/run.developer roles/vpcaccess.user; do project_role github-deployer-backend "${role}"; done
  for role in roles/cloudsql.admin roles/redis.admin roles/compute.networkAdmin roles/vpcaccess.admin \
    roles/artifactregistry.admin roles/serviceusage.serviceUsageAdmin; do
    project_role github-provisioner "${role}"
  done
  for name in github-deployer-backend github-deployer-frontend github-deployer-dashboard; do registry_writer "${name}"; done
  project_role github-deployer-frontend roles/run.developer
  project_role github-deployer-dashboard roles/run.developer
  act_as github-deployer-frontend gateway-frontend-runtime
  act_as github-deployer-dashboard gateway-dashboard-runtime
  # The services do not exist yet, so the first deploy needs run.admin on the project to set their
  # invoker policy. after-first-deploy narrows it to each service and takes this back.
  for name in github-deployer-backend github-deployer-frontend github-deployer-dashboard; do
    project_role "${name}" roles/run.admin
  done

  say "GitHub"
  for repo in "${BACKEND_REPO}" "${FRONTEND_REPO}" "${DASHBOARD_REPO}"; do
    github_secret "${repo}" GCP_WORKLOAD_IDENTITY_PROVIDER "${provider_name}"
    github_variable "${repo}" GCP_PROJECT_ID "${GCP_PROJECT_ID}"
    github_variable "${repo}" GCP_REGION "${REGION}"
    github_variable "${repo}" GAR_LOCATION "${GAR_LOCATION}"
    github_variable "${repo}" GAR_REPOSITORY "${GAR_REPOSITORY}"
  done
  github_secret "${BACKEND_REPO}" GCP_SERVICE_ACCOUNT_EMAIL "$(email github-deployer-backend)"
  github_secret "${BACKEND_REPO}" GCP_PROVISION_SERVICE_ACCOUNT_EMAIL "$(email github-provisioner)"
  github_secret "${FRONTEND_REPO}" GCP_SERVICE_ACCOUNT_EMAIL "$(email github-deployer-frontend)"
  github_secret "${DASHBOARD_REPO}" GCP_SERVICE_ACCOUNT_EMAIL "$(email github-deployer-dashboard)"
  github_variable "${BACKEND_REPO}" RUNTIME_SERVICE_ACCOUNT "$(email gateway-runtime)"
  github_variable "${FRONTEND_REPO}" RUNTIME_SERVICE_ACCOUNT "$(email gateway-frontend-runtime)"
  github_variable "${DASHBOARD_REPO}" RUNTIME_SERVICE_ACCOUNT "$(email gateway-dashboard-runtime)"
  github_variable "${BACKEND_REPO}" GATEWAY_KMS_KEY "${KMS_KEY}"
  github_variable "${BACKEND_REPO}" CLOUD_SQL_INSTANCE_CONNECTION_NAME "${connection}"
  github_variable "${BACKEND_REPO}" SERVERLESS_VPC_CONNECTOR gateway-vpc
  github_variable "${BACKEND_REPO}" REDIS_CA_SECRET REDIS_CA
  github_variable "${BACKEND_REPO}" MIGRATIONS_JOB true
  github_variable "${BACKEND_REPO}" SEED_ON_DEPLOY true
  github_variable "${BACKEND_REPO}" CONSOLE_PROXY_SECRET_NAME CONSOLE_PROXY_SECRET
  github_variable "${FRONTEND_REPO}" CONSOLE_PROXY_SECRET_NAME CONSOLE_PROXY_SECRET
  # The old project's values for these would send the deploy to saturn-* services and secrets that
  # the new project does not have.
  github_variable "${BACKEND_REPO}" BACKEND_CLOUD_RUN_SERVICE gateway-backend
  github_variable "${FRONTEND_REPO}" FRONTEND_CLOUD_RUN_SERVICE gateway-frontend
  github_variable "${DASHBOARD_REPO}" OPS_CLOUD_RUN_SERVICE gateway-ops
  github_variable "${DASHBOARD_REPO}" BACKEND_PUBLIC_URL https://api.eisoptric.com
  github_variable "${BACKEND_REPO}" REDIS_URL_SECRET REDIS_URL
  github_variable "${BACKEND_REPO}" SERVERLESS_VPC_CONNECTOR_RANGE "${VPC_CONNECTOR_RANGE:-10.9.0.0/28}"
  if [[ "${GITHUB_SETUP}" == "true" ]]; then
    gh variable delete SATURN_KMS_KEY -R "${GITHUB_ORG}/${BACKEND_REPO}" 2>/dev/null || true
  else
    echo "gh variable delete SATURN_KMS_KEY -R ${GITHUB_ORG}/${BACKEND_REPO}"
  fi
  if [[ "${GITHUB_SETUP}" == "true" ]]; then
    printf '%s' "${CLOUD_SQL_PASSWORD}" | gh secret set CLOUD_SQL_PASSWORD -R "${GITHUB_ORG}/${BACKEND_REPO}"
  else
    echo "# CLOUD_SQL_PASSWORD: rerun with GITHUB_SETUP=true, or run rotate-db-password.sh, to store it in GitHub"
  fi
  unset CLOUD_SQL_PASSWORD

  cat <<EOF

Done with setup. Next, in this order:
  1. Cloudflare: change the Transform Rule so X-Eisoptric-Origin-Auth carries the new
     ORIGIN_AUTH_SECRET (gcloud secrets versions access latest --secret ORIGIN_AUTH_SECRET --project ${GCP_PROJECT_ID}).
  2. Deploy ${BACKEND_REPO} from main, then ${FRONTEND_REPO} and ${DASHBOARD_REPO}.
  3. Point api.eisoptric.com and console.eisoptric.com at the new services, the way the old ones were.
  4. Sign in as ${SEED_USER_EMAIL}, then: GCP_PROJECT_ID=${GCP_PROJECT_ID} bash infra/gcp/move-project.sh after-first-deploy
EOF
}

after_first_deploy() {
  say "Deployers: run.admin on their own services only"
  narrow() {
    retry gcloud run services add-iam-policy-binding "$2" --project "${GCP_PROJECT_ID}" --region "${REGION}" \
      --member "serviceAccount:$(email "$1")" --role roles/run.admin
  }
  narrow github-deployer-backend gateway-backend
  narrow github-deployer-backend gateway-worker
  narrow github-deployer-frontend gateway-frontend
  narrow github-deployer-dashboard gateway-ops
  for name in github-deployer-backend github-deployer-frontend github-deployer-dashboard; do
    retry gcloud projects remove-iam-policy-binding "${GCP_PROJECT_ID}" \
      --member "serviceAccount:$(email "${name}")" --role roles/run.admin --condition None
  done

  say "First admin: stop mounting the seed and disable its values"
  github_variable "${BACKEND_REPO}" SEED_ON_DEPLOY false
  for name in SEED_USER_EMAIL SEED_USER_PASSWORD; do
    for version in $(gcloud secrets versions list "${name}" --project "${GCP_PROJECT_ID}" --filter state=ENABLED --format='value(name.basename())'); do
      gcloud secrets versions disable "${version}" --secret "${name}" --project "${GCP_PROJECT_ID}" >/dev/null
    done
  done
  cat <<EOF

Done. Deploy ${BACKEND_REPO} once more so the seed is no longer mounted, then run
uptime-checks.sh against ${GCP_PROJECT_ID}. The old project is untouched; shut it down when you no
longer need it.
EOF
}

case "${STEP}" in
  setup) setup ;;
  after-first-deploy) after_first_deploy ;;
  *) echo "usage: move-project.sh setup | after-first-deploy" >&2; exit 1 ;;
esac
