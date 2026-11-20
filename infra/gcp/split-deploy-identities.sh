#!/usr/bin/env bash
# Gives each repo its own deploy identity and each service its own runtime identity.
# Only adds accounts and bindings; nothing existing is removed. Safe to re-run.
# Run as a project IAM admin. Afterwards point each repo at its new deployer (the script
# prints the GitHub commands) and deploy once. Then run retire-shared-deployer.sh.
# See infra/gcp/README.md, "Split and narrow the deploy identities".
set -euo pipefail

: "${GCP_PROJECT_ID:?GCP_PROJECT_ID is required}"
GITHUB_ORG="${GITHUB_ORG:-eisoptric}"
REGION="${GCP_REGION:-asia-east1}"
GAR_LOCATION="${GAR_LOCATION:-asia-east1}"
GAR_REPOSITORY="${GAR_REPOSITORY:-gateway}"
POOL="${WIF_POOL:-github}"
BACKEND_REPO="${BACKEND_REPO:-MCP-gateway-backend}"
FRONTEND_REPO="${FRONTEND_REPO:-MCP-gateway-frontend}"
PROJECT_NUMBER="$(gcloud projects describe "${GCP_PROJECT_ID}" --format='value(projectNumber)')"

email() { echo "$1@${GCP_PROJECT_ID}.iam.gserviceaccount.com"; }

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

ensure_sa() {
  if ! gcloud iam service-accounts describe "$(email "$1")" --project "${GCP_PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$1" --project "${GCP_PROJECT_ID}" --display-name "$2" >/dev/null
  fi
  echo "  $(email "$1")"
}

project_role() {
  retry gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
    --member "serviceAccount:$(email "$1")" --role "$2" --condition None
}

# Lets a repo's main-branch workflows act as this deployer, and nothing else.
bind_repo() {
  retry gcloud iam service-accounts add-iam-policy-binding "$(email "$1")" --project "${GCP_PROJECT_ID}" \
    --role roles/iam.workloadIdentityUser \
    --member "principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/attribute.repository/${GITHUB_ORG}/$2"
}

# The deployer may deploy a service that runs as this one account only.
act_as() {
  retry gcloud iam service-accounts add-iam-policy-binding "$(email "$2")" --project "${GCP_PROJECT_ID}" \
    --role roles/iam.serviceAccountUser --member "serviceAccount:$(email "$1")"
}

# run.admin on one existing service, so --allow-unauthenticated can set its invoker policy.
service_admin() {
  if gcloud run services describe "$2" --project "${GCP_PROJECT_ID}" --region "${REGION}" >/dev/null 2>&1; then
    retry gcloud run services add-iam-policy-binding "$2" --project "${GCP_PROJECT_ID}" --region "${REGION}" \
      --member "serviceAccount:$(email "$1")" --role roles/run.admin
  else
    echo "  service $2 does not exist yet: grant roles/run.admin on it after its first deploy" >&2
  fi
}

registry_writer() {
  retry gcloud artifacts repositories add-iam-policy-binding "${2:-${GAR_REPOSITORY}}" \
    --project "${GCP_PROJECT_ID}" --location "${GAR_LOCATION}" \
    --member "serviceAccount:$(email "$1")" --role roles/artifactregistry.writer
}

echo "Service accounts"
ensure_sa github-deployer-backend "GitHub deployer (Backend)"
ensure_sa github-provisioner "GitHub provisioner (Backend)"
ensure_sa github-deployer-frontend "GitHub deployer (Frontend)"
ensure_sa github-deployer-dashboard "GitHub deployer (Dashboard)"
ensure_sa github-deployer-demosystem "GitHub deployer (demosystem)"
ensure_sa gateway-frontend-runtime "Eisoptric frontend runtime"
ensure_sa gateway-dashboard-runtime "Eisoptric dashboard runtime"
ensure_sa acme-demo-runtime "ACME demo runtime"

echo "Runtime identities: logs and metrics; the frontend also reads the origin secret"
for runtime in gateway-frontend-runtime gateway-dashboard-runtime acme-demo-runtime; do
  project_role "${runtime}" roles/logging.logWriter
  project_role "${runtime}" roles/monitoring.metricWriter
done
retry gcloud secrets add-iam-policy-binding ORIGIN_AUTH_SECRET --project "${GCP_PROJECT_ID}" \
  --member "serviceAccount:$(email gateway-frontend-runtime)" --role roles/secretmanager.secretAccessor

echo "Backend deployer"
bind_repo github-deployer-backend "${BACKEND_REPO}"
project_role github-deployer-backend roles/run.developer
project_role github-deployer-backend roles/vpcaccess.user
registry_writer github-deployer-backend
act_as github-deployer-backend gateway-runtime
service_admin github-deployer-backend gateway-backend
service_admin github-deployer-backend gateway-worker

echo "Backend provisioner"
bind_repo github-provisioner "${BACKEND_REPO}"
for role in roles/cloudsql.admin roles/redis.admin roles/compute.networkAdmin roles/vpcaccess.admin \
  roles/artifactregistry.admin roles/serviceusage.serviceUsageAdmin; do
  project_role github-provisioner "${role}"
done

deployer() {
  local name="$1" repo="$2" runtime="$3" service="$4" registry="${5:-${GAR_REPOSITORY}}"
  echo "${repo} deployer"
  bind_repo "${name}" "${repo}"
  project_role "${name}" roles/run.developer
  registry_writer "${name}" "${registry}"
  act_as "${name}" "${runtime}"
  service_admin "${name}" "${service}"
}
deployer github-deployer-frontend "${FRONTEND_REPO}" gateway-frontend-runtime gateway-frontend
deployer github-deployer-dashboard Dashboard gateway-dashboard-runtime gateway-dashboard
# demosystem pushes its image to its own registry, acme.
deployer github-deployer-demosystem demosystem acme-demo-runtime acme-demo acme

cat <<EOF

Done. Point each repo at its own identities:

  gh secret set GCP_SERVICE_ACCOUNT_EMAIL -R ${GITHUB_ORG}/${BACKEND_REPO} --body $(email github-deployer-backend)
  gh secret set GCP_PROVISION_SERVICE_ACCOUNT_EMAIL -R ${GITHUB_ORG}/${BACKEND_REPO} --body $(email github-provisioner)
  gh secret set GCP_SERVICE_ACCOUNT_EMAIL -R ${GITHUB_ORG}/${FRONTEND_REPO} --body $(email github-deployer-frontend)
  gh variable set RUNTIME_SERVICE_ACCOUNT -R ${GITHUB_ORG}/${FRONTEND_REPO} --body $(email gateway-frontend-runtime)
  gh secret set GCP_SERVICE_ACCOUNT_EMAIL -R ${GITHUB_ORG}/Dashboard --body $(email github-deployer-dashboard)
  gh variable set RUNTIME_SERVICE_ACCOUNT -R ${GITHUB_ORG}/Dashboard --body $(email gateway-dashboard-runtime)
  gh secret set GCP_SERVICE_ACCOUNT -R ${GITHUB_ORG}/demosystem --body $(email github-deployer-demosystem)
  gh variable set RUNTIME_SERVICE_ACCOUNT -R ${GITHUB_ORG}/demosystem --body $(email acme-demo-runtime)

Then deploy each repo once and check it serves. Only then run retire-shared-deployer.sh.
EOF
