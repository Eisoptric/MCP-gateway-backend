#!/usr/bin/env bash
# Cloud Monitoring uptime checks on GET /health for the API and the console, and an alert
# policy that emails ALERT_EMAIL when either fails. See infra/gcp/README.md, "Uptime checks".
#
# The checks target each Cloud Run service directly (resource type cloud_run_revision), not
# the Cloudflare hostname, so Cloudflare's bot protection cannot challenge them. /health is
# exempt from origin auth in both services, so no secret is needed. The checks stop working
# once a service's ingress is internal-and-cloud-load-balancing; see the README.
#
# Run as someone who can edit monitoring (roles/monitoring.editor). Safe to re-run: each
# check, the notification channel and the alert policy are created once and found by name.
set -euo pipefail

: "${GCP_PROJECT_ID:?GCP_PROJECT_ID is required}"
: "${ALERT_EMAIL:?ALERT_EMAIL is required: where an outage email goes}"
REGION="${GCP_REGION:-asia-east1}"
BACKEND_SERVICE="${BACKEND_CLOUD_RUN_SERVICE:-saturn-backend}"
FRONTEND_SERVICE="${FRONTEND_CLOUD_RUN_SERVICE:-saturn-frontend}"
# Three regions is the minimum Cloud Monitoring accepts.
CHECK_REGIONS="${UPTIME_CHECK_REGIONS:-asia-pacific,usa-oregon,europe}"
CHECK_PERIOD_MINUTES="${UPTIME_CHECK_PERIOD_MINUTES:-5}"
P=(--project "${GCP_PROJECT_ID}")
MONITORING_API="https://monitoring.googleapis.com/v3/projects/${GCP_PROJECT_ID}"

# Prints the full name (projects/P/uptimeCheckConfigs/ID) of the check, creating it if needed.
uptime_check() {
  local display="$1" service="$2" name
  name="$(gcloud monitoring uptime list-configs "${P[@]}" \
    --filter "displayName=\"${display}\"" --format 'value(name)' | head -n 1)"
  if [ -z "${name}" ]; then
    gcloud monitoring uptime create "${display}" "${P[@]}" \
      --resource-type cloud-run-revision \
      --resource-labels "project_id=${GCP_PROJECT_ID},service_name=${service},location=${REGION}" \
      --protocol https --path /health --request-method get --status-codes 200 \
      --period "${CHECK_PERIOD_MINUTES}" --timeout 20 --regions "${CHECK_REGIONS}" >&2
    name="$(gcloud monitoring uptime list-configs "${P[@]}" \
      --filter "displayName=\"${display}\"" --format 'value(name)' | head -n 1)"
  fi
  [ -n "${name}" ] || { echo "Could not find uptime check ${display}" >&2; exit 1; }
  echo "${name}"
}

echo "Uptime checks" >&2
backend_check="$(uptime_check "Saturn API /health" "${BACKEND_SERVICE}")"
frontend_check="$(uptime_check "Saturn console /health" "${FRONTEND_SERVICE}")"

# Notification channels have no GA gcloud command, so the REST API is used.
echo "Email notification channel" >&2
token="$(gcloud auth print-access-token)"
api() { curl -sSf -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" "$@"; }
channel="$(api -G "${MONITORING_API}/notificationChannels" \
  --data-urlencode "filter=type=\"email\" AND labels.email_address=\"${ALERT_EMAIL}\"" |
  python3 -c 'import json,sys; c=json.load(sys.stdin).get("notificationChannels", []); print(c[0]["name"] if c else "")')"
if [ -z "${channel}" ]; then
  channel="$(api -X POST "${MONITORING_API}/notificationChannels" \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"type": "email", "displayName": "Saturn uptime", "labels": {"email_address": sys.argv[1]}}))' "${ALERT_EMAIL}")" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
fi

echo "Alert policy" >&2
POLICY_NAME="Saturn uptime"
if [ -n "$(gcloud monitoring policies list "${P[@]}" --filter "displayName=\"${POLICY_NAME}\"" --format 'value(name)')" ]; then
  echo "Alert policy '${POLICY_NAME}' already exists; edit it in the console to change it." >&2
else
  policy_file="$(mktemp)"
  trap 'rm -f "${policy_file}"' EXIT
  # One condition per check. A check fails when more than one region reports a failure for
  # ten minutes, so a single slow cold start or one checker region's trouble is not an outage.
  python3 - "${policy_file}" "${POLICY_NAME}" "${channel}" \
    "API|${backend_check##*/}" "Console|${frontend_check##*/}" <<'PY'
import json
import sys

path, display, channel, *checks = sys.argv[1:]
conditions = []
for item in checks:
    label, check_id = item.split("|", 1)
    conditions.append({
        "displayName": f"{label} /health is failing",
        "conditionThreshold": {
            "filter": (
                'metric.type="monitoring.googleapis.com/uptime_check/check_passed" '
                f'AND metric.label.check_id="{check_id}"'
            ),
            "aggregations": [{
                "alignmentPeriod": "1200s",
                "perSeriesAligner": "ALIGN_NEXT_OLDER",
                "crossSeriesReducer": "REDUCE_COUNT_FALSE",
                "groupByFields": ["resource.label.*"],
            }],
            "comparison": "COMPARISON_GT",
            "thresholdValue": 1,
            "duration": "600s",
            "trigger": {"count": 1},
        },
    })
policy = {
    "displayName": display,
    "combiner": "OR",
    "conditions": conditions,
    "notificationChannels": [channel],
    "documentation": {
        "content": "GET /health on a Saturn Cloud Run service failed from more than one region. "
        "See infra/gcp/README.md, \"Uptime checks\".",
        "mimeType": "text/markdown",
    },
}
with open(path, "w") as f:
    json.dump(policy, f)
PY
  gcloud monitoring policies create "${P[@]}" --policy-from-file "${policy_file}" >&2
fi

echo "Done. Checks: ${backend_check}, ${frontend_check}. Alerts go to ${ALERT_EMAIL}." >&2
