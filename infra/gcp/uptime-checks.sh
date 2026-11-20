#!/usr/bin/env bash
# "Uptime checks from Cloud Monitoring" in infra/gcp/README.md: an uptime check on /health for the
# API and the console, run from Google's probes through Cloudflare the way a visitor arrives, and
# an alert policy that emails ALERT_EMAIL when a check fails from two regions or more.
#
# This replaces the scheduled GitHub workflow, which failed on every run: on the free plan,
# Cloudflare's Bot Fight Mode challenges GitHub-hosted runners, and no rule can exempt them.
# Requests from Google Cloud pass, as the worker's own check of the API through its public address
# shows. Safe to re-run: an existing channel, check or policy is reused, never duplicated.
set -euo pipefail

: "${GCP_PROJECT_ID:?GCP_PROJECT_ID is required}"
: "${ALERT_EMAIL:?ALERT_EMAIL is required: the address that receives uptime alerts}"
HOSTS="${UPTIME_HOSTS:-api.eisoptric.com console.eisoptric.com}"
# At least three regions. A check alerts when two of them fail, so one probe's bad network is not
# reported as an outage.
REGIONS="${UPTIME_REGIONS:-asia-pacific,usa-oregon,europe}"
PERIOD_MINUTES="${UPTIME_PERIOD_MINUTES:-5}"
API="https://monitoring.googleapis.com/v3/projects/${GCP_PROJECT_ID}"

# Calls the Monitoring REST API. Notification channels have no GA gcloud command.
monitoring() {
  curl -sSf -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" "$@"
}

echo "Enabling the Monitoring API"
gcloud services enable monitoring.googleapis.com --project "${GCP_PROJECT_ID}"

echo "Email channel for ${ALERT_EMAIL}"
channel=$(monitoring --get "${API}/notificationChannels" \
  --data-urlencode "filter=type=\"email\" AND labels.email_address=\"${ALERT_EMAIL}\"" |
  python3 -c 'import json, sys; print(next((c["name"] for c in json.load(sys.stdin).get("notificationChannels", [])), ""))')
if [ -z "${channel}" ]; then
  channel=$(ALERT_EMAIL="${ALERT_EMAIL}" python3 -c 'import json, os; print(json.dumps({"type": "email", "displayName": "Eisoptric uptime", "labels": {"email_address": os.environ["ALERT_EMAIL"]}}))' |
    monitoring -X POST "${API}/notificationChannels" --data-binary @- |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["name"])')
fi
echo "  ${channel}"

for host in ${HOSTS}; do
  name="Eisoptric ${host}"
  echo "Uptime check ${name}"
  check=$(gcloud monitoring uptime list-configs --project "${GCP_PROJECT_ID}" \
    --filter "displayName=\"${name}\"" --format "value(name)" | head -n 1)
  if [ -z "${check}" ]; then
    gcloud monitoring uptime create "${name}" --project "${GCP_PROJECT_ID}" \
      --resource-type uptime-url --resource-labels "host=${host},project_id=${GCP_PROJECT_ID}" \
      --protocol https --path /health --validate-ssl true --status-codes 200 \
      --period "${PERIOD_MINUTES}" --timeout 20 --regions "${REGIONS}"
    check=$(gcloud monitoring uptime list-configs --project "${GCP_PROJECT_ID}" \
      --filter "displayName=\"${name}\"" --format "value(name)" | head -n 1)
  fi
  : "${check:?the uptime check for ${host} was not found after creating it}"
  echo "  ${check}"

  echo "Alert policy ${name} is down"
  policy=$(gcloud monitoring policies list --project "${GCP_PROJECT_ID}" \
    --filter "displayName=\"${name} is down\"" --format "value(name)" | head -n 1)
  if [ -n "${policy}" ]; then
    echo "  ${policy} (kept as it is)"
    continue
  fi
  file=$(mktemp)
  # The policy Cloud Monitoring's console makes for an uptime check: it fires when more than one
  # region reports a failure within 20 minutes.
  NAME="${name}" HOST="${host}" CHECK_ID="${check##*/}" CHANNEL="${channel}" python3 - >"${file}" <<'EOF'
import json, os

check_filter = (
    'metric.type="monitoring.googleapis.com/uptime_check/check_passed" '
    f'AND metric.label.check_id="{os.environ["CHECK_ID"]}" AND resource.type="uptime_url"'
)
print(json.dumps({
    "displayName": f'{os.environ["NAME"]} is down',
    "combiner": "OR",
    "conditions": [{
        "displayName": f'https://{os.environ["HOST"]}/health fails from two regions',
        "conditionThreshold": {
            "filter": check_filter,
            "aggregations": [{
                "alignmentPeriod": "1200s",
                "perSeriesAligner": "ALIGN_NEXT_OLDER",
                "crossSeriesReducer": "REDUCE_COUNT_FALSE",
                "groupByFields": ["resource.label.project_id", "resource.label.host"],
            }],
            "comparison": "COMPARISON_GT",
            "thresholdValue": 1,
            "duration": "60s",
            "trigger": {"count": 1},
        },
    }],
    "notificationChannels": [os.environ["CHANNEL"]],
    "documentation": {
        "mimeType": "text/markdown",
        "content": "GET /health did not answer 200 through Cloudflare. "
                   "See /status for the API, database and Redis, and the Cloud Run logs.",
    },
}))
EOF
  gcloud monitoring policies create --project "${GCP_PROJECT_ID}" --policy-from-file "${file}"
  rm -f "${file}"
done

echo "Done. Each check's first results appear in Monitoring > Uptime checks within ${PERIOD_MINUTES} minutes."
