#!/usr/bin/env bash
set -euo pipefail

# KRONYX end-to-end flow with configurable constraints.
# Requires services already running on localhost or custom *_URL values.

METER_URL="${METER_URL:-http://localhost:8081}"
TOKEN_URL="${TOKEN_URL:-http://localhost:8082}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8083}"
LEDGER_URL="${LEDGER_URL:-http://localhost:8084}"

ACTION_TYPE="${ACTION_TYPE:-deploy.promote_to_prod}"
RESOURCE="${RESOURCE:-service/api}"
SUBJECT_ID="${SUBJECT_ID:-alice}"
SUBJECT_GROUP="${SUBJECT_GROUP:-sre}"
SUBJECT_MFA="${SUBJECT_MFA:-true}"
PHASE="${PHASE:-change_window_open}"
TTL_SECONDS="${TTL_SECONDS:-120}"
MAX_TTL_SECONDS="${MAX_TTL_SECONDS:-300}"
REQUEST_ID="${REQUEST_ID:-req-$(date +%s)}"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required binary: $1" >&2
    exit 1
  }
}

check_constraints() {
  [[ "$TTL_SECONDS" =~ ^[0-9]+$ ]] || { echo "TTL_SECONDS must be integer" >&2; exit 1; }
  [[ "$MAX_TTL_SECONDS" =~ ^[0-9]+$ ]] || { echo "MAX_TTL_SECONDS must be integer" >&2; exit 1; }

  if (( TTL_SECONDS <= 0 )); then
    echo "TTL_SECONDS must be > 0" >&2
    exit 1
  fi
  if (( MAX_TTL_SECONDS > 600 )); then
    echo "MAX_TTL_SECONDS must be <= 600 for high-risk bounded authority" >&2
    exit 1
  fi
  if (( TTL_SECONDS > MAX_TTL_SECONDS )); then
    echo "TTL_SECONDS cannot exceed MAX_TTL_SECONDS" >&2
    exit 1
  fi
  [[ "$ACTION_TYPE" == "deploy.promote_to_prod" || "$ACTION_TYPE" == "secrets.write" || "$ACTION_TYPE" == "payments.initiate_wire" ]] || {
    echo "ACTION_TYPE must be one of supported governed actions" >&2
    exit 1
  }
}

healthcheck() {
  local url="$1"
  curl -sf "$url/healthz" >/dev/null
}

json_post() {
  local url="$1"
  local payload="$2"
  curl -sS -X POST "$url" -H 'content-type: application/json' -d "$payload"
}

main() {
  require_bin curl
  require_bin jq
  check_constraints

  healthcheck "$METER_URL"
  healthcheck "$TOKEN_URL"
  healthcheck "$GATEWAY_URL"
  healthcheck "$LEDGER_URL"

  eval_payload=$(cat <<JSON
{
  "request_id":"$REQUEST_ID",
  "action_type":"$ACTION_TYPE",
  "resource":"$RESOURCE",
  "env":"prod",
  "subject":{"id":"$SUBJECT_ID","attrs":{"mfa":"$SUBJECT_MFA"},"groups":["$SUBJECT_GROUP"]},
  "payload":{"artifact":"sha256:abc","service":"api","from_env":"stage","to_env":"prod"},
  "bounds":{"change_window":"approved"},
  "phase":"$PHASE",
  "requested_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
)

  meter_resp=$(json_post "$METER_URL/v1/evaluate" "$eval_payload")
  decision=$(echo "$meter_resp" | jq -r '.result.decision')
  [[ "$decision" == "allow" ]] || {
    echo "meter denied action: $meter_resp" >&2
    exit 2
  }

  token_payload=$(cat <<JSON
{
  "meter_result":"$decision",
  "action_type":"$ACTION_TYPE",
  "subject":"$SUBJECT_ID",
  "resource":"$RESOURCE",
  "bounds":{"change_window":"approved"},
  "audience":"enforcement-gateway",
  "ttl_seconds":$TTL_SECONDS,
  "max_ttl_seconds":"$MAX_TTL_SECONDS"
}
JSON
)

  token_resp=$(json_post "$TOKEN_URL/v1/token" "$token_payload")
  token=$(echo "$token_resp" | jq -r '.token')
  token_id=$(echo "$token_resp" | jq -r '.claims.token_id')
  nonce=$(echo "$token_resp" | jq -r '.claims.nonce')
  revocation_ref=$(echo "$token_resp" | jq -r '.claims.revocation_ref')
  [[ -n "$token" && "$token" != "null" ]] || { echo "failed to mint token: $token_resp" >&2; exit 3; }

  exec_resp=$(curl -sS -X POST "$GATEWAY_URL/v1/execute" \
    -H "authorization: Bearer $token" \
    -H "X-Kronyx-Nonce: $nonce" \
    -H 'content-type: application/json' \
    -d '{"operation":"deploy","service":"api","artifact":"sha256:abc"}')

  status=$(echo "$exec_resp" | jq -r '.status')
  [[ "$status" == "accepted" ]] || { echo "gateway rejected execution: $exec_resp" >&2; exit 4; }

  req_hash=$(printf '%s' "$eval_payload" | sha256sum | awk '{print $1}')
  receipt_payload=$(cat <<JSON
{
  "request_hash":"$req_hash",
  "policy_version":"$(echo "$meter_resp" | jq -r '.policy_version')",
  "evaluation_result":"$decision",
  "token_id":"$token_id",
  "actor":"$SUBJECT_ID",
  "resource":"$RESOURCE",
  "connector":"deploy-controller",
  "connector_code":200,
  "summary":"execution accepted by gateway"
}
JSON
)

  receipt_resp=$(json_post "$LEDGER_URL/v1/receipts" "$receipt_payload")
  entry_hash=$(echo "$receipt_resp" | jq -r '.entry_hash')
  [[ -n "$entry_hash" && "$entry_hash" != "null" ]] || { echo "receipt append failed: $receipt_resp" >&2; exit 5; }

  revoke_payload=$(printf '{"revocation_ref":"%s"}' "$revocation_ref")
  curl -sS -o /dev/null -w '%{http_code}' -X POST "$TOKEN_URL/v1/revoke" -H 'content-type: application/json' -d "$revoke_payload" | grep -q '^204$'

  echo "KRONYX E2E PASS"
  echo "token_id=$token_id"
  echo "receipt_entry_hash=$entry_hash"
}

main "$@"
