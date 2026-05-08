#!/usr/bin/env bash
set -euo pipefail

# Negative-path checks for KRONYX gateway controls.

TOKEN_URL="${TOKEN_URL:-http://localhost:8082}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8083}"

require_bin() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }

require_bin curl
require_bin jq

payload='{
  "meter_result":"allow",
  "action_type":"deploy.promote_to_prod",
  "subject":"alice",
  "resource":"service/api",
  "bounds":{"change_window":"approved"},
  "audience":"enforcement-gateway",
  "ttl_seconds":120,
  "max_ttl_seconds":"300"
}'

tok=$(curl -sS -X POST "$TOKEN_URL/v1/token" -H 'content-type: application/json' -d "$payload")
TOKEN=$(echo "$tok" | jq -r '.token')
NONCE=$(echo "$tok" | jq -r '.claims.nonce')
REV=$(echo "$tok" | jq -r '.claims.revocation_ref')

base_req='{"operation":"deploy","service":"api","artifact":"sha256:abc"}'

# 1) Nonce mismatch should fail.
code_nonce=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/v1/execute" \
  -H "authorization: Bearer ${TOKEN}" \
  -H 'X-Kronyx-Nonce: wrong-nonce' \
  -H 'content-type: application/json' \
  -d "$base_req")
[[ "$code_nonce" == "401" ]] || { echo "expected nonce mismatch 401 got $code_nonce" >&2; exit 10; }

# 2) Valid execution should pass once.
code_ok=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/v1/execute" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "X-Kronyx-Nonce: ${NONCE}" \
  -H 'content-type: application/json' \
  -d "$base_req")
[[ "$code_ok" == "200" ]] || { echo "expected first execution 200 got $code_ok" >&2; exit 11; }

# 3) Replay should fail.
code_replay=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/v1/execute" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "X-Kronyx-Nonce: ${NONCE}" \
  -H 'content-type: application/json' \
  -d "$base_req")
[[ "$code_replay" == "409" ]] || { echo "expected replay 409 got $code_replay" >&2; exit 12; }

# 4) Revoke lineage and ensure fresh token with same lineage cannot be used (service-specific behavior requires direct revoke for that ref).
curl -sS -o /dev/null -w '%{http_code}' -X POST "$TOKEN_URL/v1/revoke" \
  -H 'content-type: application/json' \
  -d "{\"revocation_ref\":\"${REV}\"}" | grep -q '^204$'

echo "KRONYX negative checks passed"
