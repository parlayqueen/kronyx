# KRONYX Terminal Commands

## 1) Bootstrap
```bash
cd /workspace/kronyx
go version
make test
make build
```

## 2) Start services in separate terminals
```bash
# terminal 1
cd /workspace/kronyx
METER_ADDR=:8081 go run ./services/meter
```

```bash
# terminal 2
cd /workspace/kronyx
TOKEN_ADDR=:8082 go run ./services/token-service
```

```bash
# terminal 3 (after extracting keys from token-service)
cd /workspace/kronyx
export KRONYX_PUBLIC_KEYS='{"keys":[{"kid":"<kid>","x":"<x>","kty":"OKP","crv":"Ed25519"}]}'
go run ./services/enforcement-gateway
```

```bash
# terminal 4
cd /workspace/kronyx
go run ./services/receipt-ledger
```

## 3) Query token-service keyring
```bash
curl -s http://localhost:8082/v1/keys | jq
```

## 4) Meter policy evaluation
```bash
curl -sS -X POST http://localhost:8081/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "request_id":"req-001",
    "action_type":"deploy.promote_to_prod",
    "resource":"service/api",
    "env":"prod",
    "subject":{"id":"alice","attrs":{"mfa":"true"},"groups":["sre"]},
    "payload":{"artifact":"sha256:abc","service":"api","from_env":"stage","to_env":"prod"},
    "bounds":{"change_window":"approved"},
    "phase":"change_window_open",
    "requested_at":"2026-03-25T00:00:00Z"
  }' | jq
```

## 5) Mint execution token
```bash
curl -sS -X POST http://localhost:8082/v1/token \
  -H 'content-type: application/json' \
  -d '{
    "meter_result":"allow",
    "action_type":"deploy.promote_to_prod",
    "subject":"alice",
    "resource":"service/api",
    "bounds":{"change_window":"approved"},
    "audience":"enforcement-gateway",
    "ttl_seconds":120,
    "max_ttl_seconds":"300"
  }' | tee /tmp/kronyx-token.json | jq
```

## 6) Execute via enforcement gateway
```bash
TOKEN=$(jq -r '.token' /tmp/kronyx-token.json)

curl -sS -X POST http://localhost:8083/v1/execute \
  -H "authorization: Bearer ${TOKEN}" \
  -H 'content-type: application/json' \
  -d '{"operation":"deploy","service":"api","artifact":"sha256:abc"}' | jq
```

## 7) Append receipt
```bash
curl -sS -X POST http://localhost:8084/v1/receipts \
  -H 'content-type: application/json' \
  -d '{
    "request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "policy_version":"2026.03.25",
    "evaluation_result":"allow",
    "token_id":"tok-001",
    "actor":"alice",
    "resource":"service/api",
    "connector":"deploy-controller",
    "connector_code":200,
    "summary":"deployment promoted"
  }' | jq
```

## 8) Revoke token lineage
```bash
REVOCATION_REF=$(jq -r '.claims.revocation_ref' /tmp/kronyx-token.json)

curl -i -X POST http://localhost:8082/v1/revoke \
  -H 'content-type: application/json' \
  -d "{\"revocation_ref\":\"${REVOCATION_REF}\"}"

curl -s http://localhost:8082/v1/revocations | jq
```

## 9) Quick health checks
```bash
curl -sf http://localhost:8081/healthz && echo meter-ok
curl -sf http://localhost:8082/healthz && echo token-ok
curl -sf http://localhost:8083/healthz && echo gateway-ok
curl -sf http://localhost:8084/healthz && echo ledger-ok
```

## 10) Automated constrained E2E script
```bash
cd /workspace/kronyx
bash -n scripts/kronyx-e2e.sh
TTL_SECONDS=120 MAX_TTL_SECONDS=300 ACTION_TYPE=deploy.promote_to_prod ./scripts/kronyx-e2e.sh
```

## 11) Negative control checks
```bash
cd /workspace/kronyx
bash -n scripts/kronyx-negative.sh
./scripts/kronyx-negative.sh
```

## 12) Strict revocation-feed mode (fail-closed)
```bash
cd /workspace/kronyx
export TOKEN_SERVICE_URL=http://localhost:8082
export REQUIRE_REVOCATION_FEED=true
export REVOCATION_MAX_STALENESS_SECONDS=30
export TOKEN_CLOCK_SKEW_SECONDS=30
# then start gateway
go run ./services/enforcement-gateway
```

## 13) Key rotation (token-service)
```bash
curl -sS -X POST http://localhost:8082/v1/keys | jq
curl -sS http://localhost:8082/v1/keys | jq
```

## 14) Policy reload (meter)
```bash
# requires METER_POLICY_PATH to be set when meter starts
curl -sS -X POST http://localhost:8081/v1/policy | jq
curl -sS http://localhost:8081/v1/policy | jq
```
