# KRONYX

Execution-time governance reference implementation.

## Services
- `services/meter`: deterministic policy evaluation.
- `services/token-service`: signed execution token minting.
- `services/enforcement-gateway`: token validation and connector gate.
- `services/receipt-ledger`: append-only receipt chain.

## Quickstart
```bash
make test
make run-meter
make run-token
make run-gateway
make run-ledger
# optional once services are up
make e2e
```

## Runbook
- Terminal commands: `docs/runbooks/terminal-commands.md`


## Operational APIs
- Meter: `GET/POST /v1/policy` for policy inspection and hot reload.
- Token service: `POST /v1/keys` for signing key rotation.
