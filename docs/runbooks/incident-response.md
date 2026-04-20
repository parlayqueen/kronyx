# Runbook: Governance Service Degradation

1. Set gateway mode to `deny_high_risk`.
2. Verify token-service signing key health and revocation endpoint.
3. If ledger unavailable > 60s, pause high-risk connectors.
4. Reconcile staged receipts after recovery and verify chain continuity.
