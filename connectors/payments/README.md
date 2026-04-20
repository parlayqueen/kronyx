# Payments Connector Enforcement

All payment initiation requests must include token hash and idempotency key.
Reject duplicate token IDs and mismatched beneficiary/resource bindings.
