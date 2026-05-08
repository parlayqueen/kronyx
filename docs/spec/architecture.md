# KRONYX Architecture

Subsystems: Meter, Token Service, Enforcement Gateway, Receipt Ledger.

Invariants:
1. Dangerous actions require a valid token minted from an allow decision.
2. Tokens are audience-scoped, time-bounded, nonce-bound, and revocable.
3. All executions emit append-only hash-chained receipts.
4. Governance outages fail closed for high-risk actions.

5. Revocation feed freshness can be enforced at gateway with fail-closed staleness bounds.
