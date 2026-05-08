# Vault Connector Enforcement

Use Vault response-wrapping tokens scoped to the KRONYX execution token ID.
Reject writes when wrapped token metadata does not match `token_id`, `nonce`, and audience.
