# Threat Model

- Replay of captured token -> mitigated by nonce + single-use registry.
- Confused deputy via broad connector creds -> mitigated by gateway + connector-side token binding.
- Receipt tampering -> mitigated by append-only chained hashes and periodic integrity scan.
- Meter outage -> fail closed for high-risk actions.
