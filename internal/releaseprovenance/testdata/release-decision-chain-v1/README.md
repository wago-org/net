# Synthetic release decision chain v1 vectors

These files are deterministic interoperability fixtures only. They are not a
production decision, signed release, publisher identity, trust root, or hosted
activation signal.

The directory contains one canonical synthetic `trusted-distribution/v1`
receipt and exact sidecar, canonical linked `production-readiness/v2` ready and
blocked receipts with exact sidecars, a tampered readiness receipt paired with a
basename-correct stale checksum, and an individually valid readiness receipt
whose opaque key label does not match the intermediary receipt. `vectors.json`
binds every fixture byte by SHA-256 and defines positive, blocked, tamper,
wrong-link, and wrong external-constraint cases.

No statement, raw signature, public key, trust policy, private key, signed
release, production identity, real readiness decision, or hosted-automation
claim is stored here. The repeated digests and opaque labels are synthetic test
data and are not trusted for any deployment.
