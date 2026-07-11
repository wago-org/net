# Production-readiness receipt interoperability vectors

These files are public **synthetic test vectors**, not a production decision,
release authorization, publisher identity, trust root, or hosted-automation
configuration. Every commit and digest is conspicuously synthetic. Never use the
key label or any digest in this directory as production trust input.

`ready.json` and `blocked.json` are canonical
`github.com/wago-org/net/production-readiness/v1` receipts with exact adjacent
SHA-256 sidecars. A valid blocked receipt is retained evidence and must verify
successfully; activation still requires the caller to separately enforce
`ready=true`.

`blocked-tampered.json` changes the trusted key label while deliberately retaining
the original blocked-receipt digest in its basename-correct sidecar. It must be
rejected. `vectors.json` also exercises wrong independently provisioned subject,
statement-digest, and trust-policy-digest constraints. Tests check every listed
file digest, canonical JSON bytes, sidecar syntax, both positive decisions, and
all negative outcomes.
