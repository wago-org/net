# Trusted-distribution receipt interoperability vectors

These files are public **synthetic test vectors**, not a signed release,
production trust root, publisher identity, release authorization, readiness
decision, or hosted-automation configuration. Every commit and digest is
conspicuously synthetic. No statement, raw signature, public key, trust policy,
or private key is stored here. Never use any label or digest in this directory
as production trust input.

`trusted-distribution.json` is a canonical
`github.com/wago-org/net/trusted-distribution/v1` receipt with an exact adjacent
SHA-256 sidecar. It represents only the shape of retained evidence from a prior
successful explicit-policy signature and archive verification.

`trusted-distribution-tampered.json` changes the opaque key label while
intentionally retaining the original receipt digest in its basename-correct
sidecar. It must be rejected. `vectors.json` also exercises wrong independently
provisioned subject, statement-digest, signature-digest, and trust-policy-digest
constraints. Tests check every listed file digest, canonical JSON bytes, sidecar
syntax, the positive case, and all negative outcomes.
