# Detached Ed25519 interoperability vectors

These files are public **test vectors**, not a release, publisher identity, or
trust root. The private test key is not stored in this repository. Never trust
the public key in `trust-policy.json` for production.

All signatures use Ed25519 over the exact statement file bytes, including the
final LF. Do not hash, normalize, reserialize, or base64-decode the statement
before verification. The detached signature files are raw 64-byte values. The
public key is the canonical padded base64 encoding of the raw 32-byte key.

`vectors.json` records the expected cases and SHA-256 digests:

- `valid`: `signature.ed25519` verifies over `statement.json`;
- `altered-statement`: the valid signature does not verify over
  `statement-altered.json`; and
- `altered-signature`: `signature-invalid.ed25519` does not verify over the
  original statement.

The statement uses conspicuously synthetic subject and provenance/archive
digests. Its review-subject and publication shapes match the v1 verifier policy
so repository tests also prove canonical JSON, trust-policy anti-rollback
constraints, key decoding, and the raw cryptographic outcomes. Full distribution
verification additionally requires a real review archive matching every signed
field; these vectors intentionally provide no such archive.
