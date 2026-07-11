# Deterministic release signoff

The release gate is `scripts/release-signoff.sh`. It runs from a clean plugin
checkout with clean production audit repositories, current Wago/networking
review worktrees, and the external workers checkout. It writes disposable logs
under `.wago/release-signoff/`.

## Pinned inputs

The script refuses revision drift before doing work:

| Repository | Required revision |
|---|---|
| Wago merged lifecycle/worker branch | `97e6f91e6c822491577faa86f3c30aa5a8fff1e8` |
| Wago lifecycle/reset parent | `54499ba5135f69a062e23a7255f4a408d6cecf8c` |
| Wago worker parent | `ffd5ef4b122cbd019897eeea3503789ab5860e4a` |
| lneto | `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` |
| WASI audit | `3df6c766ad00e83b314da799dbf9a77b409ad19d` |
| Current Wago lifecycle review | `e44b1baa6eabfba07967a4458fdb56983cb054ae` |
| Current networking registration review | `5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e` |
| External workers | `1e9139756d8a3c631c59c00b028038c83bfa8341` |

By default the production inputs are `.audit/wago`, `.audit/lneto`, and
`.audit/wasi`; current review inputs are `.wago/wago-current-plugin-lifecycle`,
`.wago/net-current-plugin-registration`, and `.wago/workers-plugin`. `../wago`
must resolve to the production Wago audit checkout because `go.mod` deliberately
uses the adjacent development replacement. Override locations with `WAGO_DIR`,
`LNETO_DIR`, `WASI_DIR`, `CURRENT_WAGO_DIR`, `CURRENT_NET_DIR`, and
`WORKERS_DIR`; revision checks still apply.

## Gate

```sh
scripts/release-signoff.sh
```

The gate performs, in order:

1. revision, merge-parent, toolchain, symlink, and initial clean-tree checks;
   the exact reviewed plugin-plan compatibility decision; a moving-ref
   publication/pool topology refresh for current Wago/net/workers; and an
   isolated audit of the reviewed docs/CI-only WASI upstream snapshot;
2. workspace and `GOWORK=off` Go tests, race tests, vet, package listing, and a
   no-change `go mod tidy`;
3. bounded fuzz smoke for DNS wire parsing, DNS ABI layouts, checked DNS guest
   memory, and shared ABI layouts (`FUZZTIME=3s` by default);
4. guest UDP/TCP poll and fixed UDP queue benchmarks with `-benchmem`;
5. TinyGo tests and a `linux/arm64` standard-Go package cross-build;
6. a separately cross-compiled `linux/arm64` test binary and bounded execution
   smoke when a native arm64 or `qemu-aarch64` runner is available;
7. source-boundary checks proving lneto imports remain in
   `internal/backend/lneto` and forbidden blocking/backoff APIs remain absent;
8. standard-Go and TinyGo custom CLI builds that blank-import `register`, compare
   inspection byte-for-byte, and require exactly four capabilities and 24
   imports (1 core, 6 DNS, 11 TCP, 6 UDP);
9. Wago `src/wago` plus facade tests, and focused lifecycle/worker/class race
   tests, using a temporary helper only for Wago main's unrelated missing
   `trapCode` test helper;
10. the complete pinned lneto test suite;
11. the pinned WASI suite, accepting only the documented native preview-1
    SIGSEGV signature if it remains; and
12. final clean-tree checks for production and current review repositories;
13. deterministic non-thin Git object packs for the exact plugin subject,
    production Wago/lneto/WASI inputs, current Wago/networking review subjects,
    and external workers, including all required ordered parents;
14. isolated reconstruction of the current Wago/net/workers/lneto workspace and
    Wago's local WASI module from those packs, with an initially empty module
    cache, network-disabled module resolution, exact `go.mod`/`go.sum` inventory,
    standard Go, focused linked-child race, vet, workers, TinyGo, and exact
    four-capability/24-import inspection checks;
15. deterministic machine-readable provenance plus SHA-256 verification of every
    retained evidence artifact and the manifest itself; and
16. standalone semantic verification and deterministic export of a compressed
    downstream review bundle.

Protocol-submodule release acceptance also includes
`internal/dependencytest`'s root/single/pair/all `go list -deps` matrix. During
the structural lneto Stage 4 split, those fixtures deliberately require the
shared `internal/backend/lneto/core`, all three extracted TCP/UDP/DNS adapters,
and the aggregate assembler in every graph. This is evidence of the remaining
root construction edge, not compile-isolation signoff. Before release completion,
the gate must be
changed to reject every omitted TCP/UDP/DNS adapter and namespace facet after
selective backend contributions replace the aggregate assembler.

`scripts/arm64-execution-signoff.sh` always cross-compiles a `CGO_ENABLED=0`
arm64 test binary before runner selection. `ARM64_EXECUTION=auto` (the release default)
records `executed-native`, `executed-qemu`, or a truthful `skipped-no-runner`
status. Use `ARM64_EXECUTION=required` on an arm64/QEMU CI tier so absence of a
runner is fatal; use `ARM64_EXECUTION=skip` only for an explicitly shortened job.
The smoke runs metadata plus real UDP, TCP, and DNS backend paths under a two
minute timeout. This executed result is intentionally distinct from the package
cross-build and must not be described as native support when skipped.

The linked-worker/class integration test is standard-Go/race-only (`!tinygo`):
it drives Wago's native JIT worker goroutines and blocking cooperative dispatch.
TinyGo still compiles and tests the complete networking packages, and the custom
TinyGo CLI includes the registered production plugin and must emit byte-identical
inspection.

The temporary Wago helper is removed by a shell trap. Any other Wago/WASI error,
revision drift, module-file change, generated artifact, or dirty tree fails the
gate. Set `RUN_WASI=0` only for a deliberately shortened PR job; release runs
must leave it enabled. `ALLOW_DIRTY=1` exists only for developing the signoff
scripts themselves and is not a release setting.

## Provenance artifacts

A passing gate writes `provenance.json` using schema
`github.com/wago-org/net/release-provenance/v2`. The manifest contains:

- the exact plugin revision/tree and Wago, lneto, and WASI revisions/trees,
  including Wago's ordered merge parents;
- first-class current networking, current Wago, and external workers review
  subjects with exact revisions, trees, and ordered parent lists;
- explicit current-review and production-Wago publication states, while fixing
  external workers as published, pooling as unsupported, publisher authentication
  as externally required, and hosted release automation as disabled;
- exact Go and TinyGo version strings;
- every named test, race, vet, tidy, fuzz, benchmark, source-boundary, TinyGo,
  cross-build, arm64-execution, inspection, audit-repository, and clean-tree
  result from `checks.tsv`;
- the byte-identical Go/TinyGo inspection hash, exact capability list, total
  import count, and imports grouped by module;
- the cross-build target separately from the arm64 execution status, runner, and
  compiled smoke-binary checksum;
- sorted paths, sizes, kinds, and SHA-256 hashes for all retained logs, generated
  inspection inputs/binaries, source-object packs/inventories, and status files;
  and
- narrowly accepted exceptions and truthful skipped-execution limitations.

`evidence.sha256` covers every retained artifact that existed before provenance
emission. `provenance.sha256` covers the canonical indented JSON manifest. The
release script verifies both checksum files before packaging. The manifest
deliberately has no wall-clock timestamp, hostname, absolute checkout path, or
hosted-CI assertion; identical inputs and evidence produce identical JSON.

## Standalone review verification

A passing gate exports `.wago/release-signoff.review.tar.gz`, its adjacent
`.sha256` file, and an unsigned canonical
`.wago/release-signoff.review.distribution.json` statement with its own checksum.
The archive contains only the manifest-listed evidence plus
`evidence.sha256`, `provenance.json`, and `provenance.sha256`. This includes seven
non-thin packs under `source-objects/` and canonical object inventories. The
production net pack contains the exact release subject's commit and complete
source tree; production Wago contains the merge commit, both ordered parent
commits, and all three complete source trees; lneto and WASI contain their exact
pinned commits and trees. Separate packs contain the exact current networking
review, current Wago lifecycle replay, and external workers commit/tree closures.
The isolated review output also records the exact local module mapping and
committed Go checksum lines used while `GOPROXY=off`; its fresh `GOMODCACHE`
acquires no module payload. No moving remote ref is needed to inspect those
snapshots. Tar paths are sorted;
uid/gid, names, modes, and timestamps are normalized; gzip metadata is fixed.
Byte-identical evidence therefore produces a byte-identical archive.

A downstream reviewer with Git installed can validate an extracted signoff
directory or the archive without the Wago, lneto, WASI, workers, current review,
or plugin source checkouts and without rerunning tests:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify -bundle /path/to/release-signoff.review.tar.gz
```

To require a separately obtained expected plugin commit, add
`-subject <40-hex-commit>`. To bind both values from a trusted distribution
channel, use strict mode with an independently obtained archive digest:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify \
  -bundle /path/to/release-signoff.review.tar.gz \
  -strict-distribution \
  -subject <40-hex-commit> \
  -bundle-sha256 <64-hex-sha256>
```

Strict mode rejects extracted directories and requires both values; the bundle
hash is checked before extraction and the subject is checked against canonical
provenance. Successful output also reports the recorded current-plugin and
production-Wago publication states, `publisher_authentication=external-required`,
and `hosted_release_automation=disabled`. This is hash pinning, not a signature
scheme or a hosted release activation claim.

The adjacent distribution statement is deterministic canonical JSON using schema
`github.com/wago-org/net/distribution-statement/v1`. It records only the exact
plugin subject, provenance SHA-256, review-bundle SHA-256, first-class review
subjects, and publication status already verified from the archive. It is kept
outside the archive to avoid a digest cycle and is suitable as the byte-exact
payload for detached signing by an external publisher system. It deliberately
contains no signature, key-discovery hint, or publisher identity claim. Recreate
it explicitly with:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode statement \
  -bundle /path/to/release-signoff.review.tar.gz \
  -out /path/to/release.distribution.json \
  -strict-distribution \
  -subject <40-hex-commit> \
  -bundle-sha256 <64-hex-sha256>
```

An external publisher may sign the exact statement bytes with Ed25519 and
publish the raw 64-byte detached signature separately. Verification requires an
operator-supplied canonical trust policy; no repository file, signature field,
key ID, URL, environment default, or network service is consulted to discover a
key. The v1 policy has this exact shape, with a canonical padded base64 32-byte
Ed25519 public key, an opaque local key label, and optional exact anti-rollback
constraints. An external activation system should provision both constraints
through its trusted channel; omitting them preserves key-only verification for
review interoperability:

```json
{
  "schema": "github.com/wago-org/net/distribution-trust-policy/v1",
  "keyId": "publisher-release-2026",
  "algorithm": "ed25519",
  "publicKey": "<canonical-base64-public-key>",
  "statementSha256": "<64-lowercase-hex-statement-digest>",
  "subject": "<40-lowercase-hex-plugin-commit>"
}
```

Public detached-signature interoperability vectors live under
`internal/releaseprovenance/testdata/distribution-signature-v1/`. They include a
canonical synthetic statement, canonical constrained trust policy, raw 64-byte
valid and invalid signatures, an altered canonical statement, and a checksummed
case manifest. The vector key is explicitly test-only and has no publisher
identity or production trust. Repository tests require exact-file-byte Ed25519
verification to accept only the positive case; no private key is tracked.

Verify a signed statement and bind it back to the archive with:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify-signed \
  -bundle /path/to/release-signoff.review.tar.gz \
  -statement /path/to/release.distribution.json \
  -signature /trusted-channel/release.distribution.sig \
  -trust-policy /operator-config/wago-net-trust-policy.json \
  -out /automation/release.trusted-distribution.json
```

The verifier checks any supplied policy statement-digest and subject constraints
before accepting the detached signature over the exact canonical statement
bytes, validates the archive digest before extraction, performs the full
standalone provenance/source-pack verification, and requires the statement's
subject, provenance digest, review subjects, and publication status to match the
archive. This prevents a still-valid signature made by the same key for another
or older statement from silently satisfying a pinned activation policy. The
trust-policy key ID is reported as an operator label only and cannot trigger
implicit key discovery. Successful signed verification also reports the SHA-256
values of the exact raw signature and canonical trust-policy bytes, so signature
replacement or policy rotation remains visible even if an operator reuses an
opaque key label. When `-out` is supplied, it atomically retains a canonical
`github.com/wago-org/net/trusted-distribution/v1` receipt plus adjacent `.sha256`
sidecar. That intermediary evidence binds the Ed25519 algorithm, opaque key
label, subject, statement, signature, trust-policy, provenance, and archive
digests. It records successful cryptographic and archive verification, not a
real-world publisher identity or production-readiness decision. Unsigned
`verify`, unconstrained key-only signed review, and strict hash-pinned
verification remain available for workflows that do not assert a pinned
production selection.

A retained trusted-distribution receipt can be checked later without the review
archive, statement, signature bytes, trust policy, or public key when the
verifier independently receives the exact subject plus statement, signature,
and canonical trust-policy digests selected by its trusted channel:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify-trusted-receipt \
  -receipt /automation/release.trusted-distribution.json \
  -subject <40-lowercase-hex-plugin-commit> \
  -statement-sha256 <64-lowercase-hex-statement-digest> \
  -signature-sha256 <64-lowercase-hex-signature-digest> \
  -trust-policy-sha256 <64-lowercase-hex-policy-digest>
```

Standalone verification requires canonical JSON, the exact adjacent `.sha256`
sidecar, complete receipt semantics, and all four external constraints. It
preserves evidence that the original command verified the exact cryptographic
and archive inputs; it does not repeat Ed25519 verification, establish publisher
identity, or make a production-readiness decision. Activation must still use the
strict readiness profile below against the original trusted inputs.

Public interoperability vectors live under
`internal/releaseprovenance/testdata/trusted-distribution-receipt-v1/`. They
provide one canonical synthetic receipt with its exact sidecar, a
basename-correct stale checksum for a tampered receipt, and wrong subject,
statement, signature, and trust-policy constraint cases. No statement, raw
signature, public key, trust policy, private key, signed release, production
identity, or readiness decision is stored there.

## Production release-candidate readiness

`scripts/release-candidate-readiness.sh` is the strict activation profile. It
freshly verifies the original archive, statement, detached signature, and
explicit policy; independently checks the canonical trusted-distribution receipt
retained by `verify-signed -out`; requires both results to bind the same key
label, subject, statement, signature, policy, provenance, and archive; then
requires:

- `currentPlugin=adopted` for exact fetchable current Wago/networking/workers
  subjects;
- `productionWagoMerge=published` while preserving both ordered parents;
- an `executed-*` linux/arm64 smoke result, not only a cross-build; and
- zero accepted exceptions, including both current WASI preview-1 exceptions.

Invoke it only with separately provisioned trust inputs:

```sh
REVIEW_BUNDLE=/path/to/release-signoff.review.tar.gz \
DISTRIBUTION_STATEMENT=/path/to/release.distribution.json \
DISTRIBUTION_SIGNATURE=/trusted-channel/release.distribution.sig \
DISTRIBUTION_TRUST_POLICY=/operator-config/wago-net-trust-policy.json \
TRUSTED_DISTRIBUTION_RECEIPT=/automation/release.trusted-distribution.json \
PRODUCTION_READINESS_RECEIPT=/automation/release.production-readiness.json \
  scripts/release-candidate-readiness.sh
```

The command atomically replaces the deterministic
`github.com/wago-org/net/production-readiness/v2` JSON decision and its adjacent
`.sha256` sidecar before exiting nonzero when any blocker remains. The v2 receipt
binds the Ed25519 algorithm, opaque trusted key label, exact subject, statement,
signature, canonical trust-policy, trusted-distribution receipt, provenance, and
review-bundle SHA-256 values plus the readiness boolean and ordered blockers.
The v1 receipt and verifier remain available for compatibility, but the strict
script now requires the linked v2 contract. A verification error emits no new
decision; a valid but blocked candidate retains
a checksummed denial for external automation rather than losing the reason in a
nonzero process result. The currently recorded review state is deliberately not
production-ready even with a cryptographically valid test signature: its exact
blockers are `current-plugin-not-adopted`,
`production-wago-merge-unpublished`, `linux-arm64-not-executed`, and the two
accepted WASI exception IDs. The profile does not activate hosted automation;
it is a prerequisite that must pass before an external publisher may enable it.

A retained receipt can be verified later without the review archive, signature,
or public key, provided the verifier independently receives the exact subject,
statement digest, and canonical trust-policy digest selected by its trusted
channel:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify-readiness-receipt \
  -receipt /automation/release.production-readiness.json \
  -subject <40-lowercase-hex-plugin-commit> \
  -statement-sha256 <64-lowercase-hex-statement-digest> \
  -trust-policy-sha256 <64-lowercase-hex-policy-digest>
```

Standalone verification requires the exact adjacent `.sha256` sidecar, canonical
JSON bytes, complete receipt semantics, and all three external constraints. It
returns success for either a valid ready decision or a valid blocked decision;
`ready=false` is retained evidence rather than corruption. Activation automation
must separately require `ready=true` after verification.

Public receipt interoperability vectors live under
`internal/releaseprovenance/testdata/readiness-receipt-v1/`. They provide
canonical synthetic ready and blocked receipts with exact sidecars, a
basename-correct stale checksum for a tampered receipt, and wrong subject,
statement, and trust-policy constraint cases. The vectors are not a production
decision or trust input and do not enable hosted automation.

The complete v2 retained chain can be verified without the original archive,
statement, signature bytes, policy, or public key when an independent trusted
channel supplies all five selection values:

```sh
GOWORK=off go run ./internal/cmd/release-review \
  -mode verify-release-decision-chain \
  -trusted-receipt /automation/release.trusted-distribution.json \
  -receipt /automation/release.production-readiness.json \
  -subject <40-lowercase-hex-plugin-commit> \
  -statement-sha256 <64-lowercase-hex-statement-digest> \
  -signature-sha256 <64-lowercase-hex-signature-digest> \
  -trust-policy-sha256 <64-lowercase-hex-policy-digest> \
  -trusted-receipt-sha256 <64-lowercase-hex-intermediary-receipt-digest>
```

The chain verifier checks canonical JSON and exact adjacent sidecars for both
receipts, all explicit constraints, the intermediary receipt digest, and exact
algorithm, opaque key label, subject, statement, signature, policy, provenance,
and archive linkage. It accepts either a valid ready or blocked decision. It does
not repeat Ed25519 or archive verification, establish publisher identity, or
make a fresh readiness decision; activation must separately require `ready=true`.
The standalone v1 readiness verifier above remains compatible with previously
retained receipts.

Public complete-chain interoperability vectors live under
`internal/releaseprovenance/testdata/release-decision-chain-v1/`. They bind every
listed fixture byte by SHA-256 and exercise synthetic linked ready and blocked
chains, a basename-correct stale readiness checksum, an individually valid but
wrongly linked opaque key label, and wrong subject, statement, signature, policy,
and intermediary-receipt constraints. No statement, signature bytes, public key,
trust policy, private key, signed release, production identity, real readiness
decision, or hosted-activation claim is stored there.

Verification rejects a different schema; changed or
unordered evidence; unknown or noncanonical manifest fields; unsafe archive
paths; wrong exact production or first-class current-review subjects, trees, or
parent order; inconsistent checks, exceptions, limitations, targets, revisions,
toolchains, or inspection
facts; and any extra or missing artifact. Each Git pack is indexed in an isolated
bare repository, checked for pack integrity, compared exactly with its canonical
object inventory, and required to contain no more and no less than the selected
commit objects plus their complete tree/blob closures. The manifest tree IDs and
ordered Wago parents are then re-derived from the packed objects. Verification
also requires the complete four-capability, 24-import surface and distinguishes
cross-build from executed or skipped arm64. Pack and bundle checksums establish
integrity and source availability, not publisher authenticity: obtain the
expected subject and archive checksum through a trusted release channel and use
strict mode when both are mandatory. The manifest records publisher
authentication as an external requirement and does not claim hosted CI
publication or that the local Wago merge has an upstream ref.

To export the source packs independently before provenance generation:

```sh
SOURCE_OBJECT_SUBJECT=$(git rev-parse HEAD) \
SOURCE_OBJECT_DIR=.wago/release-signoff/source-objects \
  scripts/release-source-objects.sh
```

To export or reproduce a bundle and its unsigned canonical statement from an existing passing evidence directory:

```sh
SIGNOFF_DIR=.wago/release-signoff \
REVIEW_BUNDLE=.wago/release-signoff.review.tar.gz \
  scripts/release-review-bundle.sh
```

## CI tiers

Use the same script rather than maintaining a second command matrix:

- **Pull request:** `RUN_WASI=0 FUZZTIME=1s scripts/release-signoff.sh` on native
  `linux/amd64` with Go 1.24.4 and TinyGo 0.41.1.
- **Nightly:** `RUN_WASI=1 FUZZTIME=30s scripts/release-signoff.sh`, retaining the
  `.wago/release-signoff` logs as artifacts.
- **Release candidate:** the default gate, plus repeated benchmarks on an idle
  pinned runner, the release tag/commit recorded beside `revisions.txt`, an
  externally signed canonical statement, and a passing
  `scripts/release-candidate-readiness.sh` decision.
- **Cross-platform:** native race/TinyGo remain required on `linux/amd64`; the
  gate also cross-builds standard Go for `linux/arm64`. An arm64 tier must set
  `ARM64_EXECUTION=required` and retain `arm64/status.txt`, `runner.txt`, the
  binary checksum, and test log before claiming executed arm64 support.

Hosted CI cannot truthfully fetch the current Wago prerequisite yet: the merged
commit above exists on the local `net/instance-close-hooks` audit branch and must
first be upstreamed without overwriting either Wago main or the divergent worker
history. `scripts/wago-upstream-review.sh` and
`docs/wago-upstream-review.md` verify and document the exact two-parent topology,
current remote divergence, and immutable-publication requirement.
`scripts/wago-plugin-plan-compat.sh` and
`docs/wago-plugin-plan-compatibility.md` separately pin the reviewed redesign
snapshot and prove why it requires a lifecycle/identity/worker migration rather
than a silent pin replacement. `scripts/current-plugin-review-signoff.sh`,
`scripts/current-plugin-topology-audit.sh`, and
`docs/current-plugin-review.md` bind and reconstruct the hardened current-main
review while keeping unpublished subjects review-only and pooling unsupported.
`scripts/wasi-upstream-preview1-audit.sh` and
`docs/wasi-upstream-preview1-audit.md` prove that the reviewed newer WASI tree
changes only documentation and CI, then reproduce the same native preview-1
SIGSEGV from an isolated exact-object export; the release pin therefore remains
unchanged. Once the networking merge is published, CI
should check out the exact pinned Wago, lneto, and WASI
revisions in the required adjacent layout and invoke this script. Do not replace
the pin with a moving branch.

## Updating pins

A pin update is a reviewed release change. Re-run the full gate, update the table
and constants together, record why each revision moved, and verify both Wago
merge parents. Never update a pin merely to make a failing checkout pass.
