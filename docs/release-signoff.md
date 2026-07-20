# Deterministic release signoff

The release gate is `scripts/release-signoff.sh`. It runs from a clean plugin
checkout with an exact clean production-Wago worktree, clean lneto/WASI inputs,
current Wago/networking review worktrees, and the external workers checkout. It
writes disposable logs under `.wago/release-signoff/`. The default production
Wago worktree is `.wago/wago-production-97e6f91`; the default current-review
worktrees are `.wago/wago-current-plugin-lifecycle-ff04a6b1` and
`.wago/net-current-plugin-registration-18615546`. Release output paths are
validated before replacement: by default they must stay beneath the plugin
checkout's `.wago/` artifact root, and obvious destructive targets such as `/`,
`$HOME`, source repositories, their ancestors, and the active working directory
are rejected even when an explicit override is supplied.

## TLS granular-only signoff status

The outbound `net.tls` client is intentionally absent from the aggregate
`register` bundle and its historical aggregate evidence. Standard-Go unit,
focused race, source-boundary, dependency-isolation, ABI, certificate/hostname,
ALPN, truncation, corruption, bounded-queue, quota, and worker-join checks apply
to explicit `tls.Register` composition fixtures separately. TLS has no
self-registering extension and no canonical custom-CLI policy entry because a
zero-configuration bundle would have to invent deployment trust and identity
authority. Aggregate completeness therefore remains exact without claiming TLS
signoff. TLS must not be called production-ready until the complete release gate
is regenerated with TLS-aware lifecycle evidence and a truthful TinyGo decision
for `crypto/tls` and `crypto/x509`.

## Pinned inputs

The script refuses revision drift before doing work:

| Repository | Required revision |
|---|---|
| Wago merged lifecycle/worker branch | `97e6f91e6c822491577faa86f3c30aa5a8fff1e8` (tree `adbba31c51996f1c1d6d3c2069de8ddf0afd94ee`) |
| Wago lifecycle/reset parent | `54499ba5135f69a062e23a7255f4a408d6cecf8c` |
| Wago worker parent | `ffd5ef4b122cbd019897eeea3503789ab5860e4a` |
| lneto | `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` |
| WASI audit | `3df6c766ad00e83b314da799dbf9a77b409ad19d` |
| Current Wago main + preview-1/managed/exact-slot review | `d556b20ff8667a8ae17b1ca399c74a949ac78f2f` |
| Current networking socket-lifecycle review | `362ddf815904340aefc526d4bc57e1c7a24d36c9` |
| External workers | `1e9139756d8a3c631c59c00b028038c83bfa8341` |

By default the production inputs are `.wago/wago-production-97e6f91`,
`.audit/lneto`, and `.audit/wasi`; current review inputs are
`.wago/wago-current-plugin-lifecycle-ff04a6b1`,
`.wago/net-current-plugin-registration-18615546`, and
`.wago/workers-plugin`. Prepare or verify the production Wago worktree with:

```sh
scripts/prepare-production-wago.sh
```

The preparation script may read Git objects from `.audit/wago`, even when that
source worktree has user-owned modifications, but it never resets, cleans, or
overwrites that source. An existing substitute must already be clean and match
the exact revision, tree, and ordered parents; wrong or dirty substitutes fail
closed. The release gate generates a disposable Go workspace and module file so
workspace Go, `GOWORK=off` Go, TinyGo, arm64 cross-compilation, and custom CLI
builds all select this exact clean source instead of the development
`go.mod`/`go.work` replacements. Override locations with `WAGO_DIR`,
`LNETO_DIR`, `WASI_DIR`, `CURRENT_WAGO_DIR`, `CURRENT_NET_DIR`, and
`WORKERS_DIR`; all revision and cleanliness checks still apply.

## Gate

```sh
scripts/release-signoff.sh
```

The gate performs, in order:

1. revision, tree, ordered merge-parent, toolchain, selected-module, and initial
   clean-tree checks; the exact reviewed plugin-plan compatibility decision; a moving-ref
   publication/pool topology refresh for current Wago/net/workers; a dual-line
   audit of the production-derived and current integrated Wago preview-1 fixes;
   and an isolated audit of the reviewed production-line WASI snapshot;
2. workspace and `GOWORK=off` Go tests, race tests, vet, package listing, and a
   no-change `go mod tidy`;
3. deterministic discovery and bounded execution of every current Go fuzz
   target, including wire parsers, ABI layouts, guest memory, resource handles,
   exact-instance lifecycle, and protocol operation models (`FUZZTIME=3s` by
   default, with the complete package/target manifest and per-target logs retained);
4. deterministic discovery of every current Go benchmark, followed by one
   bounded run per package/target with `-benchmem`, `100ms`, `count=1`, and
   `cpu=1`; zero discovered targets, any failed target, or incomplete evidence
   fails the gate after all discovered targets have been attempted;
5. TinyGo tests and a `linux/arm64` standard-Go package cross-build;
6. a separately cross-compiled `linux/arm64` test binary and bounded execution
   smoke when a native arm64 or `qemu-aarch64` runner is available; set
   `ARM64_EXECUTION=skip` when arm64 execution is outside the selected release
   profile, which records `skipped-disabled` without claiming or retaining an
   execution artifact;
7. source-boundary checks proving lneto imports remain in
   `internal/backend/lneto` and forbidden blocking/backoff APIs remain absent;
8. standard-Go and TinyGo custom CLI builds for the explicit all-protocol
   `register` bundle and all eleven granular bundles (`tcp`, `udp`, `dns`,
   `icmpv4`, `ntp`, `mdns`, `dhcpv4`, `linklocal4`, `ipv6`, `icmpv6`, and
   `dhcpv6`); byte-for-byte inspection comparison via production `plugin inspect`
   or current `pkg inspect`; and exact policy-defined capability/import counts.
   Historical packed
   review subjects that predate granular packages retain the aggregate-only
   inspection path and legacy artifact names;
9. Wago `src/wago` plus facade tests, and focused lifecycle/worker/class race
   tests, using a temporary helper only for Wago main's unrelated missing
   `trapCode` test helper;
10. the complete pinned lneto test suite;
11. the pinned WASI non-corpus and four passing corpus cases, plus four isolated
    faulting cases accepted only when they match the exact package, test,
    SIGSEGV code, equal address/PC, and `runtime.sigpanic` return-PC signature; and
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

### Current repository validation on July 15, 2026

The current branch passed standard Go, shuffled Go, race/shuffle, vet, source
boundaries, checkptr, accepted-diagnostic linux/386 coverage, TinyGo, focused
lifecycle race repetitions, and custom CLI inspection. Discovery found **40 fuzz
targets in 30 packages**, **168 benchmarks in 49 packages**, and **12 custom CLI
bundles** (eleven granular plus the explicit all-protocol bundle). Every fuzz
target passed a one-second smoke run; every benchmark passed once with `100ms`,
`count=1`, `cpu=1`, and `-benchmem`; and every Go/TinyGo bundle inspection was
byte-identical under its policy entry.

This is not a claim that the complete strict release signoff passed. The exact
strict attempt stopped during prerequisite cleanliness checks because the
pre-existing external production worktree `.wago/wago-production-97e6f91` has
`M src/wago/bottomref_test.go`. The release process must not clean, reset,
overwrite, or bypass that worktree with `ALLOW_DIRTY=1`; rerun only after its
owner makes the exact pinned worktree clean. Hosted release automation remains
disabled, and publication/adoption/readiness blockers remain external to this
repository validation.

### Protocol-submodule validation on July 11, 2026

The selective architecture passed workspace and `GOWORK=off` tests, race, vet,
TinyGo, source boundaries, direct and granular dependency fixtures, twentyfold
focused protocol/core repetitions, eight practical one-second fuzz targets,
allocation-reporting guest-poll/UDP-queue benchmarks, linux/arm64 package and
smoke-binary cross-compilation, and standard-Go/TinyGo inspection of `net`,
`net-tcp`, `net-udp`, and `net-dns`. The pack-only cold-cache reconstruction of
the pinned historical current-plugin review also passed after the custom CLI
kept its aggregate-only compatibility mode. Arm64 execution was truthfully
`skipped-no-runner`.

The moving-ref compatibility blocker is resolved locally. Current Wago review
`d556b20ff8667a8ae17b1ca399c74a949ac78f2f` preserves exact lineage through
exact-slot fix `d556b20f`, managed-wrapper fix `59ce1c13`, patch-equivalent
preview-1 fix `16163fb8`, upstream main `ff04a6b1`, benchmark-only parent
`bbaa494e`, and authoritative lifecycle commit `1a912c69`. The two later
upstream commits change no `src/wago` file. The integrations directly invoke
local wrapper table entries and bound forced synchronous callbacks to declared
slots, preserving external managed-worker callbacks while the wrapper-descriptor
WASI correction remains active. Selective networking review
`362ddf815904340aefc526d4bc57e1c7a24d36c9` passes standard Go, focused race,
vet, TinyGo, and exact direct, managed, failed-setup, and external-worker socket
cleanup. Active retained UDP data, TCP listeners and outbound streams, pending
DNS queries, resource tables, quotas, readiness registrations, packet links,
and attachment maps are checked through Wago lifecycle close. Pack-only
cold-cache reconstruction retains these checks. The reconstructed custom CLI inspects all four keys:
`net`, `net-tcp`, `net-udp`, and `net-dns`.

A strict `RUN_WASI=1 FUZZTIME=1s` run passed on July 11, 2026, at plugin subject
`e76869c4991b408e1c25093fd98ced52f369d3f2`. It used the clean
`.wago/wago-production-97e6f91` worktree while preserving the pre-existing
`.audit/wago/src/wago/bottomref_test.go` modification. Standard workspace and
module-mode Go, race, vet, idempotent generated-module tidy, eight fuzz targets,
benchmarks, TinyGo, arm64 cross-build, granular custom CLI inspection, exact Wago
and lneto suites, the accepted WASI signature, final clean-tree checks, all seven
source packs, cold-cache current-review reconstruction, provenance verification,
and standalone bundle verification passed. The provenance SHA-256 was
`4ecf8956e6ede7d4bd1e4733a011cd20f257173ce8c37a9b430da39761226c1e`; the
review bundle SHA-256 was
`fe615d7af0eb86dc3526be5eb2c347860cb02d5db7af12a039c517d1f0c867a2`.
Arm64 execution remained truthfully `skipped-no-runner`; current
Wago/networking review subjects and the production ordered-parent Wago merge
remain unpublished, and that historical run retained the then-broad WASI
preview-1 exceptions.

A newer strict `RUN_WASI=1 FUZZTIME=1s` run passed on July 11, 2026, at plugin
subject `ee30bb92e4813c42b80f5ab3ef3162e4bdfdeaf0`. The WASI gates now require an
exact matrix: `markdown`, `crcsum`, `base64x`, and `jsonproc` pass, while isolated
`blake3sum`, `script`, `regexmatch`, and `bignum` runs must each fail only
`github.com/wago-org/wasi/p1` with SIGSEGV code `0x1`, equal fault address/PC,
and the same `runtime.sigpanic` return PC. Positive and negative matcher fixtures
reject other tests, packages, panics, timeouts, extra selected tests, and
address/PC drift. The complete release path again passed standard/module Go,
race, vet, tidy, fuzz, benchmarks, TinyGo, arm64 cross-build, granular custom
CLI inspection, Wago/lneto, final clean trees, seven source packs, cold-cache
review reconstruction, provenance, and standalone bundle verification. It
recorded 115 artifacts, two exact accepted exceptions, one arm64 limitation,
provenance SHA-256
`ad999e2801f75d7f482f889ae02a251dbcb9673d577dc58135444cad08833ef9`, review
bundle SHA-256
`d1d5409df116719a4cd0bc89af524f47a65914828513f11b8b32b73ac1cf1a9a`, and
distribution-statement SHA-256
`069a352b766a66e5bbf8cc249d9a4a376df08e3d796a363b172ff76ea59f56a7`.
Publication truth and `skipped-no-runner` remained unchanged.

A historical post-integration strict rerun at plugin subject
`2021be6cebcb65e17cb10e7839e151db92747d1d` correctly stopped when the Wago
moving ref advanced. The current topology now binds upstream main
`ff04a6b1093628e025e3c2f78aa6ba6184e78bcb` (tree
`cc15e8c2eb42a396f34d0e50d2dc69b4e1722db4`, parent `bbaa494e`), intermediate
benchmark commit `bbaa494e` (tree `4d52d41637015b021b3ec50fe23c790fe6124d20`,
parent `1a912c69`), authoritative lifecycle commit `1a912c69`, and the three
fresh review children above; production selection and exception status remain
unchanged.

The historical pre-ledger-amend strict `RUN_WASI=1 FUZZTIME=1s` run at plugin
subject `09ac5c6ca8abc26f5da18e28eb583aaf1d04b7ba` passed the complete gate on
the prior current-Wago review `da4db3c9`. It retained production Wago `97e6f91`,
the exact two WASI exceptions, and truthful `skipped-no-runner` arm64 status. Provenance
SHA-256 was `2ba169276160007b58d7d03e06218a51bf91b87e22062520857c2358ea75b4eb`,
review bundle SHA-256 was
`1c3ba2be1df84966e66ed5a7aceca02253cdd9e91f60bd2963da7c1ca8922116`, and
distribution-statement SHA-256 was
`9d1566adf2fb3c415fe56ca69940adf66b9c956706b9fd925fccbad46491120e`.

Production-derived Wago fix review
`5c7f76dba0aa82ca94a1dd644318ed062b03f7cc` (tree
`442d6a7506260565bccb01e32e016f6dccc25d6c`, direct parent production merge
`97e6f91`) keeps synchronous-host funcrefs on the wrapper ABI. Current-Wago port
`16163fb8` has the same stable patch ID. Managed-wrapper child `59ce1c13` and
exact-slot child `d556b20f` (tree
`457770eff0a8af628715ae1305151d5f534d0af4`) preserve managed table callbacks
and strict declared callback widths without weakening the wrapper correction.
`scripts/wasi-preview1-fix-review.sh` re-fetches publication refs, verifies both exact lineages, runs full current Wago,
focused race, TinyGo, production WASI `1a7eeb2`, and current capability-based
WASI `cbdb9b32`. Production still selects exact `97e6f91`; remove the two
exceptions only after a fixed subject is published without rewriting the merge,
selected as the production Wago input, and the strict gate passes with zero
exceptions.

Protocol-submodule release acceptance also includes
`internal/dependencytest`'s root/single/pair/all `go list -deps` matrix. Every
fixture requires the shared instance, ABI, namespace, and lneto cores. Each
selected protocol must contribute its public facade, checked binding,
instance-operation package, fixed ABI, namespace facet, and exact lneto adapter;
every omitted protocol unit is rejected. Granular `tcp/register`, `udp/register`,
and `dns/register` graphs are checked separately and must contain only their
selected protocol, while root `register` must contain all three without reaching
`compat`. All selective production graphs also reject the temporary aggregate
namespace package and aggregate lneto assembler.

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

The temporary Wago helper is created only in the selected clean substitute and
removed by a shell trap. The dirty source audit worktree is never used for that
helper. The WASI exception runner disables core dumps and executes each named
faulting subtest in its own `go test` process; a successful formerly faulting case
also fails closed so the exception must be removed and the production input
reviewed. Any other Wago/WASI error, revision/tree/parent drift, selected-module
mismatch, generated-module instability, repository module-file change, generated
artifact, or dirty selected tree fails the gate. Set `RUN_WASI=0` only for a deliberately shortened PR job; release runs
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
- positive discovered benchmark target/package counts, the exact
  `100ms`/`count=1`/`cpu=1`/`benchmem=true` settings, and the canonical benchmark
  check detail;
- the byte-identical Go/TinyGo inspection hash, exact capability list, total
  import count, and imports grouped by module;
- the cross-build target separately from the arm64 execution status, runner, and
  compiled smoke-binary checksum;
- sorted paths, sizes, kinds, and SHA-256 hashes for all retained logs, generated
  inspection inputs/binaries, source-object packs/inventories, and status files,
  including `benchmark/targets.tsv`, `benchmark/detail.txt`, and exactly one
  nonempty package-grouped `benchmark/logs/.../<target>.log` per manifest row;
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
review, current Wago integrated-fix review, and external workers commit/tree closures.
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

The source-object exporter now stages a sibling temporary directory and renames
it into place only after successful generation, preserving any previous valid
result until the replacement is ready. Set
`ALLOW_SOURCE_OBJECT_DIR_OUTSIDE_WAGO=1` only for an intentional external
artifact directory; the Go path-safety policy still rejects destructive targets.

To export or reproduce a bundle and its unsigned canonical statement from an existing passing evidence directory:

```sh
SIGNOFF_DIR=.wago/release-signoff \
REVIEW_BUNDLE=.wago/release-signoff.review.tar.gz \
  scripts/release-review-bundle.sh
```

## Bounded fuzz smoke

Run the complete current fuzz surface without maintaining a hand-written target
list:

```sh
FUZZTIME=1s scripts/fuzz-smoke.sh
```

The runner discovers package/target pairs from `go test -json -list`, sorts them
deterministically, executes every target for the configured duration, reports
each pass or failure, and exits nonzero only after all discovered targets have
been attempted. Set `FUZZ_LOG_DIR` to retain `targets.tsv` and one log per target.
Scheduled and manually dispatched GitHub CI runs this one-second matrix; release
signoff uses the same runner with its selected `FUZZTIME` and retains the logs.

## Bounded benchmark smoke

Run the complete current benchmark surface without a hand-written target list:

```sh
BENCH_LOG_DIR="$PWD/.wago/benchmark-smoke" scripts/benchmark-smoke.sh
```

The runner uses the exact selected dependency workspace, discovers targets with
`go test -json -list '^Benchmark' ./...`, sorts and deduplicates package/target
pairs into `targets.tsv`, fails when discovery is empty, and attempts every
target even when an earlier target fails. Each target receives one bounded
`-benchmem` run with defaults `BENCHTIME=100ms`, `BENCHCOUNT=1`, and
`BENCHCPU=1`. `detail.txt` records the canonical positive target/package counts
and settings, while `logs/<package>/<target>.log` retains each nonempty result.
Release provenance rejects unsorted or empty manifests, missing/empty/extra logs,
settings drift, detail drift, and artifact-inventory tampering. Scheduled and
manual CI invoke this same script and retain the evidence directory.

## CI tiers

The hosted workflow is intentionally smaller than strict release signoff while
external release prerequisites remain unavailable:

- **Pull request and push:** run ordinary, shuffled, race, vet, source-boundary,
  checkptr, and accepted-diagnostic linux/386 coverage on native `linux/amd64`
  with Go 1.24.4.
- **Nightly/manual evidence:** run `FUZZTIME=1s scripts/fuzz-smoke.sh` and
  `BENCH_LOG_DIR="$RUNNER_TEMP/benchmark-smoke" scripts/benchmark-smoke.sh` in
  hosted CI, retaining the discovered benchmark manifest, canonical detail, and
  per-target logs. The full local release profile remains
  `RUN_WASI=1 FUZZTIME=30s scripts/release-signoff.sh` once all external pinned
  prerequisites are clean and fetchable.
- **Strict local release:** run `RUN_WASI=1 scripts/release-signoff.sh` only with
  exact clean pinned worktrees; do not use `ALLOW_DIRTY=1` to turn a prerequisite
  failure into a release result.
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
`scripts/wasi-upstream-preview1-audit.sh`,
`scripts/test-wasi-preview1-exception.sh`, and
`docs/wasi-upstream-preview1-audit.md` prove that the reviewed newer WASI tree
changes only documentation and CI, then bind the retained production exception
to the exact four-pass/four-fault preview-1 matrix. The separate
`scripts/wasi-preview1-fix-review.sh` verifies the minimized Wago-only root cause,
patch-equivalent production/current fix commits, the current managed-wrapper
compatibility child, and complete passes for production WASI `1a7eeb2` and
current WASI `cbdb9b32`. The production WASI pin therefore remains unchanged,
while production exception removal waits for fixed Wago publication and adoption. Once the networking merge is published, CI
should check out the exact pinned Wago, lneto, and WASI
revisions in the required adjacent layout and invoke this script. Do not replace
the pin with a moving branch.

## Updating pins

A pin update is a reviewed release change. Re-run the full gate, update the table
and constants together, record why each revision moved, and verify both Wago
merge parents. Never update a pin merely to make a failing checkout pass.
