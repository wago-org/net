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
  pinned runner and the release tag/commit recorded beside `revisions.txt`.
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
