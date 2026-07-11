# Deterministic release signoff

The release gate is `scripts/release-signoff.sh`. It runs from a clean plugin
checkout with three clean audit repositories and writes disposable logs under
`.wago/release-signoff/`.

## Pinned inputs

The script refuses revision drift before doing work:

| Repository | Required revision |
|---|---|
| Wago merged lifecycle/worker branch | `97e6f91e6c822491577faa86f3c30aa5a8fff1e8` |
| Wago lifecycle/reset parent | `54499ba5135f69a062e23a7255f4a408d6cecf8c` |
| Wago worker parent | `ffd5ef4b122cbd019897eeea3503789ab5860e4a` |
| lneto | `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` |
| WASI audit | `3df6c766ad00e83b314da799dbf9a77b409ad19d` |

By default these are `.audit/wago`, `.audit/lneto`, and `.audit/wasi`.
`../wago` must resolve to the Wago audit checkout because `go.mod` deliberately
uses the adjacent development replacement. Override locations with `WAGO_DIR`,
`LNETO_DIR`, and `WASI_DIR`; revision checks still apply.

## Gate

```sh
scripts/release-signoff.sh
```

The gate performs, in order:

1. revision, merge-parent, toolchain, symlink, initial clean-tree, and exact
   reviewed plugin-plan compatibility-decision checks;
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
12. final clean-tree checks for all four repositories; and
13. deterministic machine-readable provenance plus SHA-256 verification of every
    retained evidence artifact and the manifest itself.

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
`github.com/wago-org/net/release-provenance/v1`. The manifest contains:

- the exact plugin revision/tree and Wago, lneto, and WASI revisions/trees,
  including Wago's ordered merge parents;
- exact Go and TinyGo version strings;
- every named test, race, vet, tidy, fuzz, benchmark, source-boundary, TinyGo,
  cross-build, arm64-execution, inspection, audit-repository, and clean-tree
  result from `checks.tsv`;
- the byte-identical Go/TinyGo inspection hash, exact capability list, total
  import count, and imports grouped by module;
- the cross-build target separately from the arm64 execution status, runner, and
  compiled smoke-binary checksum;
- sorted paths, sizes, kinds, and SHA-256 hashes for all retained logs, generated
  inspection inputs/binaries, inventories, and status files; and
- narrowly accepted exceptions and truthful skipped-execution limitations.

`evidence.sha256` covers every retained artifact that existed before provenance
emission. `provenance.sha256` covers the canonical indented JSON manifest. The
release script verifies both checksum files before reporting success. The
manifest deliberately has no wall-clock timestamp, hostname, absolute checkout
path, or hosted-CI assertion; identical inputs and evidence produce identical
JSON.

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
than a silent pin replacement. Once the networking merge is published, CI
should check out the exact pinned Wago, lneto, and WASI
revisions in the required adjacent layout and invoke this script. Do not replace
the pin with a moving branch.

## Updating pins

A pin update is a reviewed release change. Re-run the full gate, update the table
and constants together, record why each revision moved, and verify both Wago
merge parents. Never update a pin merely to make a failing checkout pass.
