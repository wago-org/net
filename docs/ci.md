# Continuous integration

`.github/workflows/ci.yml` runs on pull requests, pushes to `main`, manual
dispatches, and a weekly schedule. The workflow uses Go 1.24.4 with the Go module
and build caches enabled and has seven bounded jobs:

- **quality** runs the ordinary suite, one shuffled suite, `go vet`, and the
  backend/source-boundary guard;
- **tls-standard-go** runs `scripts/tls-signoff.sh`, retaining the exact public
  composition, security, ABI, dependency, mixed-transport, EOF, quota, and worker
  lifecycle ordinary/race evidence;
- **tinygo-supported** installs pinned TinyGo 0.41.1 and runs
  `scripts/tinygo-supported-test.sh` across the exact 123-package supported
  surface while retaining the reviewed five-package TLS exclusion;
- **race** runs the complete suite with the race detector and shuffle, with five
  repetitions only for scheduled or manually requested deep checks;
- **fuzz-smoke** runs all targets discovered by `scripts/fuzz-smoke.sh` on weekly
  schedules and manual dispatches;
- **benchmark-smoke** runs all targets discovered by
  `scripts/benchmark-smoke.sh` on weekly schedules and manual dispatches, then
  retains `targets.tsv`, `detail.txt`, and every package-grouped target log;
- **portability** runs strict pointer instrumentation and the strongest truthful
  linux/386 coverage currently possible.

TLS is intentionally absent from TinyGo rather than represented by a stub. The
TinyGo job uploads its supported and excluded manifests, canonical detail, and
per-package logs on failure and for scheduled/manual runs. The standard-Go TLS
job similarly retains its package/test manifests and logs. Static repository
tests require both script invocations and the pinned TinyGo version to remain in
the workflow.

The module intentionally develops against exact local Wago and lneto worktrees.
`scripts/ci-prepare-dependencies.sh` creates the ignored `.audit/wago` and
`.audit/lneto` replacements at the pinned reviewed revisions when they are not
already present. Existing worktrees at those exact revisions are preserved,
including local uncommitted audit changes; CI fetches detached exact commits
rather than compiling a moving branch. The fuzz and benchmark runners call the
same workspace-selection helper, so fresh hosted runners, local exact `.audit`
worktrees, and release-generated workspaces select pinned dependencies rather
than ambient `go.work` state.

## Discovered benchmark evidence

Run the scheduled/manual benchmark command locally with a new evidence path:

```sh
BENCH_LOG_DIR="$PWD/.wago/benchmark-smoke" scripts/benchmark-smoke.sh
```

The runner fails on zero discovery, sorts and deduplicates the `targets.tsv`
manifest, attempts every target, and defaults to one `100ms`, `cpu=1`,
`-benchmem` run per target. `detail.txt` records positive target/package counts
plus the exact settings, and `logs/<package>/<target>.log` records each result.
The workflow uploads the whole `benchmark-smoke` directory even when a target
fails, while release signoff records the same detail in `checks.tsv` and requires
the complete nonempty log set during standalone provenance verification.

## Checkptr strategy

Run the hosted check locally with:

```sh
scripts/ci-checkptr.sh
```

The script first compiles and initializes every package and test binary with
`-gcflags=all=-d=checkptr=2`. It then runs every test under the same
instrumentation except these two allocation-only assertions:

- `TestInstallNamespaceServicesAvoidsPerProtocolScratchForCommonSelections` in
  the root package;
- `TestNamespaceCompositionAvoidsPerServiceHeapGrowthForPlannedSuite` in
  `internal/namespace/core`.

Checkptr instrumentation intentionally adds allocations, so those tests cannot
truthfully enforce their ordinary-build exact `testing.AllocsPerRun` budgets in
that mode. They are named explicitly in the script and still run unchanged in
both ordinary and shuffled CI suites. No package is omitted: the two affected
packages are compiled under checkptr and all of their other tests execute under
checkptr.

## linux/386 strategy and blocker

Run the hosted architecture check locally with:

```sh
scripts/ci-386.sh
```

The script derives every repository package whose complete dependency graph
excludes Wago, then runs that full backend-neutral set on linux/386 with CGO
disabled. The `internal/dependencytest` meta-package is excluded from that set
because its tests intentionally spawn `go list` against Wago-dependent fixture
graphs; it remains covered by the ordinary suites and the full 386 attempt. The
script also attempts `GOARCH=386 go test ./...` every time. The complete build is
currently blocked in pinned Wago at
`src/core/compiler/frontend/frontend.go` because that compiler references
`runtime.HostCtrlFrameBytes`, which Wago's runtime package does not define for
386.

The script accepts only that exact known compiler diagnostic after the
backend-neutral tests pass. Any additional compiler diagnostic, test failure, or
panic fails CI. If Wago gains 386 support, the same full attempt must pass and
the script reports the blocker as resolved; the limitation therefore remains
visible rather than becoming a permanent package skip.
