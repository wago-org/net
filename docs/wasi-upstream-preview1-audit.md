# WASI upstream preview-1 audit

Networking's production release gate remains pinned to Wago WASI
`3df6c766ad00e83b314da799dbf9a77b409ad19d`. The separately reviewed
production-line review snapshot is
`1a7eeb215229e05bcb0f09d5cb3280d231739def`, two documentation/CI commits
later. Current `origin/main` is now `cbdb9b32a3f28c0e63c7ab40d9c59712162367c4`,
which adds capability-based registration for current Wago and is reviewed
separately below. The native fault is minimized and locally fixed in
production-derived Wago review `5c7f76dba0aa82ca94a1dd644318ed062b03f7cc`,
but that Wago subject is not yet a published production input.

Run the retained production exception audit after fetching WASI and Wago refs:

```sh
git -C .audit/wasi fetch --all --prune
scripts/wasi-upstream-preview1-audit.sh
```

Run the separate fixed-Wago review without mutating `.audit/wasi`:

```sh
scripts/wasi-preview1-fix-review.sh
```

The production upstream audit uses the exact reviewed objects and reports later
movement of `origin/main`. `REQUIRE_CURRENT_WASI=1` intentionally fails after
that movement until its production pin policy is explicitly revised. The
separate fixed-Wago review binds and tests exact current WASI `cbdb9b32` without
changing the production input.

## Upstream WASI review result

The reviewed WASI range changes exactly two paths:

- `.github/workflows/ci.yml` adds an upstream GitHub Actions workflow using a
  sibling Wago checkout, Go 1.22, format/vet/build, race-enabled tests, and
  coverage upload;
- `README.md` is restyled and expanded, followed by a badge-only cleanup.

The executable audit hashes the complete Git tree inventory after excluding
those paths and requires the pinned and reviewed inventories to be equal. There
is no WASI implementation, test-corpus, manifest, or module change in the range.
The new workflow's moving Wago checkout and major-version action tags are
upstream CI choices, not immutable release evidence for this plugin.

The retained exception is no longer a broad `SIGSEGV` grep. Both the reviewed
and pinned production inputs must match this exact `p1.TestWASIApps` matrix on
linux/amd64 with Go 1.24.4:

- pass: `markdown`, `crcsum`, `base64x`, and `jsonproc`;
- native fault: `blake3sum`, `script`, `regexmatch`, and `bignum`.

Each fault runs alone in a subprocess and must fail only package
`github.com/wago-org/wasi/p1` with `fatal error: fault`, SIGSEGV code `0x1`, an
equal hexadecimal fault address and PC, and the same unexpected return PC from
`runtime.sigpanic`. A different test, package, exit status, panic, compile/link
error, timeout, address/PC mismatch, extra selected test, successful run, or
other failure is rejected. `scripts/test-wasi-preview1-exception.sh` supplies
positive and negative matcher fixtures.

## Minimized root cause and fixed review

The `blake3sum` failure was reduced from 57,427 bytes to a 6,719-byte module with
SHA-256
`3d93d0329b190e98c4956e0abe05039954f8bf61a22f833bf5a40af5798f668d`.
It declares one returning preview-1 import only to force Wago's synchronous-host
link path; `_start` never enters that host callback. The same low-address native
jump occurs with a direct no-op `wago.HostFunc`, proving that the WASI host
implementation is not the faulting component. Disabling Wago's amd64 register
ABI makes the reduced module pass.

Wago review `5c7f76db` is a direct child of the exact ordered-parent production
merge `97e6f91e6c822491577faa86f3c30aa5a8fff1e8`. It keeps local funcref
descriptors on the wrapper ABI when a module uses synchronous host imports,
while retaining the register-ABI fast path for other modules. Its focused
reduced regression passes, and the complete reviewed WASI suite passes all eight
corpus applications against that fix. `scripts/wasi-preview1-fix-review.sh`
verifies the exact fix revision/tree/parent, the underlying production merge
revision/tree/ordered parents, the reviewed WASI revision/tree, the minimized
trigger digest, source-worktree preservation, the focused Wago regression, and
the full isolated WASI suite.

The current-Wago line is explicit rather than silently rebased. Patch-equivalent
fix port `90018dad` follows lifecycle replay `8131d967`; integration child
`540c453d` directly invokes local untagged wrapper table entries so managed
worker callbacks remain valid. Current WASI `cbdb9b32` is the direct child of
`1a7eeb2` that adopts capability-based registration. Full current Wago, focused
standard/race regressions, TinyGo, all eight current WASI corpus cases, and the
pack-only networking external-worker lifecycle gate pass on exact integration
subject `540c453d`.

## Pin and production decision

**Retain WASI `3df6c76` and production Wago `97e6f91` for published evidence.**
The production-line WASI range through `1a7eeb2` has no implementation change
to adopt, and the native correction belongs to Wago. Later `cbdb9b32` is a
current-plugin registration adaptation, not a substitute production pin. The
local fix reviews prove the accepted exceptions can be
removed after the exact Wago correction is independently reviewed, integrated
without rewriting the ordered-parent production merge history, published at an
immutable ref, selected by release tooling, and passed through the complete
strict gate. Until then, both production exception IDs remain truthful and
fail-closed rather than silently treating an unpublished local Wago child as a
production dependency.
