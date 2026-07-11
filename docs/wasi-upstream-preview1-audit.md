# WASI upstream preview-1 audit

Networking's release gate remains pinned to Wago WASI
`3df6c766ad00e83b314da799dbf9a77b409ad19d`. The separately reviewed
`origin/main` snapshot is
`1a7eeb215229e05bcb0f09d5cb3280d231739def`, two commits later.

Run the executable audit after fetching WASI and Wago refs:

```sh
git -C .audit/wasi fetch --all --prune
REQUIRE_CURRENT_WASI=1 scripts/wasi-upstream-preview1-audit.sh
```

Without `REQUIRE_CURRENT_WASI=1`, the script audits the exact reviewed objects
and reports later movement of `origin/main`. This keeps the committed release
gate reproducible while making moving-head review explicit.

## Review result

The reviewed range changes exactly two paths:

- `.github/workflows/ci.yml` adds an upstream GitHub Actions workflow using a
  sibling Wago checkout, Go 1.22, format/vet/build, race-enabled tests, and
  coverage upload;
- `README.md` is restyled and expanded, followed by a badge-only cleanup.

The executable audit hashes the complete Git tree inventory after excluding
those two paths and requires the pinned and reviewed inventories to be equal.
There is no WASI implementation, test-corpus, manifest, or module change in the
range. The new workflow's moving Wago checkout and major-version action tags are
upstream CI choices; they are not immutable release evidence for this plugin.

The script exports the exact reviewed tree into an isolated directory, supplies
the reviewed networking Wago checkout only through the existing sibling
`replace` layout, and runs:

```sh
GOWORK=off go test ./... -count=1
```

On linux/amd64 with Go 1.24.4, the suite still reaches the same native
`p1.TestWASIApps` SIGSEGV signature after the other packages run. Any successful
suite or any different failure makes the audit fail so that the exception and
pin must be reviewed rather than silently retained.

## Pin decision

**Retain `3df6c76`.** The newer commits are reviewable documentation and CI
changes, but they do not fix the native preview-1 crash. Moving the release pin
would add no implementation correction and would not permit removing the narrow
accepted exception. A future pin update requires a reviewed code fix and a full
passing isolated native suite; documentation or a green moving-head badge is not
sufficient.
