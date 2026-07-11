# Wago merged lifecycle/worker upstream review

Networking currently depends on the exact Wago merge object
`97e6f91e6c822491577faa86f3c30aa5a8fff1e8`. This object must be published
without rebasing, squashing, or replacing either parent:

```text
97e6f91 wago: integrate lifecycle hooks with worker plugins
|\
|  ffd5ef4 workers: harden lifecycle and resource bounds
54499ba wago: enforce extension reset eligibility
```

The first parent carries lifecycle hooks, exact host identity, and reset
eligibility. The second parent carries the reviewed worker implementation. The
merge resolution is the networking prerequisite: neither parent alone has the
combined contract exercised by `worker_lifecycle_test.go` and the release gate.

## Reproducible topology check

Run:

```sh
scripts/wago-upstream-review.sh
```

The script verifies the exact merge object, its ordered parents, the reviewed
main and worker ancestry, and that the parents remain divergent. It then reports
the current remote heads and whether any remote ref names the exact merge
object. Set `REQUIRE_PUBLISHED=1` to make absence of a fetchable ref fatal.

A review branch or immutable tag is suitable only if fetching it yields the
same `97e6f91` object. A squash merge, rebase, cherry-pick, or newly recreated
merge is a different prerequisite and requires a fresh networking audit and pin
update.

## Remote state observed on July 11, 2026

After fetching `origin`, the Wago audit found:

- `origin/main` at `7794acc82692aac4ff98756a46a017d0d8768087`;
- `origin/plugin-improvements` at
  `07a70b58ff26d2c8c49b5f879e7733cb375ec13f`;
- `origin/pr-232-workers-plugin` at
  `b0ca5a8f3329adb4ef7177bc81941803034fcc69`;
- no remote ref naming `97e6f91`.

The original worker parent `ffd5ef4` is an ancestor of the updated
`plugin-improvements` branch, but the networking merge is not. The updated
plugin branch also contains a broader, materially different plugin-plan and
managed-instance redesign. It is not a substitute for publishing the reviewed
merge object, and those later changes must not be silently folded into this
upstream operation.

The local merge remains based on the reviewed Wago main commit `8ef17eeb` through
its lifecycle first-parent line. Current Wago main has moved independently.
Publishing the existing merge first preserves an auditable prerequisite; any
subsequent integration with newer main should be a separate reviewed merge.

## Unrelated test defect

The pinned local lifecycle line still has two calls to an undefined test helper
`trapCode` in `src/wago/cross_instance_test.go`. The networking release gate
creates a temporary test-only helper, runs the Wago suites, and removes it. No
helper workaround is committed as networking work.

The July 11, 2026 `origin/main` version no longer references `trapCode`, so this
is a historical defect of the pinned local line rather than a reason to rewrite
or silently alter the reviewed merge. If upstream review wants the local line to
compile without the release helper, fix that defect in a separate commit whose
scope and parent are explicit.

## Reviewer checklist

1. Fetch `97e6f91` and verify `git rev-parse 97e6f91^1` is `54499ba` and
   `git rev-parse 97e6f91^2` is `ffd5ef4`.
2. Review the merge diff, not only the combined tip diff against current main.
3. Run the Wago lifecycle/worker tests and networking
   `scripts/release-signoff.sh` against the exact object.
4. Publish an immutable branch or tag that continues to name that object.
5. Only then enable hosted networking CI with the exact fetchable pin.
