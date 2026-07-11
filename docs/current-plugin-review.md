# Current plugin review evidence and publication gate

The production networking pin remains the ordered-parent Wago merge
`97e6f91e6c822491577faa86f3c30aa5a8fff1e8`. A separate review line proves the
same least-authority lifecycle contract on current Wago plugin APIs without
silently replacing that production prerequisite:

| Review source | Exact revision | Exact tree |
|---|---|---|
| Wago lifecycle replay | `e44b1baa6eabfba07967a4458fdb56983cb054ae` | `826ac3cc506c8ebe1b6631992bf9acb4304ee879` |
| Networking registration and workers composition | `5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e` | `2ab621daa95f38878ba7cae1893333cf73d759c3` |
| External workers | `1e9139756d8a3c631c59c00b028038c83bfa8341` | `ca79d1fb02f19ae15d7b166ffc179c01f9a7c212` |

`scripts/release-source-objects.sh` exports these three exact commit/tree
closures in addition to the production net/Wago/lneto/WASI evidence. The
standalone review verifier requires their revisions, trees, and ordered commit
parents. These packs establish source availability and integrity; they are not
publisher signatures and do not make an unpublished object an upstream release.

## Isolated adoption proof

After the packs are created, `scripts/current-plugin-review-signoff.sh` imports
only the bound net, Wago, workers, and lneto packs into disposable shallow
repositories. It verifies each exact commit, tree, and parent list before
checking out source, then creates an isolated Go workspace and runs:

- the complete networking standard-Go suite;
- the external linked-child cleanup test five times under the race detector;
- networking vet;
- external workers standard-Go, race, and vet checks;
- the complete networking TinyGo suite; and
- byte-identical standard-Go/TinyGo CLI inspection requiring exactly four guest
  capabilities and 24 imports.

The external worker test spawns and links a real managed child, attaches
UDP/TCP/DNS state, resolves the exact caller during a child host callback, and
proves handles, quotas, readiness registrations, and attachment maps retire
before worker-exit observation. Ordinary networking still requests only
`host.imports` and `instance.lifecycle`; the workers plugin separately requires
managed-instance authority.

The isolated gate uses immutable packed source rather than the mutable review
worktrees. Its output is retained under
`.wago/release-signoff/current-plugin-review/` and is required by standalone
bundle verification.

## Publication and pool topology

`scripts/current-plugin-topology-audit.sh` refreshes Wago, workers, and net
remote refs before deciding whether the review can be adopted. It requires the
review commits and parent order locally, requires the exact workers subject to
remain fetchable, and checks the exact current Wago documentation and workers
source before preserving the statement that pooling is unsupported.

The default `CURRENT_PLUGIN_ADOPTION=review` mode permits bound local review
objects while reporting that unpublished Wago/net subjects are not adopted.
`CURRENT_PLUGIN_ADOPTION=adopted` additionally requires the exact Wago and net
review commits to appear at upstream refs. `REQUIRE_PUBLISHED_WAGO_MERGE=1`
independently requires the production two-parent merge to be fetchable. Neither
mode permits rebasing, squashing, or substituting a moving branch.

Current Wago documentation reserves pooling for a future external plugin, the
reviewed workers repository contains no pool implementation, and the topology
audit rejects a newly visible pool-named `wago-org` repository until its exact
source is separately reviewed. This is intentionally an unsupported/no-claim
status, not evidence of compatibility with an implementation that has not been
found.
