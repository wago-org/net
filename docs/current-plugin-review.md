# Current plugin review evidence and publication gate

The production networking pin remains the ordered-parent Wago merge
`97e6f91e6c822491577faa86f3c30aa5a8fff1e8`. A separate review line proves the
same least-authority lifecycle contract on current Wago plugin APIs without
silently replacing that production prerequisite:

| Review source | Exact revision | Exact tree |
|---|---|---|
| Wago upstream lifecycle + preview-1/managed/exact-slot review | `5385ea0a7d87332cc3926459ffb20d5cc36aff6e` | `b01ebcbd8ffaa5cb2a3159f2d0b3cf20e35e6735` |
| Selective networking registration and workers composition | `173b38a4d5a0db0e6058544576942a46b9d543df` | `ca7534943e653a6c04c63ec458fc00feb6350799` |
| External workers | `1e9139756d8a3c631c59c00b028038c83bfa8341` | `ca79d1fb02f19ae15d7b166ffc179c01f9a7c212` |

`scripts/release-source-objects.sh` exports these three exact commit/tree
closures in addition to the production net/Wago/lneto/WASI evidence. The
schema-v2 provenance manifest declares them as first-class `reviewSubjects`, and
the standalone verifier requires their revisions, trees, and ordered commit
parents before deriving the same identities from the packs. These declarations
and packs establish source availability and integrity; they are not publisher
signatures and do not make an unpublished object an upstream release. The review
chain is based directly on authoritative Wago `origin/main`
`1a912c699d913fe3e398a5bc33bfdd9fbeeba391` (tree
`77f69ddfa2d574174b7534a7adedc110e7c740e4`, parent `e335cc1e`). That upstream
commit owns exact-instance caller resolution, start/failure disposal,
panic-isolated lifecycle hooks, and deterministic concurrent close. The
moving-ref topology gate binds that exact base and fails closed on any later
movement.

## Isolated adoption proof

After the packs are created, `scripts/current-plugin-review-signoff.sh` imports
only the bound net, Wago, workers, lneto, and WASI packs into disposable shallow
repositories. It verifies each exact commit, tree, and parent list before
checking out source, then creates an isolated Go workspace and runs:

- the complete networking standard-Go suite;
- the external linked-child cleanup test five times under the race detector;
- networking vet;
- external workers standard-Go, race, and vet checks;
- the complete networking TinyGo suite; and
- byte-identical standard-Go/TinyGo CLI inspection of `net`, `net-tcp`,
  `net-udp`, and `net-dns`, requiring each exact capability/import surface.

The refreshed Wago review preserves the exact lineage
`5385ea0a -> f59d96c6 -> b1721328 -> 1a912c69`. Upstream `1a912c69` is the
authoritative lifecycle implementation; `b1721328` is patch-equivalent to
production-derived preview-1 fix `5c7f76db`; `f59d96c6` directly invokes local
wrapper table entries so the managed-worker dispatcher remains safe; and
`5385ea0a` restores exact declared callback slot widths when caller resolution
forces synchronous host linking. Complete standard Go, focused race, TinyGo,
both matching WASI suites, and direct/managed/external linked-child tests pass.
The selective networking review is a direct child of
`164ee79e98d7e51bf3553fb18b46fd2044b223aa`; it preserves the root/protocol
compile boundaries while replacing forgeable direct-host test calls with real
Wasm dispatch under Wago's expiring caller identity.

The external worker test spawns and links a real managed child, attaches
UDP/TCP/DNS state, resolves the exact caller during a child host callback, and
proves handles, quotas, readiness registrations, and attachment maps retire
before worker-exit observation. Ordinary networking still requests only
`host.imports` and `instance.lifecycle`; the workers plugin separately requires
managed-instance authority.

The isolated gate uses immutable packed source rather than the mutable review
worktrees. It starts with an empty `GOMODCACHE`, sets `GOPROXY=off`, supplies all
module paths from those local checkouts (including Wago's sibling WASI replace
and the custom CLI's workers replace), and rejects any downloaded module payload.
Before testing, it requires exact SHA-256 values for every participating
`go.mod`/`go.sum` and writes a canonical module/source/sum inventory. This keeps
the committed Go checksums enforced without relying on a warm cache or network.
Its output is retained under `.wago/release-signoff/current-plugin-review/` and
is required by standalone bundle verification.

## Publication and pool topology

`scripts/current-plugin-topology-audit.sh` refreshes Wago, workers, and net
remote refs before deciding whether the review can be adopted. It requires the
integrated Wago review and its full upstream/fix/integration parent chain
locally, requires the exact workers subject to remain fetchable, and checks the
exact current Wago documentation and workers source before preserving the
statement that pooling is unsupported.

The default `CURRENT_PLUGIN_ADOPTION=review` mode permits bound local review
objects while reporting that unpublished Wago/net subjects are not adopted. The
release gate converts this audited result into canonical `publication.txt` and
schema-v2 provenance fields; publisher authentication remains `external-required`
and hosted release automation remains `disabled` regardless of local evidence.
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
