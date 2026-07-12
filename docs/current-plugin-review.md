# Current plugin review evidence and publication gate

The production networking pin remains the ordered-parent Wago merge
`97e6f91e6c822491577faa86f3c30aa5a8fff1e8`. A separate review line proves the
same least-authority lifecycle contract on current Wago plugin APIs without
silently replacing that production prerequisite:

| Review source | Exact revision | Exact tree |
|---|---|---|
| Wago current-main + preview-1/managed/exact-slot review | `d556b20ff8667a8ae17b1ca399c74a949ac78f2f` | `457770eff0a8af628715ae1305151d5f534d0af4` |
| Selective networking registration, socket-lifecycle cleanup, and workers composition | `362ddf815904340aefc526d4bc57e1c7a24d36c9` | `40e707389b44ccc075498d905265e3faa0407331` |
| External workers | `1e9139756d8a3c631c59c00b028038c83bfa8341` | `ca79d1fb02f19ae15d7b166ffc179c01f9a7c212` |

`scripts/release-source-objects.sh` exports these three exact commit/tree
closures in addition to the production net/Wago/lneto/WASI evidence. The
schema-v2 provenance manifest declares them as first-class `reviewSubjects`, and
the standalone verifier requires their revisions, trees, and ordered commit
parents before deriving the same identities from the packs. These declarations
and packs establish source availability and integrity; they are not publisher
signatures and do not make an unpublished object an upstream release. The review
chain is based directly on Wago `origin/main`
`ff04a6b1093628e025e3c2f78aa6ba6184e78bcb` (tree
`cc15e8c2eb42a396f34d0e50d2dc69b4e1722db4`, parent `bbaa494e`). Its exact
parent is benchmark-corpus commit `bbaa494ee47ece44739aeeeda333e76e6a75cb73`
(tree `4d52d41637015b021b3ec50fe23c790fe6124d20`), whose parent is authoritative
lifecycle commit `1a912c699d913fe3e398a5bc33bfdd9fbeeba391`. The two later
upstream commits change benchmark/CLI files but no `src/wago` file. Lifecycle
commit `1a912c69` owns exact-instance caller resolution, start/failure disposal,
panic-isolated lifecycle hooks, and deterministic concurrent close. The
moving-ref topology gate binds the full exact chain and fails closed on any
later movement.

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
`d556b20f -> 59ce1c13 -> 16163fb8 -> ff04a6b1 -> bbaa494e -> 1a912c69`.
Upstream `1a912c69` is the authoritative lifecycle implementation; the two later
upstream commits leave `src/wago` unchanged; `16163fb8` is patch-equivalent to
production-derived preview-1 fix `5c7f76db`; `59ce1c13` directly invokes local
wrapper table entries so the managed-worker dispatcher remains safe; and
`d556b20f` restores exact declared callback slot widths when caller resolution
forces synchronous host linking. Complete standard Go, focused race, TinyGo,
both matching WASI suites, and direct/managed/external linked-child tests pass.
The selective networking review preserves the registration review
`173b38a4d5a0db0e6058544576942a46b9d543df` through three bounded children:
`4cd6ff1e` exercises direct and managed close with a retained UDP datagram, live
TCP listener and outbound stream, and pending DNS query; `e79ae215` proves the
same resources retire when a later `AfterInstantiate` hook fails; and
`362ddf81` proves linked external-worker close retires the live socket set and
both parent and worker packet links. The chain preserves the root/protocol
compile boundaries and real Wasm dispatch under Wago's expiring caller identity.

The external worker test spawns and links a real managed child, attaches an
active UDP socket, TCP listener, outbound TCP stream, and DNS query, resolves the
exact caller during a child host callback, and proves handles, resource tables,
quotas, readiness registrations, packet links, and attachment maps retire before
worker-exit observation. Ordinary networking still requests only
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
