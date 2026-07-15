# Wago networking implementation ledger

## Mission

Deliver a production-quality family of capability-gated Wago networking plugins
with a stable backend-neutral guest ABI, deterministic per-instance ownership,
and lneto as the first backend.

## Invariants

- Networking imports are nonblocking except for bounded `poll`.
- Guest memory is validated centrally; guest slices never outlive a host call.
- Each instance owns one generation-safe resource table, bounded readiness coordinator, and finite quota account.
- Handles are opaque, kind-checked, stale-safe, and never Go pointers.
- Statuses are stable numeric values; Go error text is not guest ABI.
- Raw IP, raw Ethernet, and capture authority are denied by default.
- Protocols are independently selectable at registration and compile time: a TCP-only client exposes and compiles no UDP or DNS plugin module.
- Endpoint policy is enforced at every authority-changing operation.
- Instance cleanup is deterministic and never relies on guest destructors or finalizers.
- Each recursive iteration produces exactly three bounded atomic commits unless the project completes earlier.

## Pinned analysis revisions

- Reviewed Wago main base: `ff04a6b1093628e025e3c2f78aa6ba6184e78bcb` (tree `cc15e8c2eb42a396f34d0e50d2dc69b4e1722db4`, parent `bbaa494ee47ece44739aeeeda333e76e6a75cb73`, 2026-07-11). Intermediate benchmark commit `bbaa494e` (tree `4d52d41637015b021b3ec50fe23c790fe6124d20`) is a direct child of authoritative lifecycle commit `1a912c699d913fe3e398a5bc33bfdd9fbeeba391`; neither later upstream commit changes `src/wago`. Current integrated review `d556b20ff8667a8ae17b1ca399c74a949ac78f2f` (tree `457770eff0a8af628715ae1305151d5f534d0af4`) preserves lineage through exact callback-slot child `d556b20f`, managed-wrapper child `59ce1c136492be44f8f4d252096bda01d3ef4a22`, patch-equivalent preview-1 fix `16163fb8975443b599d1065cc357db77d3ae5840`, exact upstream main, the benchmark parent, and the authoritative lifecycle ancestor. The prior `5385ea0a -> f59d96c6 -> b1721328 -> 1a912c69` chain and all earlier ports remain historical evidence only.
- Wago merged lifecycle/worker branch: `97e6f91e6c822491577faa86f3c30aa5a8fff1e8` on `net/instance-close-hooks`, with ordered parents `54499ba5135f69a062e23a7255f4a408d6cecf8c` and `ffd5ef4b122cbd019897eeea3503789ab5860e4a`.
- External workers main: `1e9139756d8a3c631c59c00b028038c83bfa8341`, pinned as `v0.0.0-20260711080606-1e9139756d8a`. Exact Wago documentation reserves pooling for a future plugin; workers contains no pool implementation, and the refreshed `wago-org` repository inventory exposes no pool-named repository.
- Current selective networking review: `362ddf815904340aefc526d4bc57e1c7a24d36c9` (tree `40e707389b44ccc075498d905265e3faa0407331`), with exact socket-cleanup children `e79ae21532c2a60c60d0524855db0cc38dd17598` and `4cd6ff1e22d751e4a7a112a1eadf04da3e77ef1f` above registration review `173b38a4d5a0db0e6058544576942a46b9d543df`. It preserves protocol compile isolation against integrated Wago `d556b20f` and proves active UDP, TCP listener/stream, DNS, packet-link, quota, readiness, and resource cleanup for direct, managed, failed-setup, and external-worker lifecycle paths.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: production remains `3df6c766ad00e83b314da799dbf9a77b409ad19d`; production-line review `1a7eeb215229e05bcb0f09d5cb3280d231739def` changes only README/CI files and has an implementation-tree inventory identical to the pin. Current WASI `cbdb9b32a3f28c0e63c7ab40d9c59712162367c4` (tree `b77c7e975c29de5bcff9da4464ce50d9b8ad2c65`, parent `1a7eeb2`) adds capability-based registration required by current Wago. Production Wago `97e6f91` matches the exact four-pass/four-fault preview-1 matrix. Production-derived fix `5c7f76dba0aa82ca94a1dd644318ed062b03f7cc` and current integrated review `d556b20f` each pass their complete matching WASI suites, but all local Wago fix subjects remain unpublished and unadopted.

## Approved protocol-submodule target

The staged implementation and acceptance plan is maintained in
[`docs/protocol-submodule-migration.md`](docs/protocol-submodule-migration.md).

The next public API architecture must make protocol adoption simple while keeping
advanced configuration available. TCP, UDP, and DNS become separate public Go
packages and separate compilation units. The root package remains a lightweight
composition and shared-lifecycle layer and must not import any protocol package.
The intended default path is:

```go
network := wagonet.New()
tcp.Register(network)
return runtime.Use(network)
```

Additional protocols compose explicitly:

```go
network := wagonet.New()
udp.Register(network)
tcp.Register(network)
dns.Register(network, dns.Resolver("192.0.2.53"))
return runtime.Use(network)
```

Registration must be exact. Registering only TCP advertises only `net.info` and
`net.tcp`, and provides only `wago_net.abi_version` plus `wago_net_tcp.*`. The
UDP and DNS capabilities, import modules, bindings, configuration, and backend
adapters must be absent. A guest requesting an unregistered import fails ordinary
Wasm import resolution rather than reaching a placeholder that returns
`NOT_SUPPORTED`. An empty network either registers nothing or fails clearly; the
first selected protocol may add the shared `wago_net.abi_version` import.

Compile-time isolation is mandatory, not merely linker dead-code elimination or
conditional calls inside one Go package. The target package graph is:

```text
github.com/wago-org/net                 shared composition/lifecycle only
github.com/wago-org/net/tcp             TCP API, defaults, ABI bindings
github.com/wago-org/net/udp             UDP API, defaults, ABI bindings
github.com/wago-org/net/dns             DNS API, defaults, ABI bindings
internal/backend/lneto/core             shared stack/link machinery
internal/backend/lneto/tcp              TCP backend only
internal/backend/lneto/udp              UDP backend only
internal/backend/lneto/dns              DNS backend only
```

Protocol-specific configuration moves with its package (`tcp.Config`,
`udp.Config`, and `dns.Config`). The shared network builder owns exactly one
per-instance namespace, lifecycle attachment, resource identity domain, policy
composition, quota ledger, and readiness coordinator regardless of how many
submodules are selected. Subpackages register implementations into that shared
builder without the root importing them.

Defaults must make ordinary client adoption useful without constructing raw
policy rules. TCP defaults allow finite outbound client connections with
nonprivileged ephemeral local ports and bounded buffers, but listeners remain an
explicit grant. UDP defaults allow finite outbound unicast, ephemeral wildcard
binding, and replies, while privileged binds, multicast, broadcast, and broad
server binding remain explicit. DNS defaults allow valid A/AAAA queries through
an explicitly configured or inherited resolver with finite query, response,
retry, and record limits. Common restrictions receive ergonomic package options;
raw policy and quota configuration remain advanced escape hatches. Fully
permissive behavior is available only through a conspicuous option such as
`tcp.AllowAll()`, `udp.AllowAll()`, or `dns.AllowAll()`.

Self-registration is also granular: `tcp/register`, `udp/register`, and
`dns/register` compile and register only their own protocol plus shared core. The
existing root `register` package may remain as an explicit all-protocol bundle by
blank-importing those three packages. Existing `Init(Config)` behavior may remain
as a compatibility/advanced path during migration, but new documentation leads
with the selective submodule API.

Acceptance checks must inspect both runtime registration and the Go dependency
graph. TCP-only, UDP-only, DNS-only, and every supported combination must assert
exact imports and capabilities. A TCP-only fixture must have no dependency on the
UDP/DNS public packages or lneto adapters; equivalent checks apply to the other
protocols. The root package must have no protocol-package dependency, and only
the explicit aggregate registration package may include all protocols.

## Current architecture

The root extension owns distinct import modules because Wago assigns one owner
to an entire module. `wago_net` exposes `abi_version` under `net.info`;
`wago_net_udp` exposes complete namespace discovery plus UDP bind/send/receive,
close, and bounded poll under narrow `net.udp`; `wago_net_tcp` exposes the
complete listener/stream surface plus its own bounded poll under narrow
`net.tcp`; and `wago_net_dns` exposes complete bounded query iteration,
cancellation, close, and poll under narrow `net.dns`. `internal/abi` provides
uint64-checked guest ranges, disjoint multi-output validation, fixed v1
endpoint/UDP/TCP/DNS/poll layouts, and atomic encoders without exposing lneto
types. The 72-byte TCP stream layout contains handle/local/remote endpoints; the
8-byte partial-I/O result is written only for ready progress, while AGAIN/EOF
leave it unchanged. DNS uses 260-byte inline normalized names, 268-byte fixed
queries, and 560-byte atomic A/AAAA/CNAME records.

`internal/resource` provides O(1), kind-checked, generation-safe opaque handles
with never-reused table identities, safe slot retirement before generation wrap,
reverse-creation O(live) cleanup, fuzz coverage, and focused benchmarks. Each core
`Extension` owns an `internal/instance/core.Manager` that attaches one resource table,
one bounded readiness coordinator, one immutable compiled policy, and one finite
quota account to each exact Runtime-created `*wago.Instance`. Optional static IPv4
configuration transactionally creates a namespace handle and readiness entry;
UDP handles use the same rollback-safe path. Host callers resolve through optional
`wago.InstanceHostModule`, and `BeforeClose` removes state before poller, resource,
and quota teardown. The map is extension-local, not process-global. DNS queries use the same
transactional generation-safe table and readiness registration as UDP/TCP,
including copied iteration, cancellation, timeout/error readiness, rollback,
wrong-kind/stale/cross-instance rejection, and reverse-order lifecycle cleanup.

`internal/policy` compiles immutable allow/deny rules for transport, direction,
IP prefixes, port ranges, and normalized DNS suffixes. Deny always wins, unmatched
and malformed requests fail closed, and broad rules cannot bypass separate
zero-default gates for wildcard binds, loopback, multicast, limited IPv4
broadcast, or local bind/listen ports below 1024. IPv4-mapped IPv6 is rejected on
both rules and queries. Explicit operation checks cover UDP bind/send, TCP
listen/connect, and DNS resolve authority changes.

`internal/quota` accounts finite total and UDP/TCP/DNS resource counts, retained
queued bytes, DNS work, and bounded service work. Reservation/commit/rollback and
exactly-once allocation release are concurrency-safe. Guest poll uses a scoped
service charge that retains exact concurrent limits and panic cleanup without
allocating reservation/allocation tokens. Instance teardown closes readiness
registration before resources and closes the account last, then clears abandoned
reservations and rejects late work without underflow.

`internal/namespace` defines backend-neutral endpoints, categorized semantic
failures, UDP/TCP/DNS resources, readiness snapshots, and bounded manual service.
All potentially waiting operations are one-shot `Try` calls with explicit done,
would-block, in-progress, or EOF semantics. Validators cover endpoint family and
scope safety, stream partial I/O, datagram truncation including empty datagrams,
DNS record ownership, and service budget bounds. A compile-time fake backend
exercises the contract without importing lneto into the neutral layer.

`internal/packetlink` now owns fixed-capacity ingress and egress frame storage,
copies caller frames, supports explicit truncation and byte-budget rollback, and
atomically commits direct backend fills only on success. Queue-full, oversized,
and failed-fill paths retain no caller data; close clears all frame bytes.

`internal/backend/lneto` owns one `StackAsync` and packet link per namespace. Its
manual service path uses only immediate Ethernet ingress/egress, alternates work
under strict packet, byte, and operation-attempt budgets, maps lneto errors to
namespace failures, and performs deterministic two-namespace exchange. IPv4 UDP
uses adapter-owned fixed datagram queues plus lneto's immediate frame codecs
because the high-level wrappers back off and the exported mux cannot represent
empty payloads. TCP now uses fixed listener pools and outbound `tcp.Conn` storage,
but host-facing operations call only immediate `tcp.Handler` state/buffer methods
under the namespace lock; `tcp.Conn.Read`, `Write`, and `Flush` remain absent.
Connect/accept, partial I/O, EOF/reset semantics, half-close, policy, exact
resource/retained-storage quota, bounded readiness, port reuse, and abort cleanup
are covered. Accepted-stream close releases resource quota immediately; lneto's
private accepted list is preserved until the next bounded egress service probe,
which reclaims the pool slot and now reports one charged maintenance operation
even when it emits no frame. DNS uses adapter-owned immediate IPv4 UDP packets plus lneto DNS codecs,
finite concurrent queries, response/record/name retention, deterministic
service-attempt retries and timeout, semantic RCode mapping, policy and quota
ownership, and synchronous close. Responses must echo the exact requested
questions. Only a unique reachable CNAME chain and requested terminal A/AAAA
records are emitted; irrelevant/unrequested/duplicate answers are ignored,
conflicting chains and loops fail closed, and compressed wire parsing is directly
fuzzed. Truncated responses fail truthfully as temporary because TCP fallback is
not implemented.

`internal/readiness` provides a finite coordinator per instance resource table.
Registrations preserve exact handle kind, polls are level-triggered and bounded
by scans, event outputs, and namespace service attempts, and stale handles are
removed within the scan budget. Configured namespace plus UDP/TCP creation add
handles and registrations transactionally; wrong-kind close cannot unregister a
valid handle, and explicit close removes readiness before generation retirement.
Both protocol poll imports validate complete output capacity before work, use
per-instance scratch, and scope `scans + events + service_attempts` service units
for the call without heap-backed quota tokens. TCP poll is independently gated
by `net.tcp` and does not require `net.udp`. No poll sleeps or performs an
unbounded registration scan.

The companion Wago branch now merges deterministic lifecycle/reset/identity work
with the divergent worker-plugin history without overwriting either parent.
`BeforeClose` and `AfterClose` run in reverse order exactly once with shared
metadata, failed instantiation emits isolated error observers and closes any
created instance, hook panics cannot skip resource release, and direct/worker
origins are carried without increasing `Instance` size. Runtime-owned instance
metadata stores origin, GC inheritance, and optional expiring worker host-call
scope outside `Instance`; synchronous dispatch is rebound only after Runtime
ownership is attached. Low-level APIs remain hook-free, worker activation and
reset requirements commit transactionally, worker IDs/queues/runtime totals are
finite, linked parent close waits for child disposal, and exact host identity does
not expand `HostModule` or change the TinyGo-compatible `HostFunc` shape.
`Registry.RequireReinstantiation`, `Class.ResetPolicy`, and `Lease.Release`
downgrade in-place resets whenever an extension owns non-Wasm state. Networking
worker/class tests now prove UDP/TCP/DNS child state cannot cross leases.

A current-main Wago review worktree on `net/current-plugin-lifecycle-ff04a6b1` at
`d556b20ff8667a8ae17b1ca399c74a949ac78f2f` uses exact upstream main `ff04a6b1`,
whose benchmark-only parent `bbaa494e` follows authoritative lifecycle commit
`1a912c69` without changing `src/wago`, then applies patch-equivalent preview-1
fix `16163fb8`, managed-wrapper integration `59ce1c13`, and exact synchronous
callback-slot fix `d556b20f`. `HostImportAccess.CallerResolver` provides exact, expiring,
runtime-scoped caller identity under `host.imports` without granting
`instance.manage`; runtime and origin attach before imported or local start
functions; failed starts close extension state; lifecycle panics are isolated;
and concurrent close callers receive one completed result. Complete standard-Go,
focused race, TinyGo `src/wago`, current WASI, and networking direct/managed/
external-worker checks pass.

The current selective networking review at
`362ddf815904340aefc526d4bc57e1c7a24d36c9` compiles against that exact Wago
replay. Its three children above `173b38a` add exact active-socket cleanup proof
for direct, managed, failed-setup, and linked external-worker close. Ordinary networking requests only `host.imports` and
`instance.lifecycle`, uses strict checked handlers without an arity shim, and
does not request `instance.manage`. Direct and genuinely managed instances prove
exact four-capability/24-import registration, distinct UDP/TCP/DNS ownership,
and deterministic cleanup. The exact external workers source at
`1e9139756d8a3c631c59c00b028038c83bfa8341` spawns and links a real managed child
whose handles, quota, readiness, and attachment state retire before exit.

Release review bundles now include seven deterministic non-thin Git packs and
canonical inventories: production net/Wago/lneto/WASI plus exact current
networking, current Wago, and workers review source. Schema-v2 provenance declares
all three review subjects and exact publication status directly. The standalone
verifier rejects extra/missing/tampered objects, re-derives every selected tree
and parent list, and makes no publisher-authenticity or upstream-publication
claim. A committed isolated gate reconstructs current net/Wago/workers/lneto plus
Wago's local WASI module solely from those packs, begins with an empty
network-disabled module cache, requires exact module/checksum inventories, and
repeats standard Go, focused external-worker race, vet, TinyGo, and exact
inspection proof. Optional strict distribution verification additionally
requires separately supplied subject and bundle hashes. A moving-ref topology
audit leaves unpublished Wago/net subjects review-only, hosted activation
disabled, and pooling explicitly unsupported.

The review-bundle exporter emits a separate canonical distribution statement
binding the exact plugin subject, provenance hash, archive hash, review subjects,
and recorded publication truth without embedding a signature or publisher
identity. An optional verifier accepts only a raw detached Ed25519 signature and
an explicitly supplied canonical single-key trust policy; key IDs are opaque and
cannot trigger file, URL, environment, or network discovery. Optional exact
statement-digest and plugin-subject constraints prevent same-key rollback when
provisioned externally. Successful verification carries the SHA-256 of the exact
raw signature and canonical trust policy, so signature replacement or policy
rotation remains visible even if an opaque key label is reused. Public
positive/negative raw-signature vectors contain no private key or publisher
claim. Signed verification can atomically retain a separate canonical
trusted-distribution receipt plus exact sidecar binding the Ed25519 algorithm,
opaque key label, subject, statement, signature, trust-policy, provenance, and
archive digests. Standalone receipt verification requires independently supplied
subject, statement, signature, and trust-policy digests; it preserves evidence
integrity without repeating cryptography, establishing publisher identity, or
making a readiness decision. Public synthetic positive/tamper/constraint vectors
store no signature or trust key. The strict production-candidate profile freshly
repeats signature/archive verification from the original inputs, independently
checks that retained intermediary receipt, and requires exact linkage before
applying adopted-current-subject, published ordered-parent production Wago,
executed linux/arm64, and zero-exception requirements. It retains a new canonical
`production-readiness/v2` decision plus exact sidecar binding the signature and
trusted-distribution receipt digests while preserving v1 compatibility. The
complete retained chain can be verified independently under explicit subject,
statement, signature, policy, and intermediary-receipt constraints; both valid
ready and blocked decisions are evidence, not fresh cryptography or publisher
identity. Public synthetic linked ready/blocked/tamper/wrong-link vectors store
no signature, key, trust root, production decision, or hosted-activation claim.

## Completed work

- `dd82ec9a8963463e6516bf803bec58b3a89b89b3` — added deterministic Wago
  instance-close hooks. Targeted tests and race tests pass when a temporary helper
  is supplied for the unrelated missing `trapCode` test helper on Wago main.
- `eb0b79af59af5402f8d39c436123bbd33c019be7` — scaffolded the external plugin,
  packaging manifest, self-registration, ABI version/status definitions,
  architecture documentation, recursive skill, and durable ledger.
- `b3ec3be03dd809cf85e6faaa805ff8cd687d934a` — added centralized
  uint64-checked ranges, atomic output helpers, the fixed v1 IPv4/IPv6 codec,
  unit tests, and fuzz targets.
- `c005703fa32790def6befa076fcd7f9b14f20b31` — added typed generation-safe
  resource handles, strict stale/forged/wrong-kind/reuse/cross-table rejection,
  rollover retirement, deterministic cleanup, fuzzing, and benchmarks.
- `01569366a38e8f577c2764a11941908351cc9181` — added Wago's optional
  `InstanceHostModule` facade and exact identity tests while preserving minimal
  HostModule mocks and TinyGo's HostFunc shape.
- `423ac0ac765ce7aa548a666265d05c37753f477c` — attached extension-local state
  and one resource table per exact Runtime instance, with deterministic cleanup.
- `24e5d01` — added immutable endpoint/domain policy primitives, explicit
  privileged gates, precedence and normalization tests, and query fuzzing.
- `c1531fc` — added per-instance finite quota accounting with transactional
  reservations, concurrent tests, and lifecycle cleanup integration.
- `7a29b84` — added neutral endpoint/error/UDP/TCP/DNS/readiness/service
  contracts and compile-time fake backend semantic tests without adding lneto or
  guest imports.
- `dd9b06e` — added deterministic fixed-capacity packet-link ownership, atomic
  fill rollback, explicit truncation and queue semantics, close-race tests, and
  frame-ownership fuzzing.
- `a0ab41a` — added the pinned lneto dependency and one bounded `StackAsync`
  namespace service with deterministic exchange, semantic error mapping, exact
  budget tests, cleanup/race coverage, and unsupported protocol constructors.
- `8d34171` — added finite instance-scoped poll registration, level-triggered
  bounded scans/events/service, stale-handle removal, and lifecycle cleanup.
- `013fa4d` — added immutable configured instance state and transactional static
  namespace quota, handle, readiness, rollback, isolation, and lifecycle ownership.
- `af7b021` — added policy/quota-backed nonblocking IPv4 UDP resources with fixed
  queues, empty/truncated datagrams, lneto frame codecs, and deterministic close.
- `4e83723` — added transactional UDP handle/readiness ownership, kind-safe
  close, lifecycle/race/fuzz/benchmark coverage, and truthful architecture docs.
- `e0f5a97` — defined the fixed backend-neutral guest UDP/poll ABI, disjoint
  checked outputs, endpoint/result/event codecs, and complete stable status
  mapping including access denial.
- `4926424` — added exact-instance capability-gated UDP discovery, bind, send,
  receive, and close imports with generation/kind checks, policy/quota enforcement,
  failed-memory-write rollback, isolation, and deterministic guest tests.
- `d64a1f5` — added quota-accounted bounded guest polling, reusable per-instance
  event scratch, level/service/stale/cleanup tests, malformed-memory fuzzing,
  benchmark coverage, and package/docs signoff.
- `eb42b3c` — added immediate nonblocking lneto TCP listener/connect/accept,
  partial read/write, finish-connect, half-close, fixed buffers/pools, policy,
  quota, readiness, deterministic exchange/reset/EOF/close tests, and a source
  guard against the backoff wrappers.
- `c8efb7f` — added generation-safe instance-owned TCP listener/stream handles,
  transactional readiness registration, exact kind/cross/stale checks, rollback,
  partial-I/O state methods, root TCP configuration, and truthful non-advertising.
- `044c04d` — fixed v1 TCP stream and partial-I/O layouts, disjoint checked
  ranges, atomic codecs, stable IO status semantics, malformed-layout fuzz
  coverage, and documentation without registering an incomplete TCP module.
- `c07e7e1` — added unregistered checked TCP namespace/listen/connect/finish host
  functions, pre-allocation range validation, endpoint descriptors, rollback on
  impossible encoding failures, and policy/quota/kind/isolation tests.
- `6272362` — completed unregistered accept/read/write/shutdown/kind-specific
  close/TCP-poll host functions, AGAIN/EOF non-mutation, accept rollback, race,
  fuzz, bounded readiness, and guest-poll benchmark coverage.
- `9cb2b3d` — registers the complete `wago_net_tcp` table under narrow `net.tcp`,
  adds capability denial and full registered two-namespace exchange tests, and
  updates package/ABI/architecture documentation and inspection signoff while
  keeping DNS absent.
- `74e1e32` (Wago) — reconciles deterministic close hooks with the broader plugin
  lifecycle design: instantiate-error observers, close metadata, lifecycle
  origins, reverse-order before/after close, panic-isolated cleanup, transactional
  registration, low-level isolation, and exact host identity all coexist.
- `54499ba` (Wago) — adds transactional extension reset eligibility and dynamic
  class reset downgrading while preserving the 776-byte `Instance` size, minimal
  interfaces, low-level APIs, and `HostFunc` slot shape.
- `50d0694` — declares the networking reset requirement, proves snapshot-configured
  classes physically replace instances and retire UDP/TCP state between leases,
  and updates package, architecture, ABI, and ledger documentation.
- `f00adac` — adds bounded immediate lneto-backed DNS query resources with static
  resolver authority, finite response/record/retry bounds, deterministic timeout,
  semantic failures, copied A/AAAA/CNAME results, quota ownership, and race tests.
- `01aa36d` — owns DNS queries as generation-safe per-instance handles with
  readiness registration, cancellation, rollback, stale/wrong-kind/cross-instance
  rejection, deterministic cleanup, and race coverage.
- `fbd2c75` — adds fixed inline DNS name/query/record layouts, atomic codecs,
  stable iteration status mapping, malformed-memory fuzzing, and a complete but
  deliberately unregistered checked host-function table.
- `eb1e34a` — correlates exact echoed DNS questions, emits only unique reachable
  CNAME chains and requested terminal addresses, rejects conflicts/loops/malformed
  framing, and directly fuzzes compressed wire responses.
- `c471e4a` — exercises the complete checked DNS guest table against actual lneto
  namespaces for success, RCodes, timeout, truncation, cancellation, policy,
  quota, kind/isolation, bounded poll, checked memory, and lifecycle cleanup.
- `e39ed56` — registers the six-function `wago_net_dns` table under narrow
  `net.dns`, adds capability and exact metadata tests, and updates package and ABI
  documentation after full integration signoff.
- `97e6f91` (Wago merge) — integrates lifecycle/reset/identity work with worker
  primitives while preserving both histories, transactional activation, bounded
  worker quotas, panic-isolated reverse cleanup, reference-store behavior, exact
  host identity, GC inheritance, and the 776-byte `Instance` layout.
- `528594b` — proves linked workers receive exact instance-scoped networking
  state, `RequireReinstantiation` replaces class parents, UDP/TCP/DNS child
  handles retire between leases, reverse hook panics cannot skip cleanup, and
  failed callback validation releases both network state and worker quota.
- `ef86121` — adds pinned source-boundary, custom Go/TinyGo inspection, and full
  release-gate scripts plus reproducible release/CI documentation and clean-tree
  enforcement.
- `c8978a4` — adds an executable Wago upstream topology audit and review note that
  verifies the exact ordered merge parents, reports current remote divergence,
  distinguishes immutable publication from rebase/squash substitution, and
  records the pinned-line-only `trapCode` defect.
- `b3c0d13` — makes lneto accepted-slot reclamation visible as one charged bounded
  egress maintenance operation while preserving immediate resource-quota release,
  private accepted-list safety, no-frame progress truth, and actual slot reuse.
- `b6e08dc` — replaces temporary guest-poll reservation/allocation tokens with
  panic-safe scoped service accounting and removes the benchmark's
  value-to-interface boxing artifact, reducing complete pointer-backed UDP/TCP
  poll calls from three allocations to zero without changing ABI results or work
  accounting.
- `1749ae1` — pins executable evidence for the current Wago plugin-plan redesign,
  proving that lifecycle concepts remain but public exact identity, reset/class
  safety, reviewed workers, and panic-isolated close cleanup require a separate
  migration rather than a networking pin replacement.
- `ca88e01` — adds a separately cross-compiled linux/arm64 protocol smoke binary,
  native/QEMU runner detection, bounded execution, required/auto/disabled modes,
  checksummed artifacts, and truthful skipped-no-runner status distinct from the
  package cross-build.
- `d28ff4e` — records every release check, emits a timestamp-free
  machine-readable manifest for exact revisions, trees, toolchains, inspection,
  targets, evidence, exceptions, and limitations, and verifies sorted evidence
  and manifest SHA-256 files before success.
- `8b8d227` — audits reviewed WASI `origin/main` in an isolated exact-object
  export, proves the implementation inventory is unchanged across the docs/CI
  commits, reproduces only the known native preview-1 SIGSEGV, and retains the
  pinned release input with machine-recorded exception evidence.
- `a5eb683` (Wago review branch) — prototypes a `host.imports`-scoped exact caller
  resolver, correct managed-instantiation origin, and panic-isolated deterministic
  close for direct and managed plugin-plan instances without moving networking's
  production Wago pin.
- `39087ab` — adds strict repository-independent semantic verification of schema,
  exact pins and Wago parent order, checks, inspection, targets, artifacts,
  exceptions, and limitations, then exports a normalized deterministic tar.gz
  review set with a separately checksummed archive.
- `4ffec4d` (Wago review branch) — attaches runtime/origin before imported and
  local start, cleans failed instantiation state, isolates instantiate-error hook
  panics, replays local-start host calls, and makes concurrent close wait for one
  deterministic completion result.
- `49d4642` (networking review branch) — migrates ordinary registration to exact
  `host.imports` caller resolution plus `instance.lifecycle`, proves direct and
  genuinely managed UDP/TCP/DNS ownership/cleanup and exact 24-import inspection,
  and passes standard Go, race, vet, and TinyGo without moving production pins.
- `d582be7` — adds deterministic exact-object Git packs and canonical inventories
  for the production net/Wago/lneto/WASI trees, including both ordered Wago
  parents, and rejects pack, closure, tree, or parent drift.
- `e44b1ba` (Wago current review) — replays least-authority caller identity,
  start/failure cleanup, panic-isolated lifecycle, deterministic concurrent close,
  managed origin, and exact callback slot slicing onto fetched Wago main.
- `29d5916` and `5b444e9` (networking current review) — validate strict ordinary
  registration against Wago `e44b1ba`, then pin external workers and prove a real
  spawned linked child receives and retires complete networking state.
- `e359287` — binds exact current Wago/networking/workers commit, tree, and parent
  objects into deterministic review packs and standalone verification.
- `256dcb5` — reconstructs the exact current plugin workspace from immutable
  packs and gates standard Go, focused worker race, vet, TinyGo, and exact
  four-capability/24-import inspection; worker callback-validation tests retain
  their compiled source module until asynchronous spawn validation completes.
- `4f0b555` — refreshes moving refs, enforces review-only versus adopted
  publication policy, keeps the production merge parent order immutable, and
  preserves truthful unsupported pool status.
- `6a862e2` — upgrades deterministic provenance to schema v2 and declares exact
  current networking, Wago, and workers revisions, trees, and ordered parents as
  first-class review subjects verified against their source packs.
- `3500c6b` — reconstructs every current review module from bound local source,
  starts with an empty network-disabled module cache, pins exact module/checksum
  inventories, and rejects any downloaded module payload.
- `822508e` (`net: bind trusted distribution requirements`) — records explicit
  review/production publication truth without signature or hosted-activation
  claims and adds strict archive verification requiring independently supplied
  plugin-subject and bundle SHA-256 values; the moving organization inventory
  uses bounded retries for transient HTTP failures without hiding final errors.
- `196edd4` — emits a minimal canonical unsigned distribution statement outside
  the archive, binding the exact subject, provenance/archive hashes, review
  subjects, and publication status for detached signing without a digest cycle.
- `ad05d52` — verifies raw detached Ed25519 statements only against an explicitly
  supplied canonical trust policy, rejects implicit key discovery, and binds the
  signed fields back to full standalone archive/source-pack verification.
- `1712d41` (`net: gate production release candidate readiness`) — adds the strict
  trusted-statement activation profile and deterministic blocker report requiring
  published exact subjects, executed arm64 evidence, and zero accepted exceptions.
- `4f30eae` — lets the explicitly supplied trust policy pin the exact statement
  SHA-256 and/or plugin subject, rejecting valid same-key signatures for a
  different selection while preserving unsigned and key-only review modes.
- `f5e6813` — publishes exact-byte Ed25519 positive and negative interoperability
  vectors with canonical statement/policy metadata and no tracked private key,
  trust root, publisher identity, or release claim.
- `e90cb01` (`net: retain canonical production readiness receipts`) — binds strict
  decisions to the exact statement, provenance, archive, key label, and ordered
  blockers, then atomically writes canonical JSON plus an adjacent SHA-256 sidecar
  before returning the truthful ready/blocked process status.
- `fc17da1` — records the exact canonical trust-policy SHA-256 in trusted
  distribution verification and production-readiness receipts, distinguishing
  policy rotation even if an opaque key label is reused.
- `42de1b8` — independently verifies canonical retained readiness receipts and
  exact adjacent sidecars against required subject, statement, and trust-policy
  constraints while accepting valid blocked evidence.
- `5a059e3` — publishes deterministic synthetic ready/blocked receipts plus tamper
  and wrong-constraint cases without a production decision, publisher identity,
  or hosted activation.
- `d9eb62e` — atomically retains canonical trusted-distribution verification
  receipts binding exact signature, statement, policy, provenance, archive,
  subject, algorithm, and opaque key label while making no publisher-identity or
  readiness claim.
- `4eef20a` — independently verifies trusted-distribution receipt bytes and exact
  sidecars against required subject, statement, signature, and trust-policy
  constraints without treating retained evidence as fresh cryptographic proof.
- `33e53ce` — publishes deterministic synthetic trusted-distribution receipt
  positive, stale-checksum tamper, and four wrong-constraint cases without
  storing a signature, trust key, private key, signed release, production
  identity, or readiness decision.
- `86f2873` — adds a v2 readiness decision that freshly recomputes strict status
  from the original signed inputs and binds the exact signature and retained
  trusted-distribution receipt without mutating the published v1 contract.
- `8e60454` — independently verifies both canonical receipt/sidecar pairs and
  their exact linkage under explicit subject, statement, signature, policy, and
  intermediary-receipt constraints while preserving v1 compatibility.
- `39475a0` (`net: publish release decision chain interoperability cases`) —
  publishes deterministic synthetic linked ready/blocked, stale-checksum tamper,
  wrong-link, and wrong-constraint cases without storing signature bytes, a key,
  trust root, private key, signed release, production decision, or activation
  claim.
- `257658a` — adds the protocol-neutral composition registry, exact-instance host
  bridge, shared guest status/poll helpers, extracted TCP binding package, and
  public selective TCP facade with executable registration checks.
- `b1e5a2c` — extracts the six checked UDP guest bindings into
  `internal/binding/udp` while retaining a thin aggregate root shim.
- `3b87c84` — adds public selective UDP registration with exact inspection,
  unresolved-import, duplicate/freeze, nil, and exact-instance tests.
- `55ba876` — records the selective UDP migration without claiming compile
  isolation or finite defaults.
- `1401710` — extracts the six checked DNS guest bindings into
  `internal/binding/dns` while preserving the aggregate compatibility tests.
- `e5dbdf6` — adds public selective DNS registration with exact DNS-only runtime
  and ordinary unresolved TCP/UDP import tests.
- `281a6cc` — covers none, every single protocol, every pair, and all three
  through the public selective registration APIs.
- `1df0e4c` — records the selective DNS migration and its remaining compile
  isolation and finite-default blockers.
- `6f0339d` — adds explicit `compat.Init(Config)` aggregate construction and
  switches root `register` to that all-protocol bundle.
- `bd03baf` — removes production root aggregate registration and binding shims,
  retaining the historical same-package regression surface only in test code.
- `1f97b2b` — gates root, single, pair, and all-protocol fixtures with exact
  runtime inspection plus omitted public/binding dependency rejection.
- `a49f2bd` — relocates exact-instance ownership beneath
  `internal/instance/core` and switches the root lifecycle and host bridge to
  that shared package.
- `f151744` — extracts TCP listener/stream operations into
  `internal/instance/tcp`, preserves lifecycle-lock serialization and rollback,
  and rejects the operation package from non-TCP dependency graphs.
- `43f1dd9` — extracts UDP and DNS operations into their protocol packages,
  removes protocol methods from the core, and extends exact dependency gates.
- `01a8756` — extracts checked memory, address/endpoint, handle, and poll codecs
  into `internal/abi/core`, moves shared polling to that package, and keeps root
  compatibility constants literal so the root imports no protocol ABI package.
- `144afae` — extracts TCP stream/I/O layouts into `internal/abi/tcp`, switches
  TCP bindings to that compilation unit, and rejects it from non-TCP graphs.
- `46ff627` — extracts UDP receive-result and DNS name/query/record codecs into
  `internal/abi/udp` and `internal/abi/dns`, removes the combined ABI package,
  and gates every fixture against omitted protocol ABI packages.
- `a1b302f` — extracts shared namespace endpoint, failure, readiness, resource,
  service, and ownership contracts into `internal/namespace/core`, and makes the
  exact-instance manager own only that neutral base.
- `08acea5` — extracts the narrow TCP namespace/listener/stream contracts into
  `internal/namespace/tcp` and makes the unified backend implement them
  structurally without importing the TCP facet.
- `173c1f2` — extracts UDP and DNS namespace contracts and values, removes the
  aggregate namespace package from production graphs, and extends dependency
  gates for core/selected facets plus exact omitted TCP-facet rejection.
- `88756d2` — adds `internal/backend/lneto/core` with one protocol-neutral lock,
  stack, packet link, IPv4 identity, frame scratch, bounded participant scheduler,
  maintenance accounting, error mapping, and ordered deterministic close.
- `d4862d0` — composes the existing aggregate backend over that shared core while
  preserving DNS-before-UDP ingress, rotating DNS/UDP/stack egress, exact service
  budgets, one object/link owner, and DNS/TCP/UDP teardown order.
- `d4ecdfe` — extracts TCP listener/stream state into
  `internal/backend/lneto/tcp`, preserves immediate operations and accepted-slot
  maintenance charging, and records the still-unconditional aggregate import in
  dependency fixtures.
- `ce833fe` — adds one protocol-neutral core UDP-port lease domain and migrates
  explicit UDP binds plus DNS ephemeral source ports to exact shared collision,
  deterministic allocation, release, exhaustion, and close semantics.
- `d98ea0f` — extracts UDP sockets, fixed queues, frame codecs, readiness,
  policy/quota checks, and ordered service/cleanup into
  `internal/backend/lneto/udp` with focused exchange and lifecycle tests.
- `140beb2` — extracts DNS query state, wire codecs, retries, response filtering,
  readiness, policy/quota checks, and ordered service/cleanup into
  `internal/backend/lneto/dns`; release fuzzing now targets the exact package.
- `a645043` — adds immutable protocol-neutral namespace service composition and
  switches exact TCP/UDP/DNS operations to resolve only their selected facet.
- `f9c4561` — adds opaque backend contributions and delays manager construction
  until the immutable registration snapshot is frozen.
- `d7b9654` — makes public TCP/UDP/DNS descriptors install only their exact lneto
  adapter over one shared core, removes the root aggregate assembler edge, and
  preserves explicit legacy config mapping in `compat`.
- `2c6fbf4` — composes deep-copied protocol authority contributions with caller
  policy once before manager construction while preserving deny precedence.
- `6409e8e` — adds finite TCP outbound-client storage and authority defaults plus
  explicit listener, special-class, raw-policy, compatibility, and `AllowAll`
  options with actual default-flow denial tests.
- `9da92a8` — adds finite UDP ephemeral-unicast and explicit-resolver DNS client
  defaults, bounded ephemeral UDP port allocation, explicit advanced grants, and
  actual client-flow/default-denial tests while preserving `compat` policy.
- `abb48a8` — adds granular TCP/UDP/DNS self-registration packages, makes root
  `register` the explicit all-protocol bundle, and gates exact register graphs.
- `ea51e86` — directly covers advanced listener/server/special-class/suffix,
  default-suppression, raw-deny, `AllowAll`, and maximum simultaneous finite
  default behavior for TCP, UDP, and DNS.
- `b5bfc20` — instantiates every granular and aggregate self-registration factory,
  checks exact capability/import surfaces, and proves omitted imports remain
  unresolved.
- `da7ac6e` — extends standard-Go/TinyGo custom CLI inspection to granular
  protocol keys and moves release fuzz/benchmark commands to split packages.
- `c3b2b36` — adds exact revision/tree/ordered-parent verification and safe
  preparation of a clean production Wago worktree without cleaning or
  overwriting its potentially dirty source checkout.
- `685cdd7` — routes release workspace Go, module-mode Go, TinyGo, cross-build,
  custom CLI, source-pack, WASI, and provenance work through the selected clean
  production Wago source.
- `e76869c` — adds release-input fixtures proving dirty source preservation and
  fail-closed wrong/dirty substitutes, including linked-worktree compatibility.
- `e080b17` — records the exact clean-production-input strict signoff and remaining
  publication, arm64, and WASI blockers.
- `5c7f76db` (Wago production-derived fix review) — keeps synchronous-host funcref descriptors on
  the wrapper ABI, adds a minimized 6,719-byte regression, and makes the complete
  production-line preview-1 corpus pass without changing the guest ABI.
- `90018dad` (Wago current fix port) — applies the exact same stable patch ID to
  current lifecycle review `8131d967` and passes current WASI `cbdb9b32`.
- `540c453d` (Wago prior current integration) — directly invokes local untagged wrapper
  table entries for managed instances, preserving real external-worker callbacks
  while retaining the preview-1 correction; focused standard/race, full Wago,
  TinyGo, current WASI, and pack-only networking review gates passed on prior base
  `18615546`.
- `cf2409d3` (Wago refreshed lifecycle review) — replays the hardened lifecycle,
  caller identity, start/failure cleanup, deterministic close, and callback-slot
  changes onto exact upstream `2fbb34a5`; its stable patch ID matches `8131d967`.
- `2a9bf214` (Wago refreshed current fix) — replays the wrapper-descriptor
  preview-1 correction onto `cf2409d3`; its stable patch ID remains
  `6d81fbd5e4857b686580a2d18bec4f5ada227224`, matching production fix `5c7f76db`.
- `da4db3c9` (Wago refreshed current integration) — replays managed local wrapper
  table invocation onto `2a9bf214`; full Wago, focused race, TinyGo, current WASI,
  and direct/managed/external-worker networking lifecycle coverage pass.
- `b1721328` (Wago current upstream preview-1 fix) — ports the wrapper-descriptor
  correction directly onto authoritative upstream lifecycle commit `1a912c69`;
  stable patch ID remains `6d81fbd5e4857b686580a2d18bec4f5ada227224`.
- `f59d96c6` (Wago current upstream managed integration) — directly invokes local
  untagged wrapper table entries while preserving dispatcher behavior for tagged
  register-ABI and foreign-home descriptors.
- `5385ea0a` (Wago current upstream exact-slot integration) — bounds forced
  synchronous host callbacks to declared parameter/result slots, preserving
  strict networking handlers under `CallerResolver`; focused race, full Wago,
  TinyGo, current WASI, and direct/managed/external-worker networking pass.
- `16163fb8` (Wago refreshed current-main preview-1 fix) — ports the exact
  wrapper-descriptor correction onto upstream `ff04a6b1`; stable patch ID remains
  `6d81fbd5e4857b686580a2d18bec4f5ada227224`, matching production fix `5c7f76db`.
- `59ce1c13` (Wago refreshed current-main managed integration) — preserves direct
  local untagged wrapper invocation and dispatcher behavior for tagged or
  foreign-home descriptors on the exact current upstream base.
- `d556b20f` (Wago refreshed current-main exact-slot integration) — preserves
  declared callback slot widths under forced synchronous caller resolution;
  full Wago, focused race, TinyGo, current WASI, and direct/managed/external-
  worker networking tests pass.
- `a3c6123` — adds an exact-object audit for the Wago preview-1 fix review,
  underlying ordered-parent production merge, reviewed WASI tree, minimized
  trigger digest, focused Wago regression, and full isolated WASI suite.
- `ee30bb9` — replaces broad WASI crash matching with exact isolated passing and
  faulting subtests plus fail-closed package/address/PC/runtime-signature checks.

## Active work

The approved protocol-submodule architecture and its local acceptance surface are
implemented. Advanced authority tests now prove explicit TCP wildcard/privileged
listeners, UDP server/multicast/broadcast grants, DNS suffix-only policy,
default suppression, conspicuous `AllowAll`, and deny precedence. Simultaneous
ordinary defaults reach exactly eight TCP streams, eight UDP sockets, and eight
DNS queries under shared default quotas before truthful `RESOURCE_LIMIT`.

Self-registration factories `net-tcp`, `net-udp`, `net-dns`, and `net` now have
direct runtime inspection tests. Granular factories expose only their protocol
plus `wago_net.abi_version`, and omitted Wasm imports fail normal resolution.
The custom CLI release gate builds and compares standard-Go/TinyGo inspection for
all four keys. The refreshed current networking review now contains granular
packages itself, while aggregate-only compatibility remains available solely for
older historical source packs.

On July 11, 2026, workspace and `GOWORK=off` tests, race, vet, TinyGo,
source-boundary, direct/granular dependency fixtures, twentyfold focused tests,
eight practical one-second fuzz targets, allocation-reporting benchmarks,
linux/arm64 package and smoke-binary cross-compilation, granular custom CLI
inspection, deterministic source packs, and pack-only cold-cache external
reconstruction passed. The refreshed development release run additionally
completed 130,261 DNS-wire, 95,213 DNS-layout, 370,461 TCP-layout, 364,817
UDP-layout, 353,915 shared-layout, 54,760 guest-DNS, 78,312 guest-TCP, and 80,892
guest-UDP fuzz executions. Benchmarks measured 125.8 ns/op for guest UDP poll,
115.2 ns/op for guest TCP poll, and 20.83 ns/op for the UDP queue, all at 0 B/op
and 0 allocs/op. Arm64 execution remained `skipped-no-runner`.

The exact-object compatibility review is green: integrated Wago `d556b20f` and
selective networking `362ddf81` pass standard Go, focused race, vet, TinyGo,
exact least-authority direct/managed/external-worker lifecycle tests, granular
custom CLI inspection, deterministic source packs, and cold-cache pack-only
reconstruction. Dual-line review proves production fix `5c7f76db` and current
fix port `16163fb8` have the same stable patch ID; managed child `59ce1c13` and
exact-slot child `d556b20f` pass current WASI `cbdb9b32` without regressing
managed callbacks or strict host handler arity. The moving-ref topology gate now
binds upstream main `ff04a6b1`, intermediate benchmark commit `bbaa494e`, and
authoritative lifecycle ancestor `1a912c69`, while proving the later upstream
movement changes no `src/wago` file and failing closed on further movement. This
refresh required no networking source change. Full current Wago, focused race,
TinyGo, current WASI, and fivefold direct/managed/external-worker race coverage
pass on the new chain. Custom CLI inspection selects current `pkg inspect` while
retaining production `plugin inspect` compatibility.

The complete heavyweight local release gate is green. The prior strict
`RUN_WASI=1 FUZZTIME=1s` run at `ee30bb92e4813c42b80f5ab3ef3162e4bdfdeaf0`
used exact clean production Wago revision `97e6f91`, tree `adbba31c`, and ordered
parents `54499ba5` / `ffd5ef4b` while leaving the user-owned
`.audit/wago/src/wago/bottomref_test.go` modification untouched. Standard and
module-mode Go, race, vet, generated-module tidy, fuzz, benchmarks, TinyGo,
arm64 cross-build, granular custom CLI, Wago/lneto, exact WASI matrix, clean-tree,
source-pack, pack-only current-review, provenance, and standalone bundle checks
passed. The exact matrix records passing `markdown`, `crcsum`, `base64x`, and
`jsonproc`, and isolated native faults for `blake3sum`, `script`, `regexmatch`,
and `bignum`. Provenance SHA-256 was
`ad999e2801f75d7f482f889ae02a251dbcb9673d577dc58135444cad08833ef9`; bundle
SHA-256 was `d1d5409df116719a4cd0bc89af524f47a65914828513f11b8b32b73ac1cf1a9a`;
distribution-statement SHA-256 was
`069a352b766a66e5bbf8cc249d9a4a376df08e3d796a363b172ff76ea59f56a7`.
The refreshed pre-ledger-amend strict run at root subject `09ac5c6` also passed
end to end against current Wago `da4db3c9`: topology, dual-line fix review,
standard/module/race/vet/tidy, eight one-second fuzz targets, allocation-free
benchmarks, TinyGo, arm64 cross-build, granular custom CLI inspection, production
Wago/lneto and exact WASI suites, final clean trees, seven source packs,
cold-cache reconstruction, provenance, and standalone bundle verification. Fuzz
executions were 114,297 DNS-wire, 174,589 DNS-layout, 388,010 TCP-layout, 384,621
UDP-layout, 381,957 shared-layout, 56,466 guest-DNS, 82,997 guest-TCP, and 85,844
guest-UDP. Benchmarks were 118.9 ns/op guest UDP poll, 110.3 ns/op guest TCP poll,
and 20.10 ns/op UDP queue, all 0 B/op and 0 allocs/op. Provenance SHA-256 was
`2ba169276160007b58d7d03e06218a51bf91b87e22062520857c2358ea75b4eb`, bundle
SHA-256 was `1c3ba2be1df84966e66ed5a7aceca02253cdd9e91f60bd2963da7c1ca8922116`, and
statement SHA-256 was
`9d1566adf2fb3c415fe56ca69940adf66b9c956706b9fd925fccbad46491120e`.
Publication of current and production subjects, plus publication/adoption of an
exact fixed production Wago input before removing the two exact WASI exceptions,
remain production activation blockers rather than protocol architecture gaps.
Arm64 execution is explicitly outside the current user-selected release profile.

## Ordered backlog

1. Upstream the merged Wago lifecycle/reset/identity/worker branch at an immutable
   fetchable ref without rewriting Wago main or either parent history.
2. Publish current integrated Wago review `d556b20f` and networking review at exact
   immutable refs, then switch `CURRENT_PLUGIN_ADOPTION=adopted` only after the
   topology audit proves all adopted Wago/net/workers subjects fetchable. Do not
   substitute this for publication of the production merge.
3. Publish production-derived Wago preview-1 fix `5c7f76db` without
   rewriting the ordered-parent `97e6f91` merge history, and select that exact
   exact production input before removing either WASI exception. Activate hosted
   release automation only after that exact input is fetchable and selected.
4. Rerun the strict complete release gate on each final candidate subject using
   the exact clean production Wago worktree. Keep the dirty source-audit
   preservation fixture and the integrated Wago `d556b20f`, selective networking
   `362ddf81`, protocol, granular inspection, fuzz, benchmark, cross-build, and
   pack-only reconstruction gates unchanged.

## Blockers and discovered prerequisites

- The pinned production Wago line's `src/wago` tests still need a temporary
  test-only `trapCode` helper; current Wago main `ff04a6b1` does not have that
  historical defect. The helper is removed by the release gate.
- Integrated review `d556b20f` preserves the exact chain through exact-slot fix
  `d556b20f`, managed-wrapper fix `59ce1c13`, preview-1 fix `16163fb8`, exact
  upstream main `ff04a6b1`, benchmark-only parent `bbaa494e`, and authoritative
  lifecycle commit `1a912c69`; Wago owns exact callback slot
  slicing, expiring caller identity, start/failure cleanup, deterministic
  panic-isolated close, preview-1 wrapper descriptors, and managed wrapper-table
  dispatch. Selective networking `362ddf81` proves complete
  least-authority registration, exact protocol surfaces, active socket cleanup, and real
  external-worker composition. Deterministic packs and isolated reconstruction
  remove moving-ref dependence for review, but neither current Wago nor current
  networking review is fetchable
  from origin, so `CURRENT_PLUGIN_ADOPTION=adopted` correctly fails. Workers
  `1e913975` is fetchable. Schema-v2 provenance binds all three review subjects;
  cold-cache reconstruction uses only packed local modules with exact committed
  module/checksum inventories. The production merge still preserves ordered
  parents `54499ba` and `ffd5ef4` and remains unpublished.
- Strict hash verification can require a separately supplied plugin subject and
  review-bundle SHA-256 before extraction. A canonical statement and optional
  explicit-policy Ed25519 verifier support external publisher authentication;
  optional exact statement/subject constraints prevent same-key rollback when
  provisioned through the trusted channel. This repository still supplies no
  private key or publisher identity. The current production-readiness profile
  retains a checksummed denial after valid test signing, binds the exact canonical
  trust-policy digest, and can be independently verified as blocked evidence. That
  historical production-readiness/v2 profile retains its executed-arm64 condition;
  the current user-selected release profile explicitly disables arm64 execution and
  does not treat it as a completion blocker. The live blockers are unpublished
  current/production subjects and both accepted WASI exceptions.
- No fetchable external pool implementation is present. Exact Wago documentation
  reserves pooling for a future plugin, reviewed workers contains no pool source,
  and the refreshed public `wago-org` repository inventory has no pool-named
  repository. This is an unsupported/no-claim result, not compatibility proof.
- Reset eligibility is no longer a blocker locally. Wago transactionally commits
  `Registry.RequireReinstantiation`, dynamically downgrades existing and future
  classes, and the networking extension declares the requirement. Snapshot pool
  tests prove old UDP/TCP state is closed before a fresh lease is published; DNS
  uses the same deterministic instance teardown path.
- DNS is finite, nonblocking, capability-gated, and fully registered. Responses
  are source, destination-port, transaction-ID, checksum, fragmentation, size,
  echoed-question, chain, record, and quota bounded. UDP truncation maps to
  temporary failure because DNS-over-TCP fallback is intentionally not
  implemented in ABI v1.
- lneto's high-level TCP/UDP `Read`, `Write`, `ReadFrom`, and `WriteTo` use backoff
  loops and may block. The concrete namespace imports none of them. UDP uses
  adapter-owned bounded queues and lneto frame codecs. TCP is safely serialized
  through the namespace lock and uses only exported immediate `tcp.Handler`
  state/buffer methods plus `Listener.TryAccept`; a source test rejects accidental
  calls to `tcp.Conn.Read`, `Write`, `Flush`, `StackBlocking`, or `StackGo`.
  Closing an accepted stream releases quota immediately. Direct slot reuse is
  unsafe while lneto's private accepted list still owns the connection; the next
  bounded egress service probe performs that bookkeeping, reports one maintenance
  operation even without a frame, and makes the slot reusable.
- lneto `StackAsync` serializes operations under its own mutex. The adapter now
  bounds every ingress/egress attempt, but a short egress byte budget below the
  configured maximum frame cannot safely probe a potentially smaller packet
  because `EgressEthernet` requires a full MTU-sized destination before examining
  pending work. Such calls fail closed as would-block without consuming output.
- lneto declares Go 1.24. TinyGo 0.41.1 is now installed; TinyGo tests with
  `GOWORK=off` and a TinyGo custom Wago CLI build both pass for this repository.
  This is a validated local toolchain result, not a claim that every lneto
  platform or upstream TinyGo issue is resolved.
- Arm64 execution is optional for the current user-selected release profile.
  `ARM64_EXECUTION=skip` records `skipped-disabled` without retaining or claiming
  an executed binary; auto and required modes remain available for profiles that
  choose native or QEMU execution.
- WASI `origin/main` at `1a7eeb2` is audited. The two new commits change only
  `.github/workflows/ci.yml` and `README.md`; the implementation-tree inventory
  is byte-identical to the pin. Production Wago `97e6f91` must match the exact
  `p1.TestWASIApps` matrix: four named passes and four named native faults with
  equal fault address/PC and matching `runtime.sigpanic` return PC. A 6,719-byte
  reduction proves the host callback is never entered and identifies Wago's
  synchronous-host register-ABI indirect-call path. Wago review `5c7f76db`
  fixes it and passes all eight cases, so the remaining work is exact Wago review,
  integration, publication, and production adoption rather than a WASI pin move.

## Verification

Production protocol outcomes remain green. The complete recursion-18
pre-ledger-amend release gate passed at net subject
`b485ccac594cd2269f5d844fe232a6cb7fe19d83` with current-main review evidence:

- Plugin `go test ./... -count=1`, `GOWORK=off go test ./... -count=1`,
  `go test -race ./... -count=1`, `go vet ./...`, and `go list ./...` — pass.
  `go mod tidy` produces no module-file changes. `GOWORK=off tinygo test ./...`
  also passes with TinyGo 0.41.1.
- Backend DNS tests prove finite A/AAAA/CNAME query/result ownership, exact
  resource/queued-byte/work accounting, deterministic service-budget retries and
  timeout, policy denial, RCode and truncation mapping, exact echoed-question
  correlation, reachable-chain filtering, duplicate suppression, conflict/loop
  rejection, malformed compression/resource handling, record bounds, port reuse,
  cancellation, close races, and namespace cleanup.
- Instance DNS tests prove transactional table/readiness rollback, copied record
  validation, cancellation, generation retirement, stale/wrong-kind/cross-instance
  rejection, lifecycle cleanup, and concurrent close safety.
- Checked DNS host tests prove the registered six-function table, exact-instance
  resolution, capability denial, fixed query/record encoding, output non-mutation
  on AGAIN/EOF/errors, pre-work range/overlap/reserved-byte rejection, actual
  lneto success/NXDOMAIN/server-failure/timeout/truncation paths, bounded poll
  readiness/service, policy/quota/kind/isolation, cancel/close, cleanup, and
  fuzz-safe malformed memory.
- The committed 3-second recursion-16 gate executed 111,975 inputs/corpus 82
  for `FuzzDNSWireResponse`, 905,640/corpus 117 for `FuzzDNSV1Layouts`,
  109,035/corpus 18 for `FuzzGuestDNSMemory`, and 1,120,081/corpus 23 for shared
  `FuzzV1Layouts`; all passed.
- That gate measured 122.3 ns/op for guest UDP poll, 119.7 ns/op for guest TCP
  poll, and 20.56 ns/op for the UDP queue. All three report 0 B/op and
  0 allocs/op; timing remains informational rather than a release threshold.
- Accepted-stream maintenance tests prove close releases quota immediately while
  retaining lneto's private accepted entry, one operation-bounded no-frame egress
  service reclaims it, and a second actual connection reuses the sole pool slot.
  Backend and guest targeted tests pass repeatedly and under race.
- Source scan confirms lneto imports remain confined to `internal/backend/lneto`;
  guest-facing layers expose no lneto types. The source guard remains the only
  textual match for forbidden `tcp.Conn.Read`/`Write`/`Flush`, `StackBlocking`,
  or `StackGo` names.
- The merged Wago `src/wago` suite passes with the temporary helper for main's
  unrelated missing `trapCode`; focused worker/lifecycle/class race tests and
  `internal/genfacade` pass, and the helper is removed. `Instance` remains 776
  bytes on linux/amd64.
- Networking's new worker/class tests pass repeatedly and under race: linked
  workers receive exact host identity, own UDP/TCP/DNS resources, retire before
  class replacement is published, survive an intentionally panicking close hook
  without leaks, and release worker quota after callback-validation failure.
- lneto `GOWORK=off go test ./... -count=1` — pass.
- Standard-Go and TinyGo 0.41.1 custom Wago CLIs blank-importing
  `github.com/wago-org/net/register` build and emit byte-for-byte identical JSON.
  Inspection reports exactly capabilities `net.dns`, `net.info`, `net.tcp`,
  `net.udp` and 24 imports: one core, six DNS, six UDP, and eleven TCP.
- `GOWORK=off tinygo test ./...` passes; the linked native-JIT worker lifecycle
  integration remains standard-Go/race-only under `!tinygo`, while the complete
  production plugin is included in the TinyGo custom CLI build. A standard-Go
  `linux/arm64` package cross-build and arm64 smoke test-binary cross-compile pass.
  No native/QEMU runner is installed on this host, so execution is recorded as
  `skipped-no-runner`, not as arm64 runtime validation.
- The isolated reviewed WASI upstream audit proves only README/CI changed and
  requires implementation inventory SHA-256
  `5c2878e91b26177ddf8361c2618d0258b9b622e129b1688e4faf272ae851788c`. Both
  reviewed and pinned production inputs match the exact four-pass/four-fault
  matrix under Go 1.24.4; the matcher rejects other packages, tests, panics,
  timeouts, extra selections, and address/PC drift. The separate exact-object
  Wago fix audit verifies `5c7f76db`, trigger SHA-256
  `3d93d0329b190e98c4956e0abe05039954f8bf61a22f833bf5a40af5798f668d`, the
  focused regression, and a full passing reviewed WASI suite.
- Current integrated Wago `d556b20f` passes the complete standard-Go suite,
  focused preview-1/managed-wrapper/exact-slot race tests, TinyGo `src/wago`, and
  all eight current WASI `cbdb9b32` cases. Its exact chain uses upstream main
  `ff04a6b1`, benchmark-only parent `bbaa494e`, authoritative lifecycle ancestor
  `1a912c69`, patch-equivalent fix `16163fb8`, managed child `59ce1c13`, and
  exact-slot child `d556b20f`.
- Current networking review `362ddf81` passes standard Go, race, vet, and TinyGo
  against exact Wago `d556b20f`. Inspection grants ordinary networking only
  `host.imports` and `instance.lifecycle`, retains four capabilities and 24
  imports, and proves direct/managed UDP/TCP/DNS cleanup. External workers
  `1e913975` passes its own standard Go/race/vet checks and a real linked child
  retires all networking state.
- Seven source-object packs now bind production net/Wago/lneto/WASI plus current
  net/Wago/workers revisions, trees, and parent lists. Pack-only reconstruction
  passes complete networking standard Go, five focused external-worker race
  repetitions, vet, workers standard Go/race/vet, TinyGo, and byte-identical
  four-capability/24-import CLI inspection.
- The publication topology audit refreshes Wago/workers/net refs, observes Wago
  main `7fbc00a` and workers main `1e913975`, requires workers availability, and
  reports current Wago/net plus production merge as unpublished review-only
  objects. Pooling remains unsupported after exact docs/source/org inventory.
- The recursion-18 three-second fuzz run completed 60,072 DNS-wire,
  1,118,234 DNS-layout, 106,491 guest-DNS-memory, and 1,174,353 shared-layout
  executions. Benchmarks measured 119.8 ns/op guest UDP poll, 119.1 ns/op guest
  TCP poll, and 20.16 ns/op UDP queue, all at 0 B/op and 0 allocs/op.
- The complete release script passed from clean tracked trees, removed its
  temporary Wago helper, retained evidence only under ignored `.wago`, and left
  production/current review trees clean. It emitted schema-v1 provenance with 56
  artifacts, two accepted WASI exceptions, one arm64 limitation, provenance
  SHA-256 `c77fc534620d2dfa29ce574e364460b861fad8d855faaae6c0a782c1a260c1e6`,
  and bundle SHA-256
  `d9fe77b9cd2735222245b1873ad5edf2617e26ce915a8b99e3965f60f476d3bb`.
  Standalone directory/archive verification and all seven exact source-pack
  policies pass. `.audit` remains limited to the three production repositories.
- Recursion-19 targeted verification passes: release-provenance deterministic
  export/verification tests cover first-class review subjects, publication
  overclaim rejection, correct/wrong strict bundle hashes, missing strict inputs,
  and directory rejection. The complete pack-only current review gate passes with
  `GOPROXY=off`, an initially empty `GOMODCACHE`, no acquired module payload,
  exact module/checksum inventory, standard Go, five linked-child race runs, vet,
  workers Go/race/vet, TinyGo, and byte-identical four-capability/24-import
  inspection. The production custom CLI and complete standard-Go suite also pass.
- Recursion-20 targeted release-provenance tests pass under standard Go and
  TinyGo: canonical statements are byte-identical, contain no signature or
  publisher-identity field, reject directory generation, require explicit
  canonical Ed25519 policy, reject wrong signatures and discovery-shaped key IDs,
  and bind signed fields back to the archive. The readiness profile reports the
  exact five current blocker IDs and becomes ready only after adopted/published
  subjects, executed arm64, and zero exceptions are supplied. The actual CLI was
  exercised against the recursion-19 archive with a local test-only key and
  emitted the same deterministic denial; no test key is tracked or trusted.
- Recursion-21 targeted release-provenance tests require matching optional
  statement-digest and subject trust constraints, preserve unconstrained key-only
  signed review, and reject constraint drift before archive acceptance. Committed
  exact-byte interoperability vectors accept only the valid raw Ed25519 case and
  reject altered canonical statement and signature cases; the vector private key
  is not tracked. Canonical readiness receipt tests prove exact input hashes,
  ordered blockers, deterministic atomic rewrite, and an adjacent checksum. The
  actual strict script against the recursion-20 bundle returned status 1, retained
  a checksum-valid denial receipt, and reported the same five blocker IDs.
- Recursion-22 targeted release-provenance tests bind the exact canonical
  trust-policy SHA-256 through signed verification and strict decisions, verify
  ready and blocked retained receipts without the archive, reject stale sidecars,
  noncanonical JSON, and wrong subject/statement/policy constraints, and validate
  every exact byte and digest in the public synthetic receipt vectors.
- Recursion-23 targeted release-provenance tests bind and retain the exact raw
  signature SHA-256 alongside statement, canonical policy, provenance, archive,
  subject, algorithm, and opaque key label; prove deterministic receipt and
  sidecar rewrites; independently verify all four required selection constraints;
  reject stale checksums and noncanonical JSON; and validate every listed byte,
  digest, positive outcome, tamper case, and wrong-constraint outcome in the
  public synthetic trusted-distribution receipt vectors.
- Recursion-24 targeted release-provenance tests freshly recompute v2 readiness
  from the original signed inputs, require an exact canonical intermediary
  receipt, preserve deterministic atomic sidecars and all five blockers, verify
  both retained receipt pairs independently under five explicit constraints,
  reject stale checksums and individually valid wrong links, preserve v1
  compatibility, and validate every listed byte and linked ready/blocked/tamper/
  wrong-link outcome in the public synthetic complete-chain vectors.
- The complete recursion-22 pre-ledger-amend release gate passed at net subject
  `1fe687af90070065a6e7da3502414b11f4ca001c` after every moving ref was
  refreshed and all production/current/older repositories were clean. Three-second
  fuzz runs completed 97,879 DNS-wire, 1,080,333 DNS-layout, 117,940
  guest-DNS-memory, and 1,162,826 shared-layout executions. Benchmarks measured
  123.4 ns/op guest UDP poll, 119.7 ns/op guest TCP poll, and 20.33 ns/op UDP
  queue, all at 0 B/op and 0 allocs/op. Arm64 execution remained
  `skipped-no-runner`. The schema-v2 bundle retained 57 artifacts, two accepted
  exceptions, one limitation, review-only current subjects, unpublished
  production Wago, and disabled hosted automation. Provenance SHA-256 was
  `74b236d31e14dfca39b767efb3635a57981f7b396d99fa1fca5d91f515449c6c`,
  bundle SHA-256 was
  `07761552205e860eaaf2498d0748aa9ee83b51bf7305df4fa462acd8c3f2e95b`,
  and unsigned statement SHA-256 was
  `0e81243712998f3ff43e9ea5c3443419353bd8a14762479977fda3f0db3f74b1`.
- The complete recursion-19 pre-ledger-amend release gate passed at net subject
  `59a5035024560c1290ff8d620f79ba4f293a59f6`. Its first topology attempt exposed
  a transient GitHub organization API HTTP 502; the final subject adds three
  bounded retries for transient 429/5xx/network failures and the rerun passed
  without weakening final failure handling. Three-second fuzz runs completed
  129,646 DNS-wire, 954,267 DNS-layout, 114,152 guest-DNS-memory, and 1,106,528
  shared-layout executions. Benchmarks measured 122.2 ns/op guest UDP poll,
  121.1 ns/op guest TCP poll, and 20.63 ns/op UDP queue, all at 0 B/op and
  0 allocs/op. Arm64 execution remained `skipped-no-runner`.
- Schema-v2 provenance contains 57 artifacts, first-class current review subjects,
  `current_plugin=review-only`, `production_wago_merge=unpublished`,
  `publisher_authentication=external-required`, and
  `hosted_release_automation=disabled`. It has two accepted WASI exceptions, one
  arm64 limitation, provenance SHA-256
  `437d3597d2b9aa5edbd6b812a114bdaf2cecbba5e99d5c5253c5339545c914ec`, and
  bundle SHA-256
  `15d3b15360f0426a7c239cc92e3f1157117aa73ea07c3300f6a6317cff7e3ce7`.
  Standalone archive verification checks the supplied bundle hash before
  extraction; all seven exact source-pack policies and the cold-cache review gate
  pass. Root and all production/current/older review repositories remain clean.

## Performance baselines

Focused resource-table baselines on linux/amd64, Ryzen 7 8845HS, Go 1.24.4:

- lookup: 6.057 ns/op, 0 B/op, 0 allocs/op;
- close 1 live resource: 205.9 ns/op;
- close 64 live resources: 3.289 us/op;
- close 1024 live resources: 45.556 us/op.

The fixed UDP queue round trip remains allocation-free and measured 20.63 ns/op
in the recursion-19 release run. The complete pointer-backed guest poll paths,
including checked memory, scoped service quota, coordinator scan, and event/result
encoding, measured 122.2 ns/op for UDP and 121.1 ns/op for TCP,
both at 0 B/op and 0 allocs/op. The old two heap-backed quota
tokens are gone; the benchmark also avoids value-to-interface boxing that was not
intrinsic to a pointer-backed runtime host module. Timing remains load-sensitive
and is not a release threshold.

## Security review

Guest-visible UDP, TCP, and DNS expose only opaque handles, checked endpoint/
result/event layouts, and stable statuses. DNS uses fixed inline normalized names,
disjoint checked creation, atomic type-tagged records, stable statuses, exact
response correlation, and output non-mutation on AGAIN/EOF/error. TCP and DNS
were advertised only after their complete binding tables, rollback paths,
kind-specific closes, independent capabilities, and actual-backend integration
were tested together. Every call resolves exact instance identity; stale, wrong-
kind, cross-instance, zero, or forged handles fail closed. Policy
defaults deny unmatched and privileged endpoint classes; deny rules are order-
independent and IPv4-mapped IPv6 cannot cross family rules. Quotas have no
unlimited sentinel, reject exact limit overflow without arithmetic wrap, and
clean pending or committed state on close. Backend text never becomes guest ABI.
Runtime reset eligibility now prevents physical-instance reuse from bypassing
that close path between class leases.

Packet-link and UDP datagram storage are fixed and cleared on close; failed fills,
full queues, and insufficient budgets do not partially commit frames or payloads.
The concrete backend performs no hidden retry and cannot exceed a service
operation attempt budget. UDP rejects fragmented or bad-checksum traffic, enforces
bind/send authority separately, and retains no caller slices. TCP validates all
ranges before creation or byte consumption, writes descriptors atomically,
rolls back failed connect/accept outputs, and leaves outputs unchanged on AGAIN
or EOF. Readiness stores only generation-checked handles, bounds scans/events/
service calls independently, removes stale registrations without exposing raw
pointers, and is unregistered
before explicit handle retirement.

Remaining risks are publishing the exact production Wago merge without rewriting
its two parent histories; publishing the exact current-main Wago/networking review
subjects before adoption; the absence of a separately reviewable pool plugin;
lneto lacking a public immediate accepted-entry detach API so safe TCP slot reuse
remains one explicitly charged service probe after close; the intentionally
unsupported DNS-over-TCP fallback; and hosted release automation after immutable
Wago publication. The release gate
documents, machine-records, and narrowly checks the unchanged WASI native
preview-1 exception rather than hiding it. The review bundle carries complete
selected source trees and proves pack/object/tree/policy consistency; strict mode
can bind trusted subject and archive hashes. Canonical detached statement
verification can authenticate a key and enforce exact anti-rollback selection.
The retained trusted-distribution receipt binds exact verified inputs and supports
later integrity checks, while the linked v2 readiness receipt binds that evidence
to a recomputed decision. Independent complete-chain verification proves byte
integrity and exact linkage only; neither receipt is a signature, fresh
cryptographic/archive verification, publisher identity, or fresh readiness
assessment. Publisher identity, private-key custody, signature publication,
trust-policy provisioning, and the signed trusted channel remain external.

## Next recursion

1. Re-fetch publication refs and check whether exact production fix `5c7f76db`,
   refreshed current Wago `d556b20f`, and networking `362ddf81` have immutable
   upstream refs; do not treat local review branches as publication.
2. If production fix `5c7f76db` becomes fetchable, prepare a clean exact fixed
   production worktree, update production selection explicitly, remove the two
   exception cases only after the complete strict gate passes with zero faults,
   and preserve `97e6f91` plus its ordered parents as ancestors.
3. Adopt current Wago/networking reviews only after immutable fetchability is
   proven. Keep arm64 execution explicitly disabled unless a later release profile
   opts back into it.
4. If publication remains unavailable, improve only evidence that can be produced
   locally—such as a complete strict rerun on the refreshed current-review
   packs—without inventing publisher identity, another receipt schema, or a false
   production-ready claim.

After any supportable slice, run the committed release gate and recurse only if a
new thread can make concrete progress toward the long-term completion criteria.

## Audit recursion update — 2026-07-12 iteration 1

### Completed work

1. `d454d64` — `fix: guard destructive release output paths`
   - Added centralized Go artifact-path validation for source-object export.
   - Replaced destructive in-place rebuilds with temp-sibling generation plus atomic directory promotion.
   - Rejected `/`, `$HOME`, the plugin repo root, configured source repos, their ancestors, the active working directory, and symlinked paths that resolve through those locations.
   - Added shell defense-in-depth checks for `scripts/release-source-objects.sh` and `scripts/release-signoff.sh`.
   - Added table-driven safety tests plus replacement/preservation regressions.
2. `b93095b` — `fix: retire terminal DNS transport state`
   - Split terminal DNS handle state from active transport state.
   - Retired `byPort` dispatch and shared UDP port leases before publishing DNS success/failure.
   - Rejected late DNS ingress for non-pending/non-waiting queries.
   - Added regressions for duplicate/late responses, cancellation, timeout, parser failure, transport retirement, deterministic port reuse, and idempotent close.
   - Documented that `MaxQueries` still limits live guest handles until `close`.
3. `HEAD` — `fix: bound TCP adapter allocation from configuration`
   - Removed the theoretical `streams` slice preallocation based on `MaxOutboundStreams + MaxListeners*AcceptBacklog`.
   - Switched validation arithmetic to `uint64`, added explicit checked helpers, and simulated 32-bit representability tests.
   - Added eager-allocation bounds for listener pool storage and kept adapter stream-registry seeding to a small fixed hint.
   - Added a TCP adapter-creation benchmark alongside the existing outbound connect benchmark.

### Remaining work

Unresolved P1/P2 work from the audit prompt still includes at least:
- immutable root configuration snapshots,
- immutable `Extension.Info()` results,
- fail-closed authority helpers plus restrictive DNS suffix API cleanup,
- endpoint-transition API narrowing,
- empty-network lifecycle semantics,
- service byte-budget semantics,
- DNS option-order determinism,
- low-level `Imports` cleanup,
- closed-resource graph clearing,
- allocation-reduction follow-up work (resource-table close scratch removal, TCP/UDP/DNS reuse work, service composition),
- README and documentation reorganization,
- `wago.json` capability keyword cleanup,
- lifecycle serialization proof or attachment state machine.

### Exact tests run

Focused after each slice:
- `go test ./internal/releaseprovenance ./internal/cmd/release-source-objects`
- `bash -n scripts/release-source-objects.sh scripts/release-signoff.sh scripts/release-review-bundle.sh`
- `go test ./internal/backend/lneto/dns`
- `go test ./internal/backend/lneto/tcp`

Broad validation at recursion end:
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `scripts/check-source-boundaries.sh`
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`
- `tinygo test ./...` → blocked on this host (`tinygo: command not found`)

### Benchmark results

Initial focused baselines before changes:
- `BenchmarkAdapterTryConnectClose`: 515.1 / 539.3 / 551.8 ns/op, 1416 B/op, 6 allocs/op
- `BenchmarkAdapterTryBindClose`: 269.3 / 295.2 / 274.1 ns/op, 640 B/op, 3 allocs/op
- `BenchmarkAdapterTryResolveClose`: 410.9 / 390.5 / 391.6 ns/op, 1408 B/op, 1 alloc/op
- `BenchmarkTableCloseLive/resources=1024`: 44809 / 44513 / 45621 ns/op, 157408 B/op, 1037 allocs/op
- `BenchmarkGuestDNSPoll`: 94.20 / 94.61 / 94.71 ns/op, 0 allocs/op
- `BenchmarkGuestUDPPoll`: 120.1 / 115.0 / 115.8 ns/op, 0 allocs/op
- `BenchmarkGuestTCPPoll`: 114.8 / 115.2 / 113.0 ns/op, 0 allocs/op

Post-change hot-path reruns:
- `BenchmarkAdapterNew`: 2751 / 2705 / 2868 ns/op, 19832 B/op, 36 allocs/op
- `BenchmarkAdapterTryConnectClose`: 545.7 / 547.6 / 534.2 ns/op, 1416 B/op, 6 allocs/op
- `BenchmarkAdapterTryResolveClose`: 420.5 / 424.7 / 418.3 ns/op, 1408 B/op, 1 alloc/op

Interpretation:
- The TCP allocation fix eliminated the configuration-amplified eager `streams` slice reservation; the steady-state outbound connect path stayed at 1416 B/op and 6 allocs/op.
- DNS transport-retirement changes preserved the single-allocation query-create baseline.
- No performance claim is justified yet beyond removal of the pathological theoretical-capacity allocation hazard.

### Discovered follow-up issues / blockers

- `tinygo` is unavailable on the current host, so the required TinyGo validation remains an external environment blocker for this recursion.
- `scripts/release-signoff.sh` now has shell defense-in-depth path checks, but the broader release-output flow still deserves a later maintainability review if more artifact paths become caller-selectable.

### Next three proposed atomic commits

1. `fix: snapshot networking configuration`
2. `fix: clone extension metadata results`
3. `fix: make authority helpers fail closed`

## Audit recursion update — 2026-07-12 iteration 2

### Completed work

1. `5e8dddf` — `fix: snapshot networking configuration`
   - Deep-copied root `net.Config` at the extension boundary, including policy slices plus `Limits`, `Readiness`, and `StaticIPv4` pointees.
   - Added regressions proving post-construction caller mutation cannot invalidate later registration or instance attachment.
   - Added a race-oriented regression that mutates caller-owned config concurrently with `runtime.Use` and repeated instantiation to prove the extension no longer aliases caller-owned mutable state.
2. `6a450ae` — `fix: clone extension metadata results`
   - Made `Extension.Info()` return a deep clone of every mutable collection instead of a shared manifest-backed result.
   - Added mutation and concurrent-call aliasing regressions covering authors, tags, and compatibility engines.
3. `HEAD` — `fix: make authority helpers fail closed`
   - Made `tcp.AllowListeners()`, `udp.AllowServer()`, and `dns.AllowSuffixes()` reject empty input instead of broadening authority implicitly.
   - Added explicit `tcp.AllowAllListenerPorts()` and `udp.AllowAllServerPorts()` helpers for intentional nonprivileged all-port grants.
   - Added registration and authority regressions proving the new helpers stay explicit and do not restore unrelated default authority.

### Remaining work

Unresolved P1/P2 work from the audit prompt still includes at least:
- endpoint-transition API narrowing,
- empty-network lifecycle semantics,
- service byte-budget semantics,
- DNS option-order determinism,
- low-level `Imports` cleanup,
- closed-resource graph clearing,
- allocation-reduction follow-up work (resource-table close scratch removal, TCP/UDP/DNS reuse work, service composition),
- README and documentation reorganization,
- `wago.json` capability keyword cleanup,
- lifecycle serialization proof or an explicit attachment state machine.

### Exact tests run

Broad validation at recursion end:
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `scripts/check-source-boundaries.sh`
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`
- `tinygo test ./...` → blocked on this host (`tinygo: command not found`)

### Benchmark results

- No hot-path benchmarks were rerun for this slice.
- This slice changed configuration snapshotting, metadata cloning, and authority-option validation only; it did not intentionally change packet, poll, DNS transport, or TCP stream hot paths.
- Iteration-1 benchmark baselines remain the latest measured hot-path numbers until a later slice changes those paths again.

### Discovered follow-up issues / blockers

- `tinygo` is still unavailable on the current host, so required TinyGo validation remains an external environment blocker.
- Empty helper rejection is an intentional host Go API tightening, not a guest ABI change; broader public docs still need the planned README/documentation refresh.

### Next three proposed atomic commits

1. `fix: narrow endpoint transition authority`
2. `fix: make empty-network lifecycle semantics explicit`
3. `fix: validate service byte-budget semantics`

## Audit recursion update — 2026-07-12 iteration 3

### Completed work

1. `3592b33` — `fix: narrow endpoint transition authority`
   - Replaced the overly general endpoint-transition helper with a narrower `CheckPortAllocation` policy check that only widens a port-zero request on the original local bind address.
   - Updated the UDP bind path to use the narrowed helper before publishing an ephemeral socket.
   - Added policy regressions proving zero is not accepted as a concrete allocation result and explicit concrete-port denies still win.
2. `42807b9` — `fix: make empty-network lifecycle semantics explicit`
   - Made protocol-free networks return from `Register` before initializing instance state, attaching lifecycle hooks, or forcing `RequireReinstantiation`.
   - Added regressions proving an empty network exposes no imports or capabilities, leaves reset policy unchanged, and stays lifecycle-inert across class acquisition and release.
   - Kept configured selective networks unchanged: once any protocol module is selected, shared state still initializes normally.
3. `HEAD` — `fix: validate service byte-budget semantics`
   - Documented `ServiceBudget.Bytes` as a conservative full-frame bound: short egress budgets fail closed as would-block without probing pending output.
   - Added a core regression proving short egress byte budgets neither invoke output producers nor emit frames.
   - Added UDP, TCP, and DNS regressions proving queued egress work survives a short full-frame budget and is emitted once an exact full-frame budget is provided.
   - Updated root config snapshot regressions to register a minimal internal protocol module now that protocol-free networks intentionally remain lifecycle-inert.

### Remaining work

Unresolved P1/P2 work from the audit prompt still includes at least:
- DNS option-order determinism,
- low-level `Imports` cleanup,
- closed-resource graph clearing,
- allocation-reduction follow-up work (resource-table close scratch removal, TCP/UDP/DNS reuse work, service composition),
- README and documentation reorganization,
- `wago.json` capability keyword cleanup,
- lifecycle serialization proof or an explicit attachment state machine.

### Exact tests run

Targeted validation during the slice:
- `go test ./internal/policy ./internal/backend/lneto/udp`
- `go test ./... -run 'TestEmptyNetworkLeavesLifecycleAndResetPolicyUnchanged|TestPublicSelectiveCompositionMatrix'`
- `go test ./internal/backend/lneto/core ./internal/backend/lneto -run 'TestShortEgressByteBudgetFailsClosedWithoutProbingOutput|TestProtocolEgressSurvivesShortFullFrameBudget'`

Broad validation at recursion end:
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `scripts/check-source-boundaries.sh`
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`
- `tinygo test ./...` → blocked on this host (`tinygo: command not found`)

### Benchmark results

- No hot-path benchmarks were rerun for this slice.
- This slice changed authority validation shape, empty-network lifecycle gating, and service-budget documentation/regressions only.
- Iteration-1 benchmark baselines remain the latest measured hot-path numbers until a later slice intentionally changes those paths.

### Discovered follow-up issues / blockers

- `tinygo` is still unavailable on the current host, so required TinyGo validation remains an external environment blocker.
- The selective builder is now explicitly lifecycle-inert when no protocol is selected, but the separate low-level `Imports` helper still needs its planned cleanup so both host entry points stay equally explicit.

### Next three proposed atomic commits

1. `fix: make DNS option ordering deterministic`
2. `fix: clean low-level Imports surface`
3. `fix: clear closed resource graph state`

## Audit recursion update — 2026-07-12 iteration 4

### Completed work

1. `d970b17` — `fix: make DNS option ordering deterministic`
   - Made DNS resolver selection commute with `WithConfig`: `Resolver(...)` now records only the explicit server choice, `WithConfig(...)` records the exact storage override, and final registration combines them deterministically.
   - Preserved the documented special cases: resolver-only registration still installs finite defaults, while an explicit zero-valued `WithConfig(Config{})` still suppresses storage even if a resolver is supplied.
   - Added focused DNS option regressions covering both option orders and the explicit-zero override case.
2. `305db3e` — `fix: clean low-level Imports surface`
   - Added explicit `InfoImports()` for the low-level stateless `abi_version` surface.
   - Tightened `Imports(config)` so only the zero configuration remains accepted; any configured policy, quota, readiness, or namespace state now fails closed and returns no imports instead of implying a lifecycle-aware surface that the low-level path cannot provide.
   - Updated focused root/TCP/DNS regressions and the architecture/ABI docs to make the low-level info-only surface explicit.
3. `ab45b30` — `fix: clear closed resource graph state`
   - Cleared released quota-charge storage and retained buffers from closed UDP sockets, closed TCP listeners/streams, and terminal/closed DNS queries so finished resources stop retaining queued packet/record storage and released accounting state.
   - Kept concurrency-safe owner/local fields intact after close where the race tests require them, while still clearing nil-able connection pointers, queue storage, packet/record retention, and reusable slot/account state.
   - Added focused regressions proving closed UDP/TCP/DNS resources no longer retain released charge state or buffered packet/record storage.

### Remaining work

Unresolved P1/P2 work from the audit prompt still includes at least:
- allocation-reduction follow-up work (resource-table close scratch removal, TCP/UDP/DNS reuse work, service composition),
- README and documentation reorganization,
- `wago.json` capability keyword cleanup,
- lifecycle serialization proof or an explicit attachment state machine.

### Exact tests run

Targeted validation during the slice:
- `go test ./dns -run TestResolverAndConfigComposeIndependentOfOptionOrder`
- `go test ./... -run 'TestInfoImportsStayCoreOnlyAndRejectConfiguredState|TestTCPBindingsAreRegisteredOnlyAsCompleteTable|TestDNSBindingsAreRegisteredOnlyAsCompleteTable'`
- `go test ./internal/backend/lneto/udp ./internal/backend/lneto/tcp ./internal/backend/lneto/dns -run 'TestAdapterExchangeTruncationPortLeaseAndClose|TestAcceptedCloseRetainsSlotUntilChargedMaintenance|TestConnectResetBeforeEstablishment|TestDNSBoundedQueryRecordsAndQuotaLifecycle'`

Broad validation at recursion end:
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `scripts/check-source-boundaries.sh`
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`
- `tinygo test ./...` → blocked on this host (`tinygo: command not found`)

### Benchmark results

- No hot-path benchmarks were rerun for this slice.
- This slice changed DNS option folding, the host-only low-level import surface, and closed-resource cleanup state only.
- The earlier hot-path benchmark baselines remain the latest measured numbers until the allocation-reduction slice lands.

### Discovered follow-up issues / blockers

- `tinygo` is still unavailable on the current host, so required TinyGo validation remains an external environment blocker.
- An initial close-graph cleanup attempt that nulled owner/local references regressed the race suite; the final implementation keeps those concurrency-sensitive references stable while still clearing released accounting state and retained packet/record buffers.

### Next three proposed atomic commits

1. `perf: remove resource-table close scratch allocation`
2. `perf: reduce protocol reuse allocations`
3. `fix: make lifecycle serialization explicit`

## Audit recursion update — 2026-07-12 iteration 5

### Completed work

1. `6d0f41e` — `perf: remove resource-table close scratch allocation`
   - Reworked `internal/resource.Table.Close` to detach and close live resources incrementally instead of allocating a temporary `[]Resource` proportional to the live count.
   - Added a focused allocation regression proving close-scratch allocation no longer scales with the live resource count and a preloaded close benchmark that now stays flat at one small allocation regardless of 1, 64, or 1024 live resources.
   - Kept reverse-creation close order, idempotence, and concurrent exactly-once teardown semantics intact.
2. `a8a8559` — `perf: reduce protocol reuse allocations`
   - Reused lazily-created UDP datagram backing storage across bind/close cycles without reusing direct socket object identities, preserving stale host-pointer safety while cutting steady-state bind/close to one allocation.
   - Reused lazily-created TCP listener pool storage and outbound stream buffer backing across close/reopen cycles without reintroducing configuration-amplified eager allocation or reusing direct listener/stream object identities.
   - Reused DNS overflow-record backing for oversized record caps while preserving direct query identity safety and existing inline-record behavior; added focused allocation regressions for UDP, TCP, and DNS overflow reuse plus reran the allocation-sensitive open/close benchmarks.
3. `HEAD` — `fix: make lifecycle serialization explicit`
   - Documented that `State.mu` is the one attachment lifecycle mutex and that `Manager.Detach` intentionally unpublishes state before teardown.
   - Added focused manager regressions proving detach removes the state from fresh lookups before teardown completes, yet still waits for in-flight `WithLock` operations and `Poll` visitors to return before closing resources.
   - Updated the architecture notes so the attachment/teardown serialization contract is explicit evidence rather than an implicit implementation detail.

### Remaining work

Unresolved P1/P2 work from the audit prompt still includes at least:
- TinyGo broad-validation repair: `tinygo test ./...` now runs on this host but currently fails in `internal/releaseprovenance/sourceobjects_test.go` because `newSourceObjectFixture` and `fixtureSourceObjectSets` are defined only in `verify_test.go`, which is guarded by `//go:build !tinygo`.
- shared service-composition allocation follow-up work,
- README and broader documentation reorganization/cleanup,
- `wago.json` capability keyword cleanup.

### Exact tests run

Targeted validation during the slice:
- `go test ./internal/resource`
- `go test ./internal/resource -run 'TestTableClose(AvoidsLiveCountScratchAllocation|IsDeterministicIdempotentAndJoinsErrors|ConcurrentCloseIsExactlyOnce)$'`
- `go test ./internal/resource -run '^$' -bench 'BenchmarkTableClose(Preloaded|Live)$' -benchmem`
- `go test ./internal/backend/lneto/udp ./internal/backend/lneto/tcp ./internal/backend/lneto/dns`
- `go test ./internal/backend/lneto/udp ./internal/backend/lneto/tcp ./internal/backend/lneto/dns -run 'Test(AdapterTryBindCloseReusesDatagramBacking|ListenerAndConnectReuseReduceSteadyStateAllocations|ResolveCloseReusesOverflowRecordBacking|AcceptedCloseRetainsSlotUntilChargedMaintenance|DNSRetryTimeoutPolicyLimitsAndReuse|AdapterExchangeTruncationPortLeaseAndClose)$'`
- `go test ./internal/backend/lneto/udp ./internal/backend/lneto/tcp ./internal/backend/lneto/dns -run '^$' -bench 'Benchmark(AdapterTryBindClose|AdapterTryBindCloseZeroPayload|AdapterTryResolveClose|AdapterTryListenClose|AdapterTryConnectClose)$' -benchmem`
- `go test ./internal/instance/core`
- `go test ./internal/instance/core -run 'Test(DetachUnpublishesBeforeSerializedTeardownCompletes|PollVisitorSerializesDetachUntilVisitorReturns|ConfiguredNamespacesAreQuotaOwnedIsolatedAndGenerationSafe)$'`

Broad validation at recursion end:
- `go test ./...` — pass
- `go test -race ./...` — pass
- `go vet ./...` — pass
- `scripts/check-source-boundaries.sh` — pass
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...` — pass
- `tinygo test ./...` — fails in `internal/releaseprovenance/sourceobjects_test.go` with undefined `newSourceObjectFixture` / `fixtureSourceObjectSets` because their only definitions live in `verify_test.go` behind `//go:build !tinygo`

### Benchmark results

- `go test ./internal/resource -run '^$' -bench 'BenchmarkTableClose(Preloaded|Live)$' -benchmem`
  - `BenchmarkTableClosePreloaded/resources=1` → `37.32 ns/op`, `64 B/op`, `1 allocs/op`
  - `BenchmarkTableClosePreloaded/resources=64` → `704.9 ns/op`, `64 B/op`, `1 allocs/op`
  - `BenchmarkTableClosePreloaded/resources=1024` → `11176 ns/op`, `64 B/op`, `1 allocs/op`
- `go test ./internal/backend/lneto/udp ./internal/backend/lneto/tcp ./internal/backend/lneto/dns -run '^$' -bench 'Benchmark(AdapterTryBindClose|AdapterTryBindCloseZeroPayload|AdapterTryResolveClose|AdapterTryListenClose|AdapterTryConnectClose)$' -benchmem`
  - `BenchmarkAdapterTryBindClose` → `212.9 ns/op`, `320 B/op`, `1 allocs/op`
  - `BenchmarkAdapterTryBindCloseZeroPayload` → `209.6 ns/op`, `320 B/op`, `1 allocs/op`
  - `BenchmarkAdapterTryListenClose` → `231.9 ns/op`, `400 B/op`, `3 allocs/op`
  - `BenchmarkAdapterTryConnectClose` → `444.7 ns/op`, `936 B/op`, `4 allocs/op`
  - `BenchmarkAdapterTryResolveClose` → `505.9 ns/op`, `1408 B/op`, `1 allocs/op`
- DNS default open/close remains at one allocation because direct query wrapper identities are still intentionally not reused; the new overflow-record reuse regression covers the formerly avoidable extra allocation when `MaxRecords` exceeds the inline storage.

### Discovered follow-up issues / blockers

- TinyGo is now installed on this host (`tinygo version 0.41.1 linux/amd64`), so the prior environment blocker is gone; the remaining TinyGo failure is now a concrete repository issue in the release-provenance tests.
- Direct host-side resource pointers must remain stale after close. The allocation-reduction work therefore reuses backing storage lazily but does **not** recycle UDP socket, TCP listener/stream, or DNS query object identities.
- Fully resolving the allocation follow-up still needs a separate pass over shared service composition and any other non-resource open/close hot spots.

### Next three proposed atomic commits

1. `fix: make tinygo source-object tests self-contained`
2. `perf: reduce shared service composition allocations`
3. `docs: clean README, ABI notes, and capability keywords`

## Audit recursion update — 2026-07-12 iteration 6

### Completed work

1. `617ab35` — `fix: keep source-object provenance tests off tinygo`
   - Extracted the Git-backed source-object fixture helpers into a dedicated standard-Go helper file and gated `internal/releaseprovenance/sourceobjects_test.go` with `//go:build !tinygo`, matching the rest of the release-provenance integration suite.
   - Revalidated the source-object directory-safety and deterministic replacement/export tests under standard Go.
   - Reran `tinygo test ./internal/releaseprovenance`; the package now passes because TinyGo keeps compiling the release-provenance package while excluding the Git/exec integration tests that its test runtime cannot execute.
2. `4655565` — `perf: reduce shared service composition allocations`
   - Reworked `internal/namespace/core.ComposeNamespace` so the common empty, single-protocol, and UDP/TCP/DNS three-protocol cases keep services inline instead of allocating a per-service map.
   - Reworked root backend assembly to collect installed protocol services in stack-backed inline scratch for the current three-module surface before publishing the immutable composed namespace.
   - Added exact allocation regressions plus focused composition benchmarks proving the common compose path now stays at one allocation, with the map-backed overflow path retained for larger future compositions.
3. `HEAD` — `docs: clean README, ABI notes, and capability keywords`
   - Cleaned README low-level import wording so the core-only `InfoImports` / zero-config `Imports(Config{})` path is explicitly limited to `wago_net.abi_version`, while configured UDP/TCP/DNS resources remain Runtime-owned.
   - Updated `docs/abi-v1.md` and `docs/architecture.md` to reflect the split ABI packages and the inline common-case namespace-composition storage used by the current three-protocol surface.
   - Normalized `wago.json` capability keywords to the actually shipped surfaces only and added a metadata regression that rejects reintroducing unsupported protocol tags.

### Remaining work

- No remaining July 12, 2026 audit P1/P2 items are currently known. The release publication/adoption backlog above remains real, but it is separate from this networking audit completion gate.

### Exact tests run

Targeted validation during the slice:
- `go test ./internal/releaseprovenance -run 'Test(PrepareSourceObjectOutputDirectoryRejectsUnsafePaths|PrepareSourceObjectOutputDirectoryAllowsArtifactSubdirectory|ExportSourceObjects(ReplacesExistingDirectoryAtomically|IsDeterministic)|ReplaceDirectoryAtomicallyPreservesPreviousOutputOnFailure)$'`
- `tinygo test ./internal/releaseprovenance`
- `go test ./internal/namespace/core ./... -run 'Test(NamespaceCompositionAvoidsPerServiceHeapGrowthForCommonSelections|InstallNamespaceServicesAvoidsPerProtocolScratchForCommonSelections)$'`
- `go test ./internal/namespace/core -run '^$' -bench 'Benchmark(ComposeNamespace|ResolveNamespace(Service|Base))$' -benchmem`
- `go test ./ -run 'TestExtensionMetadataAndABIBinding$'`

Broad validation at recursion end:
- `go test ./...` — pass
- `go test -race ./...` — pass
- `go vet ./...` — pass
- `scripts/check-source-boundaries.sh` — pass
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...` — pass
- `tinygo test ./...` — pass

### Benchmark results

- `go test ./internal/namespace/core -run '^$' -bench 'Benchmark(ComposeNamespace|ResolveNamespace(Service|Base))$' -benchmem`
  - `BenchmarkComposeNamespace/empty` → `29.60 ns/op`, `128 B/op`, `1 allocs/op`
  - `BenchmarkComposeNamespace/single` → `29.16 ns/op`, `128 B/op`, `1 allocs/op`
  - `BenchmarkComposeNamespace/three` → `39.86 ns/op`, `128 B/op`, `1 allocs/op`
  - `BenchmarkComposeNamespace/overflow` → `154.6 ns/op`, `464 B/op`, `3 allocs/op`
  - `BenchmarkResolveNamespaceService` → `5.037 ns/op`, `0 B/op`, `0 allocs/op`
  - `BenchmarkResolveNamespaceBase` → `4.317 ns/op`, `0 B/op`, `0 allocs/op`

### Discovered follow-up issues / blockers

- TinyGo broad validation is no longer blocked, but its test runtime still cannot execute the Git-backed release-provenance integration fixtures directly: before the `!tinygo` gate, `tinygo test ./internal/releaseprovenance` failed with repeated `files setting not implemented` errors while the source-object tests tried to drive temporary Git repositories.
- The new allocation regressions are intentionally standard-Go-only. TinyGo's test runtime does not provide comparable allocation accounting, so those tests return early there while the full TinyGo package matrix still passes.
- Direct host-side resource pointers must remain stale after close. The shared-composition allocation reduction therefore reuses only service-selection scratch and immutable inline service storage; it does **not** revive closed UDP/TCP/DNS direct object identities.
- No further July 12 audit blockers are known after the final broad validation below.

### Next three proposed atomic commits

- None required for the July 12, 2026 networking audit. If work continues, resume from the longer-term release publication/adoption backlog tracked earlier in this file.

## Audit recursion update — 2026-07-15 iteration 3

### Completed work

1. `4f27d71` — `test: keep release fixtures TinyGo compatible`
   - Moved canonical inspection-evidence fixture generation out of the standard-Go-only verifier file into the common test build without changing generated bytes.
   - Standard Go and TinyGo now compile and exercise the same 12-bundle inspection fixture contract.
2. `a280895` — `core: make panic completion portable across TinyGo`
   - Separated panic capture from re-propagation for attachment and detachment completion so TinyGo cannot re-enter the same recovering defer.
   - Preserved cleanup-before-repanic, deterministic `ErrTeardownPanicked` waiter results, panic payloads, same-instance waiting, unrelated-instance progress, and exactly-once lifecycle record retirement.
   - Made duplicate attachment/detachment completion idempotent and retained the first detachment result.
3. `HEAD` — `docs: synchronize release evidence and teardown policy`
   - Synchronized architecture, CI, release-signoff, and ledger policy with all 12 custom CLI bundles, 40 discovered fuzz targets in 30 packages, and 168 discovered benchmarks in 49 packages.
   - Documented non-empty sorted benchmark discovery, exact `100ms` / `count=1` / `cpu=1` / `benchmem` evidence, complete per-target logs, provenance tamper rejection, typed-nil fail-closed namespace resolution, and teardown panic semantics.
   - Added a scheduled/manual hosted benchmark-smoke job that retains the manifest, canonical detail, and logs, plus a static regression tying CI and documentation to `scripts/benchmark-smoke.sh` and the current release policy.

### Completion checklist

- Workstreams A–F: complete.
- Workstream G CI/release documentation synchronization: complete.
- Criteria 1–21: complete and covered by implementation/regression validation.
- Criterion 22 repository matrix: complete; `tinygo test ./...` now passes, including panic lifecycle tests under TinyGo.
- Criterion 23: clean tracked working tree is required after this commit and final validation.
- Complete strict release signoff remains externally blocked before repository validation because `.wago/wago-production-97e6f91` is dirty at `M src/wago/bottomref_test.go`. This pre-existing external worktree must not be cleaned, reset, overwritten, or bypassed with `ALLOW_DIRTY=1`.

### Current evidence snapshot

- 40 discovered fuzz targets in 30 packages passed with `FUZZTIME=1s`.
- 168 discovered benchmarks in 49 packages passed with `100ms`, `count=1`, `cpu=1`, and `-benchmem`.
- 12 custom CLI bundles (eleven granular plus all-protocol) passed byte-identical standard-Go/TinyGo inspection.
- `tinygo test ./...` passed. The previously observed informational lneto DHCPv6 channel panic line did not recur in the passing full rerun.
- Hosted release automation is not activated or claimed; publication, adoption, signed-channel, arm64-profile, and WASI readiness policy remains as documented.

### Remaining work

No repository-owned workstream or completion criterion from this hardening request is currently known to remain. The only strict release-attempt prerequisite observed in this workspace is the externally owned dirty production-Wago worktree above. Re-run the exact strict command after that worktree becomes independently clean; do not recurse merely to modify external worktrees or manufacture a passing release result.
