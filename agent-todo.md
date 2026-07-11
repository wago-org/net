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
- Endpoint policy is enforced at every authority-changing operation.
- Instance cleanup is deterministic and never relies on guest destructors or finalizers.
- Each recursive iteration produces exactly three atomic commits unless the project completes earlier.

## Pinned analysis revisions

- Wago fetched main: `7fbc00a57624b26ba8d528d97b419b670e85f64b` (2026-07-11), parent `6070d2d71700b2cca813d7a56f807b0b4bcc2e1b`; its ancestry includes #241 `f23549c` and squashed #232 `de402df`. Current lifecycle review `e44b1baa6eabfba07967a4458fdb56983cb054ae` is based directly on that exact main.
- Wago merged lifecycle/worker branch: `97e6f91e6c822491577faa86f3c30aa5a8fff1e8` on `net/instance-close-hooks`, with ordered parents `54499ba5135f69a062e23a7255f4a408d6cecf8c` and `ffd5ef4b122cbd019897eeea3503789ab5860e4a`.
- External workers main: `1e9139756d8a3c631c59c00b028038c83bfa8341`, pinned as `v0.0.0-20260711080606-1e9139756d8a`. Exact Wago documentation reserves pooling for a future plugin; workers contains no pool implementation, and the refreshed `wago-org` repository inventory exposes no pool-named repository.
- Current networking review: `5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e`, parent `29d59163a500e96f9567f14beeb4f3bb04e6351e`, on production base `d582be74d3cd5da844f530ce5f6f16aa803ed258`.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: `3df6c766ad00e83b314da799dbf9a77b409ad19d`; reviewed `origin/main` at `1a7eeb215229e05bcb0f09d5cb3280d231739def` changes only README/CI files, has an implementation-tree inventory identical to the pin, and still reaches the native preview-1 SIGSEGV, so the release pin remains unchanged.

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
`Extension` owns an `internal/instance.Manager` that attaches one resource table,
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

A current-main Wago review worktree on `net/current-plugin-lifecycle` at
`e44b1baa6eabfba07967a4458fdb56983cb054ae` replays the hardened lifecycle
contract directly onto fetched main `7fbc00a`. `HostImportAccess.CallerResolver`
provides exact, expiring, runtime-scoped caller identity under `host.imports`
without granting `instance.manage`; runtime and origin attach before imported or
local start functions; failed starts close extension state; lifecycle panics are
isolated; and concurrent close callers receive one completed result. Wago now
passes callback parameters/results at exact declared slot widths. Complete
standard-Go, focused race, vet, facade, and TinyGo `src/wago` checks pass.

The current networking review at
`5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e` compiles against that exact Wago
replay. Ordinary networking requests only `host.imports` and
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
- `HEAD` (`net: publish release decision chain interoperability cases`) —
  publishes deterministic synthetic linked ready/blocked, stale-checksum tamper,
  wrong-link, and wrong-constraint cases without storing signature bytes, a key,
  trust root, private key, signed release, production decision, or activation
  claim.

## Active work

Recursion 24 is complete with exactly three bounded atomic commits in the
production networking repository. The strict readiness path now freshly verifies
the original archive, statement, detached signature, and explicit policy; checks
the retained trusted-distribution receipt independently; and emits a new v2
readiness decision only when both evidence paths match exactly. Complete retained
chains can be checked later without original cryptographic inputs while remaining
explicitly distinct from fresh signature/archive verification, publisher
identity, and a new readiness decision. Public synthetic chain vectors cover
linked ready and blocked outcomes, stale checksums, a valid but mismatched opaque
key label, and all five wrong external constraints. No publisher identity,
signed release, trust-root provisioning, production decision, or hosted
automation claim was added. The exact workers subject remains published, while
current Wago/networking reviews and the production ordered-parent Wago merge
remain unpublished. Pooling remains unsupported, native arm64 execution is
unavailable, and both WASI preview-1 exceptions remain active.

## Ordered backlog

1. Upstream the merged Wago lifecycle/reset/identity/worker branch at an immutable
   fetchable ref without rewriting Wago main or either parent history.
2. Publish the current-main Wago lifecycle replay and networking review at exact
   immutable refs, then switch `CURRENT_PLUGIN_ADOPTION=adopted` only after the
   topology audit proves all adopted Wago/net/workers subjects fetchable. Do not
   substitute this for publication of the production merge.
3. Activate hosted release automation only after the production Wago ref is
   fetchable, require executed linux/arm64 smoke on an arm64/QEMU tier, and remove
   the WASI exception only after reviewing and pinning an upstream fix.

## Blockers and discovered prerequisites

- The pinned production Wago line's `src/wago` tests still need a temporary
  test-only `trapCode` helper; current Wago main `7fbc00a` does not have that
  historical defect. The helper is removed by the release gate.
- Wago current main remains `7fbc00a`; the hardened review `e44b1ba` is its direct
  child and Wago owns exact callback slot slicing. Networking `5b444e9` proves
  complete least-authority registration and real external-worker composition.
  Deterministic packs and isolated reconstruction remove moving-ref dependence
  for review, but neither current Wago nor current networking review is fetchable
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
  trust-policy digest, and can be independently verified as blocked evidence. Its
  exact blockers remain unpublished current/production subjects, skipped arm64
  execution, and both accepted WASI exceptions.
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
- The arm64 signoff now cross-compiles a bounded root test binary covering
  metadata plus real UDP/TCP/DNS paths and can execute it natively or through
  `qemu-aarch64`. This linux/amd64 host exposes neither runner, so the committed
  gate truthfully records `skipped-no-runner`; `ARM64_EXECUTION=required` is the
  fatal mode for a real arm64/QEMU tier.
- WASI `origin/main` at `1a7eeb2` is now audited. The two new commits change only
  `.github/workflows/ci.yml` and `README.md`; the implementation-tree inventory
  is byte-identical to the pin, and an isolated exact-object full suite still
  reaches only the known native `p1.TestWASIApps` SIGSEGV. The release pin and
  narrow accepted exception therefore remain unchanged until an actual reviewed
  implementation fix passes.

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
- The isolated reviewed WASI upstream audit proves only README/CI changed,
  requires an identical implementation inventory SHA-256
  `5c2878e91b26177ddf8361c2618d0258b9b622e129b1688e4faf272ae851788c`, and
  still reaches the known native `p1` SIGSEGV. The pinned suite independently
  reaches the same accepted signature under Go 1.24.4; any other failure or a
  passing upstream suite would force re-review.
- The current-main Wago lifecycle replay passes the complete standard-Go suite,
  focused start/failure/close race tests, vet, facade generation checks, and
  TinyGo `src/wago`. It is based directly on `7fbc00a`, preserves #241, and proves
  exact declared callback slot lengths.
- The current networking review passes standard Go, race, vet, and TinyGo against
  exact Wago `e44b1ba`. Inspection grants ordinary networking only `host.imports`
  and `instance.lifecycle`, retains four capabilities and 24 imports, and proves
  direct/managed UDP/TCP/DNS cleanup. External workers `1e913975` passes its own
  standard Go/race/vet checks and a real linked child retires all networking state.
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
unsupported DNS-over-TCP fallback; and obtaining a real arm64/QEMU runner plus
hosted release automation after immutable Wago publication. The release gate
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

1. Re-fetch Wago, net, workers, lneto, and WASI moving refs and re-run the exact
   publication topology audit before proposing any repository change.
2. If the production Wago merge and current Wago/net review subjects have become
   available at immutable refs, adopt them in bounded atomic pin/topology/signoff
   commits while preserving ordered merge parents and least authority.
3. If those external refs remain unavailable and no arm64/WASI prerequisite has
   changed, do not invent another receipt schema or publisher identity. Record
   that fewer than three valid repository commits remain, keep all trees clean,
   and report the external publication/runtime blockers truthfully.

After any supportable slice, run the committed release gate and recurse only if a
new thread can make concrete progress toward the long-term completion criteria.
