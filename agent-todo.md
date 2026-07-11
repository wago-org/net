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

- Wago main: `8ef17eeb3a74f4982ef64d125282c1dab8c8e240` (2026-07-10).
- Wago lifecycle/reset branch: `54499ba5135f69a062e23a7255f4a408d6cecf8c` on `net/instance-close-hooks`.
- Wago `origin/plugin-improvements`: `ffd5ef4b122cbd019897eeea3503789ab5860e4a` as locally inspected in recursion 3.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: `3df6c766ad00e83b314da799dbf9a77b409ad19d`.

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
exactly-once allocation release are concurrency-safe. Instance teardown closes
readiness registration before resources and closes the account last, then clears
abandoned reservations and rejects late work without underflow.

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
are covered. DNS uses adapter-owned immediate IPv4 UDP packets plus lneto DNS codecs,
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
per-instance scratch, and reserve `scans + events + service_attempts` service
units for the call. TCP poll is independently gated by `net.tcp` and does not
require `net.udp`. No poll sleeps or performs an unbounded registration scan.

The companion Wago branch now reconciles deterministic cleanup with the broader
`origin/plugin-improvements` lifecycle model: `BeforeClose` and `AfterClose` run
in reverse order exactly once with shared metadata, failed instantiation emits
isolated error observers and closes any created instance, hook panics cannot skip
resource release, and direct/worker origins are carried without increasing
`Instance` size. Low-level APIs remain hook-free, registration stays
transactional, and optional exact host-call identity does not expand `HostModule`
or change the TinyGo-compatible `HostFunc` shape. `Registry.RequireReinstantiation`
adds a monotonic Runtime aggregate; `Class.ResetPolicy` and `Lease.Release`
downgrade in-place resets whenever an extension owns non-Wasm instance state.
The networking extension declares this requirement, so UDP/TCP resources cannot
cross class leases.

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
- `HEAD` (`net: expose the complete DNS capability`) — registers the six-function
  `wago_net_dns` table under narrow `net.dns`, adds capability and exact metadata
  tests, and updates package and ABI documentation after full integration signoff.

## Active work

Recursion 11 is complete with exactly three bounded networking commits. DNS wire
responses now require exact echoed questions, directly fuzz compressed parsing,
and expose only a unique reachable CNAME chain plus requested terminal addresses.
The complete checked guest table passes actual-backend success/failure/poll/
policy/quota/isolation/cleanup integration and is now registered as
`wago_net_dns` under narrow `net.dns`. Standard Go, race, fuzz, TinyGo, package,
benchmark, source-boundary, and custom inspection checks pass across the plugin
and pinned audit repositories except for the unchanged unrelated WASI native p1
SIGSEGV.

## Ordered backlog

1. Rebase or upstream the local Wago lifecycle/reset commits alongside the final
   form of PR #232 without dropping its worker lifecycle work.
2. Finish release/CI documentation and cross-platform deterministic signoff,
   including the complete fuzz/race/bench/TinyGo/package matrix.
3. Review remaining production-hardening opportunities such as accepted-listener
   slot reuse timing and guest poll allocation reduction without changing ABI
   truth or introducing unbounded work.

## Blockers and discovered prerequisites

- Wago main's `src/wago` tests do not compile because `cross_instance_test.go`
  references an undefined `trapCode` helper. A temporary test-only helper proves
  the lifecycle and identity changes pass; the helper is removed after checks.
- Wago PR #232 (`origin/plugin-improvements`, locally `ffd5ef4b`) remains based on
  the older `0d4f4a4` line and contains worker primitives absent from current main.
  The local branch has reconciled its lifecycle contracts and verified the focused
  worker lifecycle tests, but final upstream integration still requires a careful
  rebase/merge rather than overwriting either history.
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
  Closing an accepted stream releases quota immediately, while lneto's listener
  pool slot becomes reusable during its next bounded accept/service maintenance.
- lneto `StackAsync` serializes operations under its own mutex. The adapter now
  bounds every ingress/egress attempt, but a short egress byte budget below the
  configured maximum frame cannot safely probe a potentially smaller packet
  because `EgressEthernet` requires a full MTU-sized destination before examining
  pending work. Such calls fail closed as would-block without consuming output.
- lneto declares Go 1.24. TinyGo 0.41.1 is now installed; TinyGo tests with
  `GOWORK=off` and a TinyGo custom Wago CLI build both pass for this repository. This is
  a validated local toolchain result, not a claim that every lneto platform or
  upstream TinyGo issue is resolved.

## Verification

Latest outcomes after recursion 11:

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
- Post-change fuzzing, each for 3 seconds: `FuzzDNSWireResponse` passed 134,939
  executions with corpus 44; `FuzzDNSV1Layouts` passed 388,674 with corpus 16;
  `FuzzGuestDNSMemory` passed 21,738 with corpus 6; and shared `FuzzV1Layouts`
  passed 989,077 with corpus 23.
- Current benchmarks: `BenchmarkGuestUDPPoll` 751.0 ns/op, 120 B/op,
  3 allocs/op; `BenchmarkGuestTCPPoll` 637.2 ns/op, 120 B/op, 3 allocs/op; and
  `BenchmarkUDPDatagramQueueRoundTrip` 22.57 ns/op, 0 B/op, 0 allocs/op.
- Source scan confirms lneto imports remain confined to `internal/backend/lneto`;
  guest-facing layers expose no lneto types. The source guard remains the only
  textual match for forbidden `tcp.Conn.Read`/`Write`/`Flush`, `StackBlocking`,
  or `StackGo` names.
- Wago full `src/wago` and `internal/genfacade` tests pass with the temporary
  helper for main's unrelated missing `trapCode`; focused lifecycle/reset/
  identity race tests pass, and the helper is removed. `Instance` remains 776
  bytes on linux/amd64, exactly matching Wago main.
- Focused `origin/plugin-improvements` lifecycle/worker quota tests pass, showing
  the reconciled context/origin contracts remain compatible with that design.
- lneto `GOWORK=off go test ./... -count=1` — pass.
- Standard-Go and TinyGo 0.41.1 custom Wago CLIs blank-importing
  `github.com/wago-org/net/register` build. Inspection reports exactly
  capabilities `net.dns`, `net.info`, `net.tcp`, `net.udp` and 24 imports: one
  core, six DNS, six UDP, and eleven TCP.
- WASI `GOWORK=off go test ./... -count=1` still reaches the known native `p1`
  SIGSEGV under Go 1.24.4 after other packages pass; this remains unrelated.
- Plugin, Wago, lneto, WASI, and temporary inspection worktrees are clean after
  the three commits; ignored `go.work` continues to redirect local Wago and lneto
  dependencies.

## Performance baselines

Focused resource-table baselines on linux/amd64, Ryzen 7 8845HS, Go 1.24.4:

- lookup: 6.057 ns/op, 0 B/op, 0 allocs/op;
- close 1 live resource: 205.9 ns/op;
- close 64 live resources: 3.289 us/op;
- close 1024 live resources: 45.556 us/op.

The fixed UDP queue round trip remains allocation-free and measured 22.57 ns/op.
The complete guest poll paths, including checked memory, quota tokens,
coordinator scan, and event/result encoding, measured 751.0 ns/op for UDP and
637.2 ns/op for TCP, both at 120 B/op and 3 allocs/op in the combined signoff
run. Reducing quota-token
allocations is an optimization opportunity, not a correctness blocker.

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

Remaining risks are upstreaming the local Wago lifecycle/reset commits without
losing PR #232's worker work, lneto listener-slot reuse occurring on bounded
listener maintenance after accepted-stream close, the intentionally unsupported
DNS-over-TCP fallback for truncated responses, reducing guest poll quota-token
allocations, and extending the successful local TinyGo validation to release/CI
platforms.

## Next recursion

1. `wago: integrate lifecycle hooks with worker plugins`
   - Scope: re-verify current Wago main and `origin/plugin-improvements`, then
     rebase or merge the local lifecycle/reset/identity changes without dropping
     worker origins, transactional activation, quotas, or divergent history.
2. `wago: prove worker network reinstantiation cleanup`
   - Scope: add focused worker/class tests showing networking's reset requirement,
     reverse close hooks, panic isolation, and exact instance identity survive the
     reconciled worker lifecycle and retire UDP/TCP/DNS state between leases.
3. `net: add deterministic release signoff`
   - Scope: add reproducible CI/release documentation and scripts for standard Go,
     race, bounded fuzz corpus smoke, benchmarks, TinyGo, package/custom CLI
     inspection, source-boundary scans, and pinned dependency audit checks.

After those exactly three commits, run combined verification, update this ledger,
and recurse again if the long-term completion criteria remain unmet.
