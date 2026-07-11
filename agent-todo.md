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
- Wago lifecycle branch: `01569366a38e8f577c2764a11941908351cc9181` on `net/instance-close-hooks`.
- Wago `origin/plugin-improvements`: `ffd5ef4b122cbd019897eeea3503789ab5860e4a` as locally inspected in recursion 3.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: `3df6c766ad00e83b314da799dbf9a77b409ad19d`.

## Current architecture

The root extension owns distinct import modules because Wago assigns one owner
to an entire module. `wago_net` exposes `abi_version` under `net.info`;
`wago_net_udp` exposes complete namespace discovery plus UDP bind/send/receive,
close, and bounded poll under the narrow `net.udp` capability. TCP and DNS
modules remain absent. `internal/abi` provides uint64-checked guest ranges,
disjoint multi-output validation, fixed v1 endpoint/UDP/TCP/poll layouts, and
atomic encoders without exposing lneto types. The reserved 72-byte TCP stream
layout contains handle/local/remote endpoints; the 8-byte partial-I/O result is
written only for ready progress, while AGAIN/EOF leave it unchanged.

`internal/resource` provides O(1), kind-checked, generation-safe opaque handles
with never-reused table identities, safe slot retirement before generation wrap,
reverse-creation O(live) cleanup, fuzz coverage, and focused benchmarks. Each core
`Extension` owns an `internal/instance.Manager` that attaches one resource table,
one bounded readiness coordinator, one immutable compiled policy, and one finite
quota account to each exact Runtime-created `*wago.Instance`. Optional static IPv4
configuration transactionally creates a namespace handle and readiness entry;
UDP handles use the same rollback-safe path. Host callers resolve through optional
`wago.InstanceHostModule`, and `BeforeClose` removes state before poller, resource,
and quota teardown. The map is extension-local, not process-global.

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
are covered. DNS remains truthfully not-supported.

`internal/readiness` provides a finite coordinator per instance resource table.
Registrations preserve exact handle kind, polls are level-triggered and bounded
by scans, event outputs, and namespace service attempts, and stale handles are
removed within the scan budget. Configured namespace and UDP creation add handles
and registrations transactionally; wrong-kind close cannot unregister a valid
handle, and explicit close removes readiness before generation retirement. The
guest poll validates complete output capacity before work, uses per-instance
scratch, and reserves `scans + events + service_attempts` service units for the
call. No poll sleeps or performs an unbounded registration scan.

The companion Wago branch adds `HookRegistry.BeforeClose`, reverse-order
exactly-once invocation, cleanup on failed post-instantiation setup, class
`ResetReinstantiate` coverage, low-level API isolation, and transactional hook
registration without increasing `Instance` size. It also exposes optional exact
host-call instance identity without expanding `HostModule` or changing `HostFunc`.

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
- `HEAD` (`net: define the checked guest TCP ABI`) — fixes reserved v1 TCP stream
  and partial-I/O layouts, disjoint checked ranges, atomic codecs, stable IO
  status semantics, malformed-layout fuzz coverage, and documentation without
  registering an incomplete TCP module.

## Active work

Recursion 7 is complete with exactly three bounded commits. Immediate lneto TCP,
instance-owned listener/stream handles, and the reserved checked guest TCP ABI are
complete internally. `wago_net_tcp` remains absent until every host binding is
implemented and tested together; DNS remains absent and unsupported. Wago
lifecycle reconciliation and reset-policy enforcement remain prerequisites for
upstream production use.

## Ordered backlog

1. Implement all checked TCP host bindings behind unregistered binding tables,
   then expose `wago_net_tcp` and `net.tcp` only when the module is complete.
2. Reconcile and upstream the Wago close-hook/identity changes against PR #232,
   including enforceable reset eligibility for networking extensions.
3. Harden bounded DNS ownership and guest imports before advertising DNS.
4. Complete TinyGo, package, fuzz/race/benchmark, and release signoff.

## Blockers and discovered prerequisites

- Wago main's `src/wago` tests do not compile because `cross_instance_test.go`
  references an undefined `trapCode` helper. A temporary test-only helper proves
  the lifecycle and identity changes pass; the helper is removed after checks.
- Wago PR #232 (`origin/plugin-improvements`, locally `ffd5ef4b`) independently
  contains broader `BeforeClose`/`AfterClose` lifecycle work. Reconcile the branch
  before upstreaming; do not silently overwrite either design.
- `ResetMemorySnapshot` reuses one physical instance across leases and does not
  invoke close or reset hooks. Networking classes require `ResetReinstantiate`.
  Wago still lacks an extension reset hook or eligibility control that can engine-
  enforce this restriction.
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
- lneto declares Go 1.24. TinyGo support remains unproven (issue #138), and TinyGo
  is not installed in this environment.

## Verification

Latest outcomes after recursion 7:

- Plugin `go test ./... -count=1` and `GOWORK=off go test ./... -count=1` — pass.
- Plugin `go test -race ./... -count=1` — pass, including immediate TCP exchange,
  concurrent TCP operations versus namespace close, instance ownership, UDP guest
  operations, readiness, quota, and lifecycle.
- Plugin `go vet ./...` — pass.
- Post-commit `FuzzV1Layouts` for 3 seconds — pass, 1,183,199 executions with
  the 22-entry cached corpus while exercising TCP create/I/O range validation and
  codecs; the pre-commit run discovered five of those inputs.
- `BenchmarkGuestUDPPoll` three-run sample — 171.8–905.8 ns/op, 120 B/op,
  3 allocs/op on the recorded Ryzen 7 8845HS host. The allocation-free internal
  UDP queue baseline remains 21.53–47.70 ns/op, 0 B/op, 0 allocs/op.
- Post-commit `BenchmarkGuestUDPPoll` — 173.6 ns/op, 120 B/op, 3 allocs/op;
  `BenchmarkUDPDatagramQueueRoundTrip` — 20.51 ns/op, 0 B/op, 0 allocs/op.
- Guest tests prove capability denial, unavailable namespace truthfulness,
  two-instance/cross-handle isolation, policy denial, exact quota, empty and
  truncated datagrams, queue full, failed-output rollback, stale close, rebind,
  level transitions, service bounds, stale poll removal, and cleanup.
- Source scan — lneto imports remain confined to `internal/backend/lneto`; guest,
  ABI, instance, policy, quota, resource, and readiness layers expose no lneto
  types. The TCP adapter contains no host-facing `tcp.Conn.Read`, `Write`,
  `Flush`, `StackBlocking`, or `StackGo` call.
- Wago `GOWORK=off go test ./internal/genfacade -count=1` — pass.
- Wago `GOWORK=off go test ./src/wago -count=1` and focused lifecycle/identity
  race tests pass with the temporary missing `trapCode` helper; helper removed.
- lneto `GOWORK=off go test ./... -count=1` — pass.
- Generated custom Wago CLI blank-importing `github.com/wago-org/net/register`
  builds and `plugin inspect net --json` reports exactly `net.info`, `net.udp`,
  `wago_net.abi_version`, and the six complete `wago_net_udp` imports including
  bounded `poll`; TCP and DNS remain absent.
- Plugin, Wago, lneto, and WASI trees are clean after the three commits; ignored
  `go.work` continues to redirect local Wago and lneto dependencies.
- TinyGo remains unavailable (`command -v tinygo` produced no path). WASI native
  `p1` SIGSEGV under Go 1.24.4 was not rerun and remains an unrelated audit issue.

## Performance baselines

Focused resource-table baselines on linux/amd64, Ryzen 7 8845HS, Go 1.24.4:

- lookup: 6.057 ns/op, 0 B/op, 0 allocs/op;
- close 1 live resource: 205.9 ns/op;
- close 64 live resources: 3.289 us/op;
- close 1024 live resources: 45.556 us/op.

The fixed UDP queue round trip remains allocation-free at 21.53–47.70 ns/op.
The complete guest poll path, including checked memory, quota tokens, coordinator
scan, and event/result encoding, measured 171.8–905.8 ns/op with 120 B/op and
3 allocs/op in the latest concurrent three-run sample. Reducing quota-token
allocations is an optimization opportunity, not a correctness blocker.

## Security review

Guest-visible UDP now exposes only opaque handles, checked endpoint/result/event
layouts, and stable statuses. Reserved TCP layouts likewise contain no backend
identity and are not advertised before complete bindings exist. Every call
resolves exact instance identity, and
stale, wrong-kind, cross-instance, zero, or forged handles fail closed. Policy
defaults deny unmatched and privileged endpoint classes; deny rules are order-
independent and IPv4-mapped IPv6 cannot cross family rules. Quotas have no
unlimited sentinel, reject exact limit overflow without arithmetic wrap, and
clean pending or committed state on close. Backend text never becomes guest ABI.

Packet-link and UDP datagram storage are fixed and cleared on close; failed fills,
full queues, and insufficient budgets do not partially commit frames or payloads.
The concrete backend performs no hidden retry and cannot exceed a service
operation attempt budget. UDP rejects fragmented or bad-checksum traffic, enforces
bind/send authority separately, and retains no caller slices. Readiness stores
only generation-checked handles, bounds scans/events/service calls independently,
removes stale registrations without exposing raw pointers, and is unregistered
before explicit handle retirement.

Remaining risks are engine enforcement of the `ResetMemorySnapshot` prohibition,
correctly reconciling Wago PR #232, finishing all checked TCP guest bindings before
advertising the capability, lneto listener-slot reuse occurring on bounded
listener maintenance after accepted-stream close, ensuring future protocol
adapters repeat policy checks and pair every quota reservation, reducing guest
poll quota-token allocations, and completing TinyGo validation when available.

## Next recursion

1. `net: add checked TCP creation host functions`
   - Scope: implement unregistered TinyGo-compatible binding functions for TCP
     namespace discovery, listen, connect, and finish-connect. Prevalidate all
     complete ranges before allocation, write stream descriptors on OK/IN_PROGRESS,
     and roll back handles on impossible encoding failures.
   - Tests: malformed memory, denied policy, exact quota, stale/cross/wrong handles,
     failed-output rollback, connect progress, and two-instance isolation.
2. `net: add checked TCP stream host functions`
   - Scope: implement unregistered accept, partial read/write, shutdown, separate
     listener/stream close, and TCP poll bindings using exact State operations.
     AGAIN/EOF must not mutate outputs; no guest slice may outlive the call.
   - Tests: partial metadata, would-block, EOF, accept rollback, close races,
     malformed-memory fuzzing, bounded poll readiness, and benchmarks.
3. `net: expose the complete TCP capability`
   - Scope: register `wago_net_tcp` and narrow `net.tcp` only after the binding
     table is complete, keep low-level `Imports` stateless, update package/docs,
     and verify custom Wago inspection exposes exactly the intended modules.
   - Tests: capability denial, full guest two-namespace exchange, TinyGo-compatible
     signatures, race/fuzz/package signoff, and truthful absence of DNS.

After those exactly three commits, run combined verification, update this ledger,
and recurse again if the long-term completion criteria remain unmet.
