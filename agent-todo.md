# Wago networking implementation ledger

## Mission

Deliver a production-quality family of capability-gated Wago networking plugins
with a stable backend-neutral guest ABI, deterministic per-instance ownership,
and lneto as the first backend.

## Invariants

- Networking imports are nonblocking except for bounded `poll`.
- Guest memory is validated centrally; guest slices never outlive a host call.
- Each instance owns one generation-safe resource table and one finite quota account.
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

The external plugin module owns only the core import module `wago_net`. Protocols
will use independently owned modules such as `wago_net_udp` and `wago_net_tcp`
because Wago rejects two extensions claiming one import module. The guest-visible
surface still provides only `abi_version`, `net.info`, the ABI version constant,
and the common status taxonomy. `internal/abi` provides checked guest-memory
ranges and the fixed 32-byte IPv4/IPv6 address codec.

`internal/resource` provides O(1), kind-checked, generation-safe opaque handles
with never-reused table identities, safe slot retirement before generation wrap,
reverse-creation O(live) cleanup, fuzz coverage, and focused benchmarks. Each core
`Extension` owns an `internal/instance.Manager` that attaches one resource table
and one finite quota account to each exact Runtime-created `*wago.Instance`,
resolves host callers through optional `wago.InstanceHostModule`, and removes
state in `BeforeClose`. The map is extension-local, not process-global.

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
resources before closing the account, then clears abandoned reservations and
rejects late work without underflow.

`internal/namespace` defines backend-neutral endpoints, categorized semantic
failures, UDP/TCP/DNS resources, readiness snapshots, and bounded manual service.
All potentially waiting operations are one-shot `Try` calls with explicit done,
would-block, in-progress, or EOF semantics. Validators cover endpoint family and
scope safety, stream partial I/O, datagram truncation including empty datagrams,
DNS record ownership, and service budget bounds. A compile-time fake backend
exercises the contract. No lneto type or dependency is present in plugin packages.
No concrete namespace, link, poller, or guest protocol imports exist yet.

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
- `HEAD` (`net: define backend-neutral namespace interfaces`) — added neutral
  endpoint/error/UDP/TCP/DNS/readiness/service contracts and compile-time fake
  backend semantic tests without adding lneto or guest imports.

## Active work

Recursion 3 is complete with exactly three bounded commits. The next recursion
should build the deterministic link and first bounded lneto service adapter, then
add a bounded readiness coordinator without exposing protocol imports prematurely.

## Ordered backlog

1. Reconcile and upstream the Wago close-hook/identity changes against PR #232.
2. Add a deterministic bounded packet link and lneto namespace/service backend.
3. Add instance-scoped readiness registration and bounded poll/service coordination.
4. Implement and harden UDP before TCP and DNS.
5. Add guest protocol imports only after policy, quota, memory, readiness, and
   backend semantics are proven together.

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
  loops and may block. Recursion 3 inspected lower handlers only after the neutral
  contracts were designed: UDP handler queue methods and TCP listener `TryAccept`
  are promising, while registration cleanup and a focused nonblocking TCP API
  still need adapter work or upstream changes.
- lneto `StackAsync` serializes stack operations under its own mutex and exposes
  immediate ingress/egress plus start/result DNS operations. The adapter must add
  explicit service budgets and must not turn these calls into unbounded loops.
- lneto declares Go 1.24. TinyGo support remains unproven (issue #138), and TinyGo
  is not installed in this environment.

## Verification

Latest outcomes after recursion 3:

- Plugin `go test ./... -count=1` — pass.
- Plugin `go test -race ./... -count=1` — pass, including concurrent quota tests.
- Plugin `go vet ./...` — pass.
- `FuzzSlice` for 3 seconds — pass, 405,838 executions.
- `FuzzDecodeAddressV1` for 3 seconds — pass, 405,422 executions.
- `FuzzTableHandles` for 3 seconds — pass, 464,732 executions.
- `FuzzPolicyQueries` for 3 seconds — pass, 780,731 executions after the final
  privileged-local-port correction.
- Source/dependency scan — no plugin package imports `github.com/soypat/lneto`.
- Wago `GOWORK=off go test ./internal/genfacade -count=1` — pass.
- Wago `GOWORK=off go test ./src/wago -count=1` with a temporary uncommitted
  `trapCode` helper — pass.
- Focused Wago lifecycle/identity race tests with the helper — pass.
- lneto `GOWORK=off go test ./... -count=1` — pass.
- Generated custom Wago binary blank-importing `github.com/wago-org/net/register`
  — build pass; `plugin inspect net --json` truthfully reports only `net.info` and
  `wago_net.abi_version`.
- Plugin, Wago, lneto, and WASI working trees are clean after the three commits.
- WASI native `p1` SIGSEGV under Go 1.24.4 was not rerun in this slice; it remains
  an unrelated known audit failure from prior recursions.
- TinyGo — not installed.

## Performance baselines

Focused resource-table baselines on linux/amd64, Ryzen 7 8845HS, Go 1.24.4:

- lookup: 6.057 ns/op, 0 B/op, 0 allocs/op;
- close 1 live resource: 205.9 ns/op;
- close 64 live resources: 3.289 us/op;
- close 1024 live resources: 45.556 us/op.

No guest networking hot path exists yet. Policy and quota code is bounded, but
benchmarks should be added when protocol adapters begin invoking them per packet
or per I/O attempt.

## Security review

Current guest-visible code still exposes no handles, endpoints, packets, DNS
names, or protocol operations. Policy defaults deny unmatched requests and all
privileged endpoint classes; deny rules are order-independent and IPv4-mapped
IPv6 cannot cross family rules. Quotas have no unlimited sentinel, reject exact
limit overflow without arithmetic wrap, and clean pending or committed state on
instance close. Backend contracts prohibit retry/backoff loops inside Try methods,
return no backend-owned DNS slices, validate service reports against every budget
dimension, and categorize errors without making backend text guest ABI.

Remaining risks are engine enforcement of the `ResetMemorySnapshot` prohibition,
correctly reconciling Wago PR #232, proving lneto deregistration and close behavior,
ensuring future protocol adapters call policy at every endpoint change and pair
every quota reservation, and making readiness/poll bounded under adversarial load.

## Next recursion

1. `net: add a deterministic bounded packet link`
   - Scope: fixed-capacity ingress/egress frame ownership with one-shot Try methods,
     explicit truncation/queue-full behavior, deterministic close, and no retained
     caller buffers.
   - Tests/fuzz: ordering, exact capacities, rollback on failure, close races, and
     malformed/oversized frames.
2. `net: add bounded lneto namespace service`
   - Scope: own one lneto stack per namespace, adapt the deterministic link, map
     lneto errors into namespace failure categories, implement `TryService` with
     strict packet/byte/operation budgets, and truthfully return not-supported for
     protocol constructors not yet implemented.
   - Tests: deterministic two-namespace packet exchange, exact budget limits,
     no-spin empty service, cleanup, race, and compile-time interface assertion.
3. `net: add bounded readiness coordination`
   - Scope: instance-scoped pollable registration and level-triggered snapshots,
     bounded event output/service attempts, stale resource removal, and no sleeping
     or unbounded scans. Do not add guest poll imports unless the semantics are
     complete enough to advertise truthfully.

After those exactly three commits, run combined verification, update this ledger,
and recurse again if the long-term completion criteria remain unmet.
