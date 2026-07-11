# Wago networking implementation ledger

## Mission

Deliver a production-quality family of capability-gated Wago networking plugins
with a stable backend-neutral guest ABI, deterministic per-instance ownership,
and lneto as the first backend.

## Invariants

- Networking imports are nonblocking except for bounded `poll`.
- Guest memory is validated centrally; guest slices never outlive a host call.
- Each instance owns one generation-safe resource table.
- Handles are opaque, kind-checked, stale-safe, and never Go pointers.
- Statuses are stable numeric values; Go error text is not guest ABI.
- Raw IP, raw Ethernet, and capture authority are denied by default.
- Endpoint policy is enforced at every authority-changing operation.
- Instance cleanup is deterministic and never relies on guest destructors or finalizers.
- Each recursive iteration produces exactly three atomic commits unless the project completes earlier.

## Pinned analysis revisions

- Wago main: `8ef17eeb3a74f4982ef64d125282c1dab8c8e240` (2026-07-10).
- Wago lifecycle branch: `01569366a38e8f577c2764a11941908351cc9181` on `net/instance-close-hooks`.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: `3df6c766ad00e83b314da799dbf9a77b409ad19d`.

## Current architecture

The external plugin module owns only the core import module `wago_net`. Protocols
will use independently owned modules such as `wago_net_udp` and `wago_net_tcp`
because Wago rejects two extensions claiming one import module. The core currently
provides `abi_version`, `net.info`, the ABI version constant, and the common status
taxonomy. `internal/abi` provides checked guest-memory ranges and the fixed 32-byte
IPv4/IPv6 address codec.

`internal/resource` now provides O(1), kind-checked, generation-safe opaque handles
with never-reused table identities, safe slot retirement before generation wrap,
reverse-creation O(live) cleanup, fuzz coverage, and focused benchmarks. Each core
`Extension` owns an `internal/instance.Manager` that attaches one resource table to
each exact Runtime-created `*wago.Instance`, resolves host callers through the
optional `wago.InstanceHostModule`, and removes state in `BeforeClose`. The map is
extension-local, not process-global. No policy, namespace, poller, protocol, or
lneto backend is implemented yet.

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
  architecture documentation, recursive skill, and durable ledger. Standard,
  race, and vet checks pass.
- `b3ec3be03dd809cf85e6faaa805ff8cd687d934a` — added centralized
  uint64-checked ranges, atomic output helpers, the fixed v1 IPv4/IPv6 codec,
  unit tests, and fuzz targets.
- `c005703fa32790def6befa076fcd7f9b14f20b31` — added typed generation-safe
  resource handles, strict stale/forged/wrong-kind/reuse/cross-table rejection,
  rollover retirement, deterministic cleanup, fuzzing, and benchmarks.
- `01569366a38e8f577c2764a11941908351cc9181` — added Wago's optional
  `InstanceHostModule` facade and exact identity tests for Runtime and low-level
  host calls while preserving HostModule-only mocks and TinyGo's HostFunc shape.
- `HEAD` (`net: attach per-instance lifecycle state`) — attached extension-local
  state and one resource table per exact Runtime instance, with deterministic
  failed-setup, repeated/concurrent close, isolation, cross-instance rejection,
  and `ResetReinstantiate` release coverage.

## Active work

Recursion 2 is complete with exactly three commits. The next recursion should add
endpoint policy, per-instance quota accounting, and backend-neutral namespace
contracts in three commits.

## Ordered backlog

1. Reconcile and upstream the Wago close-hook/identity changes against PR #232.
2. Add endpoint/domain policy and quota primitives.
3. Define backend-neutral namespace interfaces.
4. Construct an lneto namespace and deterministic in-memory Ethernet link.
5. Add bounded manual service, readiness, and poll.
6. Implement and harden UDP before TCP and DNS.

## Blockers and discovered prerequisites

- Wago main's `src/wago` tests do not compile because `cross_instance_test.go`
  references an undefined `trapCode` helper. A temporary test-only helper proves
  the lifecycle change itself passes; this unrelated upstream defect is not part
  of the lifecycle commit.
- Wago PR #232 (`plugin-improvements`) independently contains broader
  `BeforeClose`/`AfterClose` lifecycle work, while Wago main lacks both focused
  lifecycle commits. Reconcile the working branch with that PR before upstreaming;
  do not silently overwrite its design.
- `ResetMemorySnapshot` reuses one physical instance across leases and therefore
  does not invoke close hooks on release. The plugin now explicitly documents this
  policy as unsupported and requires `ResetReinstantiate`, but Wago still lacks a
  reset hook or extension eligibility control that could enforce the restriction.
- lneto's high-level TCP/UDP `Read`, `Write`, `ReadFrom`, and `WriteTo` use backoff
  loops and may block. Lower-level handlers are usable for some paths, but UDP
  packet-connection and registration cleanup need focused nonblocking APIs.
- lneto currently declares Go 1.24. TinyGo support is tracked by lneto issue #138
  and must not be claimed by this suite yet.

## Verification

Latest outcomes after recursion 2:

- Plugin `go test ./... -count=1` — pass.
- Plugin `go test -race ./... -count=1` — pass.
- Plugin `go vet ./...` — pass.
- `FuzzSlice` for 3 seconds — pass, 973,485 executions.
- `FuzzDecodeAddressV1` for 3 seconds — pass, 1,070,447 executions.
- `FuzzTableHandles` for 3 seconds — pass, 1,082,770 executions.
- Wago `GOWORK=off go test ./internal/genfacade -count=1` — pass.
- Wago `GOWORK=off go test ./src/wago -count=1` with a temporary uncommitted
  `trapCode` baseline helper — pass.
- Focused Wago lifecycle/identity race tests with the same temporary helper — pass.
- Wago `go vet ./src/wago` with the helper reaches only the five existing
  `possible misuse of unsafe.Pointer` warnings in `instantiate.go`; without the
  helper it first fails on Wago main's unrelated undefined `trapCode` defect.
- lneto `GOWORK=off go test ./... -count=1` — pass.
- Generated custom Wago binary blank-importing `github.com/wago-org/net/register`
  — build pass; `plugin inspect net --json` remains truthful (`net.info` and only
  `wago_net.abi_version`).
- WASI `GOWORK=off go test ./... -count=1` — unchanged existing native SIGSEGV in
  `p1` under Go 1.24.4.
- TinyGo — not installed in this environment.

## Performance baselines

Focused resource-table baselines on linux/amd64, Ryzen 7 8845HS, Go 1.24.4:

- lookup: 6.057 ns/op, 0 B/op, 0 allocs/op;
- close 1 live resource: 205.9 ns/op;
- close 64 live resources: 3.289 us/op;
- close 1024 live resources: 45.556 us/op.

The Wago lifecycle hook still preserves the documented 776-byte `Instance`
footprint. Optional instance identity adds one method to the existing concrete
host-module value and does not change `HostFunc` or the minimal `HostModule`.

## Security review

Current guest-visible code still exposes no handles, endpoints, or packet data;
resource handles and instance state are internal foundations only. Handles contain
no Go pointers, reject wrong table/kind/generation in O(1), invalidate before
backend close, and retire before generation wrap. Instance attachment uses exact
Wago identity and deterministic close hooks rather than a process-global pointer
map. Guest-memory and address hardening remains unchanged. Main risks are enforcing
the `ResetMemorySnapshot` prohibition, designing policy/quotas without confused
deputy paths, and preventing blocking lneto wrappers from entering host imports.

## Next recursion

1. `net: add endpoint policy primitives`
   - Scope: immutable allow/deny rules for IP prefixes, ports, transport direction,
     DNS suffixes, multicast/broadcast/loopback, and explicit privileged defaults.
   - Tests/fuzz: precedence, normalization, wildcard denial, mapped-address safety,
     and authority-changing operation checks.
2. `net: add per-instance quota accounting`
   - Scope: bounded counters for total resources, protocol resources, queued bytes,
     DNS work, and service budgets; reserve/commit/release without underflow or
     leak on failure.
   - Tests/race: concurrent reserve/release, rollback, exact limits, cleanup.
3. `net: define backend-neutral namespace interfaces`
   - Scope: address/endpoint-neutral UDP/TCP/DNS/service contracts with strictly
     nonblocking Try-style operations and no lneto types in guest-facing layers.
   - Tests: compile-time fake backend plus semantic contract tests; no protocol
     imports or lneto implementation yet if that would exceed the bounded slice.
