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
- Wago lifecycle branch: `dd82ec9a8963463e6516bf803bec58b3a89b89b3` on `net/instance-close-hooks`.
- lneto main: `ab1a0c735a8b534a1d6322a3e245bc11a09431e7` (2026-07-10).
- WASI audit: `3df6c766ad00e83b314da799dbf9a77b409ad19d`.

## Current architecture

The external plugin module owns only the core import module `wago_net`. Protocols
will use independently owned modules such as `wago_net_udp` and `wago_net_tcp`
because Wago rejects two extensions claiming one import module. The core currently
provides `abi_version`, `net.info`, the ABI version constant, and the common status
taxonomy. `internal/abi` provides checked guest-memory ranges and the fixed 32-byte
IPv4/IPv6 address codec. No namespace, handle table, policy, poller, protocol, or
lneto backend is implemented yet.

Wago main has no deterministic per-instance close hook. The companion Wago branch
adds `HookRegistry.BeforeClose`, reverse-order exactly-once invocation, cleanup on
failed post-instantiation setup, class `ResetReinstantiate` coverage, low-level API
isolation, and transactional hook registration without increasing `Instance` size.

## Completed work

- `dd82ec9a8963463e6516bf803bec58b3a89b89b3` — added deterministic Wago
  instance-close hooks. Targeted tests and race tests pass when a temporary helper
  is supplied for the unrelated missing `trapCode` test helper on Wago main.
- `eb0b79af59af5402f8d39c436123bbd33c019be7` — scaffolded the external plugin,
  packaging manifest, self-registration, ABI version/status definitions,
  architecture documentation, recursive skill, and durable ledger. Standard,
  race, and vet checks pass.
- `HEAD` (`net: add checked guest-memory and address codecs`) — added centralized
  uint64-checked ranges, atomic output helpers, the fixed v1 IPv4/IPv6 codec,
  unit tests, and fuzz targets.

## Active work

Recursion 1 is complete. The next recursion should implement resource identity,
the missing host-call instance identity prerequisite, and per-instance lifecycle
attachment in three commits.

## Ordered backlog

1. Integrate the Wago close-hook change into the plugin's selected Wago revision.
2. Add generation-safe, kind-safe per-instance resource handles.
3. Expose optional Runtime instance identity to host imports without expanding the
   minimal `HostModule` interface.
4. Add per-instance networking state and close-hook cleanup.
5. Add endpoint/domain policy and quota primitives.
6. Define backend-neutral namespace interfaces.
7. Construct an lneto namespace and deterministic in-memory Ethernet link.
8. Add bounded manual service, readiness, and poll.
9. Implement and harden UDP before TCP and DNS.

## Blockers and discovered prerequisites

- Wago main's `src/wago` tests do not compile because `cross_instance_test.go`
  references an undefined `trapCode` helper. A temporary test-only helper proves
  the lifecycle change itself passes; this unrelated upstream defect is not part
  of the lifecycle commit.
- Wago PR #232 (`plugin-improvements`) independently contains broader
  `BeforeClose`/`AfterClose` lifecycle work. The focused lifecycle branch should
  be reconciled with that PR before upstreaming.
- `ResetMemorySnapshot` reuses one physical instance across leases and therefore
  does not invoke close hooks on release. Resource-owning plugins need reset hooks,
  a class eligibility restriction, or forced reinstantiation before supporting
  that reset policy.
- Wago `HostModule` exposes memory but not public instance identity. Per-instance
  host-call state needs a small runtime surface or another explicit attachment
  mechanism; do not use a process-global pointer map.
- lneto's high-level TCP/UDP `Read`, `Write`, `ReadFrom`, and `WriteTo` use backoff
  loops and may block. Lower-level handlers are usable for some paths, but UDP
  packet-connection and registration cleanup need focused nonblocking APIs.
- lneto currently declares Go 1.24. TinyGo support is tracked by lneto issue #138
  and must not be claimed by this suite yet.

## Verification

Latest outcomes:

- `cd .audit/lneto && go test ./...` — pass.
- `cd .audit/wasi && go test ./...` — fails with an existing native execution
  SIGSEGV in `p1` under the current Go 1.24 environment.
- `cd .audit/wago && go test ./src/wago` — baseline compile failure: undefined
  `trapCode` in `cross_instance_test.go`.
- Wago lifecycle tests with temporary baseline helper — pass.
- Wago lifecycle race tests with temporary baseline helper — pass.
- `go test ./...` in the plugin — pass.
- `go test -race ./...` in the plugin — pass.
- `go vet ./...` in the plugin — pass.
- `go test ./internal/abi -run '^$' -fuzz '^FuzzSlice$' -fuzztime=3s` — pass,
  630,644 executions.
- `go test ./internal/abi -run '^$' -fuzz '^FuzzDecodeAddressV1$' -fuzztime=3s`
  — pass, 754,480 executions.
- `go vet ./src/wago` — reports existing unsafe-pointer warnings in
  `instantiate.go`; no new warning is attributable to the lifecycle hook.
- TinyGo — not installed in this environment.

## Performance baselines

No plugin benchmarks exist yet. The Wago lifecycle hook preserves the documented
776-byte `Instance` footprint and adds no field or allocation to instances when
no hook is registered. The memory/address helpers are allocation-free by
inspection and tests, but benchmark baselines have not yet been recorded.

## Security review

Current guest-visible code exposes no handles, endpoints, or packet data. The ABI
version and status taxonomy add no network authority. Guest-memory ranges use
uint64 arithmetic, valid zero-length end ranges, and validate full outputs before
mutation. The address codec rejects reserved bits, family ambiguity, IPv4-mapped
IPv6, invalid IPv4 tails, and structurally invalid scope/flow fields. Main risks
are future per-instance state attachment, lifecycle behavior under snapshot pool
reuse, and preventing blocking lneto wrappers from entering host imports.

## Next recursion

1. `net: add generation-safe resource handles`
   - Scope: typed kinds, zero invalid, generation rollover, O(1) live tracking.
   - Tests: stale, forged, wrong-kind, reuse, cross-table, repeated close.
2. `wago: expose optional host-call instance identity`
   - Scope: an additive interface implemented by Wago's concrete HostModule;
     preserve existing mocks and the minimal HostModule contract.
   - Tests: Runtime and low-level host imports see the exact calling instance;
     existing HostModule-only mocks remain source-compatible.
3. `net: attach per-instance lifecycle state`
   - Scope: extension-local instance map, one resource table per instance,
     deterministic BeforeClose cleanup, no process-global state.
   - Tests: isolation, failed setup, class release, concurrent close, cross-instance
     handle rejection.
